from Storage.C2spPush import push_c2sp_with_test_transport, witness_job_deadline
from Storage.Transparency import (
  create_checkpoint_for_on_connection,
  witnesses_for_checkpoint_for,
  polled_checkpoint_for
)
from Storage.TransparencyTree import append_tree_leaf_for
from Storage.TransparencyCutover import (
  begin_cutover_on_connection,
  accept_legacy_seal_on_connection,
  copy_cutover_batch_on_connection
)
from Storage.WitnessRegistry import witness_health
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessKey,
  leaf_hash_for,
  sign_witness,
  verify_witnesses_at
)

fn fixture_signer() -> SigningKeyPair!String do
  case Crypto.signing_from_seed(Bytes.from_hex("6161616161616161616161616161616161616161616161616161616161616161")?) do
    Err(_) -> Err("fixture key failed")
    Ok(value)
  end
end

fn initial(conn :: borrow PgConn) -> Result<(), String> do
  let pair = fixture_signer()?
  append_tree_leaf_for(conn, 1, 0, leaf_hash_for(1, Bytes.from_utf8("legacy"))?)?
  let seal = begin_cutover_on_connection(conn, pair.private_key, pair.public_key.bytes)?
  accept_legacy_seal_on_connection(conn,
    [sign_witness("legacy", pair.private_key, seal)?],
    [WitnessKey { witness_id: "legacy", public_key: pair.public_key.bytes }],
    1)?
  assert(copy_cutover_batch_on_connection(conn, 100, pair.private_key, pair.public_key.bytes)?)
  for index in 1..3 do
    append_tree_leaf_for(conn, 2, index, leaf_hash_for(2, Bytes.from_utf8("account/#{index}"))?)?
  end
  create_checkpoint_for_on_connection(conn, 2, pair.private_key, pair.public_key.bytes)?
  Ok(nil)
end

fn proof() -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL", ""), 1, 2, 5000)?
  assert(witness_job_deadline(pool)? == 0)
  Repo.transaction(pool, fn(conn :: borrow PgConn) -> initial(conn) end)?
  let before = DateTime.to_unix_ms(DateTime.utc_now())
  let due = witness_job_deadline(pool)?
  assert(due >= before + 15000 && due <= DateTime.to_unix_ms(DateTime.utc_now()) + 15000)
  let key = Bytes.from_hex(Env.get("MORSE_C2SP_TEST_PUBLIC_KEY", ""))?
  Pool.execute_values(pool,
    "INSERT INTO transparency_witness_registry (witness_id, public_key, operator, status, software, morse_run, note_name, push_url) VALUES ('external', $1, 'Independent fixture', 'pinned', 'c2sp', false, $2, 'https://witness.example/add-checkpoint')",
    [Binary(key), Text(Env.get("MORSE_C2SP_TEST_NAME", ""))])?
  let endpoint = Env.get("MORSE_C2SP_TEST_URL", "") <> "/add-checkpoint"
  push_c2sp_with_test_transport(pool, "external", endpoint)?
  assert(Json.as_bool(Json.object_get(Json.parse(witness_health(pool)?)?, "threshold_met")?)?)
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let pair = fixture_signer()?
      for index in 3..7 do
        append_tree_leaf_for(conn,
          2,
          index,
          leaf_hash_for(2, Bytes.from_utf8("account/#{index}"))?)?
      end
      create_checkpoint_for_on_connection(conn, 2, pair.private_key, pair.public_key.bytes)?
      Ok(nil)
    end)?
  # The witness already knows size three: the push path must handle its 409,
  # construct a real stored-node consistency proof, and admit the new response.
  push_c2sp_with_test_transport(pool, "external", endpoint)?
  push_c2sp_with_test_transport(pool, "external", endpoint)?
  let current = case polled_checkpoint_for(pool, 2)? do
    None -> return Err("missing current checkpoint")
    Some(value) -> value
  end
  assert(U64.to_int(current.tree_size)? == 7)
  let witnesses = witnesses_for_checkpoint_for(pool, 2, current.sequence)?
  assert(List.length(witnesses) == 1 && Bytes.length(List.head(witnesses).signature) == 72)
  assert(verify_witnesses_at(current,
    witnesses,
    [WitnessKey { witness_id: "external", public_key: key }],
    1,
    U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))?)?)
  assert(Json.as_bool(Json.object_get(Json.parse(witness_health(pool)?)?, "threshold_met")?)?)
  Pool.close(pool)
  Ok(true)
end

test("the directory pushes a migrated RFC log to an independent C2SP witness and admits its current quorum") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
