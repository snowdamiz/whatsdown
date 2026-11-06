from Operations import run_action
from Storage.TransparencyTree import append_tree_leaf_for
from Storage.TransparencyLog import legacy_seal
from Storage.Transparency import store_witness
from Transparency.Merkle import WitnessKey, leaf_hash_for, sign_witness

fn phase(value :: String) -> String!String do
  Json.as_string(Json.object_get(Json.parse(value)?, "phase")?)
end

fn proof() -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL", ""), 1, 2, 5000)?
  # Owns a fresh database supplied by the process proof.
  assert(phase(run_action(pool, "status", 100, "")?)? == "legacy")
  assert(run_action(pool, "rollback", 100, "") == Err("invalid cutover action"))
  case run_action(pool, "prepare", 100, "") do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  let pair = case Crypto.signing_from_seed(Bytes.from_hex("6161616161616161616161616161616161616161616161616161616161616161")?) do
    Err(_) -> return Err("fixture key failed")
    Ok(value) -> value
  end
  let key = Bytes.to_hex(pair.public_key.bytes)
  let frame = "3\n#{key}\n#{key}\n8\n1\n1\ncurrent #{key} Fixture\n-\n0\n-\n2\n1\n1\nlegacy #{key} Fixture"
  let anchor_frame = "4" <> String.slice(frame, 1, String.length(frame)) <> "\n-\n-"
  let relay_frame = "5" <> String.slice(anchor_frame, 1, String.length(anchor_frame)) <> "\n-\n0"
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      append_tree_leaf_for(conn, 1, 0, leaf_hash_for(1, Bytes.from_utf8("legacy fixture"))?)?
      Ok(nil)
    end)?
  let prepared = run_action(pool, "prepare", 100, frame)?
  assert(phase(prepared)? == "sealing")
  assert(run_action(pool, "prepare", 100, frame)? == prepared)
  assert(run_action(pool, "prepare", 100, anchor_frame)? == prepared)
  assert(run_action(pool, "prepare", 100, relay_frame)? == prepared)
  case run_action(pool, "accept", 100, frame) do
    Err(error) -> assert(error == "legacy_seal_quorum_missing")
    Ok(_) -> assert(false)
  end
  let seal = case Repo.transaction(pool, fn(conn :: borrow PgConn) -> legacy_seal(conn) end)? do
    None -> return Err("missing seal")
    Some(value) -> value
  end
  store_witness(pool,
    sign_witness("legacy", pair.private_key, seal)?,
    WitnessKey { witness_id: "legacy", public_key: pair.public_key.bytes })?
  # The signed historical policy owns this quorum; registry status cannot
  # silently replace those pins during an operator's resumable transition.
  assert(phase(run_action(pool, "accept", 100, relay_frame)?)? == "copying")
  assert(phase(run_action(pool, "resume", 1, relay_frame)?)? == "active")
  assert(phase(run_action(pool, "resume", 1, anchor_frame)?)? == "active")
  assert(phase(run_action(pool, "resume", 1, frame)?)? == "active")
  assert(phase(run_action(pool, "status", 100, "")?)? == "active")
  Pool.close(pool)
  Ok(true)
end

test("operator cutover requires pinned legacy quorum and resumes without changing an accepted seal") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
