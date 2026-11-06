from Api.Binary import BinaryResult, historical_checkpoint_request_for
from Transparency.Merkle import TransparencyCheckpoint, sign_tree_checkpoint_for
from Transparency.Wire import encode_checkpoint

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn query(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err("fixture query failed")
    Ok(bytes)
  end
end

fn insert(pool :: PoolHandle,
  table :: String,
  value :: TransparencyCheckpoint) -> Result<(), String> do
  Pool.execute_values(pool,
    "INSERT INTO "
      <> table
      <> " (sequence, tree_size, tree_root, previous_checkpoint_hash, timestamp_ms, service_public_key, service_signature) VALUES ($1::bigint, $2::bigint, $3, $4, $5::bigint, $6, $7)",
    [
      Text(U64.to_string(value.sequence)),
      Text(U64.to_string(value.tree_size)),
      Binary(value.tree_root),
      Binary(value.previous_checkpoint_hash),
      Text(U64.to_string(value.timestamp)),
      Binary(value.service_public_key),
      Binary(value.signature)
    ])?
  Ok(nil)
end

fn proof() -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL",
      "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable"),
    1,
    2,
    5000)?
  Pool.execute(pool,
    "TRUNCATE transparency_anchors, transparency_v2_anchors, witness_signatures, witness_v2_signatures, transparency_checkpoints, transparency_v2_checkpoints",
    [])?
  let signer = case Crypto.signing_generate() do
    Err(_) -> return Err("fixture key failed")
    Ok(value) -> value
  end
  let root = Crypto.sha256(Bytes.from_utf8("history root"))
  for version in [1, 2] do
    let table = if version == 1 do
      "transparency_checkpoints"
    else
      "transparency_v2_checkpoints"
    end
    for sequence in [4, 7] do
      let value = sign_tree_checkpoint_for(version,
        signer.private_key,
        signer.public_key.bytes,
        wide(sequence)?,
        wide(3)?,
        root,
        root,
        wide(1000 + sequence)?)?
      insert(pool, table, value)?
      let response = historical_checkpoint_request_for(pool, version, query(wide(sequence)?)?)
      assert(response.status == 200)
      assert(Bytes.secure_equals(response.body, encode_checkpoint(value)?))
    end
    let older = sign_tree_checkpoint_for(version,
      signer.private_key,
      signer.public_key.bytes,
      wide(4)?,
      wide(3)?,
      root,
      root,
      wide(1004)?)?
    assert(Bytes.secure_equals(historical_checkpoint_request_for(pool,
        version,
        query(wide(4)?)?).body,
      encode_checkpoint(older)?))
    # A historical query must never substitute the current checkpoint, even
    # when the requested sequence was pruned or exceeds PostgreSQL bigint.
    for sequence in ["1", "6", "8", "18446744073709551615"] do
      assert(historical_checkpoint_request_for(pool,
        version,
        query(U64.parse(sequence)?)?).status == 404)
    end
    for malformed in [Bytes.empty(), Bytes.from_utf8("00000000" <> "x"), query(wide(0)?)?] do
      assert(historical_checkpoint_request_for(pool, version, malformed).status == 400)
    end
  end
  assert(historical_checkpoint_request_for(pool, 3, query(wide(4)?)?).status == 400)
  # Querying does not poll, sign, create or refresh any checkpoint.
  let rows = Pool.query(pool,
    "SELECT count(*)::text AS count FROM transparency_checkpoints UNION ALL SELECT count(*)::text FROM transparency_v2_checkpoints",
    [])?
  assert(List.all(rows, fn(row) do Map.get(row, "count") == "2" end))
  Pool.close(pool)
  Ok(true)
end

test("exact historical checkpoint lookup preserves the version and never substitutes or creates a checkpoint") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
