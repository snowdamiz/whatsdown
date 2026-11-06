from Storage.WitnessRegistry import public_witness_registry, push_witness_registry, witness_health
from Api.Binary import BinaryResult, submit_witness_request, witnesses_request
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  sign_checkpoint,
  sign_witness
)
from Transparency.Wire import decode_witnesses, encode_witnesses

fn signer() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Ok(value)
    Err(_) -> Err("test signer failed")
  end
end

fn register(pool :: PoolHandle,
  id :: String,
  key :: Bytes,
  status :: String) -> Result<(), String> do
  Pool.execute_values(pool,
    "INSERT INTO transparency_witness_registry (witness_id, public_key, operator, status, software, morse_run) VALUES ($1, $2, 'Test operator', $3, 'mesh', false)",
    [Text(id), Binary(key), Text(status)])?
  Ok(nil)
end

fn proof() -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL",
      "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable"),
    1,
    2,
    5000)?
  # This suite owns a disposable proof database, like the other directory tests.
  Pool.execute(pool,
    "TRUNCATE transparency_anchors, witness_signatures, transparency_checkpoints, transparency_witness_registry",
    [])?
  let log_signer = signer()?
  let now = U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))?
  let zero = Bytes.from_hex(String.join(for _ in 0..32 do
      "00"
    end,
    ""))?
  let checkpoint = sign_checkpoint(log_signer.private_key,
    log_signer.public_key.bytes,
    U64.parse("1")?,
    [Crypto.sha256(Bytes.from_utf8("leaf"))],
    zero,
    now)?
  Pool.execute_values(pool,
    "INSERT INTO transparency_checkpoints (sequence, tree_size, tree_root, previous_checkpoint_hash, timestamp_ms, service_public_key, service_signature) VALUES (1, 1, $1, $2, $5::bigint, $3, $4)",
    [
      Binary(checkpoint.tree_root),
      Binary(zero),
      Binary(log_signer.public_key.bytes),
      Binary(checkpoint.signature),
      Text(U64.to_string(now))
    ])?
  let pinned = signer()?
  assert(!Json.as_bool(Json.object_get(Json.parse(witness_health(pool)?)?, "threshold_met")?)?)
  register(pool, "z-pinned", pinned.public_key.bytes, "pinned")?
  assert(submit_witness_request(pool,
    encode_witnesses([sign_witness("z-pinned", pinned.private_key, checkpoint)?])?).status == 201)
  assert(submit_witness_request(pool,
    encode_witnesses([sign_witness("unknown", pinned.private_key, checkpoint)?])?).status == 400)
  let shadow = signer()?
  register(pool, "shadow-third", shadow.public_key.bytes, "shadow")?
  let frame = encode_witnesses([sign_witness("shadow-third", shadow.private_key, checkpoint)?])?
  assert(submit_witness_request(pool, frame).status == 201)
  assert(submit_witness_request(pool, frame).status == 201)
  assert(submit_witness_request(pool,
    encode_witnesses([
      sign_witness("shadow-third", pinned.private_key, checkpoint)?
    ])?).status == 400)
  Pool.execute(pool,
    "UPDATE transparency_witness_registry SET status = 'retired', retired_at = now() WHERE witness_id = 'shadow-third'",
    [])?
  assert(submit_witness_request(pool, frame).status == 400)
  for index in 0..17 do
    let pair = signer()?
    let id = "a-shadow-#{index}"
    register(pool, id, pair.public_key.bytes, "shadow")?
    assert(submit_witness_request(pool,
      encode_witnesses([sign_witness(id, pair.private_key, checkpoint)?])?).status == 201)
  end
  let response = witnesses_request(pool)
  assert(response.status == 200)
  let values = decode_witnesses(response.body)?
  assert(List.length(values) == 16)
  assert(List.head(values).witness_id == "z-pinned")
  assert(!List.any(values, fn(value) do value.witness_id == "shadow-third" end))
  let health = Json.parse(witness_health(pool)?)?
  assert(Json.as_bool(Json.object_get(health, "threshold_met")?)?)
  assert(Json.is_null(Json.object_get(health, "anchor_lag_ms")?))
  assert(Json.as_int(Json.object_get(health, "threshold")?)? == 1)
  assert(Json.as_int(Json.object_get(health, "valid_signatures")?)? == 1)
  assert(Json.array_length(Json.object_get(Json.parse(public_witness_registry(pool)?)?,
    "witnesses")?)? == 19)
  assert(Json.array_length(Json.object_get(Json.parse(push_witness_registry(pool)?)?,
    "witnesses")?)? == 0)
  Pool.execute(pool, "UPDATE transparency_checkpoints SET timestamp_ms = 0", [])?
  assert(!Json.as_bool(Json.object_get(Json.parse(witness_health(pool)?)?, "threshold_met")?)?)
  Pool.execute(pool,
    "TRUNCATE transparency_anchors, witness_signatures, transparency_checkpoints, transparency_witness_registry",
    [])?
  Pool.close(pool)
  Ok(true)
end

test("registry admits shadow witnesses, refuses retired and unknown keys, and bounds pinned-first fan-in") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
