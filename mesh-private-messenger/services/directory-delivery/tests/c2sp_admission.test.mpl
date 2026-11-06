from Storage.Transparency import store_c2sp_response, witnesses_for_checkpoint_for
from Storage.WitnessRegistry import witness_health, push_witness_registry
from Api.Binary import submit_witness_request_for
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessKey,
  WitnessAttestation,
  sign_tree_checkpoint_for,
  sign_witness,
  verify_witnesses_at
)
from Transparency.C2sp import signature_line
from Transparency.C2spText import checkpoint_note_text
from Transparency.Wire import encode_checkpoint, encode_witnesses

fn signer() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("fixture signer failed")
    Ok(value)
  end
end

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn reply(name :: String,
  key :: borrow SigningKeyPair,
  checkpoint :: TransparencyCheckpoint,
  seconds :: Int) -> Bytes!String do
  let message = Bytes.from_utf8("cosignature/v1\ntime #{seconds}\n"
    <> checkpoint_note_text(encode_checkpoint(checkpoint)?)?)
  let signature = case Crypto.sign(key.private_key, message) do
    Err(_) -> return Err("fixture signing failed")
    Ok(value) -> value.bytes
  end
  let stamp = case Bytes.write_u64_be(wide(seconds)?) do
    Err(_) -> return Err("fixture timestamp failed")
    Ok(value) -> value
  end
  let payload = Bytes.concat(stamp, signature)?
  Ok(Bytes.from_utf8(signature_line(name, 4, key.public_key.bytes, payload)?))
end

fn reset(pool :: PoolHandle) -> Result<(), String> do
  Pool.execute(pool,
    "TRUNCATE transparency_v2_anchors, transparency_anchors, witness_signatures, transparency_checkpoints, witness_v2_signatures, transparency_v2_checkpoints, transparency_witness_registry, transparency_log_cutover",
    [])?
  Ok(nil)
end

fn proof() -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL",
      "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable"),
    1,
    2,
    5000)?
  reset(pool)?
  let log_signer = signer()?
  let external = signer()?
  let native = signer()?
  let root = Crypto.sha256(Bytes.from_utf8("fixture tree"))
  let now_ms = DateTime.to_unix_ms(DateTime.utc_now())
  let seconds = now_ms / 1000
  let zero = Bytes.from_hex(String.join(for _ in 0..32 do
      "00"
    end,
    ""))?
  let seal = sign_tree_checkpoint_for(1,
    log_signer.private_key,
    log_signer.public_key.bytes,
    wide(8)?,
    wide(5)?,
    root,
    zero,
    wide(now_ms)?)?
  let checkpoint = sign_tree_checkpoint_for(2,
    log_signer.private_key,
    log_signer.public_key.bytes,
    wide(1)?,
    wide(1)?,
    root,
    zero,
    wide(now_ms)?)?
  Pool.execute_values(pool,
    "INSERT INTO transparency_log_cutover (phase, legacy_checkpoint, legacy_witnesses, activated_at) VALUES ('active', $1, $2, now())",
    [Binary(encode_checkpoint(seal)?), Binary(encode_witnesses(List.new())?)])?
  Pool.execute_values(pool,
    "INSERT INTO transparency_v2_checkpoints (sequence, tree_size, tree_root, previous_checkpoint_hash, timestamp_ms, service_public_key, service_signature) VALUES (1, 1, $1, $2, $3::bigint, $4, $5)",
    [
      Binary(root),
      Binary(zero),
      Text(Int.to_string(now_ms)),
      Binary(log_signer.public_key.bytes),
      Binary(checkpoint.signature)
    ])?
  Pool.execute_values(pool,
    "INSERT INTO transparency_witness_registry (witness_id, public_key, operator, status, software, morse_run, note_name, push_url) VALUES ('external', $1, 'External', 'pinned', 'c2sp', false, 'example.org/witness', 'https://example.org/add-checkpoint'), ('native', $2, 'Native', 'pinned', 'mesh', true, NULL, NULL)",
    [Binary(external.public_key.bytes), Binary(native.public_key.bytes)])?
  let signature = reply("example.org/witness", external, checkpoint, seconds)?
  assert(submit_witness_request_for(pool,
    2,
    encode_witnesses([sign_witness("external", external.private_key, checkpoint)?])?).status == 400)
  for (id, response) in [
    ("missing", signature),
    ("native", reply("example.org/witness", native, checkpoint, seconds)?),
    ("external", reply("wrong.example/witness", external, checkpoint, seconds)?),
    ("external", reply("example.org/witness", native, checkpoint, seconds)?),
    ("external", reply("example.org/witness", external, checkpoint, seconds - 301)?),
    ("external", reply("example.org/witness", external, checkpoint, seconds + 61)?)
  ] do
    case store_c2sp_response(pool, id, checkpoint, response) do
      Err(_) -> nil
      Ok(_) -> assert(false)
    end
  end
  assert(List.length(witnesses_for_checkpoint_for(pool, 2, checkpoint.sequence)?) == 0)
  assert(submit_witness_request_for(pool, 1, signature).status == 400)
  assert(submit_witness_request_for(pool, 2, signature).status == 201)
  assert(submit_witness_request_for(pool, 2, Bytes.concat(signature, signature)?).status == 400)
  store_c2sp_response(pool, "external", checkpoint, signature)?
  store_c2sp_response(pool,
    "external",
    checkpoint,
    reply("example.org/witness", external, checkpoint, seconds + 1)?)?
  assert(submit_witness_request_for(pool,
    2,
    encode_witnesses([sign_witness("native", native.private_key, checkpoint)?])?).status == 201)
  let witnesses = witnesses_for_checkpoint_for(pool, 2, checkpoint.sequence)?
  assert(List.length(witnesses) == 2)
  assert(verify_witnesses_at(checkpoint,
    witnesses,
    [
      WitnessKey { witness_id: "external", public_key: external.public_key.bytes },
      WitnessKey { witness_id: "native", public_key: native.public_key.bytes }
    ],
    2,
    wide(now_ms)?)?)
  let health = Json.parse(witness_health(pool)?)?
  assert(Json.as_bool(Json.object_get(health, "threshold_met")?)?)
  assert(Json.as_int(Json.object_get(health, "log_version")?)? == 2)
  assert(Json.as_int(Json.object_get(health, "valid_signatures")?)? == 2)
  assert(Json.array_length(Json.object_get(Json.parse(push_witness_registry(pool)?)?,
    "witnesses")?)? == 1)
  Pool.execute(pool,
    "UPDATE witness_v2_signatures SET cosigned_at_ms = 0 WHERE witness_id = 'external'",
    [])?
  assert(!Json.as_bool(Json.object_get(Json.parse(witness_health(pool)?)?, "threshold_met")?)?)
  Pool.execute(pool,
    "UPDATE transparency_witness_registry SET status = 'retired', retired_at = now() WHERE witness_id = 'external'",
    [])?
  case store_c2sp_response(pool, "external", checkpoint, signature) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  reset(pool)?
  Pool.close(pool)
  Ok(true)
end

test("C2SP admission binds active registry name and algorithm, checks freshness and counts the RFC quorum") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
