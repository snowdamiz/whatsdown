from Api.AnchorWork import anchor_candidate_request_for, anchor_cosign_request
from Api.Binary import BinaryResult
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessKey,
  sign_tree_checkpoint_for,
  sign_witness,
  checkpoint_hash
)
from Transparency.AnchorWrite import (
  AnchorInstructionPair,
  anchor_post_instructions,
  anchor_cosign_instructions
)
from Transparency.Wire import encode_checkpoint, encode_witnesses

fn cat(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    return Ok(output)
  end
  cat(parts, index + 1, Bytes.concat(output, List.get(parts, index))?)
end

fn le(value :: Int, count :: Int) -> Bytes!String do
  case Bytes.write_uint_le(Int.to_string(value), count) do
    Err(_) -> Err("test integer")
    Ok(bytes)
  end
end

fn set_bytes(key :: Bytes) -> Bytes!String do
  let zeroes = Bytes.from_hex(String.repeat("00", 2520))?
  let address = Crypto.sha256(Bytes.from_utf8("witness account"))
  cat([
      Bytes.from_hex("4d575301")?,
      Crypto.sha256(Bytes.from_utf8("morse-main")),
      le(7, 2)?,
      le(1, 1)?,
      le(0, 1)?,
      le(0, 8)?,
      Bytes.slice(zeroes, 0, 16)?,
      address,
      le(9, 1)?,
      Bytes.slice(zeroes, 0, 7)?,
      Bytes.from_utf8("witness-a"),
      Bytes.slice(zeroes, 0, 55)?,
      key,
      address,
      zeroes
    ],
    0,
    Bytes.empty())
end

fn query(version :: Int, set :: Bytes) -> Bytes!String do
  let prefix = if version == 1 do
    "014157510001"
  else
    "014157510002"
  end
  cat([Bytes.from_hex(prefix <> "00000000000000070fff")?, set], 0, Bytes.empty())
end

fn field(document :: String, name :: String) -> String!String do
  Json.as_string(Json.object_get(Json.parse(document)?, name)?)
end

fn proof() -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL",
      "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable"),
    1,
    2,
    5000)?
  Pool.execute(pool,
    "TRUNCATE transparency_log_cutover, transparency_anchors, transparency_v2_anchors, witness_signatures, witness_v2_signatures, transparency_checkpoints, transparency_v2_checkpoints",
    [])?
  let signer = case Crypto.signing_generate() do
    Err(_) -> return Err("test signer")
    Ok(value) -> value
  end
  let witness = case Crypto.signing_generate() do
    Err(_) -> return Err("test witness")
    Ok(value) -> value
  end
  let root = Crypto.sha256(Bytes.from_utf8("work tree"))
  for version in [1, 2] do
    if version == 2 do
      let seal = sign_tree_checkpoint_for(1,
        signer.private_key,
        signer.public_key.bytes,
        U64.parse("7")?,
        U64.parse("3")?,
        root,
        root,
        U64.parse("1000")?)?
      Pool.execute_values(pool,
        "INSERT INTO transparency_log_cutover (phase, legacy_checkpoint, legacy_witnesses, activated_at) VALUES ('active', $1, $2, now())",
        [Binary(encode_checkpoint(seal)?), Binary(encode_witnesses([])?)])?
    end
    assert(anchor_candidate_request_for(pool, version).status == 404)
    let table = if version == 1 do
      "transparency_checkpoints"
    else
      "transparency_v2_checkpoints"
    end
    let witnesses = if version == 1 do
      "witness_signatures"
    else
      "witness_v2_signatures"
    end
    let checkpoint = sign_tree_checkpoint_for(version,
      signer.private_key,
      signer.public_key.bytes,
      U64.parse("7")?,
      U64.parse("3")?,
      root,
      root,
      U64.parse("1000")?)?
    Pool.execute_values(pool,
      "INSERT INTO "
        <> table
        <> " (sequence, tree_size, tree_root, previous_checkpoint_hash, timestamp_ms, service_public_key, service_signature) VALUES (7, 3, $1, $1, 1000, $2, $3)",
      [Binary(root), Binary(signer.public_key.bytes), Binary(checkpoint.signature)])?
    let candidate = anchor_candidate_request_for(pool, version)
    assert(candidate.status == 200)
    let document = Bytes.to_utf8(candidate.body)?
    let pair = anchor_post_instructions(checkpoint, signer.public_key.bytes, 0)?
    assert(field(document, "checkpoint")? == Bytes.to_hex(encode_checkpoint(checkpoint)?))
    assert(field(document, "ed25519")? == Bytes.to_hex(pair.ed25519))
    assert(field(document, "instruction")? == Bytes.to_hex(pair.judge))
    let request = query(version, set_bytes(witness.public_key.bytes)?)?
    let empty = anchor_cosign_request(pool, request)
    assert(empty.status == 200)
    assert(String.contains(Bytes.to_utf8(empty.body)?, "\"cosigns\":[]"))
    let attestation = sign_witness("witness-a", witness.private_key, checkpoint)?
    # Historical chain generation keys control lookup, even if the current
    # registry has changed or retired this identity.
    Pool.execute_values(pool,
      "INSERT INTO "
        <> witnesses
        <> " (checkpoint_sequence, witness_id, witness_public_key, checkpoint_hash, signature) VALUES (7, 'witness-a', $1, $2, $3)",
      [
        Binary(witness.public_key.bytes),
        Binary(checkpoint_hash(checkpoint)?),
        Binary(attestation.signature)
      ])?
    let prepared = anchor_cosign_request(pool, request)
    assert(prepared.status == 200)
    let values = Json.object_get(Json.parse(Bytes.to_utf8(prepared.body)?)?, "cosigns")?
    let first = Json.array_get(values, 0)?
    assert(Json.as_string(Json.object_get(first,
      "instruction")?)? == Bytes.to_hex(anchor_cosign_instructions(checkpoint,
        attestation,
        WitnessKey { witness_id: "witness-a", public_key: witness.public_key.bytes },
        4095,
        0,
        0)?.judge))
    let rotated = anchor_cosign_request(pool, query(version, set_bytes(signer.public_key.bytes)?)?)
    assert(rotated.status == 200)
    assert(String.contains(Bytes.to_utf8(rotated.body)?, "\"cosigns\":[]"))
    Pool.execute_values(pool,
      "UPDATE " <> witnesses <> " SET signature = $1 WHERE checkpoint_sequence = 7",
      [Binary(Bytes.from_hex(String.repeat("00", 64))?)])?
    assert(String.contains(Bytes.to_utf8(anchor_cosign_request(pool, request).body)?,
      "\"cosigns\":[]"))
  end
  assert(anchor_candidate_request_for(pool, 3).status == 400)
  assert(anchor_cosign_request(pool, Bytes.empty()).status == 400)
  assert(anchor_cosign_request(pool,
    Bytes.concat(query(2, set_bytes(witness.public_key.bytes)?)?,
      Bytes.from_hex("00")?)?).status == 400)
  Pool.execute(pool,
    "TRUNCATE transparency_log_cutover, transparency_anchors, transparency_v2_anchors, witness_signatures, witness_v2_signatures, transparency_checkpoints, transparency_v2_checkpoints",
    [])?
  Pool.close(pool)
  Ok(true)
end

test("Mesh prepares anchor work from exact versioned history and only the supplied historical generation's valid signatures") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
