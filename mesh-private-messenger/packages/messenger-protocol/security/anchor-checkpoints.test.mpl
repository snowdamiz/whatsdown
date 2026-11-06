from Transparency.Wire import decode_checkpoint, encode_checkpoint
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  WitnessKey,
  checkpoint_hash,
  verify_checkpoint,
  verify_witnesses
)
from Transparency.C2spText import checkpoint_note_text
from Transparency.AnchorReceipt import AnchorReceipt, encode_anchor_receipt
from Transparency.AnchorWrite import (
  AnchorInstructionPair,
  anchor_post_instructions,
  anchor_cosign_instructions
)

fn instruction_json(pair :: AnchorInstructionPair) -> String do
  "\"ed25519\":\""
    <> Bytes.to_hex(pair.ed25519)
    <> "\",\"instruction\":\""
    <> Bytes.to_hex(pair.judge)
    <> "\""
end

fn export_writer_fixture(checkpoint :: TransparencyCheckpoint,
  pin :: WitnessKey,
  native_signature :: Bytes,
  c2sp_signature :: Bytes,
  index :: Int) -> Result<(), String> do
  let output = Env.get("MORSE_ANCHOR_WORK_PATH", "")
  if output == "" do
    return Ok(nil)
  end
  let post = anchor_post_instructions(checkpoint, checkpoint.service_public_key, 0)?
  let receipt = encode_anchor_receipt(AnchorReceipt {
    log_version: checkpoint.version,
    sequence: checkpoint.sequence,
    tree_size: checkpoint.tree_size,
    checkpoint_hash: checkpoint_hash(checkpoint)?,
    ring_index: 0,
    transaction_signature: Bytes.from_hex(String.repeat("2a", 64))?,
    slot: U64.parse("100")?
  })?
  let attestation = WitnessAttestation {
    witness_id: pin.witness_id,
    checkpoint_hash: checkpoint_hash(checkpoint)?,
    signature: native_signature
  }
  let native = anchor_cosign_instructions(checkpoint, attestation, pin, 0, 0, 0)?
  let c2sp = if checkpoint.version == 2 do
    "{"
      <> instruction_json(anchor_cosign_instructions(checkpoint,
        %{attestation | signature: c2sp_signature},
        pin,
        0,
        0,
        0)?)
      <> ",\"witness_index\":0}"
  else
    "null"
  end
  if index == 0 do
    File.write(output, "[")?
  else
    File.append(output, ",")?
  end
  File.append(output,
    "{\"version\":"
      <> Int.to_string(checkpoint.version)
      <> ",\"service_key\":\""
      <> Bytes.to_hex(checkpoint.service_public_key)
      <> "\",\"witness_key\":\""
      <> Bytes.to_hex(pin.public_key)
      <> "\",\"checkpoint_hash\":\""
      <> Bytes.to_hex(checkpoint_hash(checkpoint)?)
      <> "\",\"receipt\":\""
      <> Bytes.to_hex(receipt)
      <> "\",\"post\":{\"checkpoint\":\""
      <> Bytes.to_hex(encode_checkpoint(checkpoint)?)
      <> "\",\"sequence\":\""
      <> U64.to_string(checkpoint.sequence)
      <> "\",\"tree_size\":\""
      <> U64.to_string(checkpoint.tree_size)
      <> "\",\"root\":\""
      <> Bytes.to_hex(checkpoint.tree_root)
      <> "\",\"timestamp_ms\":\""
      <> U64.to_string(checkpoint.timestamp)
      <> "\",\"checkpoint_hash\":\""
      <> Bytes.to_hex(checkpoint_hash(checkpoint)?)
      <> "\",\"version\":"
      <> Int.to_string(checkpoint.version)
      <> ",\"service_key\":\""
      <> Bytes.to_hex(checkpoint.service_public_key)
      <> "\","
      <> instruction_json(post)
      <> "},\"native\":{\"witness_index\":0,"
      <> instruction_json(native)
      <> "},\"c2sp\":"
      <> c2sp
      <> "}")?
  if index == 1 do
    File.append(output, "]")?
  end
  Ok(nil)
end

fn proof() -> Bool!String do
  let path = Env.get("MORSE_ANCHOR_CHECKPOINTS_PATH", "")
  if path == "" do
    return Err("run scripts/judge-checkpoint.test.mjs")
  end
  let fixtures = Json.parse(File.read(path)?)?
  for index in 0..2 do
    let fixture = Json.array_get(fixtures, index)?
    let wire = Bytes.from_hex(Json.as_string(Json.object_get(fixture, "wire")?)?)?
    let expected = Bytes.from_hex(Json.as_string(Json.object_get(fixture, "hash")?)?)?
    let checkpoint = decode_checkpoint(wire)?
    assert(checkpoint.version == index + 1)
    assert(U64.to_string(checkpoint.sequence) == "18446744073709551615")
    assert(Bytes.secure_equals(encode_checkpoint(checkpoint)?, wire))
    assert(Bytes.secure_equals(checkpoint_hash(checkpoint)?, expected))
    assert(verify_checkpoint(checkpoint,
      SigningPublicKey { bytes: checkpoint.service_public_key })?)
    let witness = Json.object_get(fixture, "witness")?
    let id = Json.as_string(Json.object_get(witness, "id")?)?
    let public_key = Bytes.from_hex(Json.as_string(Json.object_get(witness, "publicKey")?)?)?
    let native_signature = Bytes.from_hex(Json.as_string(Json.object_get(witness,
      "nativeSignature")?)?)?
    let native_statement = Bytes.from_hex(Json.as_string(Json.object_get(witness,
      "nativeStatement")?)?)?
    assert(Bytes.secure_equals(native_statement,
      Bytes.concat(Bytes.from_utf8("mesh-msg/v1/transparency-witness" <> id), expected)?))
    let pin = WitnessKey { witness_id: id, public_key: public_key }
    assert(verify_witnesses(checkpoint,
      [
        WitnessAttestation {
          witness_id: id,
          checkpoint_hash: expected,
          signature: native_signature
        }
      ],
      [pin],
      1)?)
    if checkpoint.version == 2 do
      let cosignature = Bytes.from_hex(Json.as_string(Json.object_get(witness, "c2spSignature")?)?)?
      let statement = Bytes.from_hex(Json.as_string(Json.object_get(witness, "c2spStatement")?)?)?
      assert(Bytes.secure_equals(statement,
        Bytes.from_utf8("cosignature/v1\ntime 18446744073709551615\n"
          <> checkpoint_note_text(wire)?)))
      assert(verify_witnesses(checkpoint,
        [WitnessAttestation { witness_id: id, checkpoint_hash: expected, signature: cosignature }],
        [pin],
        1)?)
      export_writer_fixture(checkpoint, pin, native_signature, cosignature, index)?
    else
      export_writer_fixture(checkpoint, pin, native_signature, Bytes.empty(), index)?
    end
  end
  Ok(true)
end

test("judge and Mesh share independent signed checkpoints in both log versions") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
