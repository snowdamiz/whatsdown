##! Verified bytes for the fixed judge instruction subset. The transaction
##! writer authenticates chain accounts and supplies actual instruction indices.
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  WitnessKey,
  checkpoint_statement,
  verify_checkpoint,
  verify_witnesses
)
from Transparency.Wire import encode_checkpoint
from Transparency.C2spText import checkpoint_note_text
from Transparency.Config import valid_witness_id

pub struct AnchorInstructionPair do
  ed25519 :: Bytes
  judge :: Bytes
end

fn cat(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    return Ok(output)
  end
  let next = case Bytes.concat(output, List.get(parts, index)) do
    Err(_) -> return Err("invalid_anchor_instruction")
    Ok(value) -> value
  end
  cat(parts, index + 1, next)
end

fn narrow(value :: Int) -> Bytes!String do
  case Bytes.write_uint_le(Int.to_string(value), 2) do
    Err(_) -> Err("invalid_anchor_instruction")
    Ok(bytes)
  end
end

fn byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("invalid_anchor_instruction")
    Ok(bytes)
  end
end

fn precompile(key :: Bytes, signature :: Bytes, statement :: Bytes) -> Bytes!String do
  if Bytes.length(key) != 32 || Bytes.length(signature) != 64 || Bytes.length(statement) > 65535 do
    return Err("invalid_anchor_instruction")
  end
  cat([
      Bytes.from_hex("01003000ffff1000ffff7000")?,
      narrow(Bytes.length(statement))?,
      Bytes.from_hex("ffff")?,
      key,
      signature,
      statement
    ],
    0,
    Bytes.empty())
end

fn checked_checkpoint(checkpoint :: TransparencyCheckpoint,
  service_key :: Bytes,
  ed_index :: Int) -> Result<(), String> do
  if ed_index < 0
    || ed_index >= 65535
    || U64.compare(checkpoint.sequence, U64.parse("0")?) == 0
    || U64.compare(checkpoint.tree_size, U64.parse("0")?) == 0
    || U64.compare(checkpoint.tree_size, U64.parse("4294967295")?) > 0
    || !verify_checkpoint(checkpoint, SigningPublicKey { bytes: service_key })? do
    Err("invalid_anchor_instruction")
  else
    Ok(nil)
  end
end

pub fn anchor_post_instructions(checkpoint :: TransparencyCheckpoint,
  service_key :: Bytes,
  ed_index :: Int) -> AnchorInstructionPair!String do
  checked_checkpoint(checkpoint, service_key, ed_index)?
  let statement = checkpoint_statement(checkpoint.version,
    checkpoint.sequence,
    checkpoint.tree_size,
    checkpoint.tree_root,
    checkpoint.previous_checkpoint_hash,
    checkpoint.timestamp,
    checkpoint.service_public_key)?
  Ok(AnchorInstructionPair {
    ed25519: precompile(service_key, checkpoint.signature, statement)?,
    judge: cat([byte(3)?, narrow(ed_index)?, encode_checkpoint(checkpoint)?], 0, Bytes.empty())?
  })
end

pub fn anchor_cosign_instructions(checkpoint :: TransparencyCheckpoint,
  attestation :: WitnessAttestation,
  witness :: WitnessKey,
  ring_index :: Int,
  witness_index :: Int,
  ed_index :: Int) -> AnchorInstructionPair!String do
  checked_checkpoint(checkpoint, checkpoint.service_public_key, ed_index)?
  if ring_index < 0
    || ring_index >= 4096
    || witness_index < 0
    || witness_index >= 16
    || !valid_witness_id(witness.witness_id)
    || !verify_witnesses(checkpoint, [attestation], [witness], 1)? do
    return Err("invalid_anchor_instruction")
  end
  if Bytes.length(attestation.signature) == 64 do
    let statement = cat([
        Bytes.from_utf8("mesh-msg/v1/transparency-witness" <> witness.witness_id),
        attestation.checkpoint_hash
      ],
      0,
      Bytes.empty())?
    return Ok(AnchorInstructionPair {
      ed25519: precompile(witness.public_key, attestation.signature, statement)?,
      judge: cat([byte(9)?, narrow(ring_index)?, narrow(ed_index)?, byte(witness_index)?],
        0,
        Bytes.empty())?
    })
  end
  let seconds = case Bytes.read_u64_be(attestation.signature, 0) do
    Err(_) -> return Err("invalid_anchor_instruction")
    Ok(value) -> value
  end
  let wire = encode_checkpoint(checkpoint)?
  let statement = Bytes.from_utf8("cosignature/v1\ntime "
    <> U64.to_string(seconds)
    <> "\n"
    <> checkpoint_note_text(wire)?)
  Ok(AnchorInstructionPair {
    ed25519: precompile(witness.public_key, Bytes.slice(attestation.signature, 8, 64)?, statement)?,
    judge: cat([
        byte(30)?,
        narrow(ring_index)?,
        narrow(ed_index)?,
        byte(witness_index)?,
        Bytes.slice(attestation.signature, 0, 8)?,
        wire
      ],
      0,
      Bytes.empty())?
  })
end
