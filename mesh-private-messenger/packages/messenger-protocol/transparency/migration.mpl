from Binary.Reader import BinaryReader, reader, read_fixed, read_vector, finish
from Transparency.Client import verify_evidence
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  WitnessKey,
  ConsistencyProof,
  InclusionProof,
  verify_checkpoint,
  verify_witnesses,
  verify_consistency,
  verify_inclusion,
  checkpoint_hash,
  leaf_hash_for
)
from Transparency.Wire import (
  TransparencyEvidence,
  encode_checkpoint,
  decode_checkpoint,
  encode_witnesses,
  decode_witnesses,
  encode_consistency_proof,
  decode_consistency_proof,
  encode_inclusion_proof,
  decode_inclusion_proof
)

pub struct LegacyBridge do
  checkpoint :: TransparencyCheckpoint
  witnesses :: List<WitnessAttestation>
  consistency :: ConsistencyProof
  inclusion :: InclusionProof
end

fn cat(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    case Bytes.concat(output, List.get(parts, index)) do
      Err(_) -> Err("invalid_legacy_bridge")
      Ok(value) -> cat(parts, index + 1, value)
    end
  end
end

# Leaf zero of the new log commits to the exact signed checkpoint at which the
# legacy log was sealed. Witness signatures are carried separately: their order
# or later availability cannot change the new log's first leaf.
pub fn legacy_bridge_leaf(checkpoint :: TransparencyCheckpoint) -> Bytes!String do
  if checkpoint.version != 1 do
    return Err("invalid_legacy_bridge_checkpoint")
  end
  cat([Bytes.from_hex("014b544d")?, encode_checkpoint(checkpoint)?], 0, Bytes.empty())
end

fn valid_policy(keys :: List<WitnessKey>, threshold :: Int) -> Bool do
  let count = List.length(keys)
  if count < 1 || count > 16 || threshold <= count / 2 || threshold > count do
    return false
  end
  for index in 0..count do
    let key = List.get(keys, index)
    let length = Bytes.length(Bytes.from_utf8(key.witness_id))
    if length < 1 || length > 64 || Bytes.length(key.public_key) != 32 do
      return false
    end
    for previous in 0..index do
      let other = List.get(keys, previous)
      if other.witness_id == key.witness_id
        || Bytes.secure_equals(other.public_key, key.public_key) do
        return false
      end
    end
  end
  true
end

# This is the only authorized v1 -> v2 trust transition. Both policies come from
# native trusted configuration, never the response. A v2 cache uses ordinary
# verification and can never enter this transition again. Freshness and account
# binding remain the caller's normal evidence checks.
pub fn verify_migrated_evidence(evidence :: TransparencyEvidence,
  bridge :: LegacyBridge,
  trusted_service_key :: SigningPublicKey,
  legacy_witnesses :: List<WitnessKey>,
  legacy_threshold :: Int,
  current_witnesses :: List<WitnessKey>,
  current_threshold :: Int,
  previous_checkpoint_bytes :: Bytes) -> Bool!String do
  if !valid_policy(current_witnesses, current_threshold) do
    return Ok(false)
  end
  Ok(verify_legacy_bridge(evidence.checkpoint,
    bridge,
    trusted_service_key,
    legacy_witnesses,
    legacy_threshold,
    previous_checkpoint_bytes)?
    && verify_evidence(evidence,
      trusted_service_key,
      current_witnesses,
      current_threshold,
      Bytes.empty())?)
end

# Witnesses verify this side before signing their first v2 checkpoint. Phones
# use verify_migrated_evidence, which additionally requires the new-log quorum
# and the requested account entry. Both authenticate the exact same bridge.
pub fn verify_legacy_bridge(current :: TransparencyCheckpoint,
  bridge :: LegacyBridge,
  trusted_service_key :: SigningPublicKey,
  legacy_witnesses :: List<WitnessKey>,
  legacy_threshold :: Int,
  previous_checkpoint_bytes :: Bytes) -> Bool!String do
  if !valid_policy(legacy_witnesses, legacy_threshold)
    || current.version != 2
    || !verify_checkpoint(current, trusted_service_key)?
    || bridge.checkpoint.version != 1
    || bridge.consistency.version != 2
    || bridge.inclusion.version != 3
    || bridge.inclusion.leaf_index != 0
    || Bytes.length(previous_checkpoint_bytes) == 0 do
    return Ok(false)
  end
  let previous = decode_checkpoint(previous_checkpoint_bytes)?
  let seal = bridge.checkpoint
  if previous.version != 1
    || !verify_checkpoint(previous, trusted_service_key)?
    || !verify_checkpoint(seal, trusted_service_key)?
    || U64.compare(seal.sequence, previous.sequence) < 0
    || U64.compare(seal.tree_size, previous.tree_size) < 0
    || U64.compare(seal.timestamp, previous.timestamp) < 0
    || U64.compare(current.timestamp, seal.timestamp) < 0
    || (U64.compare(seal.sequence, previous.sequence) == 0
      && !Bytes.secure_equals(checkpoint_hash(seal)?, checkpoint_hash(previous)?))
    || bridge.consistency.old_tree_size != U64.to_int(previous.tree_size)?
    || bridge.consistency.new_tree_size != U64.to_int(seal.tree_size)?
    || bridge.inclusion.tree_size != U64.to_int(current.tree_size)? do
    return Ok(false)
  end
  Ok(verify_witnesses(seal, bridge.witnesses, legacy_witnesses, legacy_threshold)?
    && verify_consistency(previous.tree_root, seal.tree_root, bridge.consistency)?
    && verify_inclusion(leaf_hash_for(2, legacy_bridge_leaf(seal)?)?,
      bridge.inclusion,
      current.tree_root)?)
end

fn vector(value :: Bytes) -> Bytes!String do
  let length = case Bytes.write_u32_be(U64.parse(Int.to_string(Bytes.length(value)))?) do
    Err(_) -> return Err("invalid_legacy_bridge")
    Ok(value) -> value
  end
  cat([length, value], 0, Bytes.empty())
end

pub fn encode_legacy_bridge(value :: LegacyBridge) -> Bytes!String do
  if value.checkpoint.version != 1
    || List.any(value.witnesses, fn(witness) -> Bytes.length(witness.signature) != 64 end)
    || value.consistency.version != 2
    || value.inclusion.version != 3
    || value.inclusion.leaf_index != 0
    || value.consistency.new_tree_size != U64.to_int(value.checkpoint.tree_size)? do
    return Err("invalid_legacy_bridge")
  end
  let output = cat([
      Bytes.from_hex("014b5442")?,
      encode_checkpoint(value.checkpoint)?,
      vector(encode_witnesses(value.witnesses)?)?,
      vector(encode_consistency_proof(value.consistency)?)?,
      vector(encode_inclusion_proof(value.inclusion)?)?
    ],
    0,
    Bytes.empty())?
  if Bytes.length(output) > 4942 do
    Err("invalid_legacy_bridge")
  else
    Ok(output)
  end
end

fn take(state :: BinaryReader, count :: Int) -> Result<(BinaryReader, Bytes), String> do
  case read_fixed(state, count) do
    Err(_) -> Err("invalid_legacy_bridge")
    Ok(value)
  end
end

fn take_vector(state :: BinaryReader, limit :: Int) -> Result<(BinaryReader, Bytes), String> do
  case read_vector(state, limit) do
    Err(_) -> Err("invalid_legacy_bridge")
    Ok(value)
  end
end

pub fn decode_legacy_bridge(input :: Bytes) -> LegacyBridge!String do
  let state = case reader(input, 4942) do
    Err(_) -> return Err("invalid_legacy_bridge")
    Ok(value) -> value
  end
  let (state, header) = take(state, 4)?
  if !Bytes.secure_equals(header, Bytes.from_hex("014b5442")?) do
    return Err("invalid_legacy_bridge")
  end
  let (state, checkpoint) = take(state, 188)?
  let (state, witnesses) = take_vector(state, 2630)?
  let (state, consistency) = take_vector(state, 1070)?
  let (state, inclusion) = take_vector(state, 1038)?
  case finish(state) do
    Err(_) -> return Err("invalid_legacy_bridge")
    Ok(_) -> nil
  end
  let value = LegacyBridge {
    checkpoint: decode_checkpoint(checkpoint)?,
    witnesses: decode_witnesses(witnesses)?,
    consistency: decode_consistency_proof(consistency)?,
    inclusion: decode_inclusion_proof(inclusion)?
  }
  if !Bytes.secure_equals(encode_legacy_bridge(value)?, input) do
    Err("invalid_legacy_bridge")
  else
    Ok(value)
  end
end

# Sizes belong to different logs, so no ordering relationship exists between
# them. A fixed RFC size binds the returned inclusion proof to the caller's KTK.
pub fn encode_bridge_query(legacy_size :: Int, rfc_size :: Int) -> Bytes!String do
  if legacy_size < 0 || legacy_size > 4294967295 || rfc_size < 1 || rfc_size > 4294967295 do
    return Err("invalid_bridge_query")
  end
  let old = case Bytes.write_u32_be(U64.parse(Int.to_string(legacy_size))?) do
    Err(_) -> return Err("invalid_bridge_query")
    Ok(value) -> value
  end
  let current = case Bytes.write_u32_be(U64.parse(Int.to_string(rfc_size))?) do
    Err(_) -> return Err("invalid_bridge_query")
    Ok(value) -> value
  end
  cat([Bytes.from_hex("014b4251")?, old, current], 0, Bytes.empty())
end

pub fn decode_bridge_query(input :: Bytes) -> Result<(Int, Int), String> do
  if Bytes.length(input) != 12 do
    return Err("invalid_bridge_query")
  end
  let old = case Bytes.read_u32_be(input, 4) do
    Err(_) -> return Err("invalid_bridge_query")
    Ok(value) -> U64.to_int(value)?
  end
  let current = case Bytes.read_u32_be(input, 8) do
    Err(_) -> return Err("invalid_bridge_query")
    Ok(value) -> U64.to_int(value)?
  end
  if !Bytes.secure_equals(encode_bridge_query(old, current)?, input) do
    Err("invalid_bridge_query")
  else
    Ok((old, current))
  end
end
