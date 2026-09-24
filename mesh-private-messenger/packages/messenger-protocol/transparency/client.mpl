from Transparency.Merkle import WitnessKey, checkpoint_hash, leaf_hash, merkle_root, verify_checkpoint, verify_consistency, verify_inclusion, verify_witnesses
from Transparency.Wire import TransparencyEvidence, decode_checkpoint

pub fn verify_evidence(evidence :: TransparencyEvidence,
  trusted_service_key :: SigningPublicKey,
  trusted_witnesses :: List<WitnessKey>,
  witness_threshold :: Int,
  previous_checkpoint_bytes :: Bytes) -> Bool!String do
  let current_size = U64.to_int(evidence.checkpoint.tree_size)?
  let current_valid = evidence.inclusion.tree_size == current_size && evidence.consistency.new_tree_size == current_size && verify_checkpoint(evidence.checkpoint,
    trusted_service_key)? && verify_inclusion(leaf_hash(evidence.entry_bytes)?,
    evidence.inclusion,
    evidence.checkpoint.tree_root)? && verify_witnesses(evidence.checkpoint,
    evidence.witnesses,
    trusted_witnesses,
    witness_threshold)?
  if !current_valid do
    Ok(false)
  else if Bytes.length(previous_checkpoint_bytes) == 0 do
    Ok(evidence.consistency.old_tree_size == 0 && verify_consistency(merkle_root(List.new())?,
      evidence.checkpoint.tree_root,
      evidence.consistency)?)
  else
    let previous = decode_checkpoint(previous_checkpoint_bytes)?
    let previous_size = U64.to_int(previous.tree_size)?
    let sequence_order = U64.compare(evidence.checkpoint.sequence, previous.sequence)
    let size_order = U64.compare(evidence.checkpoint.tree_size, previous.tree_size)
    let same_sequence = sequence_order == 0
    let same_checkpoint = Bytes.secure_equals(checkpoint_hash(evidence.checkpoint)?,
      checkpoint_hash(previous)?)
    if !verify_checkpoint(previous, trusted_service_key)? || sequence_order < 0 || size_order < 0 || (same_sequence && !same_checkpoint) || evidence.consistency.old_tree_size != previous_size do
      Ok(false)
    else
      verify_consistency(previous.tree_root, evidence.checkpoint.tree_root, evidence.consistency)
    end
  end
end

# Authorization uses the signed timestamp, never the time a replay arrived.

pub fn checkpoint_fresh_at(timestamp :: U64, now :: U64) -> Bool do
  case U64.to_int(timestamp) do
    Err(_) -> false
    Ok(stamp) -> case U64.to_int(now) do
      Err(_) -> false
      Ok(current) -> if stamp > current do
        stamp - current <= 60000
      else
        current - stamp <= 300000
      end
    end
  end
end
