from Transparency.Merkle import (
  TransparencyCheckpoint,
  ConsistencyProof,
  checkpoint_hash,
  proof_matches_log,
  verify_checkpoint,
  verify_consistency
)

pub fn verify_history_header(previous :: Option<TransparencyCheckpoint>,
  current :: TransparencyCheckpoint,
  trusted :: SigningPublicKey,
  now :: U64) -> Result<(), String> do
  if !verify_checkpoint(current, trusted)? do
    return Err("transparency checkpoint signature failed")
  end
  let skew = if U64.compare(current.timestamp, now) > 0 do
    U64.subtract(current.timestamp, now)?
  else
    U64.subtract(now, current.timestamp)?
  end
  if U64.compare(skew, U64.parse("60000")?) > 0 do
    return Err("transparency checkpoint clock skew")
  end
  case previous do
    None -> Ok(nil)
    Some(prior) -> if prior.version != current.version do
      Err("transparency log migration required")
    else if !verify_checkpoint(prior, trusted)? do
      Err("cached witness checkpoint signature failed")
    else if U64.compare(current.sequence, prior.sequence) < 0
      || U64.compare(current.tree_size, prior.tree_size) < 0 do
      Err("transparency log rolled back")
    else if U64.compare(current.sequence, prior.sequence) == 0 do
      if Bytes.secure_equals(checkpoint_hash(current)?, checkpoint_hash(prior)?) do
        Ok(nil)
      else
        Err("transparency checkpoint changed")
      end
    else if U64.compare(current.timestamp, prior.timestamp) <= 0 do
      Err("transparency checkpoint timestamp did not advance")
    else if U64.compare(current.sequence, U64.add(prior.sequence, U64.parse("1")?)?) == 0
      && !Bytes.secure_equals(current.previous_checkpoint_hash, checkpoint_hash(prior)?) do
      Err("transparency checkpoint link mismatch")
    else
      Ok(nil)
    end
  end
end

pub fn verify_history_proof(previous :: TransparencyCheckpoint,
  current :: TransparencyCheckpoint,
  proof :: ConsistencyProof) -> Bool!String do
  if previous.version != current.version
    || !proof_matches_log(current.version, proof.version)
    || proof.old_tree_size != U64.to_int(previous.tree_size)?
    || proof.new_tree_size != U64.to_int(current.tree_size)? do
    Ok(false)
  else
    verify_consistency(previous.tree_root, current.tree_root, proof)
  end
end
