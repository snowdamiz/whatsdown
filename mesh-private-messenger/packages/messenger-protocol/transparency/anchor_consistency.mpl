from Transparency.AnchorHttp import anchor_proof_origin, fetch_anchor_proof
from Transparency.AnchorRing import AnchorEntry
from Transparency.Fork import (
  ForkAnchor,
  ForkProof,
  ForkTarget,
  fork_at_anchor,
  fork_same_size,
  fork_rollback,
  encode_fork
)
from Transparency.Merkle import (
  TransparencyCheckpoint,
  checkpoint_hash,
  verify_checkpoint,
  verify_consistency
)
from Transparency.Wire import decode_checkpoint, decode_consistency_proof, encode_consistency_range

pub struct AnchorConsistency do
  status :: String
  checkpoint :: Bytes
  consistency :: Bytes
  fork :: Bytes
end

fn result(status :: String,
  checkpoint :: Bytes,
  proof :: Bytes,
  fork :: Bytes) -> AnchorConsistency do
  AnchorConsistency { status: status, checkpoint: checkpoint, consistency: proof, fork: fork }
end

# Only call with an entry authenticated by the native-pinned quorum reader.
# Empty witness lists deliberately accuse the service alone. Historical bitmap
# attribution requires separately authenticating that entry's witness set.
fn conflict(local :: TransparencyCheckpoint,
  entry :: AnchorEntry,
  index :: Int,
  service_key :: Bytes) -> Bytes!String do
  let anchor = ForkAnchor {
    ring_index: index,
    log_version: entry.log_version,
    service_public_key: service_key,
    sequence: entry.sequence,
    tree_size: entry.tree_size,
    tree_root: entry.tree_root,
    checkpoint_hash: entry.checkpoint_hash,
    cosigners: [],
    native_cosigners: []
  }
  for kind in [1, 3] do
    let proof = ForkProof {
      kind: kind,
      finder: Bytes.from_hex(String.repeat("00", 32))?,
      service_public_key: service_key,
      first: local,
      second: AnchorReference(index),
      contradiction: None,
      attestations: []
    }
    case fork_at_anchor(proof, SigningPublicKey { bytes: service_key }, [], anchor) do
      Ok(_) -> return encode_fork(proof)
      Err(_) -> nil
    end
  end
  Ok(Bytes.empty())
end

fn served_conflict(local :: TransparencyCheckpoint,
  served :: TransparencyCheckpoint,
  entry :: AnchorEntry,
  index :: Int,
  service_key :: Bytes) -> Bytes!String do
  if served.version != entry.log_version
    || !verify_checkpoint(served, SigningPublicKey { bytes: service_key })? do
    return Ok(Bytes.empty())
  end
  let anchored = conflict(served, entry, index, service_key)?
  if Bytes.length(anchored) > 0 do
    return Ok(anchored)
  end
  # A wrong historical response can instead contradict the phone's checkpoint
  # at a smaller size. Both signatures make that independently fileable.
  let proof = ForkProof {
    kind: 1,
    finder: Bytes.from_hex(String.repeat("00", 32))?,
    service_public_key: service_key,
    first: local,
    second: SignedCheckpoint(served),
    contradiction: None,
    attestations: []
  }
  let log = SigningPublicKey { bytes: service_key }
  case fork_same_size(proof, log, []) do
    Ok(_) -> return encode_fork(proof)
    Err(_) -> nil
  end
  let rollback = %{proof | kind: 3}
  case fork_rollback(rollback, log, []) do
    Ok(_) -> encode_fork(rollback)
    Err(_) -> Ok(Bytes.empty())
  end
end

pub fn compare_anchor(origin :: String,
  local :: TransparencyCheckpoint,
  entry :: AnchorEntry,
  index :: Int,
  service_key :: Bytes) -> AnchorConsistency!String do
  if local.version != entry.log_version
    || index < 0
    || index >= 4096
    || !verify_checkpoint(local, SigningPublicKey { bytes: service_key })? do
    return Err("invalid_anchor_comparison")
  end
  let origin = anchor_proof_origin(origin)?
  let fork = conflict(local, entry, index, service_key)?
  if Bytes.length(fork) > 0 do
    return Ok(result("mismatch", Bytes.empty(), Bytes.empty(), fork))
  end
  let route = "/v#{entry.log_version}/transparency/"
  let sequence_wire = case Bytes.write_u64_be(entry.sequence) do
    Err(_) -> return Err("integer_encoding_failed")
    Ok(value) -> value
  end
  let (status, checkpoint) = fetch_anchor_proof(origin, route <> "checkpoint", sequence_wire, 188)?
  if status != "received" do
    return Ok(result(status, checkpoint, Bytes.empty(), Bytes.empty()))
  end
  let served = case decode_checkpoint(checkpoint) do
    Err(_) -> return Ok(result("mismatch", checkpoint, Bytes.empty(), Bytes.empty()))
    Ok(value) -> value
  end
  if !verify_checkpoint(served, SigningPublicKey { bytes: service_key })?
    || served.version != entry.log_version
    || U64.compare(served.sequence, entry.sequence) != 0
    || U64.compare(served.tree_size, entry.tree_size) != 0
    || U64.compare(served.timestamp, entry.timestamp) != 0
    || !Bytes.secure_equals(served.tree_root, entry.tree_root)
    || !Bytes.secure_equals(checkpoint_hash(served)?, entry.checkpoint_hash) do
    return Ok(result("mismatch",
      checkpoint,
      Bytes.empty(),
      served_conflict(local, served, entry, index, service_key)?))
  end
  if U64.compare(local.tree_size, entry.tree_size) == 0 do
    return Ok(result(if Bytes.secure_equals(local.tree_root, entry.tree_root) do
        "consistent"
      else
        "mismatch"
      end,
      checkpoint,
      Bytes.empty(),
      Bytes.empty()))
  end
  let (old_size, old_root, new_size, new_root) = if U64.compare(local.tree_size,
    entry.tree_size) < 0 do
    (local.tree_size, local.tree_root, entry.tree_size, entry.tree_root)
  else
    (entry.tree_size, entry.tree_root, local.tree_size, local.tree_root)
  end
  let limit = U64.parse("4294967295")?
  if U64.compare(new_size, limit) > 0 do
    return Err("invalid_anchor_tree_size")
  end
  let old = U64.to_int(old_size)?
  let new = U64.to_int(new_size)?
  let (status, consistency) = fetch_anchor_proof(origin,
    route <> "consistency",
    encode_consistency_range(old, new)?,
    1070)?
  if status != "received" do
    return Ok(result(status, checkpoint, consistency, Bytes.empty()))
  end
  let proof = case decode_consistency_proof(consistency) do
    Err(_) -> return Ok(result("mismatch", checkpoint, consistency, Bytes.empty()))
    Ok(value) -> value
  end
  let valid = proof.version == local.version + 1
    && proof.old_tree_size == old
    && proof.new_tree_size == new
    && verify_consistency(old_root, new_root, proof).unwrap_or(false)
  Ok(result(if valid do
      "consistent"
    else
      "mismatch"
    end,
    checkpoint,
    consistency,
    Bytes.empty()))
end
