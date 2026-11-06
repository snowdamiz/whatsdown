from Transparency.AnchorHttp import anchor_proof_origin, fetch_anchor_proof
from Transparency.AnchorRing import AnchorEntry
from Transparency.Merkle import ConsistencyProof, verify_consistency
from Transparency.Wire import encode_consistency_range, decode_consistency_proof

# Both entries were authenticated by the pinned chain reader (the older one
# may be sealed local evidence). A paused fork cannot be hidden by changing
# the latest public root to the private branch. This is a consistency check,
# not a standalone cryptographic fork proof.
pub fn anchor_extends(origin :: String,
  previous :: AnchorEntry,
  current :: AnchorEntry,
  require_current :: Fun() -> Result<(), String>) -> String!String do
  if previous.log_version != current.log_version do
    return Err("anchor_log_version_mismatch")
  end
  if Bytes.secure_equals(previous.checkpoint_hash, current.checkpoint_hash) do
    return Ok("consistent")
  end
  let size_order = U64.compare(current.tree_size, previous.tree_size)
  if U64.compare(current.sequence, previous.sequence) <= 0 || size_order < 0 do
    return Ok("mismatch")
  end
  if size_order == 0 do
    return Ok(if Bytes.secure_equals(previous.tree_root, current.tree_root) do
      "consistent"
    else
      "mismatch"
    end)
  end
  if U64.compare(current.tree_size, U64.parse("4294967295")?) > 0 do
    return Err("invalid_anchor_tree_size")
  end
  let old = U64.to_int(previous.tree_size)?
  let new = U64.to_int(current.tree_size)?
  let (status, response) = fetch_anchor_proof(anchor_proof_origin(origin)?,
    "/v#{current.log_version}/transparency/consistency",
    encode_consistency_range(old, new)?,
    1070,
    require_current)?
  if status != "received" do
    return Ok(status)
  end
  let path = case decode_consistency_proof(response) do
    Err(_) -> return Ok("mismatch")
    Ok(value) -> value
  end
  Ok(if path.version == current.log_version + 1
    && path.old_tree_size == old
    && path.new_tree_size == new
    && verify_consistency(previous.tree_root, current.tree_root, path).unwrap_or(false) do
    "consistent"
  else
    "mismatch"
  end)
end
