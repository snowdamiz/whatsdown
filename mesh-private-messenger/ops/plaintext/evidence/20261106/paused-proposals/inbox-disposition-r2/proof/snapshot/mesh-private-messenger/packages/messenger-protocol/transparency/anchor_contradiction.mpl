from Transparency.AnchorHttp import anchor_proof_origin, fetch_anchor_proof
from Transparency.AnchorRing import AnchorEntry
from Transparency.AnchorEvidence import retain_anchor_signatures
from Transparency.LeafProof import (
  LeafQuery,
  LeafProof,
  encode_leaf_query,
  encode_leaf_proof,
  decode_leaf_proof
)
from Transparency.Fork import ForkProof, ForkPaths, ForkTarget, encode_fork
from Transparency.Merkle import (
  TransparencyCheckpoint,
  InclusionProof,
  verify_checkpoint,
  verify_inclusion
)

pub struct AnchorLeafEvidence do
  status :: String
  fork :: Bytes
  response :: Bytes
end

fn absent(status :: String, response :: Bytes) -> AnchorLeafEvidence do
  AnchorLeafEvidence { status: status, fork: Bytes.empty(), response: response }
end

# The entry must already be authenticated by the release-pinned chain reader.
# A refusal, malformed path, wrong range, or unchanged leaf is not an F2 proof.
pub fn discover_anchor_contradiction(origin :: String,
  local :: TransparencyCheckpoint,
  entry :: AnchorEntry,
  ring_index :: Int,
  service_key :: Bytes,
  private :: LeafProof,
  require_current :: Fun() -> Result<(), String>) -> AnchorLeafEvidence!String do
  let origin = anchor_proof_origin(origin)?
  let key = SigningPublicKey { bytes: service_key }
  encode_leaf_proof(private)?
  if local.version != entry.log_version
    || ring_index < 0
    || ring_index >= 4096
    || !verify_checkpoint(local, key)?
    || private.inclusion.version != local.version + 1
    || U64.compare(local.tree_size, U64.parse(Int.to_string(private.inclusion.tree_size))?) != 0
    || !verify_inclusion(private.leaf_hash, private.inclusion, local.tree_root)? do
    return Err("invalid_anchor_private_leaf")
  end
  let index = private.inclusion.leaf_index
  if U64.compare(entry.tree_size, U64.parse("4294967295")?) > 0 do
    return Err("invalid_anchor_tree_size")
  end
  let size = U64.to_int(entry.tree_size)?
  if index >= size do
    return Ok(absent("not_comparable", Bytes.empty()))
  end
  let (status, response) = fetch_anchor_proof(origin,
    "/v#{entry.log_version}/transparency/leaf",
    encode_leaf_query(LeafQuery { leaf_index: index, tree_size: size })?,
    1074,
    require_current)?
  if status != "received" do
    return Ok(absent(status, response))
  end
  let public = case decode_leaf_proof(response) do
    Err(_) -> return Ok(absent("mismatch", response))
    Ok(value) -> value
  end
  if public.inclusion.version != local.version + 1
    || public.inclusion.tree_size != size
    || public.inclusion.leaf_index != index
    || !verify_inclusion(public.leaf_hash, public.inclusion, entry.tree_root).unwrap_or(false) do
    return Ok(absent("mismatch", response))
  end
  if Bytes.secure_equals(public.leaf_hash, private.leaf_hash) do
    return Ok(absent("same_leaf", response))
  end
  let proof = ForkProof {
    kind: 2,
    finder: Bytes.from_hex(String.repeat("00", 32))?,
    service_public_key: service_key,
    first: local,
    second: AnchorReference(ring_index),
    attestations: [],
    contradiction: Some(ForkPaths {
      leaf_index: U64.parse(Int.to_string(index))?,
      first_path: private.inclusion.leaf_hashes,
      first_leaf: private.leaf_hash,
      second_path: public.inclusion.leaf_hashes,
      second_leaf: public.leaf_hash
    })
  }
  # Reuse the canonical fork verifier before publishing evidence or a pause.
  let verified = retain_anchor_signatures(proof, key, [], entry, [])?
  Ok(AnchorLeafEvidence { status: "mismatch", fork: encode_fork(verified)?, response: response })
end
