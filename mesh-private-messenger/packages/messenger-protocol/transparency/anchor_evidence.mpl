from Transparency.AnchorRing import AnchorEntry
from Transparency.AnchorWitnessSet import AnchorWitnessSet, AnchorCosigner, anchor_cosigners
from Transparency.Fork import ForkAnchor, ForkProof, ForkTarget, fork_at_anchor
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessKey,
  WitnessAttestation,
  verify_witnesses
)
from Transparency.Wire import encode_witnesses

# The caller must authenticate the set's PDA, owner, log and generation through
# chain verification first. Decoding a supplied account is not authentication.
pub fn evidence_anchor(log_id :: Bytes,
  index :: Int,
  service_key :: Bytes,
  entry :: AnchorEntry,
  set :: AnchorWitnessSet) -> ForkAnchor!String do
  if Bytes.length(log_id) != 32
    || Bytes.length(service_key) != 32
    || !Bytes.secure_equals(log_id, set.log_id)
    || index < 0
    || index >= 4096 do
    return Err("anchor_witness_set_mismatch")
  end
  let cosigners = anchor_cosigners(entry, set)?
  Ok(ForkAnchor {
    ring_index: index,
    log_version: entry.log_version,
    service_public_key: service_key,
    sequence: entry.sequence,
    tree_size: entry.tree_size,
    tree_root: entry.tree_root,
    checkpoint_hash: entry.checkpoint_hash,
    cosigners: for value in cosigners do
      WitnessKey { witness_id: value.witness_id, public_key: value.public_key }
    end,
    native_cosigners: for value in cosigners when value.native do
      WitnessKey { witness_id: value.witness_id, public_key: value.public_key }
    end
  })
end

fn attestation_for(checkpoint :: TransparencyCheckpoint,
  values :: List<WitnessAttestation>,
  pin :: WitnessKey,
  native_only :: Bool) -> Option<WitnessAttestation>!String do
  for value in values do
    if (!native_only || Bytes.length(value.signature) == 64)
      && verify_witnesses(checkpoint, [value], [pin], 1)? do
      return Ok(Some(value))
    end
  end
  Ok(None)
end

# Preserve at most one valid private-side signature per release-pinned key.
# Public cosigns may arrive later. The verifier intersects these signatures
# with authenticated historical cosigners to decide actual attribution.
# In particular, a C2SP cosigner cannot be accused of native rollback metadata.
pub fn retain_anchor_signatures(proof :: ForkProof,
  service_key :: SigningPublicKey,
  release_pins :: List<WitnessKey>,
  entry :: AnchorEntry,
  signatures :: List<WitnessAttestation>) -> ForkProof!String do
  encode_witnesses(signatures)?
  let index = case proof.second do
    AnchorReference(value) -> value
    SignedCheckpoint(_) -> return Err("fork_anchor_reference_required")
  end
  let anchor = ForkAnchor {
    ring_index: index,
    log_version: entry.log_version,
    service_public_key: service_key.bytes,
    sequence: entry.sequence,
    tree_size: entry.tree_size,
    tree_root: entry.tree_root,
    checkpoint_hash: entry.checkpoint_hash,
    cosigners: [],
    native_cosigners: []
  }
  let base = %{proof | attestations: []}
  # This also validates all release pins and the public cosigner lists before
  # trying signatures; bad signature input cannot invent a service fork.
  fork_at_anchor(base, service_key, release_pins, anchor)?
  let selected = for pin in release_pins do
    attestation_for(proof.first, signatures, pin, proof.kind == 3)?
  end
  let attestations = List.flat_map(selected,
    fn(value) do
      case value do
        None -> []
        Some(signature) -> [signature]
      end
    end)
  let enriched = %{base | attestations: attestations}
  fork_at_anchor(enriched, service_key, release_pins, anchor)?
  Ok(enriched)
end

# The entry and its immutable generation must both come from authenticated
# chain reads. Registry membership does not add to the release's trust policy.
pub fn attribute_anchor_fork(proof :: ForkProof,
  service_key :: SigningPublicKey,
  release_pins :: List<WitnessKey>,
  log_id :: Bytes,
  entry :: AnchorEntry,
  set :: AnchorWitnessSet,
  signatures :: List<WitnessAttestation>) -> ForkProof!String do
  let retained = retain_anchor_signatures(proof, service_key, release_pins, entry, signatures)?
  let index = case retained.second do
    AnchorReference(value) -> value
    SignedCheckpoint(_) -> return Err("fork_anchor_reference_required")
  end
  fork_at_anchor(retained,
    service_key,
    release_pins,
    evidence_anchor(log_id, index, service_key.bytes, entry, set)?)?
  Ok(retained)
end
