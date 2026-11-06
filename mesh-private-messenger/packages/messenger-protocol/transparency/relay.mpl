from Transparency.AnchorChain import (
  AnchorPins,
  AnchorSnapshot,
  AnchorRecord,
  AnchorWitnessRecord,
  sample_anchor_sources,
  read_anchor_header,
  read_anchor_log,
  read_anchor_log_context,
  read_anchor_record,
  read_anchor_witness_record
)
from Transparency.AnchorRing import AnchorHeader, AnchorEntry
from Transparency.AnchorLog import AnchorLog
from Transparency.AnchorWitnessSet import AnchorWitnessSet, AnchorWitness
from Transparency.AnchorEvidence import evidence_anchor
from Transparency.AnchorRegistry import CollectibleWitnesses, read_collectible_witnesses
from Transparency.Fork import (
  ForkProof,
  ForkTarget,
  ForkAnchor,
  ForkVerdict,
  ForkPaths,
  decode_fork,
  fork_hash,
  fork_same_size,
  fork_contradiction,
  fork_rollback,
  fork_at_anchor
)
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessKey,
  WitnessAttestation,
  InclusionProof,
  verify_checkpoint,
  verify_inclusion
)

pub struct RelayVerification do
  proof :: Bytes
  proof_hash :: Bytes
  finder :: Bytes
  verdict :: ForkVerdict
  service_slashed :: Bool
  context_slot :: U64
  anchor_header :: Bytes
  anchor_entry :: Bytes
  witness_set :: Bytes
  witness_scope :: String
end

fn signed(proof :: ForkProof,
  key :: SigningPublicKey,
  pins :: List<WitnessKey>) -> ForkVerdict!String do
  if proof.kind == 1 do
    fork_same_size(proof, key, pins)
  else if proof.kind == 2 do
    fork_contradiction(proof, key, pins)
  else
    fork_rollback(proof, key, pins)
  end
end

# Reject malformed or incorrectly signed submissions before any RPC work.
# Keys and log version come from operator configuration, never from FRK.
fn candidate(wire :: Bytes, key :: SigningPublicKey, version :: Int) -> ForkProof!String do
  if Bytes.length(wire) > 8192 || Bytes.length(key.bytes) != 32 || (version != 1 && version != 2) do
    return Err("invalid_relay_submission")
  end
  let proof = decode_fork(wire)?
  if proof.first.version != version || !Bytes.secure_equals(proof.service_public_key, key.bytes) do
    return Err("relay_log_mismatch")
  end
  if !verify_checkpoint(proof.first, key)? do
    return Err("fork_checkpoint_signature_failed")
  end
  case proof.second do
    SignedCheckpoint(_) -> do
      signed(proof, key, [])?
      nil
    end
    AnchorReference(_) -> case proof.contradiction do
      None -> nil
      Some(paths) -> do
        let private = InclusionProof {
          version: version + 1,
          leaf_index: U64.to_int(paths.leaf_index)?,
          tree_size: U64.to_int(proof.first.tree_size)?,
          leaf_hashes: paths.first_path
        }
        if !verify_inclusion(paths.first_leaf, private, proof.first.tree_root)? do
          return Err("fork_not_proven")
        end
      end
    end
  end
  Ok(proof)
end

pub fn validate_relay_submission(service_key :: Bytes,
  version :: Int,
  wire :: Bytes) -> ForkProof!String do
  candidate(wire, SigningPublicKey { bytes: service_key }, version)
end

fn bare_anchor(index :: Int, key :: Bytes, entry :: AnchorEntry) -> ForkAnchor!String do
  if entry.witness_generation != 0 || entry.cosign_bitmap != 0 || entry.native_bitmap != 0 do
    return Err("anchor_witness_set_mismatch")
  end
  Ok(ForkAnchor {
    ring_index: index,
    log_version: entry.log_version,
    service_public_key: key,
    sequence: entry.sequence,
    tree_size: entry.tree_size,
    tree_root: entry.tree_root,
    checkpoint_hash: entry.checkpoint_hash,
    cosigners: [],
    native_cosigners: []
  })
end

fn keys(set :: AnchorWitnessSet) -> List<WitnessKey> do
  for witness in set.witnesses do
    WitnessKey { witness_id: witness.witness_id, public_key: witness.public_key }
  end
end

# This is cryptographic preflight, not a promise that the judge will admit or
# pay a proof. The writer must still enforce its durable spend policy and the
# judge must enforce proof age, bonded state, finder custody and pay-once PDAs.
# An ACV context supplied by a phone/monitor is deliberately not an input.
pub fn verify_relay_fork(pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  wire :: Bytes,
  minimum_slot :: U64) -> RelayVerification!String do
  let key = SigningPublicKey { bytes: service_key }
  let proof = candidate(wire, key, version)?
  let pins = sample_anchor_sources(pins)?
  case proof.second do
    SignedCheckpoint(_) -> do
      let (log, log_slot) = read_anchor_log_context(pins, service_key, version, minimum_slot)?
      let (verdict, context, scope) = if List.length(proof.attestations) == 0 do
        (signed(proof, key, [])?, log_slot, "none")
      else
        let registry = read_collectible_witnesses(pins, log_slot)?
        # Each immutable identity may retain a bond after membership rotation.
        let accused = List.flat_map(for pin in registry.keys when List.length(List.filter(proof.attestations,
            fn(attestation) do attestation.witness_id == pin.witness_id end)) > 0 do
            signed(proof, key, [pin])?.witnesses
          end,
          fn(values) -> values end)
        if List.length(accused) > 16 do
          return Err("invalid_relay_witnesses")
        end
        (ForkVerdict { service_public_key: service_key, witnesses: accused },
          registry.context_slot,
          "collectible-registry")
      end
      Ok(RelayVerification {
        proof: wire,
        proof_hash: fork_hash(proof)?,
        finder: proof.finder,
        verdict: verdict,
        service_slashed: log.service_slashed,
        context_slot: context,
        anchor_header: Bytes.empty(),
        anchor_entry: Bytes.empty(),
        witness_set: Bytes.empty(),
        witness_scope: scope
      })
    end
    AnchorReference(index) -> do
      let snapshot = read_anchor_header(pins, minimum_slot)?
      let log = read_anchor_log(pins, service_key, version, snapshot.context_slot)?
      let distance = (snapshot.header.head - index + 4096) % 4096
      if distance >= snapshot.header.count do
        return Err("relay_anchor_missing")
      end
      let record = read_anchor_record(pins, snapshot, distance)?
      let (verdict, witness_set, scope) = if record.entry.witness_generation == 0 do
        (fork_at_anchor(proof, key, [], bare_anchor(index, service_key, record.entry)?)?,
          Bytes.empty(),
          "none")
      else
        let set = read_anchor_witness_record(pins,
          record.entry.witness_generation,
          snapshot.context_slot)?
        let anchor = evidence_anchor(pins.log_id, index, service_key, record.entry, set.set)?
        (fork_at_anchor(proof, key, keys(set.set), anchor)?, set.bytes, "historical-anchor")
      end
      Ok(RelayVerification {
        proof: wire,
        proof_hash: fork_hash(proof)?,
        finder: proof.finder,
        verdict: verdict,
        service_slashed: log.service_slashed,
        context_slot: snapshot.context_slot,
        anchor_header: snapshot.bytes,
        anchor_entry: record.bytes,
        witness_set: witness_set,
        witness_scope: scope
      })
    end
  end
end
