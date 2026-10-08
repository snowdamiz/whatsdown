from Mobile.AnchorSteps import (
  AnchorContext,
  AnchorExchange,
  AnchorStop,
  anchor_asks,
  anchor_call,
  anchor_kind_directory,
  anchor_kind_finder,
  anchor_lift,
  anchor_local,
  anchor_waiting
)
from Mobile.LookupProofs import LookupProof, lookup_proofs_load
from Mobile.Transparency import canonical_transparency_checkpoint
from Mobile.Types import MobileSecurityConfig
from Security.Config import SecurityConfig, SecurityWitness
from Storage.Keys import platform_key
from Transparency.CompactWire import (
  TransparencyLeafQuery,
  WitnessCosignature,
  transparency_decode_leaf_proof,
  transparency_encode_leaf_query
)
from Transparency.Fork import (
  ForkEvidence,
  ForkLog,
  fork_decode,
  fork_encode,
  fork_proof_hash,
  fork_verify
)
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  WitnessKey,
  checkpoint_hash
)
from Transparency.Tree import tlog_verify_inclusion
from Transparency.Wire import encode_checkpoint

##! Mobile.GossipEvidence: the FRK proofs checkpoint gossip builds once this
##! device holds a contact's service-signed checkpoint that cannot be true
##! alongside its own (plan §6.16 step 6). Same-size (kind 1) and rollback
##! (kind 3) forks need only the two checkpoints. When the two only disagree
##! over their leaves, each leaf this device looked up (Mobile.LookupProofs) is
##! asked for in the contact's version through the directory's leaf query
##! (KTP v2); one that reads differently proves a contradiction (kind 2). Each
##! proof names a fresh finder address from the app (the same hook as the
##! anchor check) and is checked as the judge checks it before it is kept.

struct GossipDraft do
  kind :: Int
  first :: TransparencyCheckpoint
  first_attestations :: List<WitnessAttestation>
  leaf_index :: Int
  first_path :: List<Bytes>
  first_leaf :: Bytes
  second_path :: List<Bytes>
  second_leaf :: Bytes
end

fn zeros() -> Bytes do
  case Bytes.repeat(0, 32) do
    Ok(value) -> value
    Err(_) -> Bytes.empty()
  end
end

fn size_of(value :: TransparencyCheckpoint) -> Int do
  case U64.to_int(value.tree_size) do
    Ok(size) -> size
    Err(_) -> -1
  end
end

fn fork_log(config :: MobileSecurityConfig) -> ForkLog do
  ForkLog {
    service_public_key: config.transparency_service_public_key,
    witnesses: for witness in config.config.witnesses do
      WitnessKey { witness_id: witness.witness_id, public_key: witness.public_key }
    end
  }
end

fn attestations_for(proofs :: List<LookupProof>,
  checkpoint :: TransparencyCheckpoint) -> List<WitnessAttestation> do
  let encoded = case encode_checkpoint(checkpoint) do
    Ok(value) -> value
    Err(_) -> Bytes.empty()
  end
  case List.find(List.reverse(proofs),
    fn proof -> Bytes.secure_equals(proof.checkpoint, encoded) end) do
    Some(proof) -> proof.attestations
    None -> List.new()
  end
end

## The attestations this device verified on `checkpoint`, as GCA carries
## them (KTW v2 kind 1).

pub fn gossip_own_cosignatures(database_path :: String,
  checkpoint :: TransparencyCheckpoint) -> List<WitnessCosignature>!String do
  let proofs = lookup_proofs_load(database_path, platform_key()?)?
  Ok(for value in attestations_for(proofs, checkpoint) do
    WitnessCosignature {
      kind: 1,
      witness_id: value.witness_id,
      checkpoint_hash: value.checkpoint_hash,
      timestamp: 0,
      signature: value.signature
    }
  end)
end

# A contact's attestations count only for pinned witnesses on its checkpoint;
# fork_verify then checks each signature.

fn contact_attestations(witnesses :: List<WitnessCosignature>,
  digest :: Bytes,
  log :: ForkLog) -> List<WitnessAttestation> do
  let pinned = for value in witnesses when value.kind == 1
    && Bytes.secure_equals(value.checkpoint_hash, digest)
    && List.any(log.witnesses, fn key -> key.witness_id == value.witness_id end) do
    WitnessAttestation {
      witness_id: value.witness_id,
      checkpoint_hash: value.checkpoint_hash,
      signature: value.signature
    }
  end
  List.reduce(pinned,
    List.new(),
    fn kept, value -> if List.any(kept, fn other -> other.witness_id == value.witness_id end) do
      kept
    else
      List.append(kept, value)
    end end)
end

# ponytail: at most 8 witnesses implicated per proof (FRK holds 16
# attestations); a larger set would need one proof per group of eight.

fn paired(first :: List<WitnessAttestation>,
  second :: List<WitnessAttestation>) -> List<WitnessAttestation> do
  let both = List.take(List.filter(first,
      fn value -> List.any(second, fn other -> other.witness_id == value.witness_id end) end),
    8)
  let pairs = List.flat_map(both,
    fn value -> [value]
      ++ List.take(List.filter(second, fn other -> other.witness_id == value.witness_id end),
        1) end)
  let rest = List.filter(first ++ second,
    fn value -> !List.any(pairs,
      fn kept -> kept.witness_id == value.witness_id
        && Bytes.secure_equals(kept.checkpoint_hash, value.checkpoint_hash) end) end)
  List.take(pairs ++ rest, 16)
end

fn evidence(draft :: GossipDraft,
  finder :: Bytes,
  config :: MobileSecurityConfig,
  other :: TransparencyCheckpoint,
  second_attestations :: List<WitnessAttestation>) -> ForkEvidence do
  ForkEvidence {
    kind: draft.kind,
    finder: finder,
    service_public_key: config.transparency_service_public_key,
    first: draft.first,
    second: Some(other),
    ring_index: 0,
    attestations: paired(draft.first_attestations, second_attestations),
    leaf_index: draft.leaf_index,
    first_path: draft.first_path,
    first_leaf: draft.first_leaf,
    second_path: draft.second_path,
    second_leaf: draft.second_leaf
  }
end

fn verified_bytes(value :: ForkEvidence, log :: ForkLog) -> Option<Bytes> do
  case fork_encode(value) do
    Err(_) -> None
    Ok(bytes) -> case fork_decode(bytes) do
      Err(_) -> None
      Ok(decoded) -> case fork_verify(decoded, log, None) do
        Ok(_) -> Some(bytes)
        Err(_) -> None
      end
    end
  end
end

# One proof from one draft: its finder address is asked for under a tag named
# after the proof hash, which leaves the finder out and so is known first.

fn proof(ctx :: AnchorContext,
  draft :: GossipDraft,
  other :: TransparencyCheckpoint,
  second_attestations :: List<WitnessAttestation>) -> Result<Option<Bytes>, AnchorStop> do
  let log = fork_log(ctx.config)
  let unnamed = evidence(draft, zeros(), ctx.config, other, second_attestations)
  let hash = case verified_bytes(unnamed, log) do
    None -> return Ok(None)
    Some(bytes) -> anchor_local(fork_proof_hash(bytes))?
  end
  let answer = anchor_call(ctx,
    anchor_kind_finder(),
    "gossip-finder:#{Bytes.to_hex(hash)}",
    "",
    Bytes.empty())?
  let finder = if answer.status == 200 && Bytes.length(answer.answer) == 32 do
    answer.answer
  else
    zeros()
  end
  Ok(verified_bytes(evidence(draft, finder, ctx.config, other, second_attestations), log))
end

fn proofs_of(ctx :: AnchorContext,
  drafts :: List<GossipDraft>,
  other :: TransparencyCheckpoint,
  witnesses :: List<WitnessCosignature>) -> Result<List<Bytes>, AnchorStop> do
  let digest = anchor_local(checkpoint_hash(other))?
  let second = contact_attestations(witnesses, digest, fork_log(ctx.config))
  let built = for draft in drafts do
    proof(ctx, draft, other, second)
  end
  anchor_waiting(List.flat_map(built, fn value -> anchor_asks(value) end))?
  Ok(List.flat_map(built,
    fn value -> case value do
      Ok(Some(bytes)) -> [bytes]
      _ -> List.new()
    end end))
end

fn load_proofs(database_path :: String) -> List<LookupProof>!String do
  lookup_proofs_load(database_path, platform_key()?)
end

fn stored_proofs(ctx :: AnchorContext) -> Result<List<LookupProof>, AnchorStop> do
  anchor_local(load_proofs(ctx.database_path))
end

## A same-size (1) or rollback (3) fork between this device's checkpoint and
## the contact's: the proofs, once their finder addresses are in.

pub fn gossip_fork_proofs(ctx :: AnchorContext,
  own :: TransparencyCheckpoint,
  other :: TransparencyCheckpoint,
  witnesses :: List<WitnessCosignature>,
  kind :: Int) -> Result<List<Bytes>, AnchorStop> do
  let stored = stored_proofs(ctx)?
  let draft = GossipDraft {
    kind: kind,
    first: own,
    first_attestations: attestations_for(stored, own),
    leaf_index: 0,
    first_path: List.new(),
    first_leaf: Bytes.empty(),
    second_path: List.new(),
    second_leaf: Bytes.empty()
  }
  proofs_of(ctx, [draft], other, witnesses)
end

fn leaf_query(index :: Int, size :: Int) -> Bytes!String do
  transparency_encode_leaf_query(TransparencyLeafQuery {
    leaf_index: index,
    tree_size: size,
    tree: 1
  })
end

# The contact's version of leaf `index`: its leaf and path when the directory's
# answer proves it under the contact's root.

fn their_leaf(answer :: AnchorExchange,
  index :: Int,
  other :: TransparencyCheckpoint) -> Option<(Bytes, List<Bytes>)> do
  if answer.status != 200 do
    None
  else
    case transparency_decode_leaf_proof(answer.answer) do
      Err(_) -> None
      Ok(proof) -> if proof.inclusion.leaf_index == index
        && proof.inclusion.tree_size == size_of(other)
        && tlog_verify_inclusion(1,
          proof.leaf_hash,
          index,
          size_of(other),
          proof.inclusion.path,
          other.tree_root) do
        Some((proof.leaf_hash, proof.inclusion.path))
      else
        None
      end
    end
  end
end

fn contradiction(ctx :: AnchorContext,
  stored :: List<LookupProof>,
  lookup :: LookupProof,
  other :: TransparencyCheckpoint) -> Result<Option<GossipDraft>, AnchorStop> do
  let mine = case canonical_transparency_checkpoint(lookup.checkpoint) do
    Ok(value) -> value
    Err(_) -> return Ok(None)
  end
  let size = size_of(other)
  if lookup.leaf_index >= size || lookup.leaf_index >= size_of(mine) || size == size_of(mine) do
    return Ok(None)
  end
  let answer = anchor_call(ctx,
    anchor_kind_directory(),
    "gossip-leaf:#{lookup.leaf_index}:#{size}",
    "/v1/transparency/leaf",
    anchor_lift(leaf_query(lookup.leaf_index, size), "invalid_anchor_request")?)?
  case their_leaf(answer, lookup.leaf_index, other) do
    None -> Ok(None)
    Some((leaf, path)) -> if Bytes.secure_equals(leaf, lookup.leaf) do
      Ok(None)
    else
      Ok(Some(GossipDraft {
        kind: 2,
        first: mine,
        first_attestations: attestations_for(stored, mine),
        leaf_index: lookup.leaf_index,
        first_path: lookup.path,
        first_leaf: lookup.leaf,
        second_path: path,
        second_leaf: leaf
      }))
    end
  end
end

fn distinct_leaves(values :: List<LookupProof>) -> List<LookupProof> do
  List.reduce(values,
    List.new(),
    fn kept, value -> if List.any(kept, fn other -> other.leaf_index == value.leaf_index end) do
      kept
    else
      List.append(kept, value)
    end end)
end

## Two checkpoints whose sizes differ in the order their sequences do, with no
## consistency proof between them: a contradiction proof for each leaf this
## device looked up that the contact's version holds otherwise (at most two).
## None found is not a fork anyone can prove; nothing is raised.

pub fn gossip_contradiction_proofs(ctx :: AnchorContext,
  other :: TransparencyCheckpoint,
  witnesses :: List<WitnessCosignature>) -> Result<List<Bytes>, AnchorStop> do
  let stored = stored_proofs(ctx)?
  let found = for lookup in distinct_leaves(List.reverse(stored)) do
    contradiction(ctx, stored, lookup, other)
  end
  anchor_waiting(List.flat_map(found, fn value -> anchor_asks(value) end))?
  let drafts = List.flat_map(found,
    fn value -> case value do
      Ok(Some(draft)) -> [draft]
      _ -> List.new()
    end end)
  proofs_of(ctx, List.take(drafts, 2), other, witnesses)
end
