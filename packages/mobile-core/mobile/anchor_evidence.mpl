from Mobile.Types import MobileSecurityConfig, MobileTransparencyView
from Security.Config import SecurityConfig
from Mobile.AnchorSteps import (
  AnchorContext,
  AnchorExchange,
  AnchorStop,
  anchor_asks,
  anchor_call,
  anchor_kind_directory,
  anchor_kind_finder,
  anchor_kind_relay,
  anchor_lift,
  anchor_local,
  anchor_rpc,
  anchor_soft,
  anchor_waiting
)
from Mobile.Chain import (
  ChainAccount,
  ChainLog,
  ChainProof,
  ChainRingEntry,
  ChainWitness,
  chain_decode_proof,
  chain_program_account,
  chain_program_request,
  chain_project_program
)
from Mobile.LookupProofs import LookupProof, lookup_proofs_load
from Transparency.CompactWire import CompactInclusion, TransparencyLeafProof
from Mobile.Transparency import canonical_transparency_checkpoint
from Mobile.TrustAlarm import (
  TrustAlarm,
  TrustFrk,
  TrustRelay,
  trust_alarm_anchor_mismatch,
  trust_alarm_raise,
  trust_alarms_load,
  trust_alarms_store,
  trust_frk,
  trust_summary_of
)
from Storage.Keys import platform_key
from Transparency.CompactWire import (
  TransparencyLeafQuery,
  transparency_decode_leaf_proof,
  transparency_encode_leaf_query
)
from Transparency.Fork import (
  ForkEvidence,
  ForkLog,
  ForkRingEntry,
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

##! Mobile.AnchorEvidence: what the anchor check does once the phone's view
##! and the public record disagree (plan §6.7, §6.9): it keeps the evidence,
##! builds FRK proofs in which a ring reference stands in for the public
##! version, files them with every pinned relay, and later reads the chain to
##! see whether a proof landed and which address the judge paid.
##!
##! Same-size (kind 1) and rollback (kind 3) forks need only the two versions.
##! A contradiction (kind 2) names a leaf this device looked up
##! (Mobile.LookupProofs) with its path in the phone's version; the public
##! version's leaf and path come from the directory's leaf query checked
##! against the ring root, or, when the directory will not answer, are left
##! for the relays to complete.

struct AnchorDraft do
  kind :: Int
  checkpoint :: TransparencyCheckpoint
  attestations :: List<WitnessAttestation>
  leaf_index :: Int
  first_path :: List<Bytes>
  first_leaf :: Bytes
  second_path :: List<Bytes>
  second_leaf :: Bytes
  complete :: Bool
end

fn limit() -> Int do
  8
end

fn stored_proofs(database_path :: String) -> List<LookupProof>!String do
  lookup_proofs_load(database_path, platform_key()?)
end

fn stored_alarms(database_path :: String) -> List<TrustAlarm>!String do
  trust_alarms_load(database_path, platform_key()?)
end

fn zeros(length :: Int) -> Bytes do
  case Bytes.repeat(0, length) do
    Ok(value) -> value
    Err(_) -> Bytes.empty()
  end
end

fn int_of(value :: U64) -> Int do
  case U64.to_int(value) do
    Ok(parsed) -> parsed
    Err(_) -> -1
  end
end

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

# Which fork two versions prove on their own (INTERFACES §5): 1 same size with
# another root, 3 sequence and size order disagree (or one sequence, two
# checkpoints), 0 when only a proof over the leaves can tell.

pub fn anchor_fork_kind(local :: TransparencyCheckpoint, entry :: ChainRingEntry) -> Int!String do
  let sequence = int_of(local.sequence)
  let size = int_of(local.tree_size)
  let digest = checkpoint_hash(local)?
  if size == entry.tree_size && !Bytes.secure_equals(local.tree_root, entry.root) do
    Ok(1)
  else if (sequence < entry.sequence && size > entry.tree_size)
    || (sequence > entry.sequence && size < entry.tree_size)
    || (sequence == entry.sequence && !Bytes.secure_equals(digest, entry.hash)) do
    Ok(3)
  else
    Ok(0)
  end
end

pub fn anchor_fork_log(log :: ChainLog) -> ForkLog do
  ForkLog {
    service_public_key: log.service_key,
    witnesses: List.map(log.witnesses,
      fn witness -> WitnessKey {
        witness_id: witness.witness_id,
        public_key: witness.public_key
      } end)
  }
end

pub fn anchor_ring_entry(entry :: ChainRingEntry) -> ForkRingEntry!String do
  Ok(ForkRingEntry {
    sequence: wide(entry.sequence)?,
    tree_size: wide(entry.tree_size)?,
    root: entry.root,
    checkpoint_hash: entry.hash,
    cosign_bitmap: entry.bitmap
  })
end

fn plain(kind :: Int,
  checkpoint :: TransparencyCheckpoint,
  attestations :: List<WitnessAttestation>) -> AnchorDraft do
  AnchorDraft {
    kind: kind,
    checkpoint: checkpoint,
    attestations: attestations,
    leaf_index: 0,
    first_path: List.new(),
    first_leaf: Bytes.empty(),
    second_path: List.new(),
    second_leaf: Bytes.empty(),
    complete: true
  }
end

fn leaf_tag(index :: Int, size :: Int) -> String do
  "leaf:#{index}:#{size}"
end

fn leaf_query(index :: Int, size :: Int) -> Bytes!String do
  transparency_encode_leaf_query(TransparencyLeafQuery {
    leaf_index: index,
    tree_size: size,
    tree: 1
  })
end

# The directory's answer for leaf `index` in the public version: its leaf and
# path when they prove it under the ring root, None when refused or wrong.

fn public_leaf(answer :: AnchorExchange,
  index :: Int,
  entry :: ChainRingEntry) -> Option<(Bytes, List<Bytes>)> do
  if answer.status != 200 do
    None
  else
    case transparency_decode_leaf_proof(answer.answer) do
      Err(_) -> None
      Ok(proof) -> if proof.inclusion.leaf_index == index
        && proof.inclusion.tree_size == entry.tree_size
        && tlog_verify_inclusion(1,
          proof.leaf_hash,
          index,
          entry.tree_size,
          proof.inclusion.path,
          entry.root) do
        Some((proof.leaf_hash, proof.inclusion.path))
      else
        None
      end
    end
  end
end

fn contradiction(ctx :: AnchorContext,
  proof :: LookupProof,
  checkpoint :: TransparencyCheckpoint,
  entry :: ChainRingEntry) -> Result<Option<AnchorDraft>, AnchorStop> do
  let tag = leaf_tag(proof.leaf_index, entry.tree_size)
  let answer = anchor_call(ctx,
    anchor_kind_directory(),
    tag,
    "/v1/transparency/leaf",
    anchor_lift(leaf_query(proof.leaf_index, entry.tree_size), "invalid_anchor_request")?)?
  let draft = %{plain(2, checkpoint, proof.attestations) |
    leaf_index: proof.leaf_index,
    first_path: proof.path,
    first_leaf: proof.leaf,
    second_leaf: zeros(32),
    complete: false
  }
  case public_leaf(answer, proof.leaf_index, entry) do
    None -> Ok(Some(draft))
    Some((leaf, path)) -> if Bytes.secure_equals(leaf, proof.leaf) do
      Ok(None)
    else
      Ok(Some(%{draft | second_path: path, second_leaf: leaf, complete: true}))
    end
  end
end

# One lookup's proof against the public version: kind 1 or 3 from the
# checkpoint alone, else kind 2 at its leaf when the public tree has it.

fn from_proof(ctx :: AnchorContext,
  proof :: LookupProof,
  entry :: ChainRingEntry) -> Result<Option<AnchorDraft>, AnchorStop> do
  let checkpoint = anchor_local(canonical_transparency_checkpoint(proof.checkpoint))?
  let kind = anchor_local(anchor_fork_kind(checkpoint, entry))?
  if kind != 0 do
    Ok(Some(plain(kind, checkpoint, proof.attestations)))
  else if int_of(checkpoint.tree_size) == entry.tree_size
    || proof.leaf_index >= entry.tree_size
    || proof.leaf_index >= int_of(checkpoint.tree_size) do
    Ok(None)
  else
    contradiction(ctx, proof, checkpoint, entry)
  end
end

fn draft_key(value :: AnchorDraft) -> Bytes do
  let digest = case checkpoint_hash(value.checkpoint) do
    Ok(hash) -> hash
    Err(_) -> Bytes.empty()
  end
  let index = if value.kind == 2 do
    Int.to_string(value.leaf_index)
  else
    ""
  end
  case Bytes.concat(digest, Bytes.from_utf8("#{value.kind}:#{index}")) do
    Ok(key) -> key
    Err(_) -> digest
  end
end

fn distinct(values :: List<AnchorDraft>, output :: List<AnchorDraft>) -> List<AnchorDraft> do
  case values do
    [] -> output
    value :: rest -> if List.any(output,
      fn kept -> Bytes.secure_equals(draft_key(kept), draft_key(value)) end) do
      distinct(rest, output)
    else
      distinct(rest, List.append(output, value))
    end
  end
end

fn somes(values :: List<Result<Option<AnchorDraft>, AnchorStop>>) -> List<AnchorDraft> do
  List.flat_map(values,
    fn value -> case value do
      Ok(Some(draft)) -> [draft]
      _ -> List.new()
    end end)
end

fn asks_all(values :: List<Result<Option<AnchorDraft>, AnchorStop>>) -> List<Bytes> do
  List.flat_map(values, fn value -> anchor_asks(value) end)
end

fn failure(values :: List<Result<Option<AnchorDraft>, AnchorStop>>) -> Option<AnchorStop> do
  List.find(List.flat_map(values,
      fn value -> case value do
        Err(stop) -> [stop]
        Ok(_) -> List.new()
      end end),
    fn stop -> List.length(stop.asks) == 0 end)
end

fn drafts(ctx :: AnchorContext,
  entry :: ChainRingEntry,
  local :: TransparencyCheckpoint,
  kind :: Int) -> Result<List<AnchorDraft>, AnchorStop> do
  let proofs = List.reverse(anchor_local(stored_proofs(ctx.database_path))?)
  let local_bytes = anchor_local(encode_checkpoint(local))?
  let own = List.filter(proofs, fn proof -> Bytes.secure_equals(proof.checkpoint, local_bytes) end)
  let attestations = case own do
    [] -> List.new()
    proof :: _ -> proof.attestations
  end
  if kind != 0 do
    Ok([plain(kind, local, attestations)])
  else
    let results = for proof in proofs do
      from_proof(ctx, proof, entry)
    end
    anchor_waiting(asks_all(results))?
    case failure(results) do
      Some(stop) -> Err(stop)
      None -> Ok(List.take(distinct(somes(results), List.new()), limit()))
    end
  end
end

fn finder(ctx :: AnchorContext, index :: Int) -> Result<Bytes, AnchorStop> do
  let answer = anchor_call(ctx, anchor_kind_finder(), "finder:#{index}", "", Bytes.empty())?
  if answer.status == 200 && Bytes.length(answer.answer) == 32 do
    Ok(answer.answer)
  else
    Ok(zeros(32))
  end
end

fn evidence(draft :: AnchorDraft,
  finder_address :: Bytes,
  service_key :: Bytes,
  entry :: ChainRingEntry) -> ForkEvidence do
  ForkEvidence {
    kind: draft.kind,
    finder: finder_address,
    service_public_key: service_key,
    first: draft.checkpoint,
    second: None,
    ring_index: entry.index,
    attestations: List.take(draft.attestations, 16),
    leaf_index: draft.leaf_index,
    first_path: draft.first_path,
    first_leaf: if draft.kind == 2 do
      draft.first_leaf
    else
      Bytes.empty()
    end,
    second_path: draft.second_path,
    second_leaf: if draft.kind == 2 do
      draft.second_leaf
    else
      Bytes.empty()
    end
  }
end

# A complete proof is checked as the judge would before it is kept; an
# incomplete one (kind 2 without the public side) is kept for the relays.

fn proof_bytes(draft :: AnchorDraft,
  finder_address :: Bytes,
  log :: ChainLog,
  entry :: ChainRingEntry) -> Option<Bytes> do
  case fork_encode(evidence(draft, finder_address, log.service_key, entry)) do
    Err(_) -> None
    Ok(bytes) -> if !draft.complete do
      Some(bytes)
    else
      case checked(bytes, log, entry) do
        Ok(_) -> Some(bytes)
        Err(_) -> None
      end
    end
  end
end

fn checked(bytes :: Bytes, log :: ChainLog, entry :: ChainRingEntry) -> List<String>!String do
  fork_verify(fork_decode(bytes)?, anchor_fork_log(log), Some(anchor_ring_entry(entry)?))
end

fn built(values :: List<AnchorDraft>,
  finders :: List<Result<Bytes, AnchorStop>>,
  index :: Int,
  log :: ChainLog,
  entry :: ChainRingEntry) -> List<(Bytes, Bool)> do
  let draft = List.get(values, index)
  case List.get(finders, index) do
    Err(_) -> List.new()
    Ok(address) -> case proof_bytes(draft, address, log, entry) do
      None -> List.new()
      Some(bytes) -> [(bytes, draft.complete)]
    end
  end
end

fn finalize(ctx :: AnchorContext,
  values :: List<AnchorDraft>,
  log :: ChainLog,
  entry :: ChainRingEntry) -> Result<List<TrustFrk>, AnchorStop> do
  let finders = for index in 0..List.length(values) do
    finder(ctx, index)
  end
  anchor_waiting(List.flat_map(finders, fn value -> anchor_asks(value) end))?
  let kept = List.flatten(for index in 0..List.length(values) do
    built(values, finders, index, log, entry)
  end)
  Ok(for (bytes, complete) in kept do
    anchor_local(trust_frk(bytes, complete))?
  end)
end

fn mismatch_alarm(ctx :: AnchorContext,
  local :: TransparencyCheckpoint,
  entry :: ChainRingEntry,
  frks :: List<TrustFrk>) -> TrustAlarm!String do
  Ok(TrustAlarm {
    kind: trust_alarm_anchor_mismatch(),
    active: true,
    raised_at: ctx.now,
    service_key: ctx.config.transparency_service_public_key,
    first: trust_summary_of(local)?,
    second: %{trust_summary_of(local)? |
      sequence: entry.sequence,
      tree_size: entry.tree_size,
      root: entry.root
    },
    frks: frks
  })
end

fn active_mismatch(ctx :: AnchorContext) -> Option<TrustAlarm>!String do
  let alarms = stored_alarms(ctx.database_path)?
  Ok(List.find(alarms,
    fn value -> value.active
      && value.kind == trust_alarm_anchor_mismatch()
      && Bytes.secure_equals(value.service_key, ctx.config.transparency_service_public_key) end))
end

# The phone's view and the public record disagree: fail closed at once (the
# alarm is raised before any proof exists), then build and keep the proofs.
# An active mismatch that already holds proofs is left as it is.

pub fn anchor_evidence_mismatch(ctx :: AnchorContext,
  log :: ChainLog,
  entry :: ChainRingEntry,
  local :: TransparencyCheckpoint,
  kind :: Int) -> Result<(), AnchorStop> do
  let existing = anchor_local(active_mismatch(ctx))?
  let has_proofs = case existing do
    Some(alarm) -> List.length(alarm.frks) > 0
    None -> false
  end
  if has_proofs do
    return Ok(nil)
  end
  let raised = case existing do
    Some(_) -> true
    None -> false
  end
  if !raised do
    anchor_local(trust_alarm_raise(ctx.database_path,
      anchor_local(mismatch_alarm(ctx, local, entry, List.new()))?))?
  end
  let built = drafts(ctx, entry, local, kind)?
  let frks = finalize(ctx, built, log, entry)?
  if List.length(frks) > 0 do
    anchor_local(trust_alarm_raise(ctx.database_path,
      anchor_local(mismatch_alarm(ctx, local, entry, frks))?))?
  end
  Ok(nil)
end

fn relay_tag(frk :: TrustFrk, url :: String) -> String do
  let hash = case fork_proof_hash(frk.bytes) do
    Ok(value) -> Bytes.to_hex(value)
    Err(_) -> ""
  end
  "relay:#{hash}:#{url}"
end

# A relay answers 202 while it lands the proof and 200 once it has landed,
# with the proof hash it is landing (it may have completed the proof).

fn parsed_hash(body :: Bytes) -> Bytes!String do
  let root = Json.parse(Bytes.to_utf8(body)?)?
  let value = Bytes.from_hex(Json.as_string(Json.object_get(root, "proof_hash")?)?)?
  if Bytes.length(value) == 32 do
    Ok(value)
  else
    Err("invalid_proof_hash")
  end
end

fn reported_hash(body :: Bytes) -> Bytes do
  case parsed_hash(body) do
    Ok(value) -> value
    Err(_) -> zeros(32)
  end
end

fn filed(relay :: TrustRelay, answer :: AnchorExchange) -> TrustRelay do
  if answer.status == 200 || answer.status == 202 do
    %{relay | status: 1, proof_hash: reported_hash(answer.answer)}
  else if answer.status >= 400
    && answer.status < 500
    && answer.status != 408
    && answer.status != 429 do
    %{relay | status: 2}
  else
    %{relay | status: 0}
  end
end

fn file_relay(ctx :: AnchorContext,
  active :: Bool,
  frk :: TrustFrk,
  relay :: TrustRelay) -> Result<TrustRelay, AnchorStop> do
  if relay.status != 0 || !active do
    Ok(relay)
  else
    let answer = anchor_call(ctx,
      anchor_kind_relay(),
      relay_tag(frk, relay.url),
      relay.url <> "/v1/fork-evidence",
      frk.bytes)?
    Ok(filed(relay, answer))
  end
end

# Every proof of every active alarm goes to every pinned relay; a relay that
# did not answer (or was busy) is tried again on the next run.

pub fn anchor_filing(ctx :: AnchorContext) -> Result<(), AnchorStop> do
  let alarms = anchor_local(stored_alarms(ctx.database_path))?
  let results = for alarm in alarms do
    for frk in alarm.frks do
      for relay in frk.relays do
        file_relay(ctx, alarm.active, frk, relay)
      end
    end
  end
  let asks = List.flat_map(results,
    fn per_alarm -> List.flat_map(per_alarm,
      fn per_frk -> List.flat_map(per_frk, fn value -> anchor_asks(value) end) end) end)
  let updated = for index in 0..List.length(alarms) do
    with_relays(List.get(alarms, index), List.get(results, index))
  end
  if List.length(alarms) > 0 do
    anchor_local(trust_alarms_store(ctx.database_path, updated))?
  end
  anchor_waiting(asks)
end

fn relay_of(results :: List<Result<TrustRelay, AnchorStop>>,
  relays :: List<TrustRelay>,
  slot :: Int) -> TrustRelay do
  case List.get(results, slot) do
    Ok(relay) -> relay
    Err(_) -> List.get(relays, slot)
  end
end

fn frk_with_relays(frk :: TrustFrk, results :: List<Result<TrustRelay, AnchorStop>>) -> TrustFrk do
  let relays = for slot in 0..List.length(frk.relays) do
    relay_of(results, frk.relays, slot)
  end
  %{frk | relays: relays}
end

fn with_relays(alarm :: TrustAlarm,
  results :: List<List<Result<TrustRelay, AnchorStop>>>) -> TrustAlarm do
  let frks = for position in 0..List.length(alarm.frks) do
    frk_with_relays(List.get(alarm.frks, position), List.get(results, position))
  end
  %{alarm | frks: frks}
end

fn proof_hashes(frk :: TrustFrk) -> List<Bytes> do
  let own = case fork_proof_hash(frk.bytes) do
    Ok(value) -> [value]
    Err(_) -> List.new()
  end
  let empty = zeros(32)
  List.reduce(for relay in frk.relays when relay.status == 1
      && !Bytes.secure_equals(relay.proof_hash, empty) do
      relay.proof_hash
    end,
    own,
    fn kept, hash -> if List.any(kept, fn value -> Bytes.secure_equals(value, hash) end) do
      kept
    else
      List.append(kept, hash)
    end end)
end

fn proof_record(ctx :: AnchorContext, projection :: Bytes) -> ChainProof!String do
  let judge = ctx.config.config.judge_program_id
  case chain_program_account(projection)? do
    None -> Err("proof_not_found")
    Some((_, account)) -> do
      let proof = chain_decode_proof(account.data)?
      if account.owner != judge || proof.log != ctx.config.config.log_account do
        Err("proof_not_found")
      else
        Ok(proof)
      end
    end
  end
end

# The judge's pay-once record for one read, when it exists for the pinned log.

fn landed_proof(ctx :: AnchorContext,
  read :: Result<Option<Bytes>, AnchorStop>) -> List<ChainProof> do
  case read do
    Ok(Some(projection)) -> case proof_record(ctx, projection) do
      Ok(proof) -> [proof]
      Err(_) -> List.new()
    end
    _ -> List.new()
  end
end

fn landed_frk(ctx :: AnchorContext, frk :: TrustFrk) -> Result<TrustFrk, AnchorStop> do
  if frk.landed || !List.any(frk.relays, fn relay -> relay.status == 1 end) do
    return Ok(frk)
  end
  let log_bytes = anchor_lift(Bytes.from_base58(ctx.config.config.log_account), "chain_invalid")?
  let judge = ctx.config.config.judge_program_id
  let reads = for hash in proof_hashes(frk) do
    anchor_soft(anchor_rpc(ctx,
      "proof:#{Bytes.to_hex(hash)}",
      chain_program_request(judge, 112, [(0, pair(5)), (8, log_bytes), (40, hash)]),
      fn body -> chain_project_program(body) end))
  end
  anchor_waiting(List.flat_map(reads, fn value -> anchor_asks(value) end))?
  let found = List.flat_map(reads, fn value -> landed_proof(ctx, value) end)
  case found do
    [] -> Ok(frk)
    proof :: _ -> Ok(%{frk | landed: true, paid_to: proof.paid_to, slot: proof.slot})
  end
end

fn frk_landing(results :: List<Result<TrustFrk, AnchorStop>>,
  frks :: List<TrustFrk>,
  position :: Int) -> TrustFrk do
  case List.get(results, position) do
    Ok(frk) -> frk
    Err(_) -> List.get(frks, position)
  end
end

fn with_landing(alarm :: TrustAlarm, results :: List<Result<TrustFrk, AnchorStop>>) -> TrustAlarm do
  let frks = for position in 0..List.length(alarm.frks) do
    frk_landing(results, alarm.frks, position)
  end
  %{alarm | frks: frks}
end

fn pair(tag :: Int) -> Bytes do
  case Bytes.from_list([tag, 1]) do
    Ok(value) -> value
    Err(_) -> Bytes.empty()
  end
end

# After filing, the phone reads the judge's pay-once record for each proof
# (morse-judge-v1.md §4.6): whether it landed, and which address was paid.

pub fn anchor_landing(ctx :: AnchorContext) -> Result<(), AnchorStop> do
  let alarms = anchor_local(stored_alarms(ctx.database_path))?
  let results = for alarm in alarms do
    for frk in alarm.frks do
      landed_frk(ctx, frk)
    end
  end
  let asks = List.flat_map(results,
    fn per_alarm -> List.flat_map(per_alarm, fn value -> anchor_asks(value) end) end)
  let changed = List.any(results,
    fn per_alarm -> List.any(per_alarm,
      fn value -> case value do
        Ok(frk) -> frk.landed
        Err(_) -> false
      end end) end)
  if changed do
    let updated = for index in 0..List.length(alarms) do
      with_landing(List.get(alarms, index), List.get(results, index))
    end
    anchor_local(trust_alarms_store(ctx.database_path, updated))?
  end
  anchor_waiting(asks)
end
