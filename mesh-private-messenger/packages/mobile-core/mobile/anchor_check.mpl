from Transparency.AnchorConsistency import AnchorConsistency, compare_anchor
from Transparency.AnchorContradiction import AnchorLeafEvidence, discover_anchor_contradiction
from Transparency.AnchorContinuity import anchor_extends
from Mobile.TransparencyCache import cached_checkpoint_bytes, cached_transparency_bytes
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessKey,
  WitnessAttestation,
  verify_checkpoint
)
from Transparency.Wire import decode_checkpoint, decode_witnesses, encode_witnesses
from Transparency.Fork import ForkProof, ForkTarget, decode_fork, encode_fork
from Transparency.AnchorEvidence import retain_anchor_signatures, attribute_anchor_fork
from Transparency.AnchorContext import (
  AnchorEvidenceContext,
  encode_anchor_context,
  decode_anchor_context
)
from Transparency.LeafProof import LeafProof, decode_leaf_proof, compact_leaf_proof
from Transparency.AnchorChain import (
  AnchorPins,
  AnchorAddresses,
  AnchorSnapshot,
  AnchorFreshness,
  AnchorRecord,
  AnchorWitnessRecord,
  read_anchor_record,
  read_anchor_witness_record,
  anchor_addresses,
  configured_anchor_pins,
  sample_anchor_sources,
  read_anchor_header,
  read_anchor_log,
  read_anchor_freshness
)
from Transparency.AnchorRpc import validate_anchor_sources
from Mobile.AnchorSchedule import (
  AnchorClaim,
  AnchorSchedule,
  claim_anchor_check,
  finish_anchor_check_with_blobs,
  load_anchor_schedule
)
from Mobile.Codec import (
  current_time,
  mobile_join,
  mobile_byte,
  mobile_write_u64,
  mobile_read_u64,
  encode_output_list
)
from Mobile.Platform import native_security_config
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import platform_key, seal_local, local_context
from Solana.Read import Pubkey
from Transparency.Config import SecurityConfig, LogWitnessPolicy, witness_policy_for_log
from Transparency.AnchorLog import AnchorLog
from Transparency.AnchorRing import AnchorHeader, AnchorEntry, decode_anchor_entry

# "observed" authenticates the public account and its posting time only. It
# does not assert consistency with this phone's private transparency view.
pub struct AnchorObservation do
  status :: String
  checked_at :: U64
  context_slot :: U64
  posted_slot :: U64
  block_time :: U64
end

pub struct AnchorView do
  checkpoint :: Bytes
  origin :: String
  witnesses :: List<WitnessAttestation>
  leaf :: Bytes
end

fn statuses() -> List<String> do
  [
    "pending",
    "observed",
    "stale",
    "rpc_unavailable",
    "rpc_disagree",
    "clock_unavailable",
    "empty",
    "service_slashed",
    "consistent",
    "mismatch",
    "proof_unavailable"
  ]
end

fn blank(status :: String) -> AnchorObservation!String do
  let zero = U64.parse("0")?
  Ok(AnchorObservation {
    status: status,
    checked_at: zero,
    context_slot: zero,
    posted_slot: zero,
    block_time: zero
  })
end

# Endpoint rotation and witness policy updates cannot clear a slash or reset
# the hourly limit for the same judge, log and service key.
pub fn anchor_identity(pins :: AnchorPins, service_key :: Bytes, version :: Int) -> Bytes!String do
  let addresses = anchor_addresses(pins.program, pins.log_name)?
  if Bytes.length(service_key) != 32
    || (version != 1 && version != 2)
    || !Bytes.secure_equals(addresses.log_id, pins.log_id)
    || !Bytes.secure_equals(addresses.ring.bytes, pins.ring.bytes) do
    return Err("invalid_anchor_pins")
  end
  Ok(Crypto.sha256(mobile_join([
      Bytes.from_utf8("morse-anchor-observation-v1"),
      pins.program.bytes,
      pins.ring.bytes,
      pins.log_id,
      service_key,
      mobile_byte(version)?
    ],
    0,
    Bytes.empty())?))
end

fn status_code(status :: String) -> Int!String do
  for index in 0..List.length(statuses()) do
    if List.get(statuses(), index) == status do
      return Ok(index)
    end
  end
  Err("invalid_anchor_observation")
end

fn encode_observation(value :: AnchorObservation) -> Bytes!String do
  mobile_join([
      Bytes.from_utf8("ACO1"),
      mobile_byte(status_code(value.status)?)?,
      mobile_write_u64(value.checked_at)?,
      mobile_write_u64(value.context_slot)?,
      mobile_write_u64(value.posted_slot)?,
      mobile_write_u64(value.block_time)?
    ],
    0,
    Bytes.empty())
end

pub fn load_anchor_observation(path :: String,
  key :: borrow StorageKey,
  identity :: Bytes) -> AnchorObservation!String do
  let bytes = load_anchor_schedule(path, key, identity)?.last_result
  if Bytes.length(bytes) == 0 do
    return blank("pending")
  end
  if Bytes.length(bytes) != 37
    || !Bytes.secure_equals(Bytes.slice(bytes, 0, 4)?, Bytes.from_utf8("ACO1")) do
    return Err("invalid_anchor_observation")
  end
  let code = Bytes.get(bytes, 4)?
  if code >= List.length(statuses()) do
    return Err("invalid_anchor_observation")
  end
  Ok(AnchorObservation {
    status: List.get(statuses(), code),
    checked_at: mobile_read_u64(Bytes.slice(bytes, 5, 8)?)?,
    context_slot: mobile_read_u64(Bytes.slice(bytes, 13, 8)?)?,
    posted_slot: mobile_read_u64(Bytes.slice(bytes, 21, 8)?)?,
    block_time: mobile_read_u64(Bytes.slice(bytes, 29, 8)?)?
  })
end

fn failed_observation(previous :: AnchorObservation,
  now :: U64,
  error :: String) -> AnchorObservation do
  let status = if error == "anchor_rpc_disagree" do
    "rpc_disagree"
  else if error == "anchor_clock_skew" || error == "invalid_anchor_clock" do
    "clock_unavailable"
  else
    "rpc_unavailable"
  end
  %{previous | status: status, checked_at: now}
end

struct AnchorAttempt do
  observation :: AnchorObservation
  evidence :: Bytes
  fork :: Bytes
end

fn attempt(value :: AnchorObservation) -> AnchorAttempt do
  AnchorAttempt { observation: value, evidence: Bytes.empty(), fork: Bytes.empty() }
end

# A failed optional attribution read cannot discard an already proven service
# fork. Keep valid private signatures even before a public cosign arrives.
fn with_attribution(pins :: AnchorPins,
  snapshot :: AnchorSnapshot,
  record :: AnchorRecord,
  service_key :: Bytes,
  release_pins :: List<WitnessKey>,
  signatures :: List<WitnessAttestation>,
  fork :: Bytes) -> Result<(Bytes, Bytes), String> do
  if Bytes.length(fork) == 0 do
    return Ok((fork, Bytes.empty()))
  end
  let proof = decode_fork(fork)?
  case proof.second do
    SignedCheckpoint(_) -> return Ok((encode_fork(%{proof | attestations: signatures})?,
      Bytes.empty()))
    AnchorReference(_) -> nil
  end
  let key = SigningPublicKey { bytes: service_key }
  let retained = retain_anchor_signatures(proof, key, release_pins, record.entry, signatures)?
  let encoded = encode_fork(retained)?
  if record.entry.witness_generation == 0 || List.length(retained.attestations) == 0 do
    return Ok((encoded, Bytes.empty()))
  end
  let witnesses = case read_anchor_witness_record(pins,
    record.entry.witness_generation,
    snapshot.context_slot) do
    Err(_) -> return Ok((encoded, Bytes.empty()))
    Ok(value) -> value
  end
  case attribute_anchor_fork(retained,
    key,
    release_pins,
    pins.log_id,
    record.entry,
    witnesses.set,
    signatures) do
    Err(_) -> Ok((encoded, Bytes.empty()))
    Ok(attributed) -> Ok((encode_fork(attributed)?, witnesses.bytes))
  end
end

fn observe(pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  now :: U64,
  previous :: AnchorObservation,
  release_pins :: List<WitnessKey>,
  view :: AnchorView,
  previous_anchor :: Option<AnchorEntry>) -> AnchorAttempt!String do
  let local_bytes = view.checkpoint
  let origin = view.origin
  let sampled = sample_anchor_sources(pins)?
  let snapshot = case read_anchor_header(sampled, previous.context_slot) do
    Err(error) -> return Ok(attempt(failed_observation(previous, now, error)))
    Ok(value) -> value
  end
  let value = AnchorObservation {
    status: "observed",
    checked_at: now,
    context_slot: snapshot.context_slot,
    posted_slot: snapshot.header.last_slot,
    block_time: U64.parse("0")?
  }
  let log = case read_anchor_log(sampled, service_key, version, snapshot.context_slot) do
    Ok(log) -> log
    Err(error) -> return Ok(attempt(failed_observation(value, now, error)))
  end
  # Slash checks run even for empty or stale rings. An authenticated refusal is
  # retained; a future unslashed response or outage never restores this key.
  if log.service_slashed do
    return Ok(attempt(%{value | status: "service_slashed"}))
  end
  if snapshot.header.count == 0 do
    return Ok(attempt(%{value | status: "empty"}))
  end
  let freshness = case read_anchor_freshness(sampled,
    snapshot,
    U64.to_int(U64.divide(now, U64.parse("1000")?)?)?) do
    Ok(freshness) -> freshness
    Err(error) -> return Ok(attempt(failed_observation(value, now, error)))
  end
  let value = %{value | block_time: U64.parse(Int.to_string(freshness.block_time_seconds))?}
  if freshness.stale do
    return Ok(attempt(%{value | status: "stale"}))
  end
  if Bytes.length(local_bytes) == 0 do
    return Ok(attempt(value))
  end
  let local = decode_checkpoint(local_bytes)?
  # Archived legacy caches are authenticated by the migration bridge before
  # they enter this new log. They cannot be compared across hash versions.
  if local.version != version
    || !verify_checkpoint(local, SigningPublicKey { bytes: service_key })? do
    return Ok(attempt(value))
  end
  if String.length(origin) == 0 do
    return Ok(attempt(%{value | status: "proof_unavailable"}))
  end
  let record = case read_anchor_record(sampled, snapshot, 0) do
    Err(error) -> return Ok(attempt(failed_observation(value, now, error)))
    Ok(value) -> value
  end
  if record.entry.log_version != version do
    return Ok(attempt(%{value | status: "rpc_unavailable"}))
  end
  # Checking both directions also authenticates the public prefix when this
  # device is ahead of the anchor writer. It needs just the newest ring entry.
  let compared = compare_anchor(origin, local, record.entry, snapshot.header.head, service_key)?
  let leaf = if compared.status != "consistent"
    && Bytes.length(compared.fork) == 0
    && Bytes.length(view.leaf) > 0 do
    discover_anchor_contradiction(origin,
      local,
      record.entry,
      snapshot.header.head,
      service_key,
      decode_leaf_proof(view.leaf)?)?
  else
    AnchorLeafEvidence { status: "not_checked", fork: Bytes.empty(), response: Bytes.empty() }
  end
  let compared = if leaf.status == "mismatch" do
    %{compared | status: "mismatch", fork: leaf.fork}
  else
    compared
  end
  # Preserve the original public side of an unresolved mismatch. A newer
  # public root must extend it before it may replace that saved observation.
  # A newly verified fork is always retained even if continuity is unavailable.
  if Bytes.length(compared.fork) == 0 do
    case previous_anchor do
      None -> nil
      Some(previous) -> do
        let continuity = anchor_extends(origin, previous, record.entry)?
        if continuity != "consistent" do
          return Ok(attempt(%{value | status: continuity}))
        end
      end
    end
  end
  let (fork, witness_set) = with_attribution(sampled,
    snapshot,
    record,
    service_key,
    release_pins,
    view.witnesses,
    compared.fork)?
  let evidence = if compared.status == "mismatch" do
    encode_anchor_context(AnchorEvidenceContext {
      identity: anchor_identity(pins, service_key, version)?,
      checked_at: now,
      context_slot: snapshot.context_slot,
      header: snapshot.bytes,
      ring_index: snapshot.header.head,
      entry: record.bytes,
      checkpoint: local_bytes,
      origin: origin,
      served_checkpoint: compared.checkpoint,
      consistency: compared.consistency,
      fork: fork,
      witnesses: encode_witnesses(view.witnesses)?,
      witness_set: witness_set,
      private_leaf: view.leaf,
      served_leaf: leaf.response
    })?
  else
    Bytes.empty()
  end
  Ok(AnchorAttempt {
    observation: %{value | status: compared.status},
    evidence: evidence,
    fork: fork
  })
end

# The native entry point supplies these pins and time. Explicit inputs let the
# same Mesh implementation run against local RPC fixtures and device clocks.
pub fn check_anchor_at(path :: String,
  key :: borrow StorageKey,
  pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  now :: U64,
  key_changed :: Bool) -> AnchorObservation!String do
  check_anchor_view_at(path,
    key,
    pins,
    service_key,
    version,
    now,
    key_changed,
    cached_checkpoint_bytes(path, key)?,
    Bytes.to_utf8(cached_transparency_bytes(path, key, "transparency-origin/v1")?)?)
end

# A key-change caller has already authenticated the candidate's signature,
# witness policy and consistency with its cache. Check that candidate before
# accepting it, rather than checking only yesterday's cached checkpoint.
pub fn check_anchor_view_at(path :: String,
  key :: borrow StorageKey,
  pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  now :: U64,
  key_changed :: Bool,
  checkpoint :: Bytes,
  origin :: String) -> AnchorObservation!String do
  check_anchor_attested_at(path,
    key,
    pins,
    service_key,
    version,
    now,
    key_changed,
    [],
    AnchorView { checkpoint: checkpoint, origin: origin, witnesses: [], leaf: Bytes.empty() })
end

fn pending_anchor_context(path :: String,
  key :: borrow StorageKey,
  identity :: Bytes) -> AnchorEvidenceContext!String do
  let context = decode_anchor_context(cached_transparency_bytes(path, key, "anchor-evidence/v1")?)?
  if !Bytes.secure_equals(context.identity, identity) do
    return Err("anchor_evidence_mismatch")
  end
  Ok(context)
end

fn context_view(context :: AnchorEvidenceContext) -> AnchorView!String do
  Ok(AnchorView {
    checkpoint: context.checkpoint,
    origin: context.origin,
    witnesses: if Bytes.length(context.witnesses) == 0 do
      []
    else
      decode_witnesses(context.witnesses)?
    end,
    leaf: context.private_leaf
  })
end

pub fn check_anchor_attested_at(path :: String,
  key :: borrow StorageKey,
  pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  now :: U64,
  key_changed :: Bool,
  release_pins :: List<WitnessKey>,
  view :: AnchorView) -> AnchorObservation!String do
  encode_witnesses(view.witnesses)?
  if Bytes.length(view.leaf) > 0 do
    compact_leaf_proof(decode_leaf_proof(view.leaf)?, decode_checkpoint(view.checkpoint)?)?
  end
  let identity = anchor_identity(pins, service_key, version)?
  validate_anchor_sources(pins.endpoints)?
  let previous = load_anchor_observation(path, key, identity)?
  if previous.status == "service_slashed" do
    return Ok(previous)
  end
  let claim = case claim_anchor_check(path, key, identity, now, key_changed)? do
    None -> return Ok(previous)
    Some(value) -> value
  end
  # A rejected candidate is not in the normal cache. Retry the saved view so
  # an older cache or another contact cannot clear its mismatch. If a new key
  # change also needs checking, both comparisons must succeed under this claim.
  let (checked, baseline) = if previous.status == "mismatch" do
    let context = pending_anchor_context(path, key, identity)?
    (context_view(context)?, Some(decode_anchor_entry(context.entry)?))
  else
    (view, None)
  end
  let result = observe(pins, service_key, version, now, previous, release_pins, checked, baseline)?
  let result = if result.observation.status == "consistent"
    && key_changed
    && Bytes.length(view.checkpoint) > 0
    && !Bytes.secure_equals(view.checkpoint, checked.checkpoint) do
    observe(pins, service_key, version, now, result.observation, release_pins, view, baseline)?
  else
    result
  end
  let observed = result.observation
  # Only a new complete consistency verification can release an earlier
  # mismatch. Stale accounts, RPC outages and missing caches cannot clear it.
  let value = if previous.status == "mismatch"
    && observed.status != "consistent"
    && observed.status != "service_slashed" do
    %{observed | status: "mismatch"}
  else
    observed
  end
  let (labels, blobs) = if Bytes.length(result.evidence) > 0 do
    let label = "anchor-evidence/v1"
    let blob = seal_local(result.evidence, key, local_context(label)?)?
    if Bytes.length(result.fork) > 0
      && Bytes.length(cached_transparency_bytes(path, key, "transparency-fork/v1")?) == 0 do
      let fork_label = "transparency-fork/v1"
      let context_label = "transparency-fork-anchor/v1"
      ([label, fork_label, context_label],
        [
          blob,
          seal_local(result.fork, key, local_context(fork_label)?)?,
          seal_local(result.evidence, key, local_context(context_label)?)?
        ])
    else
      ([label], [blob])
    end
  else
    ([], [])
  end
  let retry = value.status != "observed"
    && value.status != "consistent"
    && value.status != "service_slashed"
  finish_anchor_check_with_blobs(path,
    key,
    claim,
    now,
    retry,
    encode_observation(value)?,
    labels,
    blobs)?
  Ok(value)
end

pub fn check_native_anchor(path :: String, key_changed :: Bool) -> AnchorObservation!String do
  let config = native_security_config()?
  let pins = case configured_anchor_pins(config)? do
    None -> return blank("off")
    Some(value) -> value
  end
  ensure_schema(path)?
  let key = platform_key()?
  let bytes = cached_transparency_bytes(path, key, "transparency-witnesses/v2")?
  let witnesses = if Bytes.length(bytes) == 0 do
    []
  else
    decode_witnesses(bytes)?
  end
  check_anchor_attested_at(path,
    key,
    pins,
    config.service_public_key,
    config.log_version,
    current_time()?,
    key_changed,
    witness_policy_for_log(config, config.log_version)?.keys,
    AnchorView {
      checkpoint: cached_checkpoint_bytes(path, key)?,
      origin: Bytes.to_utf8(cached_transparency_bytes(path, key, "transparency-origin/v1")?)?,
      witnesses: witnesses,
      leaf: cached_transparency_bytes(path, key, "transparency-leaf/v1")?
    })
end

pub fn check_native_anchor_view(path :: String,
  checkpoint :: Bytes,
  origin :: String,
  witnesses :: List<WitnessAttestation>,
  leaf :: Bytes) -> AnchorObservation!String do
  let config = native_security_config()?
  let pins = case configured_anchor_pins(config)? do
    None -> return blank("off")
    Some(value) -> value
  end
  ensure_schema(path)?
  let key = platform_key()?
  check_anchor_attested_at(path,
    key,
    pins,
    config.service_public_key,
    config.log_version,
    current_time()?,
    true,
    witness_policy_for_log(config, config.log_version)?.keys,
    AnchorView { checkpoint: checkpoint, origin: origin, witnesses: witnesses, leaf: leaf })
end

pub fn anchor_service_refused(path :: String, key :: borrow StorageKey) -> Bool!String do
  # Releases before anchor activation have no observation at all. Keep their
  # existing trust-validation path and errors until a check has actually run.
  case load_blob(path, "anchor-schedule/v1") do
    Err(error) -> if error == "local_state_not_found" do
      return Ok(false)
    else
      return Err(error)
    end
    Ok(_) -> nil
  end
  let config = native_security_config()?
  let pins = case configured_anchor_pins(config)? do
    None -> return Ok(false)
    Some(value) -> value
  end
  let identity = anchor_identity(pins, config.service_public_key, config.log_version)?
  if Bytes.length(load_anchor_schedule(path, key, identity)?.active_token) != 0 do
    # The claim precedes every RPC. Until its result commits, new trust cannot
    # race a slash response or bypass a failed durable completion. A crashed
    # claim can be replaced after its reserved hour; existing ratchets continue.
    return Err("anchor_check_pending")
  end
  let status = load_anchor_observation(path, key, identity)?.status
  if status == "mismatch" do
    Err("anchor_mismatch")
  else
    Ok(status == "service_slashed")
  end
end

pub fn anchor_observation_output(value :: AnchorObservation) -> Bytes!String do
  encode_output_list(for field in [
    value.status,
    U64.to_string(value.checked_at),
    U64.to_string(value.context_slot),
    U64.to_string(value.posted_slot),
    U64.to_string(value.block_time)
  ] do
    Bytes.from_utf8(field)
  end)
end
