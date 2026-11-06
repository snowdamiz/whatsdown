from Monitor.Config import MonitorConfig
from Monitor.Policy import monitor_threshold, monitor_successors
from Monitor.Registry import registry_key_changes
from Monitor.State import (
  MonitorState,
  MonitorAttendance,
  MonitorAttendanceCounts,
  load_monitor_state,
  save_monitor_state,
  claim_monitor_attendance,
  finish_monitor_attendance,
  monitor_attendance_counts
)
from Transparency.Config import SecurityConfig
from Transparency.AnchorChain import (
  AnchorPins,
  AnchorSnapshot,
  AnchorRecord,
  AnchorFreshness,
  AnchorWitnessRecord,
  sample_anchor_sources,
  read_anchor_header,
  read_anchor_log,
  read_anchor_freshness,
  read_anchor_record,
  read_anchor_batch,
  read_anchor_witness_record
)
from Transparency.AnchorRing import AnchorHeader, AnchorEntry, decode_anchor_entry
from Transparency.AnchorLog import AnchorLog
from Transparency.AnchorWitnessSet import AnchorWitnessSet
from Transparency.AnchorHttp import fetch_anchor_proof
from Transparency.AnchorConsistency import AnchorConsistency, compare_anchor
from Transparency.AnchorContradiction import AnchorLeafEvidence, discover_anchor_contradiction
from Transparency.AnchorContext import AnchorEvidenceContext, encode_anchor_context
from Transparency.Fork import ForkProof, decode_fork
from Transparency.LeafProof import LeafQuery, LeafProof, encode_leaf_query, decode_leaf_proof
from Transparency.Merkle import TransparencyCheckpoint, checkpoint_hash, verify_checkpoint
from Transparency.Wire import decode_checkpoint, encode_checkpoint

fn save(config :: MonitorConfig, state :: MonitorState) -> MonitorState!String do
  save_monitor_state(config.path, config.identity, state.revision, state)?
  load_monitor_state(config.path, config.identity)
end

fn distance(snapshot :: AnchorSnapshot, index :: Int) -> Int!String do
  let offset = (snapshot.header.head - index + 4096) % 4096
  if index < 0 || index >= 4096 || offset >= snapshot.header.count do
    Err("monitor_history_gap")
  else
    Ok(offset)
  end
end

fn same(left :: Bytes, right :: Bytes) -> Bool!String do
  case monitor_successors([decode_anchor_entry(left)?], Some(decode_anchor_entry(right)?)) do
    Err(_) -> Ok(false)
    Ok(_) -> Ok(true)
  end
end

fn first_checkpoint(config :: MonitorConfig,
  record :: AnchorRecord,
  index :: Int) -> AnchorConsistency!String do
  let entry = record.entry
  let query = case Bytes.write_u64_be(entry.sequence) do
    Err(_) -> return Err("integer_encoding_failed")
    Ok(value) -> value
  end
  let (status, bytes) = fetch_anchor_proof(config.origin,
    "/v#{entry.log_version}/transparency/checkpoint",
    query,
    188)?
  let empty = AnchorConsistency {
    status: "proof_unavailable",
    checkpoint: bytes,
    consistency: Bytes.empty(),
    fork: Bytes.empty()
  }
  if status != "received" do
    return Ok(%{empty | status: status})
  end
  let checkpoint = case decode_checkpoint(bytes) do
    Err(_) -> return Ok(%{empty | status: "mismatch"})
    Ok(value) -> value
  end
  if !verify_checkpoint(checkpoint,
    SigningPublicKey { bytes: config.primary.service_public_key })? do
    return Ok(%{empty | status: "mismatch"})
  end
  if checkpoint.version == entry.log_version
    && Bytes.secure_equals(checkpoint_hash(checkpoint)?, entry.checkpoint_hash)
    && U64.compare(checkpoint.sequence, entry.sequence) == 0
    && U64.compare(checkpoint.tree_size, entry.tree_size) == 0
    && U64.compare(checkpoint.timestamp, entry.timestamp) == 0
    && Bytes.secure_equals(checkpoint.tree_root, entry.tree_root) do
    Ok(%{empty | status: "consistent"})
  else if checkpoint.version == entry.log_version do
    # A signed but wrong historical answer can itself prove equivocation.
    compare_anchor(config.origin, checkpoint, entry, index, config.primary.service_public_key)
  else
    Ok(%{empty | status: "mismatch"})
  end
end

fn retain(config :: MonitorConfig,
  state :: MonitorState,
  snapshot :: AnchorSnapshot,
  record :: AnchorRecord,
  index :: Int,
  comparison :: AnchorConsistency,
  private_leaf :: Bytes,
  served_leaf :: Bytes,
  now :: Int) -> Result<(), String> do
  if Bytes.length(state.proof) > 0 do
    return Ok(nil)
  end
  let proof = decode_fork(comparison.fork)?
  # Persist service evidence immediately. Historical witness attribution is a
  # separate operation and must not delay or prevent retaining this proof.
  let context = encode_anchor_context(AnchorEvidenceContext {
    identity: config.identity,
    checked_at: U64.parse(Int.to_string(now))?,
    context_slot: snapshot.context_slot,
    header: snapshot.bytes,
    ring_index: index,
    entry: record.bytes,
    checkpoint: encode_checkpoint(proof.first)?,
    origin: config.origin,
    served_checkpoint: comparison.checkpoint,
    consistency: comparison.consistency,
    fork: comparison.fork,
    witnesses: Bytes.empty(),
    witness_set: Bytes.empty(),
    private_leaf: private_leaf,
    served_leaf: served_leaf
  })?
  save(config, %{state | proof: comparison.fork, proof_context: context})?
  Ok(nil)
end

fn probe_leaf(config :: MonitorConfig,
  local :: TransparencyCheckpoint,
  record :: AnchorRecord,
  index :: Int,
  leaf :: Int) -> Result<(Bytes, Bytes, Bytes), String> do
  let (status, private) = fetch_anchor_proof(config.origin,
    "/v#{local.version}/transparency/leaf",
    encode_leaf_query(LeafQuery { leaf_index: leaf, tree_size: U64.to_int(local.tree_size)? })?,
    1074)?
  if status != "received" do
    return Err("proof_unavailable")
  end
  let contradiction = discover_anchor_contradiction(config.origin,
    local,
    record.entry,
    index,
    config.primary.service_public_key,
    decode_leaf_proof(private)?)?
  Ok((private, contradiction.response, contradiction.fork))
end

# Rotate a bounded probe through the common prefix. A missing/malformed path is
# not evidence. Advance durably before I/O so one censored leaf cannot starve
# every later index on repeated polls or restarts.
fn probe(config :: MonitorConfig,
  snapshot :: AnchorSnapshot,
  record :: AnchorRecord,
  index :: Int,
  comparison :: AnchorConsistency,
  now :: Int) -> Bool!String do
  let state = load_monitor_state(config.path, config.identity)?
  if Bytes.length(state.checkpoint) == 0 do
    return Ok(false)
  end
  let local = decode_checkpoint(state.checkpoint)?
  let common = if U64.compare(local.tree_size, record.entry.tree_size) < 0 do
    local.tree_size
  else
    record.entry.tree_size
  end
  if U64.compare(common, U64.parse("4294967295")?) > 0 do
    return Ok(false)
  end
  let size = U64.to_int(common)?
  if size == 0 do
    return Ok(false)
  end
  let count = if size > 16 do
    16
  else
    size
  end
  for _attempt in 0..count do
    let state = load_monitor_state(config.path, config.identity)?
    let leaf = state.probe_index % size
    let next = save(config, %{state | probe_index: (leaf + 1) % size})?
    case probe_leaf(config, local, record, index, leaf) do
      Err(_) -> nil
      Ok((private, public, fork)) -> if Bytes.length(fork) > 0 do
        retain(config,
          next,
          snapshot,
          record,
          index,
          %{comparison | fork: fork},
          private,
          public,
          now)?
        return Ok(true)
      end
    end
  end
  Ok(false)
end

fn advance(config :: MonitorConfig,
  snapshot :: AnchorSnapshot,
  now :: Int) -> List<String>!String do
  let initial = load_monitor_state(config.path, config.identity)?
  if Bytes.length(initial.proof) > 0 do
    return Ok(["fork_detected"])
  end
  let available = if Bytes.length(initial.entry) == 0 do
    snapshot.header.count
  else
    let offset = distance(snapshot, initial.ring_index)?
    let current = read_anchor_record(config.pins, snapshot, offset)?
    if !same(current.bytes, initial.entry)? do
      return Err("monitor_history_gap")
    end
    offset
  end
  if available == 0 do
    if Bytes.length(initial.pending_entry) > 0 do
      return Err("monitor_pending_comparison_lost")
    end
    return Ok([])
  end
  let count = if available > 32 do
    32
  else
    available
  end
  let records = read_anchor_batch(config.pins, snapshot, available - 1, count)?
  for position in 0..count do
    let record = List.get(records, position)
    let index = (snapshot.header.head - available + 1 + position + 4096) % 4096
    let state = load_monitor_state(config.path, config.identity)?
    if Bytes.length(state.pending_entry) > 0 do
      if state.pending_index != index || !same(state.pending_entry, record.bytes)? do
        return Err("monitor_pending_comparison_lost")
      end
    end
    let pending = save(config, %{state | pending_entry: record.bytes, pending_index: index})?
    let comparison = if Bytes.length(pending.checkpoint) == 0 do
      first_checkpoint(config, record, index)?
    else
      compare_anchor(config.origin,
        decode_checkpoint(pending.checkpoint)?,
        record.entry,
        index,
        config.primary.service_public_key)?
    end
    if Bytes.length(comparison.fork) > 0 do
      retain(config,
        pending,
        snapshot,
        record,
        index,
        comparison,
        Bytes.empty(),
        Bytes.empty(),
        now)?
      return Ok(["fork_detected"])
    end
    if comparison.status != "consistent" do
      if comparison.status == "mismatch"
        && probe(config, snapshot, record, index, comparison, now)? do
        return Ok(["fork_detected"])
      end
      return Ok([
        if comparison.status == "mismatch" do
          "consistency_mismatch"
        else
          "proof_unavailable"
        end
      ])
    end
    save(config,
      %{pending |
        ring_index: index,
        entry: record.bytes,
        checkpoint: comparison.checkpoint,
        pending_entry: Bytes.empty(),
        pending_index: -1,
        probe_index: 0
      })?
  end
  Ok(if available > count do
    ["catching_up"]
  else
    []
  end)
end

fn attendance_one(config :: MonitorConfig,
  snapshot :: AnchorSnapshot,
  saved :: MonitorAttendance) -> Result<(), String> do
  let offset = case distance(snapshot, saved.ring_index) do
    Err(_) -> do
      finish_monitor_attendance(config.path, config.identity, saved, "lost")?
      return Ok(nil)
    end
    Ok(value) -> value
  end
  let record = read_anchor_record(config.pins, snapshot, offset)?
  if !same(record.bytes, saved.entry)? do
    finish_monitor_attendance(config.path, config.identity, saved, "lost")?
    return Ok(nil)
  end
  let entry = record.entry
  let witnesses = if entry.witness_generation == 0 do
    None
  else
    Some(read_anchor_witness_record(config.pins,
      entry.witness_generation,
      snapshot.context_slot)?.set)
  end
  let met = monitor_threshold(entry, witnesses, config.policies)?
  if met do
    finish_monitor_attendance(config.path, config.identity, saved, "met")?
  else if U64.compare(snapshot.context_slot, U64.add(entry.slot, U64.parse("1500")?)?) > 0 do
    finish_monitor_attendance(config.path, config.identity, saved, "missed")?
  end
  Ok(nil)
end

fn attendance(config :: MonitorConfig, snapshot :: AnchorSnapshot) -> List<String>!String do
  let waiting = claim_monitor_attendance(config.path, config.identity)?
  let failures = for saved in waiting do
    case attendance_one(config, snapshot, saved) do
      Err(_) -> true
      Ok(_) -> false
    end
  end
  Ok(if List.any(failures, fn(failed) do failed end) do
    ["witness_check_unavailable"]
  else
    []
  end)
end

fn safe_error(error :: String) -> String do
  if error == "monitor_history_gap" || error == "monitor_pending_comparison_lost" do
    error
  else
    "chain_unavailable"
  end
end

fn chain(config :: MonitorConfig, now :: Int) -> List<String>!String do
  let state = load_monitor_state(config.path, config.identity)?
  let config = %{config | pins: sample_anchor_sources(config.pins)?}
  let snapshot = read_anchor_header(config.pins, state.context_slot)?
  let log = read_anchor_log(config.pins,
    config.primary.service_public_key,
    config.log_version,
    snapshot.context_slot)?
  save(config, %{state | context_slot: snapshot.context_slot})?
  if snapshot.header.count == 0 do
    return Ok(["anchor_empty"])
  end
  let freshness = case read_anchor_freshness(config.pins, snapshot, now / 1000) do
    Err(_) -> ["anchor_clock_unavailable"]
    Ok(value) -> if value.age_seconds > 3600 do
      ["anchor_stale"]
    else
      []
    end
  end
  let progress = case advance(config, snapshot, now) do
    Err(error) -> [safe_error(error)]
    Ok(issues) -> issues
  end
  Ok(freshness
    ++ progress
    ++ attendance(config, snapshot)?
    ++ if log.service_slashed do
      ["service_slashed"]
    else
      []
    end)
end

fn registry(config :: MonitorConfig) -> List<String>!String do
  let response = Http.build(:get, config.origin <> "/v1/transparency/registry")
    |> Http.max_redirects(0)
    |> Http.timeout(3000)
    |> Http.max_response_bytes(524288)
    |> Http.send()?
  if response.status != 200 do
    return Err("registry_unavailable")
  end
  let document = Bytes.to_utf8(response.body_bytes)?
  let state = load_monitor_state(config.path, config.identity)?
  let changes = registry_key_changes(state.registry, document, config.policies)?
  if List.length(changes) > 0 do
    # Keep the approved baseline. Accepting a changed key here would erase the
    # alert on the next poll even though no operator approved a new policy.
    Ok(["registry_key_changed"])
  else
    save(config, %{state | registry: document})?
    Ok([])
  end
end

# Public entry point shared by the executable and live HTTP/RPC tests. Network
# failures become cached degraded reports. Durable failures remain errors.
pub fn run_monitor_once(config :: MonitorConfig, now :: Int) -> String!String do
  if now < 0 do
    return Err("invalid_monitor_clock")
  end
  load_monitor_state(config.path, config.identity)?
  let chain_issues = case chain(config, now) do
    Err(error) -> [safe_error(error)]
    Ok(value) -> value
  end
  let registry_issues = case registry(config) do
    Err(_) -> ["registry_unavailable"]
    Ok(value) -> value
  end
  let state = load_monitor_state(config.path, config.identity)?
  let counts = monitor_attendance_counts(config.path, config.identity)?
  let issues = chain_issues
    ++ registry_issues
    ++ if counts.pending > 0 do
      ["witness_threshold_pending"]
    else
      []
    end
    ++ if counts.missed > 0 do
      ["witness_threshold_missed"]
    else
      []
    end
    ++ if counts.lost > 0 do
      ["witness_history_lost"]
    else
      []
    end
    ++ if Bytes.length(state.proof) > 0 && !List.contains(chain_issues, "fork_detected") do
      ["fork_detected"]
    else
      []
    end
  let encoded_issues = String.join(for issue in issues do
      Json.encode_string(issue)
    end,
    ",")
  let report = "{\"version\":1,\"log\":"
    <> Json.encode_string(config.pins.log_name)
    <> ",\"log_version\":#{config.log_version}"
    <> ",\"checked_at_ms\":#{now},\"healthy\":#{List.length(issues) == 0},\"issues\":[#{encoded_issues}]"
    <> ",\"context_slot\":\"#{U64.to_string(state.context_slot)}\",\"ring_index\":#{state.ring_index}"
    <> ",\"attendance\":{\"pending\":#{counts.pending},\"met\":#{counts.met},\"missed\":#{counts.missed},\"lost\":#{counts.lost}}"
    <> ",\"evidence\":#{Bytes.length(state.proof) > 0}}"
  save(config, %{state | report: report})?
  Ok(report)
end
