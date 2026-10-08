##! The checks around the ring: the directory's current checkpoint against
##! the newest anchor, cosignature thresholds once each anchor's cosign window
##! has closed, the supported sets against the Log's witness list, the
##! directory's witness registry, and filing fork proofs with relays.

from Monitor.Chain import (
  ChainLog,
  ChainWitness,
  RingEntry,
  monitor_cosigned,
  monitor_decode_entry,
  monitor_entry_offset
)
from Monitor.Flags import MonitorConfig
from Monitor.Directory import (
  RegistryWitness,
  monitor_dir_attestations,
  monitor_dir_checkpoint,
  monitor_dir_registry,
  monitor_relay_file
)
from Monitor.Evidence import monitor_side_of_checkpoint, monitor_side_of_entry
from Monitor.Pairs import PairResult, monitor_check_pair
from Monitor.Report import Context, monitor_finding, monitor_report
from Monitor.Ring import monitor_prev
from Monitor.Rpc import AgreedAccount, monitor_rpc_agree, monitor_same_bytes
from Monitor.Store import (
  Filing,
  Finding,
  StoredEntry,
  monitor_entries_open,
  monitor_entry_cosign,
  monitor_filing_put,
  monitor_filings,
  monitor_findings_with_proof,
  monitor_kv_get,
  monitor_kv_put,
  monitor_observed_put,
  monitor_store_atomic
)
from Security.Config import SecurityConfig, SecurityWitness
from Transparency.Merkle import WitnessAttestation, checkpoint_hash, verify_checkpoint
from Transparency.Wire import encode_checkpoint, encode_witnesses

# --- The directory's current checkpoint against the newest anchor. Each one
# is kept (with the attestations served for it) as the signed side of any
# later proof.

fn keep_observed(ctx :: Context,
  checkpoint_bytes :: Bytes,
  hash :: Bytes,
  sequence :: Int) -> List<WitnessAttestation>!String do
  let attestations = case monitor_dir_attestations(ctx.config.directory) do
    Err(_) -> List.new()
    Ok(values) -> List.take(List.filter(values,
        fn value -> Bytes.secure_equals(value.checkpoint_hash, hash) end),
      16)
  end
  monitor_observed_put(ctx.db,
    hash,
    sequence,
    checkpoint_bytes,
    encode_witnesses(attestations)?,
    ctx.now_ms)?
  Ok(attestations)
end

pub fn monitor_check_view(ctx :: Context) -> String!String do
  case monitor_dir_checkpoint(ctx.config.directory) do
    Err(reason) -> Ok("directory checkpoint: #{reason}")
    Ok(None) -> Ok("")
    Ok(Some(checkpoint)) -> if !verify_checkpoint(checkpoint,
      SigningPublicKey { bytes: ctx.log.service_key })? do
      Ok("the directory serves a checkpoint the Log's service key did not sign")
    else
      let hash = checkpoint_hash(checkpoint)?
      let side = monitor_side_of_checkpoint(checkpoint, List.new())?
      let attestations = keep_observed(ctx, encode_checkpoint(checkpoint)?, hash, side.sequence)?
      case monitor_prev(ctx)? do
        None -> Ok("")
        Some(tip) -> case monitor_check_pair(ctx,
          monitor_side_of_entry(tip),
          %{side | attestations: attestations},
          "directory-view")? do
          PairPending(reason) -> Ok("directory view: #{reason}")
          _ -> Ok("")
        end
      end
    end
  end
end

# --- Cosignature thresholds.

fn list_index(log :: ChainLog, witness :: SecurityWitness) -> Option<Int> do
  List.find(Range.to_list(0..List.length(log.witnesses)),
    fn index -> List.get(log.witnesses, index).witness_id == witness.witness_id
      && Bytes.secure_equals(List.get(log.witnesses, index).public_key, witness.public_key) end)
end

# How many of a set's witnesses cosigned the entry: a witness counts through
# the Log list entry with its ID and its pinned key.

pub fn monitor_set_cosigns(log :: ChainLog, set :: SecurityConfig, entry :: RingEntry) -> Int do
  List.length(List.filter(set.witnesses,
    fn witness -> case list_index(log, witness) do
      None -> false
      Some(index) -> monitor_cosigned(log, entry, index)
    end end))
end

fn best_shortfall(ctx :: Context, entry :: RingEntry) -> (Int, Int) do
  List.reduce(ctx.config.sets,
    (-1, 0),
    fn best, set do
      let count = monitor_set_cosigns(ctx.log, set, entry)
      let (have, _) = best
      if count > have do
        (count, set.threshold)
      else
        best
      end
    end)
end

fn met(ctx :: Context, entry :: RingEntry) -> Bool do
  List.any(ctx.config.sets, fn set -> monitor_set_cosigns(ctx.log, set, entry) >= set.threshold end)
end

fn final_entry(ctx :: Context,
  stored :: StoredEntry,
  entry :: RingEntry) -> Option<RingEntry>!String do
  if stored.bitmap_known do
    Ok(Some(entry))
  else
    let agreed = monitor_rpc_agree(ctx.config.rpc_urls,
      ctx.log.ring,
      monitor_entry_offset(entry.index),
      104,
      monitor_same_bytes)?
    let current = monitor_decode_entry(entry.index, agreed.data)?
    if Bytes.secure_equals(current.hash, entry.hash) do
      Ok(Some(current))
    else
      Ok(None)
    end
  end
end

fn judge_cosigns(ctx :: Context, stored :: StoredEntry, entry :: RingEntry) -> Result<(), String> do
  case final_entry(ctx, stored, entry)? do
    None -> monitor_entry_cosign(ctx.db, stored.position, entry.bytes, "none")
    Some(current) -> if met(ctx, current) do
      monitor_entry_cosign(ctx.db, stored.position, current.bytes, "met")
    else
      let (have, needed) = best_shortfall(ctx, current)
      monitor_report(ctx,
        monitor_finding(ctx,
          "threshold:#{Bytes.to_hex(current.hash)}",
          "P1",
          "below_threshold",
          "anchor #{current.sequence} (tree size #{current.tree_size}, ring index #{current.index}) closed its cosign window with #{have} of the #{needed} cosignatures the best supported set needs",
          "{\"sequence\":#{current.sequence},\"ring_index\":#{current.index},\"bitmap\":#{current.bitmap},\"checkpoint_hash\":#{Json.encode_string(Bytes.to_hex(current.hash))}}"))?
      monitor_entry_cosign(ctx.db, stored.position, current.bytes, "below")
    end
  end
end

fn cosign_rows(ctx :: Context, rows :: List<StoredEntry>) -> Result<(), String> do
  case rows do
    [] -> Ok(nil)
    stored :: rest -> do
      let entry = monitor_decode_entry(stored.ring_index, stored.entry)?
      if entry.evidence != 0 do
        monitor_entry_cosign(ctx.db, stored.position, entry.bytes, "none")?
      else if ctx.slot > entry.slot + 1500 do
        judge_cosigns(ctx, stored, entry)?
      end
      cosign_rows(ctx, rest)
    end
  end
end

# Anchors whose 1,500-slot cosign window has closed (by the older of the two
# providers' finalized slots) must carry a threshold for some supported set.

pub fn monitor_check_cosigns(ctx :: Context) -> Result<(), String> do
  let rows = monitor_entries_open(ctx.db, 4096)?
  monitor_store_atomic(ctx.db, fn() do cosign_rows(ctx, rows) end)
end

# --- The supported sets against the Log's witness list.

fn set_label(set :: SecurityConfig) -> String do
  String.slice(Bytes.to_hex(set.set_id), 0, 16)
end

fn check_listed(ctx :: Context,
  set :: SecurityConfig,
  witness :: SecurityWitness) -> Result<(), String> do
  case List.find(ctx.log.witnesses, fn listed -> listed.witness_id == witness.witness_id end) do
    None -> monitor_report(ctx,
      monitor_finding(ctx,
        "unlisted:#{set_label(set)}:#{witness.witness_id}",
        "warn",
        "pinned_not_listed",
        "witness #{witness.witness_id}, pinned by set #{set_label(set)}, is not in the Log's witness list, so its cosignatures cannot count",
        "{\"witness_id\":#{Json.encode_string(witness.witness_id)}}"))
    Some(listed) -> if Bytes.secure_equals(listed.public_key, witness.public_key) do
      Ok(nil)
    else
      monitor_report(ctx,
        monitor_finding(ctx,
          "listkey:#{witness.witness_id}:#{Bytes.to_hex(listed.public_key)}",
          "P1",
          "list_key_differs",
          "the Log lists witness #{witness.witness_id} with key #{Bytes.to_hex(listed.public_key)}, but set #{set_label(set)} pins #{Bytes.to_hex(witness.public_key)}",
          "{\"witness_id\":#{Json.encode_string(witness.witness_id)}}"))
    end
  end
end

pub fn monitor_check_sets(ctx :: Context) -> Result<(), String> do
  each(ctx.config.sets,
    fn set -> each(set.witnesses, fn witness -> check_listed(ctx, set, witness) end) end)
end

# --- The directory's witness registry. A key change under an existing ID is
# never an announced rotation (rotation always means a new ID), and a pinned
# witness must stay in the registry under its pinned key.

fn snapshot_text(entries :: List<RegistryWitness>) -> String do
  String.join(List.map(entries,
      fn entry -> "#{entry.witness_id}=#{Bytes.to_hex(entry.public_key)}" end),
    ",")
end

fn previous_key(snapshot :: String, witness_id :: String) -> String do
  let prefix = witness_id <> "="
  case List.find(String.split(snapshot, ","), fn part -> String.starts_with(part, prefix) end) do
    None -> ""
    Some(part) -> String.slice(part, String.length(prefix), String.length(part))
  end
end

fn check_changed(ctx :: Context,
  snapshot :: String,
  entry :: RegistryWitness) -> Result<(), String> do
  let before = previous_key(snapshot, entry.witness_id)
  let now = Bytes.to_hex(entry.public_key)
  if before == "" || before == now do
    Ok(nil)
  else
    monitor_report(ctx,
      monitor_finding(ctx,
        "regkey:#{entry.witness_id}:#{now}",
        "P1",
        "registry_key_changed",
        "the registry changed witness #{entry.witness_id}'s key from #{before} to #{now} without a new witness ID",
        "{\"witness_id\":#{Json.encode_string(entry.witness_id)},\"old_key\":#{Json.encode_string(before)},\"new_key\":#{Json.encode_string(now)}}"))
  end
end

fn check_pinned(ctx :: Context,
  entries :: List<RegistryWitness>,
  witness :: SecurityWitness) -> Result<(), String> do
  case List.find(entries, fn entry -> entry.witness_id == witness.witness_id end) do
    None -> monitor_report(ctx,
      monitor_finding(ctx,
        "regmissing:#{witness.witness_id}",
        "P1",
        "pinned_witness_missing",
        "pinned witness #{witness.witness_id} is missing from the directory's registry",
        "{\"witness_id\":#{Json.encode_string(witness.witness_id)}}"))
    Some(entry) -> if Bytes.secure_equals(entry.public_key, witness.public_key) do
      Ok(nil)
    else
      monitor_report(ctx,
        monitor_finding(ctx,
          "regpin:#{witness.witness_id}:#{Bytes.to_hex(entry.public_key)}",
          "P1",
          "pinned_key_differs",
          "the registry holds key #{Bytes.to_hex(entry.public_key)} for pinned witness #{witness.witness_id}, which is pinned with #{Bytes.to_hex(witness.public_key)}",
          "{\"witness_id\":#{Json.encode_string(witness.witness_id)}}"))
    end
  end
end

fn each<T>(values :: List<T>, work :: Fun(T) -> Result<(), String>) -> Result<(), String> do
  case values do
    [] -> Ok(nil)
    value :: rest -> do
      work(value)?
      each(rest, work)
    end
  end
end

pub fn monitor_check_registry(ctx :: Context) -> String!String do
  case monitor_dir_registry(ctx.config.directory) do
    Err(reason) -> Ok("registry: #{reason}")
    Ok(entries) -> do
      let snapshot = monitor_kv_get(ctx.db, "registry")?
      each(entries, fn entry -> check_changed(ctx, snapshot, entry) end)?
      each(ctx.config.sets,
        fn set -> each(set.witnesses, fn witness -> check_pinned(ctx, entries, witness) end) end)?
      monitor_kv_put(ctx.db, "registry", snapshot_text(entries))?
      Ok("")
    end
  end
end

# --- Filing fork proofs with every relay until each has answered for good
# (2xx, or a 4xx other than 408/429).

fn settled(status :: Int) -> Bool do
  status >= 200 && status < 500 && status != 408 && status != 429
end

fn file_one(ctx :: Context,
  proof_hash :: String,
  frk :: Bytes,
  relay :: String) -> Result<(), String> do
  let prior = case List.find(monitor_filings(ctx.db, proof_hash)?,
    fn value -> value.relay == relay end) do
    None -> Filing { proof_hash: proof_hash, relay: relay, status: 0, attempts: 0 }
    Some(value) -> value
  end
  if settled(prior.status) || prior.attempts >= 50 do
    Ok(nil)
  else
    let status = case monitor_relay_file(relay, frk) do
      Err(_) -> 0
      Ok(value) -> value
    end
    if !settled(status) do
      println("warn morse-monitor #{ctx.config.log_name} relay_filing: #{relay} answered #{status} for proof #{proof_hash}")
    end
    monitor_filing_put(ctx.db, %{prior | status: status, attempts: prior.attempts + 1}, ctx.now_ms)
  end
end

pub fn monitor_file_proofs(ctx :: Context) -> Result<(), String> do
  each(monitor_findings_with_proof(ctx.db)?,
    fn finding -> each(ctx.config.relays,
      fn relay -> file_one(ctx, finding.proof_hash, finding.frk, relay) end) end)
end
