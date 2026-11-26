##! Following the anchor ring: read the Log and ring header, take every entry
##! written since the last position (in ring order, across the wrap), and
##! notice when the ring lapped the monitor (a gap is reported, never
##! papered over). Entries then go through the pair checks in order.

from Monitor.Chain import (
  ChainLog,
  ChainWitness,
  RingEntry,
  RingHeader,
  monitor_decode_entries,
  monitor_decode_entry,
  monitor_decode_header,
  monitor_decode_log,
  monitor_entry_offset,
  monitor_log_id,
  monitor_log_length,
  monitor_ring_capacity
)
from Monitor.Flags import MonitorConfig
from Monitor.Directory import AnchorRecord, monitor_dir_anchor
from Monitor.Evidence import Side, monitor_side_of_checkpoint, monitor_side_of_entry
from Monitor.Mirror import MirrorStep, monitor_mirror_sync
from Monitor.Pairs import PairResult, monitor_check_pair, monitor_unproven
from Monitor.Report import Context, monitor_finding, monitor_report
from Monitor.Rpc import AgreedAccount, monitor_rpc_agree, monitor_same_bytes
from Monitor.Store import (
  StoredEntry,
  monitor_entries_pending,
  monitor_entry_add,
  monitor_entry_cosign,
  monitor_entry_pair,
  monitor_kv_get,
  monitor_kv_put,
  monitor_observed_get,
  monitor_store_atomic
)
from Transparency.Merkle import TransparencyCheckpoint, verify_checkpoint
from Transparency.Wire import decode_checkpoint, decode_witnesses

pub struct ChainView do
  log :: ChainLog
  header :: RingHeader
  slot :: Int
end

fn owned(account :: AgreedAccount, judge :: String, what :: String) -> Result<(), String> do
  if account.owner == judge do
    Ok(nil)
  else
    Err("the #{what} is not owned by the judge program")
  end
end

pub fn monitor_read_chain(config :: MonitorConfig) -> ChainView!String do
  let account = monitor_rpc_agree(config.rpc_urls,
    config.log_account,
    0,
    monitor_log_length(),
    monitor_same_bytes)?
  owned(account, config.judge, "Log account")?
  let log = monitor_decode_log(account.data)?
  if !Bytes.secure_equals(log.log_id, monitor_log_id(config.log_name)?) do
    Err("the Log account is not the #{config.log_name} log")
  else
    let header = monitor_rpc_agree(config.rpc_urls, log.ring, 0, 64, monitor_same_bytes)?
    owned(header, config.judge, "anchor ring")?
    Ok(ChainView {
      log: log,
      header: monitor_decode_header(header.data)?,
      slot: if account.slot < header.slot do
        account.slot
      else
        header.slot
      end
    })
  end
end

# Two reads of ring entries agree when everything but the cosign bitmaps
# (bytes 96-97, which cosign transactions keep setting for 1,500 slots) is
# the same.

fn without_bitmaps(data :: Bytes, index :: Int, output :: List<Bytes>) -> List<Bytes> do
  if (index + 1) * 104 > Bytes.length(data) do
    output
  else
    let head = case Bytes.slice(data, index * 104, 96) do
      Err(_) -> Bytes.empty()
      Ok(value) -> value
    end
    let tail = case Bytes.slice(data, index * 104 + 98, 6) do
      Err(_) -> Bytes.empty()
      Ok(value) -> value
    end
    without_bitmaps(data, index + 1, output ++ [head, tail])
  end
end

fn all_same(left :: List<Bytes>, right :: List<Bytes>) -> Bool do
  case (left, right) do
    ([], []) -> true
    (a :: rest_a, b :: rest_b) -> Bytes.secure_equals(a, b) && all_same(rest_a, rest_b)
    _ -> false
  end
end

fn same_entries(left :: Bytes, right :: Bytes) -> Bool do
  Bytes.length(left) == Bytes.length(right)
    && all_same(without_bitmaps(left, 0, List.new()), without_bitmaps(right, 0, List.new()))
end

struct ReadEntries do
  entries :: List<RingEntry>
  known :: Bool
end

fn read_slice(ctx :: Context, first :: Int, count :: Int) -> ReadEntries!String do
  let agreed = monitor_rpc_agree(ctx.config.rpc_urls,
    ctx.log.ring,
    monitor_entry_offset(first),
    104 * count,
    same_entries)?
  owned(agreed, ctx.config.judge, "anchor ring")?
  Ok(ReadEntries {
    entries: monitor_decode_entries(first, agreed.data)?,
    known: Bytes.secure_equals(agreed.data, agreed.other)
  })
end

# count entries from physical index start, oldest first, in slices of at
# most 512 that never cross the end of the ring.

fn read_run(ctx :: Context,
  start :: Int,
  count :: Int,
  output :: List<(RingEntry, Bool)>) -> List<(RingEntry, Bool)>!String do
  if count <= 0 do
    Ok(output)
  else
    let room = monitor_ring_capacity() - start
    let take = if count < room && count < 512 do
      count
    else if room < 512 do
      room
    else
      512
    end
    let slice = read_slice(ctx, start, take)?
    read_run(ctx,
      (start + take) % monitor_ring_capacity(),
      count - take,
      output ++ List.map(slice.entries, fn entry -> (entry, slice.known) end))
  end
end

fn sentinel_holds(ctx :: Context, sentinel :: String) -> Bool!String do
  let parts = String.split(sentinel, ":")
  case String.to_int(List.get(parts, 0)) do
    None -> Ok(false)
    Some(index) -> do
      let slice = read_slice(ctx, index, 1)?
      Ok(Bytes.to_hex(List.get(slice.entries, 0).hash) == List.get(parts, 1))
    end
  end
end

fn oldest(header :: RingHeader) -> Int do
  if header.count < monitor_ring_capacity() do
    0
  else
    header.head
  end
end

fn gap(ctx :: Context, header :: RingHeader) -> Result<(), String> do
  monitor_report(ctx,
    monitor_finding(ctx,
      "gap:#{ctx.slot}",
      "warn",
      "ring_gap",
      "the ring lapped the monitor: entries written after ring index #{header.head} were overwritten before they were read, so some anchor pairs went unchecked",
      "{\"head\":#{header.head},\"count\":#{header.count},\"slot\":#{ctx.slot}}"))
end

fn add_all(db :: SqliteConn, read :: List<(RingEntry, Bool)>) -> Result<(), String> do
  case read do
    [] -> Ok(nil)
    (entry, known) :: rest -> do
      monitor_entry_add(db, entry.index, entry.bytes, known, entry.epoch)?
      add_all(db, rest)
    end
  end
end

fn store_entries(ctx :: Context,
  header :: RingHeader,
  read :: List<(RingEntry, Bool)>) -> Result<(), String> do
  monitor_store_atomic(ctx.db,
    fn() do
      add_all(ctx.db, read)?
      if List.length(read) > 0 do
        let (entry, _) = List.last(read)
        monitor_kv_put(ctx.db, "ring_sentinel", "#{entry.index}:#{Bytes.to_hex(entry.hash)}")?
        monitor_kv_put(ctx.db, "position", "#{entry.index}:#{Bytes.to_hex(entry.bytes)}")?
      end
      monitor_kv_put(ctx.db, "ring_next", Int.to_string(header.head))
    end)
end

# Reads the entries written since the last cycle into the pending queue.
# Returns how many were read.

pub fn monitor_follow_ring(ctx :: Context, header :: RingHeader) -> Int!String do
  let next = monitor_kv_get(ctx.db, "ring_next")?
  let sentinel = monitor_kv_get(ctx.db, "ring_sentinel")?
  let (start, count) = case String.to_int(next) do
    None -> (oldest(header), header.count)
    Some(position) -> if sentinel == "" || sentinel_holds(ctx, sentinel)? do
      (position, (header.head - position + monitor_ring_capacity()) % monitor_ring_capacity())
    else
      gap(ctx, header)?
      (oldest(header), header.count)
    end
  end
  let read = read_run(ctx, start, count, List.new())?
  store_entries(ctx, header, read)?
  Ok(List.length(read))
end

# --- Pair checks over the pending queue.

pub type EntryOutcome do
  EntryStop(reason :: String)
  EntryDone(prev :: Option<RingEntry>, state :: String, verified :: Bool)
end

fn stored_prev(ctx :: Context) -> Option<RingEntry>!String do
  let text = monitor_kv_get(ctx.db, "prev")?
  let parts = String.split(text, ":")
  if List.length(parts) != 2 do
    Ok(None)
  else
    case (String.to_int(List.get(parts, 0)), Bytes.from_hex(List.get(parts, 1))) do
      (Some(index), Ok(bytes)) -> Ok(Some(monitor_decode_entry(index, bytes)?))
      _ -> Ok(None)
    end
  end
end

pub fn monitor_prev(ctx :: Context) -> Option<RingEntry>!String do
  stored_prev(ctx)
end

# Keeps the monitor's copy of the log following the anchors (64 requests of
# 1,024 leaves per call). A copy that does not hash to the anchored root is
# reported and rebuilt.

pub fn monitor_follow_copy(ctx :: Context, target :: RingEntry) -> Result<(), String> do
  case monitor_mirror_sync(ctx.db, ctx.config.directory, target.tree_size, target.root, 64)? do
    MirrorMismatch -> monitor_report(ctx,
      monitor_finding(ctx,
        "leaves:#{Bytes.to_hex(target.hash)}",
        "warn",
        "leaves_mismatch",
        "the directory's leaf hashes do not hash to the root anchored at tree size #{target.tree_size}; the monitor's copy of the log was discarded and is being rebuilt",
        "{\"tree_size\":#{target.tree_size},\"root\":#{Json.encode_string(Bytes.to_hex(target.root))}}"))
    _ -> Ok(nil)
  end
end

fn served(ctx :: Context,
  checkpoint :: Option<TransparencyCheckpoint>,
  hash :: Bytes) -> Option<Side>!String do
  let fallback = case monitor_observed_get(ctx.db, hash)? do
    None
    Some((bytes, attestations)) -> Some((decode_checkpoint(bytes)?,
      decode_witnesses(attestations)?))
  end
  let chosen = case checkpoint do
    Some(value) -> Some((value, List.new()))
    None -> fallback
  end
  case chosen do
    None -> Ok(None)
    Some((value, attestations)) -> do
      let side = monitor_side_of_checkpoint(value, attestations)?
      if Bytes.secure_equals(side.hash, hash)
        && verify_checkpoint(value, SigningPublicKey { bytes: ctx.log.service_key })? do
        Ok(Some(side))
      else
        Ok(None)
      end
    end
  end
end

fn recorded_side(entry :: RingEntry, hash :: Bytes, tree_size :: Int) -> Side do
  let side = monitor_side_of_entry(entry)
  %{side | hash: hash, tree_size: tree_size, entry: None}
end

# The directory's record of what it anchored under this sequence must name
# the same checkpoint as the ring.

fn anchor_record(ctx :: Context, entry :: RingEntry) -> PairResult!String do
  case monitor_dir_anchor(ctx.config.directory, entry.sequence) do
    Err(reason) -> Ok(PairPending("anchor record #{entry.sequence}: #{reason}"))
    Ok(None) -> Ok(PairConsistent)
    Ok(Some(record)) -> if Bytes.secure_equals(record.checkpoint_hash, entry.hash)
      && record.tree_size == entry.tree_size do
      Ok(PairConsistent)
    else
      case served(ctx, record.checkpoint, record.checkpoint_hash)? do
        Some(side) -> monitor_check_pair(ctx, monitor_side_of_entry(entry), side, "anchor-record")
        None -> monitor_unproven(ctx,
          "anchor-record",
          monitor_side_of_entry(entry),
          recorded_side(entry, record.checkpoint_hash, record.tree_size),
          "the directory's anchor record for sequence #{entry.sequence} names checkpoint #{Bytes.to_hex(record.checkpoint_hash)}, not the one the ring holds",
          ",\"anchor_record\":#{record.raw}")
      end
    end
  end
end

fn evidence_entry(ctx :: Context,
  entry :: RingEntry,
  prev :: Option<RingEntry>) -> EntryOutcome!String do
  let side = monitor_side_of_entry(entry)
  let flagged = "the ring stores it as evidence (flag #{entry.evidence}): post_anchor found it contradicts the anchor before it"
  case prev do
    None -> do
      monitor_unproven(ctx, "ring-evidence", side, side, flagged, "")?
      Ok(EntryDone(prev, "done", false))
    end
    Some(tip) -> case monitor_check_pair(ctx, monitor_side_of_entry(tip), side, "ring-evidence")? do
      PairPending(reason) -> Ok(EntryStop(reason))
      PairConsistent -> do
        monitor_unproven(ctx, "ring-evidence", monitor_side_of_entry(tip), side, flagged, "")?
        Ok(EntryDone(prev, "done", false))
      end
      _ -> Ok(EntryDone(prev, "done", false))
    end
  end
end

fn consistent(result :: PairResult) -> Bool do
  case result do
    PairConsistent -> true
    _ -> false
  end
end

fn anchor_entry(ctx :: Context, entry :: RingEntry, tip :: RingEntry) -> EntryOutcome!String do
  # Best effort: a directory without the leaves route must not hold up the
  # pair checks (the cycle notes the copy's errors).
  case monitor_follow_copy(ctx, tip) do
    _ -> nil
  end
  case monitor_check_pair(ctx,
    monitor_side_of_entry(tip),
    monitor_side_of_entry(entry),
    "anchor-pair")? do
    PairPending(reason) -> Ok(EntryStop(reason))
    result -> case anchor_record(ctx, entry)? do
      PairPending(reason) -> Ok(EntryStop(reason))
      _ -> Ok(EntryDone(Some(entry), "done", consistent(result)))
    end
  end
end

fn process_entry(ctx :: Context,
  entry :: RingEntry,
  prev :: Option<RingEntry>) -> EntryOutcome!String do
  if entry.evidence != 0 do
    evidence_entry(ctx, entry, prev)
  else
    case prev do
      None -> case anchor_record(ctx, entry)? do
        PairPending(reason) -> Ok(EntryStop(reason))
        _ -> Ok(EntryDone(Some(entry), "done", false))
      end
      Some(tip) -> if entry.sequence <= tip.sequence do
        Ok(EntryDone(prev, "seen", false))
      else
        anchor_entry(ctx, entry, tip)
      end
    end
  end
end

fn pair_json(older :: RingEntry, newer :: RingEntry, now_ms :: Int) -> String do
  "{\"old_sequence\":#{older.sequence},\"old_tree_size\":#{older.tree_size},\"new_sequence\":#{newer.sequence},\"new_tree_size\":#{newer.tree_size},\"verified_at_ms\":#{now_ms}}"
end

fn finish(ctx :: Context,
  stored :: StoredEntry,
  prev :: Option<RingEntry>,
  next :: Option<RingEntry>,
  state :: String,
  verified :: Bool) -> Result<(), String> do
  monitor_store_atomic(ctx.db,
    fn() do
      monitor_entry_pair(ctx.db, stored.position, state)?
      if state == "seen" do
        monitor_entry_cosign(ctx.db, stored.position, stored.entry, "none")?
      end
      case (prev, next) do
        (Some(older), Some(newer)) -> if verified do
          monitor_kv_put(ctx.db, "last_pair", pair_json(older, newer, ctx.now_ms))
        else
          Ok(nil)
        end
        _ -> Ok(nil)
      end?
      case next do
        None -> Ok(nil)
        Some(entry) -> monitor_kv_put(ctx.db, "prev", "#{entry.index}:#{Bytes.to_hex(entry.bytes)}")
      end
    end)
end

fn process_rows(ctx :: Context, rows :: List<StoredEntry>) -> String!String do
  case rows do
    [] -> Ok("")
    stored :: rest -> do
      let entry = monitor_decode_entry(stored.ring_index, stored.entry)?
      let prev = stored_prev(ctx)?
      case process_entry(ctx, entry, prev)? do
        EntryStop(reason) -> Ok(reason)
        EntryDone(next, state, verified) -> do
          finish(ctx, stored, prev, next, state, verified)?
          process_rows(ctx, rest)
        end
      end
    end
  end
end

# Works through the pending entries in ring order; stops at the first pair
# the directory cannot answer for yet (returned as the reason).

# Each batch of 256 entries commits once (a first run reads up to 4,096).

pub fn monitor_check_entries(ctx :: Context) -> String!String do
  let rows = monitor_entries_pending(ctx.db, 256)?
  let reason = monitor_store_atomic(ctx.db, fn() do process_rows(ctx, rows) end)?
  if reason == "" && List.length(rows) == 256 do
    monitor_check_entries(ctx)
  else
    Ok(reason)
  end
end
