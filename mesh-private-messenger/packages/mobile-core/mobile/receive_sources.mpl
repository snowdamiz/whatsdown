from Storage.AccountGuard import (
  AccountBasis,
  load_account_basis,
  account_basis_current,
  require_account_basis
)
from Storage.Keys import open_local, local_context
from Mobile.Sessions import decode_session_ids, parse_session_record, preferred_session
from Mobile.Types import MobileLoadedSession
from Mobile.Codec import mobile_append

## An immutable receive basis plus independently bounded snapshots of every
## indexed session inspected by initial policy or self-sync acceptance. Each snapshot uses the
## existing 64-label limit; no aggregate legacy session ceiling is introduced.
pub struct ReceiveSources do
  before :: AccountBasis
  batches :: List<AccountBasis>
  session_ids :: List<Bytes>
  peer_account_id :: Bytes
  alias_label :: String
end

fn index_blob(before :: AccountBasis) -> Bytes!String do
  if List.length(before.labels) != List.length(before.records) do
    return Err("invalid_receive_sources")
  end
  for index in 0..List.length(before.labels) do
    if List.get(before.labels, index) == "sessions/v1" do
      return Ok(List.get(before.records, index))
    end
  end
  Err("invalid_receive_sources")
end

pub fn receive_basis_preserved(original :: AccountBasis, extended :: AccountBasis) -> Bool do
  Bytes.secure_equals(original.profile, extended.profile)
    && List.length(original.labels) == List.length(original.records)
    && List.length(extended.labels) == List.length(extended.records)
    && List.length(original.labels) <= List.length(extended.labels)
    && List.all(for index in 0..List.length(original.labels) do
        List.get(original.labels, index) == List.get(extended.labels, index)
          && Bytes.secure_equals(List.get(original.records, index),
            List.get(extended.records, index))
      end,
      fn(value) -> value end)
end

fn check_batch(before :: AccountBasis, batch :: AccountBasis) -> Result<(), String> do
  if List.length(batch.labels) < 1
    || List.length(batch.labels) > 64
    || List.length(batch.labels) != List.length(batch.records)
    || List.head(batch.labels) != "sessions/v1"
    || !Bytes.secure_equals(batch.profile, before.profile)
    || !Bytes.secure_equals(List.head(batch.records), index_blob(before)?) do
    return Err("account_state_changed")
  end
  Ok(nil)
end

fn capture_batches(path :: String,
  before :: AccountBasis,
  ids :: List<Bytes>,
  offset :: Int,
  output :: List<AccountBasis>) -> List<AccountBasis>!String do
  if offset >= List.length(ids) do
    return Ok(output)
  end
  let labels = for id in List.take(List.drop(ids, offset), 63) do
    "session/v1/#{Bytes.to_hex(id)}"
  end
  let batch = load_account_basis(path, ["sessions/v1"] ++ labels)?
  check_batch(before, batch)?
  capture_batches(path, before, ids, offset + 63, List.append(output, batch))
end

fn captured_peer(batches :: List<AccountBasis>,
  key :: borrow StorageKey,
  peer :: Bytes,
  batch_index :: Int,
  row_index :: Int) -> Bool!String do
  if batch_index >= List.length(batches) do
    return Ok(false)
  end
  let batch = List.get(batches, batch_index)
  if row_index >= List.length(batch.labels) do
    return captured_peer(batches, key, peer, batch_index + 1, 1)
  end
  let label = List.get(batch.labels, row_index)
  let record = parse_session_record(open_local(List.get(batch.records, row_index),
    key,
    local_context(label)?)?)?
  if Bytes.secure_equals(record.peer_account_id, peer) do
    Ok(true)
  else
    captured_peer(batches, key, peer, batch_index, row_index + 1)
  end
end

## Capture before selecting initial strongest-suite or previous policy. No
## session metadata is parsed until its original call-site requires it, retaining
## earlier prekey-error priority. Normal initial messages require no alias row.
pub fn capture_receive_sessions(path :: String,
  key :: borrow StorageKey,
  before :: AccountBasis,
  expected_ids :: List<Bytes>) -> ReceiveSources!String do
  let index = index_blob(before)?
  let ids = if Bytes.length(index) == 0 do
    Ok([])
  else
    decode_session_ids(open_local(index, key, local_context("sessions/v1")?)?)
  end?
  if List.length(ids) != List.length(expected_ids)
    || !List.all(for index in 0..List.length(ids) do
        Bytes.secure_equals(List.get(ids, index), List.get(expected_ids, index))
      end,
      fn(value) -> value end) do
    return Err("account_state_changed")
  end
  let batches = capture_batches(path, before, ids, 0, [])?
  if !account_basis_current(path, before) do
    return Err("account_state_changed")
  end
  Ok(ReceiveSources {
    before: before,
    batches: batches,
    session_ids: ids,
    peer_account_id: Bytes.empty(),
    alias_label: ""
  })
end

## Alias absence is relevant only after an authenticated self-sync payload
## selects that peer. Extend the original source set without refreshing it.
pub fn capture_receive_alias(path :: String,
  key :: borrow StorageKey,
  sources :: ReceiveSources,
  peer :: Bytes) -> ReceiveSources!String do
  if Bytes.length(peer) != 32
    || Bytes.length(sources.peer_account_id) != 0
    || sources.alias_label != "" do
    return Err("invalid_receive_sources")
  end
  let alias_label = if captured_peer(sources.batches, key, peer, 0, 1)? do
    ""
  else
    let digest = Crypto.sha256(mobile_append(Bytes.from_utf8("mesh-msg/mobile/conversation-alias/v1"),
      peer)?)
    "session/v1/#{Bytes.to_hex(digest)}"
  end
  let batches = if alias_label == "" do
    Ok(sources.batches)
  else
    let alias = load_account_basis(path, ["sessions/v1", alias_label])?
    check_batch(sources.before, alias)?
    if Bytes.length(List.get(alias.records, 1)) != 0 do
      Err("receive_alias_exists")
    else
      Ok(List.append(sources.batches, alias))
    end
  end?
  if !account_basis_current(path, sources.before) do
    return Err("account_state_changed")
  end
  Ok(%{sources | batches: batches, peer_account_id: peer, alias_label: alias_label})
end

pub fn capture_receive_sources(path :: String,
  key :: borrow StorageKey,
  before :: AccountBasis,
  expected_ids :: List<Bytes>,
  peer :: Bytes) -> ReceiveSources!String do
  capture_receive_alias(path, key, capture_receive_sessions(path, key, before, expected_ids)?, peer)
end

fn captured_record(sources :: ReceiveSources,
  key :: borrow StorageKey,
  batch_index :: Int,
  row :: Int) -> Option<MobileLoadedSession>!String do
  let batch = List.get(sources.batches, batch_index)
  let label = List.get(batch.labels, row)
  if label == sources.alias_label do
    return Ok(None)
  end
  let index = batch_index * 63 + row - 1
  if index >= List.length(sources.session_ids) do
    return Err("invalid_receive_sources")
  end
  Ok(Some(MobileLoadedSession {
    session_id: List.get(sources.session_ids, index),
    label: label,
    record: parse_session_record(open_local(List.get(batch.records, row),
      key,
      local_context(label)?)?)?
  }))
end

fn captured_records(sources :: ReceiveSources,
  key :: borrow StorageKey) -> List<MobileLoadedSession>!String do
  let chunks = for batch_index in 0..List.length(sources.batches) do
    let batch = List.get(sources.batches, batch_index)
    for row in 1..List.length(batch.labels) do
      captured_record(sources, key, batch_index, row)?
    end
  end
  Ok(List.flat_map(List.flat_map(chunks, fn(values) -> values end),
    fn(value) do
      case value do
        None -> []
        Some(row) -> [row]
      end
    end))
end

fn preferred_record(rows :: List<MobileLoadedSession>, index :: Int) -> MobileLoadedSession do
  let current = List.get(rows, index)
  if index + 1 >= List.length(rows) do
    current
  else
    preferred_session(current, preferred_record(rows, index + 1))
  end
end

pub fn receive_captured_peer(sources :: ReceiveSources,
  key :: borrow StorageKey,
  peer :: Bytes) -> MobileLoadedSession!String do
  let peers = List.filter(captured_records(sources, key)?,
    fn(value) -> Bytes.secure_equals(value.record.peer_account_id, peer) end)
  if List.length(peers) == 0 do
    Err("session_not_found")
  else
    Ok(preferred_record(peers, 0))
  end
end

fn strongest_record(rows :: List<MobileLoadedSession>,
  peer :: Bytes,
  device :: Bytes,
  index :: Int,
  strongest :: Int) -> Int do
  if index >= List.length(rows) do
    strongest
  else
    let current = List.get(rows, index).record
    let matches = Bytes.secure_equals(current.peer_account_id, peer)
      && Bytes.secure_equals(current.peer_device_id, device)
    let next = if matches && current.strongest_suite > strongest do
      current.strongest_suite
    else
      strongest
    end
    strongest_record(rows, peer, device, index + 1, next)
  end
end

pub fn receive_captured_strongest(sources :: ReceiveSources,
  key :: borrow StorageKey,
  peer :: Bytes,
  device :: Bytes) -> Int!String do
  Ok(strongest_record(captured_records(sources, key)?, peer, device, 0, 0))
end

pub fn require_receive_writes(before :: AccountBasis,
  sources :: Option<ReceiveSources>,
  labels :: List<String>) -> Result<(), String> do
  for label in labels do
    if String.starts_with(label, "session/v1/") && !List.contains(before.labels, label) do
      let covered = case sources do
        None -> false
        Some(value) -> List.any(value.batches, fn(batch) -> List.contains(batch.labels, label) end)
      end
      if !covered do
        return Err("invalid_receive_commit")
      end
    end
  end
  Ok(nil)
end

## The caller already owns the existing writer transaction. Every original
## snapshot, including alias absence, is checked before any write occurs.
pub fn require_receive_sources(database :: SqliteConn,
  before :: AccountBasis,
  sources :: Option<ReceiveSources>) -> Result<(), String> do
  case sources do
    None -> require_account_basis(database, before)
    Some(value) -> do
      if !receive_basis_preserved(value.before, before) do
        return Err("invalid_receive_sources")
      end
      require_account_basis(database, before)?
      for batch in value.batches do
        check_batch(value.before, batch)?
        if value.alias_label != "" && List.contains(batch.labels, value.alias_label) do
          if batch.labels != ["sessions/v1", value.alias_label]
            || Bytes.length(List.get(batch.records, 1)) != 0 do
            return Err("invalid_receive_sources")
          end
        end
        require_account_basis(database, batch)?
      end
      Ok(nil)
    end
  end
end
