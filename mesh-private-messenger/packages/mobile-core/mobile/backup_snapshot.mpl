from Binary.Reader import BinaryReader
from Mobile.Codec import (
  mobile_append,
  mobile_byte,
  mobile_join,
  mobile_read_byte,
  mobile_read_u32,
  mobile_read_u64,
  mobile_reader,
  mobile_utf8,
  mobile_vector,
  mobile_wide,
  mobile_write_u32,
  mobile_write_u64,
  take_vector_error
)
from Mobile.GroupState import group_history_entries, group_history_sealed, group_index_ids
from Mobile.History import (
  history_entries_for,
  history_sealed_for,
  history_view_once_type,
  update_conversation
)
from Mobile.Presentation import load_presentation_record, save_presentation
from Mobile.Sessions import (
  ensure_conversation_alias,
  find_peer_session,
  inner_bytes,
  load_session_ids,
  load_session_record
)
from Mobile.Types import (
  MobileGroupHistoryEntry,
  MobileHistoryEntry,
  MobileLoadedSession,
  MobilePolicyRequest,
  MobileReadBytes,
  MobileSyncPayload,
  MobileTriplePayloadRequest
)
from Protocol.EnvelopeWire import decode_inner_envelope
from Protocol.V1 import InnerEnvelope
from Storage.Records import store_updated_blobs
from Transport.Packet import ClientProfile

##! Mobile.BackupSnapshot: what a backup holds, and how it comes back
##! (`protocol/backup-wire-v1.md`, "Version 2: what a backup holds").
##!
##! A snapshot is the account's contacts and conversations with their history,
##! the history of every group, the names and photos this device shows, and an
##! opaque record the app keeps for itself. It holds no key: sessions, prekeys,
##! group state and the device's own keys stay on the device that made them.

## Who the backup belongs to: the account's username and identity, and its
## authorization key sealed under the code (empty from a device without it).

pub struct BackupAccount do
  account_id :: Bytes
  username :: String
  identity :: Bytes
  key_blob :: Bytes
end

pub struct BackupImported do
  created_at :: U64
  app_state :: Bytes
  conversations :: Int
  groups :: Int
end

fn intact(value :: Bool) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err("backup_damaged")
  end
end

## Parts joined in halves, so a large snapshot is copied a few times rather
## than once per part.

pub fn backup_join(parts :: List<Bytes>) -> Bytes!String do
  let count = List.length(parts)
  if count == 0 do
    Ok(Bytes.empty())
  else if count == 1 do
    Ok(List.head(parts))
  else
    mobile_append(backup_join(List.take(parts, count / 2))?,
      backup_join(List.drop(parts, count / 2))?)
  end
end

fn backup_vectors(parts :: List<Bytes>) -> Bytes!String do
  let framed = for part in parts do
    mobile_vector(part)?
  end
  backup_join(framed)
end

fn read_list(state :: BinaryReader, maximum :: Int, values :: List<Bytes>) -> List<Bytes>!String do
  if state.offset == Bytes.length(state.input) do
    Ok(values)
  else
    let item = take_vector_error(state, maximum, "backup_damaged")?
    read_list(item.state, maximum, List.append(values, item.value))
  end
end

fn backup_list(input :: Bytes, maximum :: Int) -> List<Bytes>!String do
  read_list(mobile_reader(input, 16777216, "backup_damaged")?, maximum, List.new())
end

fn flag(value :: Bool) -> Bytes!String do
  mobile_byte(if value do
    1
  else
    0
  end)
end

# Nothing with a timer, which a backup would outlive; no view-once content;
# no attachment reference, whose key is wrapped to this device and whose
# object is gone within days.

fn kept_history(values :: List<MobileHistoryEntry>) -> List<MobileHistoryEntry> do
  let view_once = history_view_once_type()
  let stripped = for value in values when value.inner.disappearing_seconds == 0 do
    if value.inner.message_type == view_once do
      %{value | inner: %{value.inner | body: Bytes.empty(), attachment_manifest: Bytes.empty()}}
    else
      %{value | inner: %{value.inner | attachment_manifest: Bytes.empty()}}
    end
  end
  List.filter(stripped,
    fn(value) do value.inner.message_type == view_once || Bytes.length(value.inner.body) > 0 end)
end

fn conversation_record(database_path :: String,
  wrapping_key :: borrow StorageKey,
  loaded :: MobileLoadedSession) -> Bytes!String do
  let record = loaded.record
  let history = history_entries_for(database_path, wrapping_key, record.conversation_id)?
  let entries = for value in kept_history(history) do
    mobile_append(mobile_byte(value.direction)?, inner_bytes(value.inner)?)?
  end
  backup_vectors([
    record.peer_account_id,
    record.conversation_id,
    Bytes.from_utf8(record.peer_username),
    record.safety_number,
    flag(record.blocked)?,
    mobile_write_u32(record.disappearing_seconds)?,
    backup_vectors(entries)?
  ])
end

fn known(values :: List<Bytes>, value :: Bytes) -> Bool do
  List.any(values, fn(held) do Bytes.secure_equals(held, value) end)
end

fn backup_peers(database_path :: String,
  wrapping_key :: borrow StorageKey,
  local_account_id :: Bytes,
  session_ids :: List<Bytes>,
  index :: Int,
  peers :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(session_ids) do
    Ok(peers)
  else
    let peer = load_session_record(database_path,
      wrapping_key,
      List.get(session_ids, index))?.record.peer_account_id
    let next = if Bytes.secure_equals(peer, local_account_id) || known(peers, peer) do
      peers
    else
      List.append(peers, peer)
    end
    backup_peers(database_path, wrapping_key, local_account_id, session_ids, index + 1, next)
  end
end

# A request this device never took up stays behind; a blocked peer comes along
# so that it stays blocked.

fn conversation_records(database_path :: String,
  wrapping_key :: borrow StorageKey,
  peers :: List<Bytes>,
  session_ids :: List<Bytes>) -> List<Bytes>!String do
  let chosen = for peer in peers do
    find_peer_session(database_path, wrapping_key, peer, session_ids, 0)?
  end
  let kept = List.filter(chosen,
    fn(loaded) do loaded.record.request_state == 1 || loaded.record.blocked end)
  let records = for loaded in kept do
    conversation_record(database_path, wrapping_key, loaded)?
  end
  Ok(records)
end

fn group_entry_bytes(value :: MobileGroupHistoryEntry) -> Bytes!String do
  backup_vectors([
    mobile_byte(value.direction)?,
    mobile_write_u64(value.epoch)?,
    value.sender_account_id,
    value.sender_device_id,
    mobile_write_u64(value.timestamp)?,
    value.body,
    value.message_id,
    mobile_byte(value.kind)?
  ])
end

fn kept_group_history(values :: List<MobileGroupHistoryEntry>,
  stays :: U64) -> List<MobileGroupHistoryEntry> do
  let stripped = for value in values when U64.compare(value.expires_at, stays) == 0 do
    if value.kind == 1 do
      %{value | body: Bytes.empty(), attachment: Bytes.empty()}
    else
      %{value | attachment: Bytes.empty()}
    end
  end
  List.filter(stripped, fn(value) do value.kind != 0 || Bytes.length(value.body) > 0 end)
end

fn group_record(database_path :: String,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes) -> Bytes!String do
  let history = group_history_entries(database_path, wrapping_key, group_id)?
  let entries = for value in kept_group_history(history, mobile_wide("0")?) do
    group_entry_bytes(value)?
  end
  backup_vectors([group_id, backup_vectors(entries)?])
end

fn presentation_record(database_path :: String,
  wrapping_key :: borrow StorageKey,
  key :: String) -> Bytes!String do
  let record = load_presentation_record(database_path, wrapping_key, Bytes.from_utf8(key))?
  if Bytes.length(record) == 0 do
    Ok(Bytes.empty())
  else
    backup_vectors([Bytes.from_utf8(key), record])
  end
end

fn presentation_records(database_path :: String,
  wrapping_key :: borrow StorageKey,
  keys :: List<String>) -> List<Bytes>!String do
  let found = for key in keys do
    presentation_record(database_path, wrapping_key, key)?
  end
  Ok(List.filter(found, fn(value) do Bytes.length(value) > 0 end))
end

fn presentation_keys(local :: ClientProfile,
  peers :: List<Bytes>,
  groups :: List<Bytes>) -> List<String> do
  let people = List.flat_map(peers,
    fn(peer) do ["user/" <> Bytes.to_hex(peer), "nickname/" <> Bytes.to_hex(peer)] end)
  let places = for group_id in groups do
    "group/" <> Bytes.to_hex(group_id)
  end
  ["user/" <> Bytes.to_hex(local.account_id)] ++ people ++ places
end

## The snapshot a backup seals: a header, the app's record, then the
## conversations, groups and presentation records, each a list of vectors,
## and the account: username, identity, and `account_key_blob`.

pub fn backup_snapshot(database_path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  app_state :: Bytes,
  created_at :: U64,
  account_key_blob :: Bytes) -> Bytes!String do
  if Bytes.length(app_state) > 4194304 do
    return Err("backup_app_state_too_large")
  end
  let session_ids = load_session_ids(database_path, wrapping_key)?
  let peers = backup_peers(database_path,
    wrapping_key,
    local.account_id,
    session_ids,
    0,
    List.new())?
  let conversations = conversation_records(database_path, wrapping_key, peers, session_ids)?
  let groups = group_index_ids(database_path, wrapping_key)?
  let group_records = for group_id in groups do
    group_record(database_path, wrapping_key, group_id)?
  end
  let presentations = presentation_records(database_path,
    wrapping_key,
    presentation_keys(local, peers, groups))?
  backup_vectors([
    mobile_join([
        mobile_byte(1)?,
        Bytes.from_utf8("BKS"),
        local.account_id,
        mobile_write_u64(created_at)?
      ],
      0,
      Bytes.empty())?,
    app_state,
    backup_vectors(conversations)?,
    backup_vectors(group_records)?,
    backup_vectors(presentations)?,
    backup_vectors([
      Bytes.from_utf8(local.username),
      local.entry.account_identity,
      account_key_blob
    ])?
  ])
end

fn backup_sections(snapshot :: Bytes) -> List<Bytes>!String do
  let sections = backup_list(snapshot, 16777216)?
  intact(List.length(sections) == 6)?
  let header = List.head(sections)
  intact(Bytes.length(header) == 44)?
  intact(Bytes.secure_equals(Bytes.slice(header, 0, 4)?,
    mobile_append(mobile_byte(1)?, Bytes.from_utf8("BKS"))?))?
  Ok(sections)
end

pub fn backup_account_of(snapshot :: Bytes) -> BackupAccount!String do
  let sections = backup_sections(snapshot)?
  let fields = backup_list(List.get(sections, 5), 65536)?
  intact(List.length(fields) == 3)?
  let username = mobile_utf8(List.head(fields), "backup_damaged")?
  intact(String.length(username) > 0 && Bytes.length(List.head(fields)) <= 64)?
  Ok(BackupAccount {
    account_id: Bytes.slice(List.head(sections), 4, 32)?,
    username: username,
    identity: List.get(fields, 1),
    key_blob: List.get(fields, 2)
  })
end

fn history_entry(input :: Bytes) -> MobileHistoryEntry!String do
  intact(Bytes.length(input) > 1)?
  let direction = mobile_read_byte(Bytes.slice(input, 0, 1)?)?
  intact(direction == 1 || direction == 2)?
  case decode_inner_envelope(Bytes.slice(input, 1, Bytes.length(input) - 1)?) do
    Err(_) -> Err("backup_damaged")
    Ok(inner) -> Ok(MobileHistoryEntry { direction: direction, inner: inner })
  end
end

fn same_message(left :: MobileHistoryEntry, right :: MobileHistoryEntry) -> Bool do
  Bytes.secure_equals(left.inner.sender_account_id, right.inner.sender_account_id)
    && Bytes.secure_equals(left.inner.client_message_id, right.inner.client_message_id)
end

# What the backup had and this device lacks goes first, being older; whatever
# arrived since stays after it. Restoring again adds nothing twice.

fn merged_history(restored :: List<MobileHistoryEntry>,
  existing :: List<MobileHistoryEntry>) -> List<MobileHistoryEntry> do
  List.filter(restored,
    fn(value) do !List.any(existing, fn(held) do same_message(held, value) end) end)
    ++ existing
end

fn restore_block(database_path :: String,
  wrapping_key :: borrow StorageKey,
  peer :: Bytes) -> Result<(), String> do
  let current = find_peer_session(database_path,
    wrapping_key,
    peer,
    load_session_ids(database_path, wrapping_key)?,
    0)?
  if !current.record.blocked do
    update_conversation(MobilePolicyRequest {
      database_path: database_path,
      peer_profile: peer,
      action: 2,
      value: 0
    })?
  end
  Ok(nil)
end

# A peer this device already talks to keeps its record; one it does not know
# gets the record a sibling's sync would give it, under the backup's key.

fn import_conversation(database_path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  input :: Bytes) -> Result<(), String> do
  let fields = backup_list(input, 16777216)?
  intact(List.length(fields) == 7)?
  let peer = List.get(fields, 0)
  let username = mobile_utf8(List.get(fields, 2), "backup_damaged")?
  let safety = List.get(fields, 3)
  intact(Bytes.length(peer) == 32
    && Bytes.length(List.get(fields, 1)) == 16
    && String.length(username) > 0
    && Bytes.length(List.get(fields, 2)) <= 64
    && (Bytes.length(safety) == 0 || Bytes.length(safety) == 64)
    && !Bytes.secure_equals(peer, local.account_id))?
  let filed = ensure_conversation_alias(database_path,
    wrapping_key,
    local,
    MobileSyncPayload {
      peer_username: username,
      peer_account_id: peer,
      conversation_id: List.get(fields, 1),
      client_message_id: Bytes.empty(),
      client_timestamp: mobile_wide("0")?,
      body: Bytes.empty(),
      disappearing_seconds: mobile_read_u32(List.get(fields, 5))?,
      safety_number: safety
    },
    load_session_ids(database_path, wrapping_key)?)?
  let restored = for entry in backup_list(List.get(fields, 6), 65600)? do
    history_entry(entry)?
  end
  let existing = history_entries_for(database_path, wrapping_key, filed)?
  let (label, blob) = history_sealed_for(merged_history(restored, existing), wrapping_key, filed)?
  store_updated_blobs(database_path, [label], [blob])?
  if mobile_read_byte(List.get(fields, 4))? == 1 do
    restore_block(database_path, wrapping_key, peer)?
  end
  Ok(nil)
end

fn group_entry(input :: Bytes) -> MobileGroupHistoryEntry!String do
  let fields = backup_list(input, 65346)?
  intact(List.length(fields) == 8)?
  Ok(MobileGroupHistoryEntry {
    message_id: List.get(fields, 6),
    direction: mobile_read_byte(List.get(fields, 0))?,
    epoch: mobile_read_u64(List.get(fields, 1))?,
    sender_account_id: List.get(fields, 2),
    sender_device_id: List.get(fields, 3),
    timestamp: mobile_read_u64(List.get(fields, 4))?,
    body: List.get(fields, 5),
    attachment: Bytes.empty(),
    expires_at: mobile_wide("0")?,
    kind: mobile_read_byte(List.get(fields, 7))?
  })
end

fn same_group_message(left :: MobileGroupHistoryEntry, right :: MobileGroupHistoryEntry) -> Bool do
  if Bytes.length(left.message_id) == 32 && Bytes.length(right.message_id) == 32 do
    Bytes.secure_equals(left.message_id, right.message_id)
  else
    Bytes.secure_equals(left.sender_account_id, right.sender_account_id)
      && U64.compare(left.timestamp, right.timestamp) == 0
      && Bytes.secure_equals(left.body, right.body)
  end
end

# The device is not in the group until a member adds it again; its history is
# here for when that happens, since a group's history only ever grows.

fn import_group(database_path :: String,
  wrapping_key :: borrow StorageKey,
  input :: Bytes) -> Result<(), String> do
  let fields = backup_list(input, 16777216)?
  intact(List.length(fields) == 2 && Bytes.length(List.head(fields)) == 32)?
  let group_id = List.head(fields)
  let restored = for entry in backup_list(List.get(fields, 1), 81889)? do
    group_entry(entry)?
  end
  let existing = group_history_entries(database_path, wrapping_key, group_id)?
  let merged = List.filter(restored,
    fn(value) do !List.any(existing, fn(held) do same_group_message(held, value) end) end)
    ++ existing
  let (label, blob) = group_history_sealed(merged, wrapping_key, group_id)?
  store_updated_blobs(database_path, [label], [blob])?
  Ok(nil)
end

# A newer record already here wins; a record this build cannot read is left out.

fn import_presentation(database_path :: String, input :: Bytes) -> Result<(), String> do
  let fields = backup_list(input, 16777216)?
  intact(List.length(fields) == 2)?
  case save_presentation(MobileTriplePayloadRequest {
    database_path: database_path,
    first: List.head(fields),
    second: List.get(fields, 1)
  }) do
    Err(_) -> Ok(nil)
    Ok(_) -> Ok(nil)
  end
end

pub fn backup_import(database_path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  snapshot :: Bytes) -> BackupImported!String do
  let sections = backup_sections(snapshot)?
  let header = List.head(sections)
  if !Bytes.secure_equals(Bytes.slice(header, 4, 32)?, local.account_id) do
    return Err("backup_account_mismatch")
  end
  let conversations = backup_list(List.get(sections, 2), 16777216)?
  let groups = backup_list(List.get(sections, 3), 16777216)?
  for conversation in conversations do
    import_conversation(database_path, wrapping_key, local, conversation)?
  end
  for group in groups do
    import_group(database_path, wrapping_key, group)?
  end
  for presentation in backup_list(List.get(sections, 4), 16777216)? do
    import_presentation(database_path, presentation)?
  end
  Ok(BackupImported {
    created_at: mobile_read_u64(Bytes.slice(header, 36, 8)?)?,
    app_state: List.get(sections, 1),
    conversations: List.length(conversations),
    groups: List.length(groups)
  })
end
