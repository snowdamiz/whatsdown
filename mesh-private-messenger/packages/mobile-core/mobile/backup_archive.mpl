from Mobile.BackupAttachmentReader import (
  capture_backup_attachment_reader,
  require_backup_attachment_reader_current,
  require_backup_attachment_reader_current_on,
  backup_attachment_read_completion
)
from Mobile.Codec import current_time
from Mobile.AttachmentTransport import AttachmentHttpResponse, legacy_attachment_download_response
from Mobile.Attachments import decode_reference, open_attachment_chunk_with_device
from Backups.ContentArchive import (
  BackupArchiveAttachment,
  BackupContentRecord,
  BackupContentScope,
  BackupContentArchive,
  encode_content_archive
)
from Backups.PortableV2 import PortableBackupContentArchive
from Backups.ContentArchive import BackupAttachmentPolicy, BackupAttachmentOmission
from Attachments.Protocol import AttachmentManifest
from Mobile.BackupAttachmentReader import D4BackupAttachmentReader, backup_attachment_manifest
from Mobile.Attachments import BackupAttachmentReferenceSlot, backup_attachment_reference_slots

##! Whole operations capture their own custody and sources. No native export.
from Mobile.BackupArchivePayload import BackupPayloadIdentity, backup_payload_identity
from Backups.PortableV2 import (
  PortableBackupV2Content,
  PortableBackupV2Created,
  PortableBackupV2Error,
  create_portable_backup_v2,
  restore_portable_archive
)
from Backups.TextArchive import (
  BackupArchiveRecord,
  BackupArchiveScope,
  BackupTextArchive,
  encode_text_archive
)
from Mobile.BackupAuthority import (
  D4BackupAuthority,
  capture_backup_authority_with_key,
  capture_backup_snapshot_with_key,
  require_backup_authority_current_with_key
)
from Storage.FanoutCommit import FanoutSnapshot
from Storage.Keys import platform_key, local_context, context, open_local, seal_local
from Storage.HistoryBlobs import open_history_blob, seal_history_blob
from Mobile.Sessions import decode_session_ids, parse_session_record
from Mobile.GroupState import (
  decode_group_ids,
  decode_group_history,
  group_state_label,
  group_history_label
)
from Mobile.GroupPolicyWire import group_policy_label, decode_group_policy
from Mobile.HistoryWire import decode_history
from Mobile.Types import (
  MobileHistoryEntry,
  MobileHistoryAttachment,
  MobileGroupHistoryEntry,
  MobileSessionRecord
)
from Mobile.Codec import (
  mobile_zeroes,
  mobile_byte,
  mobile_join,
  mobile_write_u64,
  mobile_read_u64,
  mobile_read_byte,
  take_fixed
)
from Binary.Reader import BinaryReader, reader, finish
from Storage.BackupArchiveCommit import (
  backup_archive_label,
  backup_archive_index_label,
  require_backup_archive_snapshot_with_key
)
from Storage.Blobs import put_blob_bounded_with_key, blob_record_hash_with_key
from Storage.AccountGuard import AccountBasis, load_account_basis_bounded_with_key
from Storage.BackupPendingCommit import (
  PendingCipherBasis,
  capture_pending_cipher_basis_with_key,
  require_pending_cipher_basis_with_key,
  publish_pending_cipher_pair_with_key,
  delete_pending_cipher_pair_with_key
)
from Mobile.Codec import (
  mobile_read_u32,
  mobile_write_u32,
  mobile_wide,
  take_vector
)
from Groups.GroupSnapshot import require_group_snapshot_custody

pub struct D4BackupSelection do
  kind :: Int
  scope_id :: Bytes
  from_time :: Option<U64>
  through_time :: Option<U64>
end

pub struct D4BackupArchiveReceipt do
  backup_id :: Bytes
  disposition :: Int
end

struct D4BackupScopeRef do
  selection :: D4BackupSelection
  peer :: Bytes
  label :: String
end

struct D4BackupRawSource do
  source :: D4BackupScopeRef
  wire :: Result<Plaintext<Bytes>, String>
end

struct D4BackupRawPrepared do
  content :: Plaintext<PortableBackupV2Content>
  encoded_extent :: Plaintext<Int>
end

struct D4BackupHistoryCapture do
  authority :: D4BackupAuthority
  refs :: List<D4BackupScopeRef>
end

struct D4BackupPreparedCreate do
  sources :: FanoutSnapshot
  created :: PortableBackupV2Created
end

struct D4BackupRowChoice do
  record :: Option<BackupArchiveRecord>
  reason :: Int
  attachment :: Bool
end

struct D4BackupPreparedRows do
  entries :: List<BackupArchiveRecord>
  candidates :: Int
  timed :: Int
  unknown :: Int
  nontext :: Int
  empty :: Int
  attachments :: Int
end

struct D4BackupPreparedScopes do
  scopes :: List<BackupArchiveScope>
  candidates :: Int
  timed :: Int
  unknown :: Int
  nontext :: Int
  empty :: Int
  attachments :: Int
end

fn backup_selection_order(a :: D4BackupSelection, b :: D4BackupSelection) -> Int do
  if a.kind != b.kind do
    a.kind - b.kind
  else if Bytes.to_hex(a.scope_id) < Bytes.to_hex(b.scope_id) do
    -1
  else if Bytes.secure_equals(a.scope_id, b.scope_id) do
    0
  else
    1
  end
end

fn backup_validate_selection(selection :: List<D4BackupSelection>) -> List<D4BackupSelection>!String do
  if List.length(selection) < 1 || List.length(selection) > 32 do
    return Err("invalid_backup_selection")
  end
  for item in selection do
    if (item.kind != 1 && item.kind != 2)
      || (item.kind == 1 && Bytes.length(item.scope_id) != 16)
      || (item.kind == 2 && Bytes.length(item.scope_id) != 32) do
      return Err("invalid_backup_selection")
    end
    case (item.from_time, item.through_time) do
      (Some(first), Some(last)) -> if U64.compare(first, last) > 0 do
        return Err("invalid_backup_selection")
      end
      _ -> nil
    end
  end
  let sorted = List.sort(selection, backup_selection_order)
  for index in 1..List.length(sorted) do
    if backup_selection_order(List.get(sorted, index - 1), List.get(sorted, index)) == 0 do
      return Err("invalid_backup_selection")
    end
  end
  Ok(sorted)
end

fn backup_blob(original :: FanoutSnapshot, label :: String) -> Bytes!String do
  for basis in original.bases do
    for index in 0..List.length(basis.labels) do
      if List.get(basis.labels, index) == label do
        return Ok(List.get(basis.records, index))
      end
    end
  end
  Err("backup_source_not_captured")
end

fn backup_metadata(original :: FanoutSnapshot,
  label :: String,
  key :: borrow StorageKey,
  maximum :: Int,
  optional :: Bool) -> Bytes!String do
  let blob = backup_blob(original, label)?
  if Bytes.length(blob) == 0 && optional do
    return Ok(Bytes.empty())
  end
  let opened = open_local(blob, key, local_context(label)?)?
  if Bytes.length(opened) > maximum do
    Err("backup_source_limit")
  else
    Ok(opened)
  end
end

fn backup_source_labels(original :: FanoutSnapshot) -> List<String> do
  List.flatten(for basis in original.bases do
    basis.labels
  end)
end

fn backup_session_ids(index :: Bytes, remaining_labels :: Int) -> List<Bytes>!String do
  # Fixed32-byte IDs permit count admission before the recursive index decoder.
  if remaining_labels < 0 || Bytes.length(index) > remaining_labels * 32 do
    return Err("backup_source_limit")
  end
  let ids = decode_session_ids(index)?
  for offset in 0..List.length(ids) do
    if List.any(List.take(ids, offset),
      fn(previous) -> Bytes.secure_equals(previous, List.get(ids, offset)) end) do
      return Err("invalid_session_index")
    end
  end
  Ok(ids)
end

fn backup_direct_ref(item :: D4BackupSelection,
  records :: List<MobileSessionRecord>,
  index :: Int,
  peer :: Option<Bytes>) -> D4BackupScopeRef!String do
  if index >= List.length(records) do
    return case peer do
      None -> Err("backup_scope_not_found")
      Some(value) -> Ok(D4BackupScopeRef {
        selection: item,
        peer: value,
        label: "history/v1/#{Bytes.to_hex(item.scope_id)}"
      })
    end
  end
  let record = List.get(records, index)
  if !Bytes.secure_equals(record.conversation_id, item.scope_id) do
    return backup_direct_ref(item, records, index + 1, peer)
  end
  case peer do
    Some(previous) -> if !Bytes.secure_equals(previous, record.peer_account_id) do
      return Err("backup_scope_ambiguous")
    end
    None -> nil
  end
  backup_direct_ref(item, records, index + 1, Some(record.peer_account_id))
end

fn backup_group_ref(item :: D4BackupSelection,
  groups :: List<Bytes>,
  index :: Int) -> D4BackupScopeRef!String do
  if index >= List.length(groups) do
    return Err("backup_scope_not_found")
  end
  let group = List.get(groups, index)
  if Bytes.secure_equals(group, item.scope_id) do
    Ok(D4BackupScopeRef { selection: item, peer: Bytes.empty(), label: group_history_label(group) })
  else
    backup_group_ref(item, groups, index + 1)
  end
end

fn backup_protect_opened(raw :: Result<Bytes, String>) -> Result<Plaintext<Bytes>, String> do
  case raw do
    Err(error)
    Ok(value) -> do
      let protected :: Plaintext<Bytes> = value
      Ok(protected)
    end
  end
end

fn backup_open_raw(original :: FanoutSnapshot,
  source :: D4BackupScopeRef,
  key :: borrow StorageKey) -> D4BackupRawSource!String do
  let blob = backup_blob(original, source.label)?
  let raw = if source.selection.kind == 1 do
    open_history_blob(blob, key, source.label)
  else
    open_local(blob, key, local_context(source.label)?)
  end
  Ok(D4BackupRawSource { source: source, wire: backup_protect_opened(raw) })
end

fn backup_in_range(selection :: D4BackupSelection, timestamp :: U64) -> Bool do
  let after_start = case selection.from_time do
    None -> true
    Some(first) -> U64.compare(timestamp, first) >= 0
  end
  let before_end = case selection.through_time do
    None -> true
    Some(last) -> U64.compare(timestamp, last) <= 0
  end
  after_start && before_end
end

fn backup_direct_row(source :: D4BackupScopeRef,
  row :: MobileHistoryEntry,
  ordinal :: Int) -> D4BackupRowChoice do
  let attachment = Bytes.length(row.inner.attachment_manifest) > 0
  let in_range = backup_in_range(source.selection, row.inner.client_timestamp)
  let reason = if !in_range do
    0
  else if row.inner.disappearing_seconds > 0 do
    2
  else if row.inner.disappearing_seconds < 0
    || row.inner.message_type < 1
    || row.inner.message_type > 5
    || List.any(row.inner.extensions,
      fn(extension) -> extension.id != 1 && extension.id != 2 end) do
    3
  else if row.inner.message_type != 1 do
    4
  else if Bytes.length(row.inner.body) == 0 && !attachment do
    5
  else
    1
  end
  let record = if reason == 1 do
    Some(BackupArchiveRecord {
      ordinal: ordinal,
      direction: row.direction,
      message_id: row.inner.client_message_id,
      sender_account: row.inner.sender_account_id,
      sender_device: row.inner.sender_device_id,
      timestamp: row.inner.client_timestamp,
      attachment_omitted: attachment,
      text: row.inner.body
    })
  else
    None
  end
  D4BackupRowChoice { record: record, reason: reason, attachment: in_range && attachment }
end

fn backup_group_row(source :: D4BackupScopeRef,
  row :: MobileGroupHistoryEntry,
  ordinal :: Int) -> D4BackupRowChoice do
  let attachment = Bytes.length(row.attachment) > 0
  let in_range = backup_in_range(source.selection, row.timestamp)
  let reason = if !in_range do
    0
  else if row.disappearing_seconds > 0 do
    2
  else if row.disappearing_seconds < 0 do
    3
  else if Bytes.length(row.body) == 0 && !attachment do
    5
  else
    1
  end
  let record = if reason == 1 do
    Some(BackupArchiveRecord {
      ordinal: ordinal,
      direction: row.direction,
      message_id: row.message_id,
      sender_account: row.sender_account_id,
      sender_device: row.sender_device_id,
      timestamp: row.timestamp,
      attachment_omitted: attachment,
      text: row.body
    })
  else
    None
  end
  D4BackupRowChoice { record: record, reason: reason, attachment: in_range && attachment }
end

fn backup_fold_rows(choices :: List<D4BackupRowChoice>,
  index :: Int,
  rows :: D4BackupPreparedRows) -> D4BackupPreparedRows do
  if index >= List.length(choices) do
    return rows
  end
  let choice = List.get(choices, index)
  let entries = case choice.record do
    None -> rows.entries
    Some(value) -> List.append(rows.entries, value)
  end
  backup_fold_rows(choices,
    index + 1,
    D4BackupPreparedRows {
      entries: entries,
      candidates: rows.candidates
        + if choice.reason == 0 do
          0
        else
          1
        end,
      timed: rows.timed
        + if choice.reason == 2 do
          1
        else
          0
        end,
      unknown: rows.unknown
        + if choice.reason == 3 do
          1
        else
          0
        end,
      nontext: rows.nontext
        + if choice.reason == 4 do
          1
        else
          0
        end,
      empty: rows.empty
        + if choice.reason == 5 do
          1
        else
          0
        end,
      attachments: rows.attachments
        + if choice.attachment do
          1
        else
          0
        end
    })
end

fn backup_prepare_scope(raw :: D4BackupRawSource) -> D4BackupPreparedRows!String do
  let wire :: Plaintext<Bytes> = raw.wire?
  let choices = if raw.source.selection.kind == 1 do
    let decoded = decode_history(wire)?
    for ordinal in 0..List.length(decoded) do
      let row = List.get(decoded, ordinal)
      if !Bytes.secure_equals(row.inner.conversation_id, raw.source.selection.scope_id) do
        return Err("backup_source_scope_mismatch")
      end
      backup_direct_row(raw.source, row, ordinal)
    end
  else
    let decoded = decode_group_history(wire)?
    for ordinal in 0..List.length(decoded) do
      backup_group_row(raw.source, List.get(decoded, ordinal), ordinal)
    end
  end
  Ok(backup_fold_rows(choices,
    0,
    D4BackupPreparedRows {
      entries: [],
      candidates: 0,
      timed: 0,
      unknown: 0,
      nontext: 0,
      empty: 0,
      attachments: 0
    }))
end

fn backup_prepare_scopes(sources :: List<D4BackupRawSource>,
  index :: Int,
  prepared :: D4BackupPreparedScopes) -> D4BackupPreparedScopes!String do
  if index >= List.length(sources) do
    return Ok(prepared)
  end
  let source = List.get(sources, index)
  let rows = backup_prepare_scope(source)?
  let scopes = if List.length(rows.entries) == 0 do
    prepared.scopes
  else
    List.append(prepared.scopes,
      BackupArchiveScope {
        kind: source.source.selection.kind,
        id: source.source.selection.scope_id,
        peer: source.source.peer,
        name: "",
        entries: rows.entries
      })
  end
  backup_prepare_scopes(sources,
    index + 1,
    D4BackupPreparedScopes {
      scopes: scopes,
      candidates: prepared.candidates + rows.candidates,
      timed: prepared.timed + rows.timed,
      unknown: prepared.unknown + rows.unknown,
      nontext: prepared.nontext + rows.nontext,
      empty: prepared.empty + rows.empty,
      attachments: prepared.attachments + rows.attachments
    })
end

fn backup_group_outgoing_owned(owner :: Bytes, scopes :: List<BackupArchiveScope>) -> Bool do
  List.all(scopes,
    fn(scope) -> scope.kind != 2
      || List.all(scope.entries,
        fn(record) -> record.direction != 1
          || Bytes.secure_equals(record.sender_account, owner) end) end)
end

# Pure protected preparation. Real source Results, errors and control stay private.
fn prepare_backup_text_raw(authority :: D4BackupAuthority,
  selection :: List<D4BackupSelection>,
  sources :: List<D4BackupRawSource>) -> D4BackupRawPrepared!String do
  if List.length(selection) != List.length(sources) do
    return Err("backup_source_incomplete")
  end
  let rows = backup_prepare_scopes(sources,
    0,
    D4BackupPreparedScopes {
      scopes: [],
      candidates: 0,
      timed: 0,
      unknown: 0,
      nontext: 0,
      empty: 0,
      attachments: 0
    })?
  if !backup_group_outgoing_owned(authority.profile.account_id, rows.scopes) do
    return Err("backup_preparation_refused")
  end
  let content :: Plaintext<PortableBackupV2Content> = PortableBackupV2Content {
    owner_account: authority.profile.account_id,
    owner_authorization_key: authority.profile.account.authorization_public_key,
    service_realm: authority.service_realm,
    candidate_count: rows.candidates,
    omitted_timed: rows.timed,
    omitted_unknown: rows.unknown,
    omitted_nontext: rows.nontext,
    omitted_empty: rows.empty,
    attachment_messages: rows.attachments,
    scopes: rows.scopes
  }
  # Fixed-width validation ID only. P0 later encodes this same content with its fresh ID.
  let encoded = case encode_text_archive(BackupTextArchive {
    backup_id: mobile_zeroes(32)?,
    owner_account: content.owner_account,
    owner_authorization_key: content.owner_authorization_key,
    service_realm: content.service_realm,
    created_at: authority.captured_at,
    candidate_count: content.candidate_count,
    omitted_timed: content.omitted_timed,
    omitted_unknown: content.omitted_unknown,
    omitted_nontext: content.omitted_nontext,
    omitted_empty: content.omitted_empty,
    attachment_messages: content.attachment_messages,
    scopes: content.scopes
  }) do
    Err(_) -> return Err("backup_preparation_refused")
    Ok(value) -> value
  end
  Ok(D4BackupRawPrepared { content: content, encoded_extent: Bytes.length(encoded) })
end

fn backup_invalid_content() -> PortableBackupV2Content do
  PortableBackupV2Content {
    owner_account: Bytes.empty(),
    owner_authorization_key: Bytes.empty(),
    service_realm: Bytes.empty(),
    candidate_count: 0,
    omitted_timed: 0,
    omitted_unknown: 0,
    omitted_nontext: 0,
    omitted_empty: 0,
    attachment_messages: 0,
    scopes: []
  }
end

# Totalization is private and pure. This invalid owner tuple cannot encode an
# archive; P0's existing zero-refusal boundary runs before code/KDF creation.
fn backup_totalized_content(raw :: Result<D4BackupRawPrepared, String>) -> Plaintext<PortableBackupV2Content> do
  case raw do
    Err(_) -> backup_invalid_content()
    Ok(prepared) -> prepared.content
  end
end

fn backup_capture_create_sources(path :: String,
  authority :: D4BackupAuthority,
  selection :: List<D4BackupSelection>,
  key :: borrow StorageKey) -> D4BackupHistoryCapture!String do
  let indices = capture_backup_snapshot_with_key(path,
    authority.sources,
    ["sessions/v1", "groups/v1"],
    key)?
  let reserve = List.reduce(selection,
    0,
    fn(total, item) -> total
      + if item.kind == 1 do
        1
      else
        3
      end end)
  let index = backup_metadata(indices, "sessions/v1", key, 6144, true)?
  let ids = backup_session_ids(index, 192 - List.length(backup_source_labels(indices)) - reserve)?
  let group_index = backup_metadata(indices, "groups/v1", key, 4616, true)?
  let groups = if Bytes.length(group_index) == 0 do
    []
  else
    decode_group_ids(group_index)?
  end
  let session_labels = for id in ids do
    "session/v1/#{Bytes.to_hex(id)}"
  end
  let metadata = capture_backup_snapshot_with_key(path, indices, session_labels, key)?
  let records = for label in session_labels do
    let record = parse_session_record(backup_metadata(metadata, label, key, 70600, false)?)?
    if !Bytes.secure_equals(record.local_account_id, authority.profile.account_id)
      || !Bytes.secure_equals(record.local_device_id, authority.profile.device_id) do
      return Err("backup_source_account_mismatch")
    end
    # The snapshot field stays opaque. It is never restored or copied to content.
    record
  end
  let refs = for item in selection do
    if item.kind == 1 do
      backup_direct_ref(item, records, 0, None)?
    else
      backup_group_ref(item, groups, 0)?
    end
  end
  let labels = List.flatten(for source in refs do
    if source.selection.kind == 1 do
      [source.label]
    else
      [
        source.label,
        group_state_label(source.selection.scope_id)?,
        group_policy_label(source.selection.scope_id)?
      ]
    end
  end)
  let captured = capture_backup_snapshot_with_key(path, metadata, labels, key)?
  for source in refs do
    if source.selection.kind == 2 do
      let state_label = group_state_label(source.selection.scope_id)?
      let snapshot = backup_metadata(captured, state_label, key, 65535, false)?
      case require_group_snapshot_custody(snapshot,
        key,
        authority.profile.account_id,
        authority.profile.device_id,
        source.selection.scope_id,
        U64.parse("1")?) do
        Err(_) -> return Err("backup_group_state_invalid")
        Ok(_) -> nil
      end
      let policy = backup_metadata(captured,
        group_policy_label(source.selection.scope_id)?,
        key,
        5,
        true)?
      if Bytes.length(policy) > 0 do
        let _policy = decode_group_policy(policy)?
        nil
      end
    end
  end
  let current = %{authority | sources: captured}
  backup_finalize(path, key, BackupFinalFence(current))?
  Ok(D4BackupHistoryCapture { authority: current, refs: refs })
end

fn backup_prepare_create(path :: String,
  authority :: D4BackupAuthority,
  selection :: List<D4BackupSelection>,
  key :: borrow StorageKey) -> D4BackupPreparedCreate!String do
  let history = backup_capture_create_sources(path, authority, selection, key)?
  let current = history.authority
  let captured = current.sources
  let refs = history.refs
  let raw_sources = for source in refs do
    backup_open_raw(captured, source, key)?
  end
  # No caller branch or effect observes the protected preparation Result.
  let content = backup_totalized_content(prepare_backup_text_raw(current, selection, raw_sources))
  let created = case create_portable_backup_v2(content, authority.captured_at) do
    Err(_) -> return Err("backup_archive_refused")
    Ok(value) -> value
  end
  Ok(D4BackupPreparedCreate { sources: captured, created: created })
end

pub fn create_backup_archive(path :: String,
  expected_profile :: Bytes,
  selection :: List<D4BackupSelection>) -> PortableBackupV2Created!String do
  let selected = backup_validate_selection(selection)?
  if !backup_valid_identity(path, expected_profile) do
    return Err("invalid_backup_request")
  end
  let key = platform_key()?
  let result = backup_create_with_key(path, expected_profile, selected, key)
  Secret.destroy(key)
  result
end

fn backup_create_with_key(path :: String,
  expected_profile :: Bytes,
  selected :: List<D4BackupSelection>,
  key :: borrow StorageKey) -> PortableBackupV2Created!String do
  let authority = capture_backup_authority_with_key(path, expected_profile, key)?
  let ready = backup_prepare_create(path, authority, selected, key)?
  backup_finalize(path, key, BackupFinalFence(%{authority | sources: ready.sources}))?
  Ok(ready.created)
end

fn backup_valid_identity(path :: String, expected_profile :: Bytes) -> Bool do
  String.length(path) >= 1
    && String.length(path) <= 4096
    && Bytes.length(expected_profile) >= 1
    && Bytes.length(expected_profile) <= 36134
end

struct D4BackupIndexEntry do
  backup_id :: Bytes
  digest :: Bytes
  created_at :: U64
end

struct D4BackupImportPlan do
  payload :: Plaintext<Bytes>
  index :: Plaintext<Bytes>
  admission :: Plaintext<Int>
end

struct D4BackupPreparedImport do
  sources :: FanoutSnapshot
  archive :: Bytes
  index :: Bytes
  disposition :: Int
end

struct D4BackupReadPlan do
  payload :: Plaintext<Bytes>
  admission :: Plaintext<Int>
end

struct D4BackupPreparedRead do
  sources :: FanoutSnapshot
  payload :: Plaintext<Bytes>
end

fn backup_index_order(a :: D4BackupIndexEntry, b :: D4BackupIndexEntry) -> Int do
  if Bytes.to_hex(a.backup_id) < Bytes.to_hex(b.backup_id) do
    -1
  else if Bytes.secure_equals(a.backup_id, b.backup_id) do
    0
  else
    1
  end
end

fn backup_encode_index(entries :: List<D4BackupIndexEntry>) -> Bytes!String do
  if List.length(entries) > 8 do
    return Err("invalid_backup_index")
  end
  for index in 0..List.length(entries) do
    let entry = List.get(entries, index)
    if Bytes.length(entry.backup_id) != 32
      || Bytes.length(entry.digest) != 32
      || (index > 0 && backup_index_order(List.get(entries, index - 1), entry) >= 0) do
      return Err("invalid_backup_index")
    end
  end
  mobile_join([mobile_byte(1)?, Bytes.from_utf8("BAI"), mobile_byte(List.length(entries))?]
      ++ List.flatten(for entry in entries do
        [entry.backup_id, entry.digest, mobile_write_u64(entry.created_at)?]
      end),
    0,
    Bytes.empty())
end

fn backup_decode_index_rows(state :: BinaryReader,
  count :: Int,
  index :: Int,
  entries :: List<D4BackupIndexEntry>) -> List<D4BackupIndexEntry>!String do
  if index >= count do
    case finish(state) do
      Err(_) -> return Err("invalid_backup_index")
      Ok(_) -> nil
    end
    return Ok(entries)
  end
  let id = take_fixed(state, 32)?
  let digest = take_fixed(id.state, 32)?
  let time = take_fixed(digest.state, 8)?
  let entry = D4BackupIndexEntry {
    backup_id: id.value,
    digest: digest.value,
    created_at: mobile_read_u64(time.value)?
  }
  if index > 0 && backup_index_order(List.get(entries, index - 1), entry) >= 0 do
    return Err("invalid_backup_index")
  end
  backup_decode_index_rows(time.state, count, index + 1, List.append(entries, entry))
end

fn backup_decode_index(input :: Plaintext<Bytes>,
  absent :: Bool) -> List<D4BackupIndexEntry>!String do
  if absent do
    if Bytes.length(input) == 0 do
      return Ok([])
    else
      return Err("invalid_backup_index")
    end
  end
  let state = case reader(input, 581) do
    Err(_) -> return Err("invalid_backup_index")
    Ok(value) -> value
  end
  let version = take_fixed(state, 1)?
  let magic = take_fixed(version.state, 3)?
  let count = take_fixed(magic.state, 1)?
  let length = mobile_read_byte(count.value)?
  if mobile_read_byte(version.value)? != 1
    || !Bytes.secure_equals(magic.value, Bytes.from_utf8("BAI"))
    || length > 8 do
    return Err("invalid_backup_index")
  end
  backup_decode_index_rows(count.state, length, 0, [])
end

fn backup_find_index(entries :: List<D4BackupIndexEntry>,
  id :: Bytes,
  index :: Int) -> Option<D4BackupIndexEntry> do
  if index >= List.length(entries) do
    None
  else if Bytes.secure_equals(List.get(entries, index).backup_id, id) do
    Some(List.get(entries, index))
  else
    backup_find_index(entries, id, index + 1)
  end
end

fn backup_index_source(original :: FanoutSnapshot,
  label :: String,
  key :: borrow StorageKey) -> Result<Plaintext<Bytes>, String> do
  let blob = backup_blob(original, label)?
  if Bytes.length(blob) == 0 do
    let empty :: Plaintext<Bytes> = Bytes.empty()
    Ok(empty)
  else
    backup_protect_opened(open_local(blob, key, local_context(label)?))
  end
end

fn backup_archive_source(original :: FanoutSnapshot,
  label :: String,
  key :: borrow StorageKey) -> Result<Plaintext<Bytes>, String> do
  let blob = backup_blob(original, label)?
  backup_protect_opened(open_history_blob(blob, key, label))
end

fn backup_owner_custody_matches(authority :: D4BackupAuthority,
  archive :: BackupPayloadIdentity) -> Bool do
  Bytes.secure_equals(archive.owner_account, authority.profile.account_id)
    && Bytes.secure_equals(archive.owner_authorization_key,
      authority.profile.account.authorization_public_key)
    && Bytes.secure_equals(archive.service_realm, authority.service_realm)
    && archive.outgoing_groups_owned
end

fn backup_owner_matches(authority :: D4BackupAuthority,
  archive :: BackupPayloadIdentity,
  confirmed_id :: Bytes) -> Bool do
  Bytes.secure_equals(archive.backup_id, confirmed_id)
    && backup_owner_custody_matches(authority, archive)
end

fn backup_prepare_import_raw(authority :: D4BackupAuthority,
  confirmed :: Bytes,
  payload :: Plaintext<Bytes>,
  index_raw :: Result<Plaintext<Bytes>, String>,
  existing_raw :: Result<Plaintext<Bytes>, String>,
  index_absent :: Bool,
  archive_absent :: Bool) -> D4BackupImportPlan!String do
  let archive = case backup_payload_identity(payload) do
    Err(_) -> return Err("backup_import_refused")
    Ok(value) -> value
  end
  if !backup_owner_matches(authority, archive, confirmed) do
    return Err("backup_import_refused")
  end
  let index_wire :: Plaintext<Bytes> = index_raw?
  let entries = backup_decode_index(index_wire, index_absent)?
  let digest = Crypto.sha256(payload)
  case backup_find_index(entries, confirmed, 0) do
    Some(entry) -> do
      if archive_absent do
        return Err("backup_import_refused")
      end
      let existing :: Plaintext<Bytes> = existing_raw?
      if !Bytes.secure_equals(entry.digest, digest)
        || U64.compare(entry.created_at, archive.created_at) != 0
        || !Bytes.secure_equals(Crypto.sha256(existing), entry.digest)
        || !Bytes.secure_equals(existing, payload) do
        return Err("backup_import_refused")
      end
      Ok(D4BackupImportPlan { payload: payload, index: index_wire, admission: 2 })
    end
    None -> do
      if !archive_absent || List.length(entries) >= 8 do
        return Err("backup_import_refused")
      end
      let next = List.sort(List.append(entries,
          D4BackupIndexEntry {
            backup_id: confirmed,
            digest: digest,
            created_at: archive.created_at
          }),
        backup_index_order)
      Ok(D4BackupImportPlan { payload: payload, index: backup_encode_index(next)?, admission: 1 })
    end
  end
end

fn backup_totalized_import(raw :: Result<D4BackupImportPlan, String>,
  payload :: Plaintext<Bytes>) -> D4BackupImportPlan do
  case raw do
    Err(_) -> D4BackupImportPlan { payload: payload, index: Bytes.empty(), admission: 0 }
    Ok(value) -> value
  end
end

fn backup_target_admission(expected :: Plaintext<Bytes>,
  actual :: Result<Plaintext<Bytes>, String>) -> Plaintext<Int> do
  case actual do
    Err(_) -> 0
    Ok(value) -> if Bytes.secure_equals(expected, value) do
      1
    else
      0
    end
  end
end

# Reviewed closed admission only:0 refusal,1 new/verified target/read,
#2 existing identical payload. Raw tags/errors/digests remain private.
fn backup_observe_admission(value :: Plaintext<Int>) -> Int do
  let closed :: Plaintext<Int> = if value == 1 || value == 2 do
    value
  else
    0
  end
  declassify(closed,
    "backup archive operations disclose only finite authenticated owner schema storage admission and identical-payload disposition; plaintext records payload digests arbitrary errors and archive index metadata remain private")
end

fn backup_prepare_import(path :: String,
  authority :: D4BackupAuthority,
  wire :: Bytes,
  code :: String,
  confirmed :: Bytes,
  key :: borrow StorageKey) -> D4BackupPreparedImport!String do
  let payload = case restore_portable_archive(code, wire) do
    Err(_) -> return Err("backup_archive_refused")
    Ok(value) -> value
  end
  let row = backup_archive_label(authority.profile.account_id, confirmed)?
  let index = backup_archive_index_label(authority.profile.account_id)?
  let captured = capture_backup_snapshot_with_key(path, authority.sources, [row, index], key)?
  let plan = backup_totalized_import(backup_prepare_import_raw(authority,
      confirmed,
      payload,
      backup_index_source(captured, index, key),
      backup_archive_source(captured, row, key),
      Bytes.length(backup_blob(captured, index)?) == 0,
      Bytes.length(backup_blob(captured, row)?) == 0),
    payload)
  let disposition = backup_observe_admission(plan.admission)
  if disposition == 0 do
    return Err("backup_archive_refused")
  end
  if disposition == 2 do
    return Ok(D4BackupPreparedImport {
      sources: captured,
      archive: Bytes.empty(),
      index: Bytes.empty(),
      disposition: disposition
    })
  end
  let raw_archive = seal_history_blob(plan.payload, key, row)
  let raw_index = seal_local(plan.index, key, local_context(index)?)
  let prepared_archive = raw_archive?
  let prepared_index = raw_index?
  # Reopen both real target-platform containers before any SQL publication.
  let archive_check = backup_target_admission(plan.payload,
    backup_protect_opened(open_history_blob(prepared_archive, key, row)))
  let index_check = backup_target_admission(plan.index,
    backup_protect_opened(open_local(prepared_index, key, local_context(index)?)))
  let verified :: Plaintext<Int> = if archive_check == 1 && index_check == 1 do
    1
  else
    0
  end
  if backup_observe_admission(verified) != 1 do
    return Err("backup_archive_refused")
  end
  Ok(D4BackupPreparedImport {
    sources: captured,
    archive: prepared_archive,
    index: prepared_index,
    disposition: disposition
  })
end

pub fn import_backup_archive(path :: String,
  expected_profile :: Bytes,
  wire :: Bytes,
  recovery_code :: String,
  confirmed_backup_id :: Bytes) -> D4BackupArchiveReceipt!String do
  if !backup_valid_identity(path, expected_profile)
    || Bytes.length(confirmed_backup_id) != 32
    || Bytes.length(wire) < 1
    || Bytes.length(wire) > 16796864
    || String.length(recovery_code) < 1
    || String.length(recovery_code) > 1024 do
    return Err("invalid_backup_request")
  end
  let key = platform_key()?
  let result = backup_import_with_key(path,
    expected_profile,
    wire,
    recovery_code,
    confirmed_backup_id,
    key)
  Secret.destroy(key)
  result
end

fn backup_import_with_key(path :: String,
  expected_profile :: Bytes,
  wire :: Bytes,
  code :: String,
  confirmed :: Bytes,
  key :: borrow StorageKey) -> D4BackupArchiveReceipt!String do
  let authority = capture_backup_authority_with_key(path, expected_profile, key)?
  let ready = backup_prepare_import(path, authority, wire, code, confirmed, key)?
  backup_finalize(path, key, BackupFinalImport(authority, ready, confirmed))?
  Ok(D4BackupArchiveReceipt { backup_id: confirmed, disposition: ready.disposition })
end

fn backup_prepare_read_raw(authority :: D4BackupAuthority,
  id :: Bytes,
  index_raw :: Result<Plaintext<Bytes>, String>,
  payload_raw :: Result<Plaintext<Bytes>, String>,
  index_absent :: Bool) -> D4BackupReadPlan!String do
  let index :: Plaintext<Bytes> = index_raw?
  let entries = backup_decode_index(index, index_absent)?
  let entry = case backup_find_index(entries, id, 0) do
    None -> return Err("backup_read_refused")
    Some(value) -> value
  end
  let payload :: Plaintext<Bytes> = payload_raw?
  let archive = case backup_payload_identity(payload) do
    Err(_) -> return Err("backup_read_refused")
    Ok(value) -> value
  end
  if !backup_owner_matches(authority, archive, id)
    || U64.compare(entry.created_at, archive.created_at) != 0
    || !Bytes.secure_equals(Crypto.sha256(payload), entry.digest) do
    return Err("backup_read_refused")
  end
  Ok(D4BackupReadPlan { payload: payload, admission: 1 })
end

fn backup_totalized_read(raw :: Result<D4BackupReadPlan, String>) -> D4BackupReadPlan do
  case raw do
    Err(_) -> D4BackupReadPlan { payload: Bytes.empty(), admission: 0 }
    Ok(value) -> value
  end
end

fn backup_prepare_read(path :: String,
  authority :: D4BackupAuthority,
  id :: Bytes,
  key :: borrow StorageKey) -> D4BackupPreparedRead!String do
  let row = backup_archive_label(authority.profile.account_id, id)?
  let index = backup_archive_index_label(authority.profile.account_id)?
  let captured = capture_backup_snapshot_with_key(path, authority.sources, [row, index], key)?
  let plan = backup_totalized_read(backup_prepare_read_raw(authority,
    id,
    backup_index_source(captured, index, key),
    backup_archive_source(captured, row, key),
    Bytes.length(backup_blob(captured, index)?) == 0))
  if backup_observe_admission(plan.admission) != 1 do
    return Err("backup_archive_refused")
  end
  Ok(D4BackupPreparedRead { sources: captured, payload: plan.payload })
end

pub fn read_backup_archive(path :: String,
  expected_profile :: Bytes,
  backup_id :: Bytes) -> Result<Plaintext<Bytes>, String> do
  if !backup_valid_identity(path, expected_profile) || Bytes.length(backup_id) != 32 do
    return Err("invalid_backup_request")
  end
  let key = platform_key()?
  let result = backup_read_with_key(path, expected_profile, backup_id, key)
  Secret.destroy(key)
  result
end

fn backup_read_with_key(path :: String,
  expected_profile :: Bytes,
  id :: Bytes,
  key :: borrow StorageKey) -> Result<Plaintext<Bytes>, String> do
  let authority = capture_backup_authority_with_key(path, expected_profile, key)?
  let ready = backup_prepare_read(path, authority, id, key)?
  backup_finalize(path, key, BackupFinalFence(%{authority | sources: ready.sources}))?
  Ok(ready.payload)
end

pub struct D4BackupArchiveSummary do
  backup_id :: Bytes
  created_at :: U64
end

struct D4BackupListPlan do
  summaries :: Plaintext<List<D4BackupArchiveSummary>>
  admission :: Plaintext<Int>
end

struct D4BackupPreparedRemove do
  sources :: FanoutSnapshot
  index :: Bytes
  remove :: Bool
end

# The encrypted v1 index is at most581 canonical bytes plus67 wrapping bytes.
# Admit that role budget in SQL before materializing it, retaining all earlier
# ciphertext bases and the original encrypted profile in the existing fence.
fn backup_capture_archive_index(path :: String,
  original :: FanoutSnapshot,
  account :: Bytes,
  key :: borrow StorageKey) -> FanoutSnapshot!String do
  let label = backup_archive_index_label(account)?
  let profile = List.head(original.bases).profile
  let used = List.reduce(original.bases,
    Bytes.length(profile),
    fn(total, basis) do total
      + List.reduce(basis.records, 0, fn(size, value) -> size + Bytes.length(value) end) end)
  let remaining = 33554432 - used
  if remaining < 0 do
    return Err("backup_source_limit")
  end
  let maximum = if remaining < 648 do
    remaining
  else
    648
  end
  let captured = load_account_basis_bounded_with_key(path,
    key,
    [label],
    40000,
    maximum,
    Bytes.length(profile) + maximum)?
  capture_backup_snapshot_with_key(path,
    FanoutSnapshot { bases: List.append(original.bases, captured) },
    [],
    key)
end

fn backup_capture_list_sources(path :: String,
  authority :: D4BackupAuthority,
  key :: borrow StorageKey) -> FanoutSnapshot!String do
  backup_capture_archive_index(path, authority.sources, authority.profile.account_id, key)
end

fn backup_prepare_list_raw(raw :: Result<Plaintext<Bytes>, String>,
  absent :: Bool) -> D4BackupListPlan!String do
  let entries = backup_decode_index(raw?, absent)?
  let summaries :: Plaintext<List<D4BackupArchiveSummary>> = for entry in entries do
    D4BackupArchiveSummary { backup_id: entry.backup_id, created_at: entry.created_at }
  end
  Ok(D4BackupListPlan { summaries: summaries, admission: 1 })
end

fn backup_prepare_list(captured :: FanoutSnapshot,
  account :: Bytes,
  key :: borrow StorageKey) -> D4BackupListPlan do
  let label = case backup_archive_index_label(account) do
    Err(_) -> return D4BackupListPlan { summaries: [], admission: 0 }
    Ok(value) -> value
  end
  let absent = case backup_blob(captured, label) do
    Err(_) -> false
    Ok(blob) -> Bytes.length(blob) == 0
  end
  case backup_prepare_list_raw(backup_index_source(captured, label, key), absent) do
    Err(_) -> D4BackupListPlan { summaries: [], admission: 0 }
    Ok(plan) -> plan
  end
end

struct D4BackupRemovePlan do
  index :: Plaintext<Bytes>
  admission :: Plaintext<Int>
end

fn backup_prepare_remove_raw(id :: Bytes,
  raw :: Result<Plaintext<Bytes>, String>,
  index_absent :: Bool,
  row_absent :: Bool) -> D4BackupRemovePlan!String do
  let original :: Plaintext<Bytes> = raw?
  let entries = backup_decode_index(original, index_absent)?
  let present = case backup_find_index(entries, id, 0) do
    None -> false
    Some(_) -> true
  end
  if present == row_absent do
    return Err("backup_archive_refused")
  end
  if row_absent do
    return Ok(D4BackupRemovePlan { index: original, admission: 1 })
  end
  let remaining = List.filter(entries, fn(entry) -> !Bytes.secure_equals(entry.backup_id, id) end)
  Ok(D4BackupRemovePlan { index: backup_encode_index(remaining)?, admission: 1 })
end

fn backup_totalized_remove(raw :: Result<D4BackupRemovePlan, String>) -> D4BackupRemovePlan do
  case raw do
    Err(_) -> D4BackupRemovePlan { index: Bytes.empty(), admission: 0 }
    Ok(plan) -> plan
  end
end

fn backup_prepare_remove(path :: String,
  authority :: D4BackupAuthority,
  id :: Bytes,
  key :: borrow StorageKey) -> D4BackupPreparedRemove!String do
  let row = backup_archive_label(authority.profile.account_id, id)?
  let index = backup_archive_index_label(authority.profile.account_id)?
  let before = backup_capture_list_sources(path, authority, key)?
  let captured = capture_backup_snapshot_with_key(path, before, [row], key)?
  let row_absent = Bytes.length(backup_blob(captured, row)?) == 0
  let plan = backup_totalized_remove(backup_prepare_remove_raw(id,
    backup_index_source(captured, index, key),
    Bytes.length(backup_blob(captured, index)?) == 0,
    row_absent))
  if backup_observe_admission(plan.admission) != 1 do
    return Err("backup_archive_refused")
  end
  if row_absent do
    return Ok(D4BackupPreparedRemove { sources: captured, index: Bytes.empty(), remove: false })
  end
  # Corrupt selected payload bytes are intentionally never opened. Only the
  # authenticated canonical index authorizes this exact internally derived ID.
  let sealed = seal_local(plan.index, key, local_context(index)?)?
  let verified = backup_target_admission(plan.index,
    backup_protect_opened(open_local(sealed, key, local_context(index)?)))
  if backup_observe_admission(verified) != 1 do
    return Err("backup_archive_refused")
  end
  Ok(D4BackupPreparedRemove { sources: captured, index: sealed, remove: true })
end

pub fn list_backup_archives(path :: String,
  expected_profile :: Bytes) -> Result<Plaintext<List<D4BackupArchiveSummary>>, String> do
  if !backup_valid_identity(path, expected_profile) do
    return Err("invalid_backup_request")
  end
  let key = platform_key()?
  let result = backup_list_with_key(path, expected_profile, key)
  Secret.destroy(key)
  result
end

fn backup_list_with_key(path :: String,
  expected_profile :: Bytes,
  key :: borrow StorageKey) -> Result<Plaintext<List<D4BackupArchiveSummary>>, String> do
  let authority = capture_backup_authority_with_key(path, expected_profile, key)?
  let captured = backup_capture_list_sources(path, authority, key)?
  let plan = backup_prepare_list(captured, authority.profile.account_id, key)
  if backup_observe_admission(plan.admission) != 1 do
    return Err("backup_archive_refused")
  end
  backup_finalize(path, key, BackupFinalFence(%{authority | sources: captured}))?
  Ok(plan.summaries)
end

pub fn remove_backup_archive(path :: String,
  expected_profile :: Bytes,
  backup_id :: Bytes) -> Result<(), String> do
  if !backup_valid_identity(path, expected_profile) || Bytes.length(backup_id) != 32 do
    return Err("invalid_backup_request")
  end
  let key = platform_key()?
  let result = backup_remove_with_key(path, expected_profile, backup_id, key)
  Secret.destroy(key)
  result
end

fn backup_remove_with_key(path :: String,
  expected_profile :: Bytes,
  id :: Bytes,
  key :: borrow StorageKey) -> Result<(), String> do
  let authority = capture_backup_authority_with_key(path, expected_profile, key)?
  let ready = backup_prepare_remove(path, authority, id, key)?
  backup_finalize(path, key, BackupFinalRemove(authority, ready, id))
end

# Preview authenticates the supplied file but makes no local archive/index
# admission decision. Import independently rechecks its exact input and ID.
fn backup_prepare_preview_raw(authority :: D4BackupAuthority,
  raw :: Result<Plaintext<Bytes>, PortableBackupV2Error>) -> D4BackupReadPlan!String do
  let payload :: Plaintext<Bytes> = case raw do
    Err(_) -> return Err("backup_archive_refused")
    Ok(value) -> value
  end
  let archive = case backup_payload_identity(payload) do
    Err(_) -> return Err("backup_archive_refused")
    Ok(value) -> value
  end
  if !backup_owner_custody_matches(authority, archive) do
    return Err("backup_archive_refused")
  end
  Ok(D4BackupReadPlan { payload: payload, admission: 1 })
end

fn backup_prepare_preview(authority :: D4BackupAuthority,
  wire :: Bytes,
  recovery_code :: String) -> D4BackupReadPlan do
  backup_totalized_read(backup_prepare_preview_raw(authority,
    restore_portable_archive(recovery_code, wire)))
end

pub fn preview_backup_archive(path :: String,
  expected_profile :: Bytes,
  wire :: Bytes,
  recovery_code :: String) -> Result<Plaintext<Bytes>, String> do
  if !backup_valid_identity(path, expected_profile)
    || Bytes.length(wire) < 1
    || Bytes.length(wire) > 16796864
    || String.length(recovery_code) < 1
    || String.length(recovery_code) > 1024 do
    return Err("invalid_backup_request")
  end
  let key = platform_key()?
  let result = backup_preview_with_key(path, expected_profile, wire, recovery_code, key)
  Secret.destroy(key)
  result
end

fn backup_preview_with_key(path :: String,
  expected_profile :: Bytes,
  wire :: Bytes,
  recovery_code :: String,
  key :: borrow StorageKey) -> Result<Plaintext<Bytes>, String> do
  let authority = capture_backup_authority_with_key(path, expected_profile, key)?
  let plan = backup_prepare_preview(authority, wire, recovery_code)
  if backup_observe_admission(plan.admission) != 1 do
    return Err("backup_archive_refused")
  end
  backup_finalize(path, key, BackupFinalFence(authority))?
  Ok(plan.payload)
end

type D4BackupFinalization do
  BackupFinalFence(authority :: D4BackupAuthority)
  BackupFinalPending(authority :: D4BackupAuthority, before :: PendingCipherBasis, mutation :: D4PendingMutation)
  BackupFinalImport(authority :: D4BackupAuthority, ready :: D4BackupPreparedImport, id :: Bytes)
  BackupFinalRemove(authority :: D4BackupAuthority, ready :: D4BackupPreparedRemove, id :: Bytes)
end

# The sole publication body receives its writer and the SAME borrowed key that
# opened custody and prepared the containers. No resource-bearing closure exists.
fn backup_finalize_on(database :: SqliteConn,
  key :: borrow StorageKey,
  action :: D4BackupFinalization) -> Result<(), String> do
  case action do
    BackupFinalPending(authority, before, mutation) -> do
      require_backup_authority_current_with_key(database, authority, key)?
      require_pending_cipher_basis_with_key(database, key, before)?
      case mutation do
        PendingFence -> Ok(nil)
        PendingPublish(wire, descriptor) -> publish_pending_cipher_pair_with_key(database,
          key,
          before,
          wire,
          descriptor)
        PendingDelete -> delete_pending_cipher_pair_with_key(database, key, before)
      end
    end
    BackupFinalFence(authority) -> require_backup_authority_current_with_key(database,
      authority,
      key)
    BackupFinalRemove(authority, ready, id) -> do
      require_backup_authority_current_with_key(database,
        %{authority | sources: ready.sources},
        key)?
      require_backup_archive_snapshot_with_key(database,
        ready.sources,
        authority.profile.account_id,
        id,
        key)?
      if ready.remove do
        let row = backup_archive_label(authority.profile.account_id, id)?
        let index = backup_archive_index_label(authority.profile.account_id)?
        let hash = blob_record_hash_with_key(database, key, row)?
        let changed = Sqlite.execute(database,
          "DELETE FROM encrypted_blobs WHERE record_hash = ?",
          [hash])?
        if changed != 1 do
          return Err("database_write_failed")
        end
        put_blob_bounded_with_key(database, key, index, ready.index, 648)?
      end
      Ok(nil)
    end
    BackupFinalImport(authority, ready, id) -> do
      require_backup_authority_current_with_key(database,
        %{authority | sources: ready.sources},
        key)?
      require_backup_archive_snapshot_with_key(database,
        ready.sources,
        authority.profile.account_id,
        id,
        key)?
      if ready.disposition == 1 do
        let row = backup_archive_label(authority.profile.account_id, id)?
        let index = backup_archive_index_label(authority.profile.account_id)?
        put_blob_bounded_with_key(database, key, row, ready.archive, 33554432)?
        put_blob_bounded_with_key(database, key, index, ready.index, 33554432)?
      end
      Ok(nil)
    end
  end
end

# Same transaction lifecycle as Records.with_record_transaction, factored into
# direct calls because the language intentionally rejects affine closure capture.
fn backup_finalize(path :: String,
  key :: borrow StorageKey,
  action :: D4BackupFinalization) -> Result<(), String> do
  let database = case Sqlite.open(path) do
    Err(_) -> return Err("database_open_failed")
    Ok(value) -> value
  end
  let started = case Sqlite.execute(database, "PRAGMA busy_timeout = 1000", []) do
    Err(error)
    Ok(_) -> Sqlite.execute(database, "BEGIN IMMEDIATE", [])
  end
  let result = case started do
    Err(_) -> Err("database_write_failed")
    Ok(_) -> case backup_finalize_on(database, key, action) do
      Err(error)
      Ok(_) -> case Sqlite.commit(database) do
        Err(_) -> Err("database_write_failed")
        Ok(_) -> Ok(nil)
      end
    end
  end
  case result do
    Err(_) -> do
      Sqlite.rollback(database)
      nil
    end
    Ok(_) -> nil
  end
  Sqlite.close(database)
  result
end

pub struct D4BackupPendingCreated do
  draft_id :: Bytes
  wire :: Bytes
  recovery_code :: String
end

pub struct D4BackupPendingState do
  kind :: Int
  draft_id :: Bytes
  created_at :: U64
  wire_size :: Int
end

type D4PendingMutation do
  PendingFence
  PendingPublish(wire :: Bytes, descriptor :: Bytes)
  PendingDelete
end

struct D4PendingDescriptor do
  account :: Bytes
  authorization :: Bytes
  realm :: Bytes
  device :: Bytes
  draft_id :: Bytes
  backup_id :: Bytes
  wire_digest :: Bytes
  wire_size :: Int
  created_at :: U64
end

struct D4PendingPlan do
  state :: Plaintext<D4BackupPendingState>
  descriptor :: Plaintext<Option<D4PendingDescriptor>>
end

fn pending_join(values :: List<Bytes>) -> Bytes!String do
  mobile_join(values, 0, Bytes.empty())
end

fn backup_pending_labels(authority :: D4BackupAuthority) -> List<String>!String do
  let digest = Crypto.sha256(pending_join([
    Bytes.from_utf8("morse-backup-pending-owner/v1\n"),
    authority.profile.account_id,
    authority.profile.device_id
  ])?)
  let prefix = "backup-pending/v1/#{Bytes.to_hex(digest)}"
  Ok(["#{prefix}/wire", "#{prefix}/descriptor"])
end

fn backup_pending_context(authority :: D4BackupAuthority) -> Bytes!String do
  let digest = Crypto.sha256(pending_join([
    Bytes.from_utf8("morse-backup-pending-context/v1\n"),
    authority.profile.account_id,
    authority.profile.account.authorization_public_key,
    authority.service_realm,
    authority.profile.device_id
  ])?)
  context(authority.profile.account_id,
    authority.profile.device_id,
    "backup-pending-context/v1/#{Bytes.to_hex(digest)}",
    14)
end

fn backup_pending_capture(path :: String,
  authority :: D4BackupAuthority,
  key :: borrow StorageKey) -> PendingCipherBasis!String do
  let labels = backup_pending_labels(authority)?
  let used = List.reduce(authority.sources.bases,
    Bytes.length(List.head(authority.sources.bases).profile),
    fn(total, basis) -> total
      + List.reduce(basis.records, 0, fn(size, value) -> size + Bytes.length(value) end) end)
  let count = List.reduce(authority.sources.bases,
    0,
    fn(total, basis) -> total + List.length(basis.labels) end)
  if count + 2 > 192 || used > 33554432 do
    return Err("backup_source_limit")
  end
  let before = capture_pending_cipher_basis_with_key(path,
    key,
    List.get(labels, 0),
    List.get(labels, 1),
    33554432 - used)?
  if !Bytes.secure_equals(before.profile, List.head(authority.sources.bases).profile) do
    return Err("account_state_changed")
  end
  Ok(before)
end

fn backup_pending_descriptor_wire(value :: D4PendingDescriptor) -> Bytes!String do
  pending_join([
    Bytes.from_utf8("BPDM"),
    mobile_byte(1)?,
    value.account,
    value.authorization,
    value.realm,
    value.device,
    value.draft_id,
    value.backup_id,
    value.wire_digest,
    mobile_write_u32(value.wire_size)?,
    mobile_write_u64(value.created_at)?
  ])
end

fn backup_pending_decode_descriptor(input :: Plaintext<Bytes>) -> D4PendingDescriptor!String do
  if Bytes.length(input) != 225 do
    return Err("invalid_pending_descriptor")
  end
  let state = case reader(input, 225) do
    Err(_) -> return Err("invalid_pending_descriptor")
    Ok(value) -> value
  end
  let magic = take_fixed(state, 5)?
  let account = take_fixed(magic.state, 32)?
  let authorization = take_fixed(account.state, 32)?
  let realm = take_fixed(authorization.state, 32)?
  let device = take_fixed(realm.state, 16)?
  let draft = take_fixed(device.state, 32)?
  let backup = take_fixed(draft.state, 32)?
  let digest = take_fixed(backup.state, 32)?
  let size = take_fixed(digest.state, 4)?
  let time = take_fixed(size.state, 8)?
  if Bytes.to_hex(magic.value) != "4250444d01" do
    return Err("invalid_pending_descriptor")
  end
  case finish(time.state) do
    Err(_) -> return Err("invalid_pending_descriptor")
    Ok(_) -> nil
  end
  Ok(D4PendingDescriptor {
    account: account.value,
    authorization: authorization.value,
    realm: realm.value,
    device: device.value,
    draft_id: draft.value,
    backup_id: backup.value,
    wire_digest: digest.value,
    wire_size: mobile_read_u32(size.value)?,
    created_at: mobile_read_u64(time.value)?
  })
end

fn backup_pending_slice(input :: Bytes, offset :: Int, size :: Int) -> Bytes!String do
  case Bytes.slice(input, offset, size) do
    Err(_) -> Err("invalid_pending_wire")
    Ok(value)
  end
end

fn backup_pending_u16(input :: Bytes) -> Int!String do
  let first = mobile_read_byte(backup_pending_slice(input, 0, 1)?)?
  let second = mobile_read_byte(backup_pending_slice(input, 1, 1)?)?
  Ok(first * 256 + second)
end

fn backup_pending_u32(input :: Bytes, offset :: Int) -> Int!String do
  mobile_read_u32(backup_pending_slice(input, offset, 4)?)
end

# Public framing only. The user-held code and actual P0 authentication are still
# required by resume; no clear header is authority or a verified preview.
fn backup_pending_chunks(state :: BinaryReader,
  id :: Bytes,
  count :: Int,
  index :: Int,
  extent :: Int) -> Result<(), String> do
  if index >= count do
    case finish(state) do
      Err(_) -> Err("invalid_pending_wire")
      Ok(_) -> Ok(nil)
    end
  else
    let chunk = take_vector(state, 65608)?
    let size = Bytes.length(chunk.value)
    if size < 73
      || size > 65608
      || Bytes.to_hex(backup_pending_slice(chunk.value, 0, 4)?) != "02424348"
      || !Bytes.secure_equals(backup_pending_slice(chunk.value, 4, 32)?, id)
      || backup_pending_u32(chunk.value, 36)? != index
      || !Bytes.secure_equals(backup_pending_slice(chunk.value, 40, 12)?, mobile_zeroes(12)?) do
      return Err("invalid_pending_wire")
    end
    let encrypted = backup_pending_u32(chunk.value, 52)?
    if encrypted < 17
      || encrypted > 65552
      || size != 56 + encrypted
      || (index < count - 1 && encrypted != 65552)
      || extent + encrypted - 16 > 16777216 do
      return Err("invalid_pending_wire")
    end
    backup_pending_chunks(chunk.state, id, count, index + 1, extent + encrypted - 16)
  end
end

fn backup_pending_wire_id(wire :: Bytes) -> Bytes!String do
  let state = case reader(wire, 16796864) do
    Err(_) -> return Err("invalid_pending_wire")
    Ok(value) -> value
  end
  let magic = take_fixed(state, 4)?
  let manifest = take_vector(magic.state, 182)?
  let count = take_fixed(manifest.state, 2)?
  let length = backup_pending_u16(count.value)?
  if Bytes.to_hex(magic.value) != "024d4246"
    || Bytes.length(manifest.value) != 182
    || Bytes.to_hex(backup_pending_slice(manifest.value, 0, 5)?) != "0245424d01"
    || backup_pending_u32(manifest.value, 21)? != 65536
    || backup_pending_u32(manifest.value, 25)? != 3
    || Bytes.to_hex(backup_pending_slice(manifest.value, 29, 1)?) != "01"
    || !Bytes.secure_equals(backup_pending_slice(manifest.value, 62, 12)?, mobile_zeroes(12)?)
    || backup_pending_u32(manifest.value, 74)? != 104
    || length < 1
    || length > 256 do
    return Err("invalid_pending_wire")
  end
  let id = backup_pending_slice(manifest.value, 30, 32)?
  backup_pending_chunks(count.state, id, length, 0, 0)?
  Ok(id)
end

fn backup_pending_empty(kind :: Int, zero :: U64) -> D4PendingPlan do
  D4PendingPlan {
    state: D4BackupPendingState {
      kind: kind,
      draft_id: Bytes.empty(),
      created_at: zero,
      wire_size: 0
    },
    descriptor: None
  }
end

fn backup_pending_plan(authority :: D4BackupAuthority,
  before :: PendingCipherBasis,
  raw :: Result<Plaintext<Bytes>, String>,
  zero :: U64) -> D4PendingPlan do
  if !before.wire.present && !before.descriptor.present do
    return backup_pending_empty(0, zero)
  end
  if !before.wire.admitted || !before.descriptor.admitted do
    return backup_pending_empty(2, zero)
  end
  let descriptor = case raw do
    Err(_) -> return backup_pending_empty(2, zero)
    Ok(value) -> case backup_pending_decode_descriptor(value) do
      Err(_) -> return backup_pending_empty(2, zero)
      Ok(output) -> output
    end
  end
  let id = case backup_pending_wire_id(before.wire.value) do
    Err(_) -> return backup_pending_empty(2, zero)
    Ok(value) -> value
  end
  if !Bytes.secure_equals(descriptor.account, authority.profile.account_id)
    || !Bytes.secure_equals(descriptor.authorization,
      authority.profile.account.authorization_public_key)
    || !Bytes.secure_equals(descriptor.realm, authority.service_realm)
    || !Bytes.secure_equals(descriptor.device, authority.profile.device_id)
    || descriptor.wire_size != Bytes.length(before.wire.value)
    || !Bytes.secure_equals(descriptor.wire_digest, Crypto.sha256(before.wire.value))
    || !Bytes.secure_equals(descriptor.backup_id, id) do
    return backup_pending_empty(2, zero)
  end
  D4PendingPlan {
    state: D4BackupPendingState {
      kind: 1,
      draft_id: descriptor.draft_id,
      created_at: descriptor.created_at,
      wire_size: descriptor.wire_size
    },
    descriptor: Some(descriptor)
  }
end

fn backup_pending_prepare_plan(authority :: D4BackupAuthority,
  before :: PendingCipherBasis,
  key :: borrow StorageKey) -> D4PendingPlan!String do
  let zero = mobile_wide("0")?
  let raw = backup_protect_opened(open_local(before.descriptor.value,
    key,
    backup_pending_context(authority)?))
  Ok(backup_pending_plan(authority, before, raw, zero))
end

# Root-reviewed finite admission only. No raw Result, descriptor or payload
# crosses this private helper; three fixed operation predicates are its callers.
fn backup_pending_observe_admission(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "pending backup export discloses only finite authenticated current owner exact draft original file acceptance and explicit invalid slot repair or exact ID discard admission; user entered recovery codes restored plaintext descriptor digests owner metadata and raw errors remain private")
end

fn backup_pending_resume_valid(authority :: D4BackupAuthority,
  plan :: D4PendingPlan,
  draft :: Bytes,
  raw :: Result<Plaintext<Bytes>, PortableBackupV2Error>) -> Plaintext<Bool> do
  if plan.state.kind != 1 || !Bytes.secure_equals(plan.state.draft_id, draft) do
    return false
  end
  let descriptor = case plan.descriptor do
    None -> return false
    Some(value) -> value
  end
  let payload = case raw do
    Err(_) -> return false
    Ok(value) -> value
  end
  case backup_payload_identity(payload) do
    Err(_) -> false
    Ok(archive) -> backup_owner_matches(authority, archive, descriptor.backup_id)
      && U64.compare(archive.created_at, descriptor.created_at) == 0
  end
end

fn backup_pending_identity_valid(path :: String, profile :: Bytes, draft :: Bytes) -> Bool do
  backup_valid_identity(path, profile) && Bytes.length(draft) == 32
end

pub fn create_pending_backup_export(path :: String,
  expected_profile :: Bytes,
  selection :: List<D4BackupSelection>) -> D4BackupPendingCreated!String do
  let selected = backup_validate_selection(selection)?
  if !backup_valid_identity(path, expected_profile) do
    return Err("invalid_backup_request")
  end
  let key = platform_key()?
  let result = backup_pending_create_with_key(path, expected_profile, selected, key)
  Secret.destroy(key)
  result
end

fn backup_pending_create_with_key(path :: String,
  expected_profile :: Bytes,
  selection :: List<D4BackupSelection>,
  key :: borrow StorageKey) -> D4BackupPendingCreated!String do
  let authority = capture_backup_authority_with_key(path, expected_profile, key)?
  let before = backup_pending_capture(path, authority, key)?
  if before.wire.present || before.descriptor.present do
    return Err("pending_export_exists")
  end
  # Include both original absences in history discovery's192-label/32MiB budget.
  let sources = capture_backup_snapshot_with_key(path,
    FanoutSnapshot {
      bases: List.append(authority.sources.bases,
        AccountBasis {
          profile: before.profile,
          labels: [before.wire_label, before.descriptor_label],
          records: [Bytes.empty(), Bytes.empty()]
        })
    },
    [],
    key)?
  let prepared = backup_prepare_create(path, %{authority | sources: sources}, selection, key)?
  let draft = case Crypto.random_bytes(32) do
    Err(_) -> return Err("pending_export_refused")
    Ok(value) -> value
  end
  let descriptor = D4PendingDescriptor {
    account: authority.profile.account_id,
    authorization: authority.profile.account.authorization_public_key,
    realm: authority.service_realm,
    device: authority.profile.device_id,
    draft_id: draft,
    backup_id: backup_pending_wire_id(prepared.created.wire)?,
    wire_digest: Crypto.sha256(prepared.created.wire),
    wire_size: Bytes.length(prepared.created.wire),
    created_at: authority.captured_at
  }
  let sealed = seal_local(backup_pending_descriptor_wire(descriptor)?,
    key,
    backup_pending_context(authority)?)?
  backup_finalize(path,
    key,
    BackupFinalPending(%{authority | sources: prepared.sources},
      before,
      PendingPublish(prepared.created.wire, sealed)))?
  Ok(D4BackupPendingCreated {
    draft_id: draft,
    wire: prepared.created.wire,
    recovery_code: prepared.created.recovery_code
  })
end

pub fn pending_backup_export_state(path :: String,
  expected_profile :: Bytes) -> Result<Plaintext<D4BackupPendingState>, String> do
  if !backup_valid_identity(path, expected_profile) do
    return Err("invalid_backup_request")
  end
  let key = platform_key()?
  let result = backup_pending_state_with_key(path, expected_profile, key)
  Secret.destroy(key)
  result
end

fn backup_pending_state_with_key(path :: String,
  expected_profile :: Bytes,
  key :: borrow StorageKey) -> Result<Plaintext<D4BackupPendingState>, String> do
  let authority = capture_backup_authority_with_key(path, expected_profile, key)?
  let before = backup_pending_capture(path, authority, key)?
  let plan = backup_pending_prepare_plan(authority, before, key)?
  backup_finalize(path, key, BackupFinalPending(authority, before, PendingFence))?
  Ok(plan.state)
end

pub fn resume_pending_backup_export(path :: String,
  expected_profile :: Bytes,
  draft_id :: Bytes,
  recovery_code :: String) -> Bytes!String do
  if !backup_pending_identity_valid(path, expected_profile, draft_id)
    || String.length(recovery_code) < 1
    || String.length(recovery_code) > 1024
    || Bytes.length(Bytes.from_utf8(recovery_code)) > 4096 do
    return Err("invalid_backup_request")
  end
  let key = platform_key()?
  let result = backup_pending_resume_with_key(path, expected_profile, draft_id, recovery_code, key)
  Secret.destroy(key)
  result
end

fn backup_pending_resume_with_key(path :: String,
  expected_profile :: Bytes,
  draft_id :: Bytes,
  recovery_code :: String,
  key :: borrow StorageKey) -> Bytes!String do
  let authority = capture_backup_authority_with_key(path, expected_profile, key)?
  let before = backup_pending_capture(path, authority, key)?
  let plan = backup_pending_prepare_plan(authority, before, key)?
  let restored = restore_portable_archive(recovery_code, before.wire.value)
  let accepted = backup_pending_resume_valid(authority, plan, draft_id, restored)
  if !backup_pending_observe_admission(accepted) do
    return Err("pending_export_refused")
  end
  backup_finalize(path, key, BackupFinalPending(authority, before, PendingFence))?
  Ok(before.wire.value)
end

pub fn discard_pending_backup_export(path :: String,
  expected_profile :: Bytes,
  draft_id :: Bytes) -> Int!String do
  if !backup_pending_identity_valid(path, expected_profile, draft_id) do
    return Err("invalid_backup_request")
  end
  let key = platform_key()?
  let result = backup_pending_discard_with_key(path, expected_profile, draft_id, key)
  Secret.destroy(key)
  result
end

fn backup_pending_discard_with_key(path :: String,
  expected_profile :: Bytes,
  draft_id :: Bytes,
  key :: borrow StorageKey) -> Int!String do
  let authority = capture_backup_authority_with_key(path, expected_profile, key)?
  let before = backup_pending_capture(path, authority, key)?
  let plan = backup_pending_prepare_plan(authority, before, key)?
  let accepted = plan.state.kind == 0
    || (plan.state.kind == 1 && Bytes.secure_equals(plan.state.draft_id, draft_id))
  if !backup_pending_observe_admission(accepted) do
    return Err("pending_export_refused")
  end
  backup_finalize(path, key, BackupFinalPending(authority, before, PendingDelete))?
  Ok(if before.wire.present || before.descriptor.present do
    1
  else
    2
  end)
end

pub fn repair_pending_backup_export(path :: String, expected_profile :: Bytes) -> Int!String do
  if !backup_valid_identity(path, expected_profile) do
    return Err("invalid_backup_request")
  end
  let key = platform_key()?
  let result = backup_pending_repair_with_key(path, expected_profile, key)
  Secret.destroy(key)
  result
end

fn backup_pending_repair_with_key(path :: String,
  expected_profile :: Bytes,
  key :: borrow StorageKey) -> Int!String do
  let authority = capture_backup_authority_with_key(path, expected_profile, key)?
  let before = backup_pending_capture(path, authority, key)?
  let plan = backup_pending_prepare_plan(authority, before, key)?
  if !backup_pending_observe_admission(plan.state.kind != 1) do
    return Err("pending_export_refused")
  end
  backup_finalize(path, key, BackupFinalPending(authority, before, PendingDelete))?
  Ok(if before.wire.present || before.descriptor.present do
    1
  else
    2
  end)
end

# Private preflight only: no action release, I/O or caller plan authority.
type D4BackupAttachmentAdmission do
  D4BackupAttachmentReadable
  D4BackupAttachmentOmitted(reason :: BackupAttachmentOmission)
end

struct D4BackupAttachmentSlotPlan do
  source_position :: Int
  scope_position :: Int
  record_ordinal :: Int
  slot_ordinal :: Int
  reference :: Option<Plaintext<Bytes>>
  manifest :: Option<Plaintext<AttachmentManifest>>
  admission :: D4BackupAttachmentAdmission
end

struct D4BackupAttachmentReadyPlan do
  policy :: BackupAttachmentPolicy
  sources :: List<D4BackupRawSource>
  content :: Plaintext<PortableBackupV2Content>
  slots :: List<D4BackupAttachmentSlotPlan>
  encoded_extent :: Int
  request_count :: Int
end

type D4BackupAttachmentPreflight do
  D4BackupAttachmentPreflightInvalid
  D4BackupAttachmentPreflightReady(plan :: D4BackupAttachmentReadyPlan)
end

# Real callers obtain observed_now themselves. This private pure preparation
# cannot load custody, perform effects, observe an action or publish data.
fn backup_prepare_attachment_state(reader :: borrow D4BackupAttachmentReader,
  selection :: List<D4BackupSelection>,
  sources :: List<D4BackupRawSource>,
  policy :: BackupAttachmentPolicy,
  observed_now :: U64) -> Plaintext<D4BackupAttachmentPreflight> do
  case backup_prepare_attachment_plan(reader, selection, sources, policy, observed_now) do
    Err(_) -> D4BackupAttachmentPreflightInvalid
    Ok(plan) -> D4BackupAttachmentPreflightReady(plan)
  end
end

struct D4BackupAttachmentRecordSource do
  ordinal :: Int
  reference :: Plaintext<Bytes>
end

struct D4BackupAttachmentFold do
  reversed_slots :: List<D4BackupAttachmentSlotPlan>
  extent :: Int
  files :: Int
  requests :: Int
end

fn backup_attachment_same_time(a :: Option<U64>, b :: Option<U64>) -> Bool do
  case (a, b) do
    (None, None) -> true
    (Some(first), Some(second)) -> U64.compare(first, second) == 0
    _ -> false
  end
end

fn backup_attachment_same_selection(a :: D4BackupSelection, b :: D4BackupSelection) -> Bool do
  a.kind == b.kind
    && Bytes.secure_equals(a.scope_id, b.scope_id)
    && backup_attachment_same_time(a.from_time, b.from_time)
    && backup_attachment_same_time(a.through_time, b.through_time)
end

# Lengths are admitted with subtraction before addition. This includes the
# header-only MCA overhead and all already retained text, even for Allow.
fn backup_attachment_extent_add(before :: Int, extra :: Int) -> Int!String do
  if before < 0 || before > 16777216 || extra < 0 || extra > 16777216 - before do
    Err("backup_attachment_preflight_refused")
  else
    Ok(before + extra)
  end
end

fn backup_attachment_record_sources(raw :: D4BackupRawSource) -> List<D4BackupAttachmentRecordSource>!String do
  let wire :: Plaintext<Bytes> = raw.wire?
  if raw.source.selection.kind == 1 do
    let rows = decode_history(wire)?
    Ok(List.flatten(for ordinal in 0..List.length(rows) do
      let row = List.get(rows, ordinal)
      if !Bytes.secure_equals(row.inner.conversation_id, raw.source.selection.scope_id) do
        return Err("backup_attachment_preflight_refused")
      end
      let choice = backup_direct_row(raw.source, row, ordinal)
      case choice.record do
        None -> []
        Some(record) -> [
          D4BackupAttachmentRecordSource {
            ordinal: record.ordinal,
            reference: if row.attachment_kind == HistoryViewOnce do
              Bytes.empty()
            else
              row.inner.attachment_manifest
            end
          }
        ]
      end
    end))
  else
    let rows = decode_group_history(wire)?
    Ok(List.flatten(for ordinal in 0..List.length(rows) do
      let row = List.get(rows, ordinal)
      let choice = backup_group_row(raw.source, row, ordinal)
      case choice.record do
        None -> []
        Some(record) -> [
          D4BackupAttachmentRecordSource { ordinal: record.ordinal, reference: row.attachment }
        ]
      end
    end))
  end
end

fn backup_attachment_omitted(policy :: BackupAttachmentPolicy,
  source_position :: Int,
  scope_position :: Int,
  record_ordinal :: Int,
  slot_ordinal :: Int,
  reference :: Option<Plaintext<Bytes>>,
  manifest :: Option<Plaintext<AttachmentManifest>>,
  reason :: BackupAttachmentOmission) -> D4BackupAttachmentSlotPlan!String do
  case policy do
    RequireArchiveAttachments -> Err("backup_attachment_preflight_refused")
    AllowArchiveAttachmentOmissions -> Ok(D4BackupAttachmentSlotPlan {
      source_position: source_position,
      scope_position: scope_position,
      record_ordinal: record_ordinal,
      slot_ordinal: slot_ordinal,
      reference: reference,
      manifest: manifest,
      admission: D4BackupAttachmentOmitted(reason)
    })
  end
end

fn backup_attachment_utf8_metadata(manifest :: AttachmentManifest) -> Bool do
  Result.is_ok(Bytes.to_utf8(manifest.filename)) && Result.is_ok(Bytes.to_utf8(manifest.mime_type))
end

# A source's canonical identities and a single empty-text record are charged
# even for the individual-alone test. Authenticated manifest bounds limit this
# intermediate to less than 537 MB, well inside Int; final admission uses the
# subtraction-checked 16 MiB accumulator below. No advertised bytes are allocated.
fn backup_attachment_above_profile(scope :: BackupArchiveScope,
  record :: BackupArchiveRecord,
  manifest :: AttachmentManifest) -> Bool do
  let alone = 195
    + 19
    + Bytes.length(scope.id)
    + Bytes.length(scope.peer)
    + Bytes.length(Bytes.from_utf8(scope.name))
    + 72
    + Bytes.length(record.message_id)
    + 50
    + Bytes.length(manifest.filename)
    + Bytes.length(manifest.mime_type)
    + manifest.plaintext_size
  manifest.plaintext_size > 16777216 || alone > 16777216
end

fn backup_attachment_prepare_slot(reader :: borrow D4BackupAttachmentReader,
  policy :: BackupAttachmentPolicy,
  source_position :: Int,
  scope_position :: Int,
  scope :: BackupArchiveScope,
  record :: BackupArchiveRecord,
  slot_ordinal :: Int,
  slot :: BackupAttachmentReferenceSlot,
  observed_now :: U64) -> D4BackupAttachmentSlotPlan!String do
  case slot do
    BackupAttachmentNoRecipient -> backup_attachment_omitted(policy,
      source_position,
      scope_position,
      record.ordinal,
      slot_ordinal,
      None,
      None,
      ArchiveAttachmentUnsupported)
    BackupAttachmentReference(reference) -> do
      # HPKE/EAM and the modern outer-ID association must succeed before any
      # expiry, nonUTF8 or individual-profile omission is considered.
      let manifest = backup_attachment_manifest(reader, reference)?
      if U64.compare(observed_now, manifest.expires_at) >= 0 do
        backup_attachment_omitted(policy,
          source_position,
          scope_position,
          record.ordinal,
          slot_ordinal,
          Some(reference),
          Some(manifest),
          ArchiveAttachmentExpired)
      else if !backup_attachment_utf8_metadata(manifest) do
        backup_attachment_omitted(policy,
          source_position,
          scope_position,
          record.ordinal,
          slot_ordinal,
          Some(reference),
          Some(manifest),
          ArchiveAttachmentUnsupported)
      else if backup_attachment_above_profile(scope, record, manifest) do
        backup_attachment_omitted(policy,
          source_position,
          scope_position,
          record.ordinal,
          slot_ordinal,
          Some(reference),
          Some(manifest),
          ArchiveAttachmentAboveProfile)
      else if (manifest.version != 1 && manifest.version != 4)
        || manifest.chunk_count < 1
        || manifest.chunk_count > 256 do
        Err("backup_attachment_preflight_refused")
      else
        Ok(D4BackupAttachmentSlotPlan {
          source_position: source_position,
          scope_position: scope_position,
          record_ordinal: record.ordinal,
          slot_ordinal: slot_ordinal,
          reference: Some(reference),
          manifest: Some(manifest),
          admission: D4BackupAttachmentReadable
        })
      end
    end
  end
end

fn backup_attachment_fold_parts(reader :: borrow D4BackupAttachmentReader,
  policy :: BackupAttachmentPolicy,
  source_position :: Int,
  scope_position :: Int,
  scope :: BackupArchiveScope,
  record :: BackupArchiveRecord,
  parts :: List<BackupAttachmentReferenceSlot>,
  index :: Int,
  observed_now :: U64,
  before :: D4BackupAttachmentFold) -> D4BackupAttachmentFold!String do
  if index >= List.length(parts) do
    return Ok(before)
  end
  if before.files >= 4096 do
    return Err("backup_attachment_preflight_refused")
  end
  let slot = backup_attachment_prepare_slot(reader,
    policy,
    source_position,
    scope_position,
    scope,
    record,
    index,
    List.get(parts, index),
    observed_now)?
  let (cost, requests) = case slot.admission do
    D4BackupAttachmentOmitted(_) -> (6, 0)
    D4BackupAttachmentReadable -> case slot.manifest do
      None -> return Err("backup_attachment_preflight_refused")
      Some(manifest) -> (50
          + Bytes.length(manifest.filename)
          + Bytes.length(manifest.mime_type)
          + manifest.plaintext_size,
        manifest.chunk_count)
    end
  end
  let extent = backup_attachment_extent_add(before.extent, cost)?
  if requests < 0 || requests > 256 || before.requests > 1048576 - requests do
    return Err("backup_attachment_preflight_refused")
  end
  backup_attachment_fold_parts(reader,
    policy,
    source_position,
    scope_position,
    scope,
    record,
    parts,
    index + 1,
    observed_now,
    D4BackupAttachmentFold {
      reversed_slots: [slot] ++ before.reversed_slots,
      extent: extent,
      files: before.files + 1,
      requests: before.requests + requests
    })
end

fn backup_attachment_fold_records(reader :: borrow D4BackupAttachmentReader,
  policy :: BackupAttachmentPolicy,
  source_position :: Int,
  scope_position :: Int,
  scope :: BackupArchiveScope,
  records :: List<D4BackupAttachmentRecordSource>,
  index :: Int,
  observed_now :: U64,
  before :: D4BackupAttachmentFold) -> D4BackupAttachmentFold!String do
  if List.length(records) != List.length(scope.entries) do
    return Err("backup_attachment_preflight_refused")
  end
  if index >= List.length(records) do
    return Ok(before)
  end
  let source = List.get(records, index)
  let record = List.get(scope.entries, index)
  if source.ordinal != record.ordinal
    || record.attachment_omitted != (Bytes.length(source.reference) > 0) do
    return Err("backup_attachment_preflight_refused")
  end
  let parts = backup_attachment_reference_slots(source.reference,
    scope.kind,
    reader.authority.profile.account_id,
    reader.authority.profile.device_id)?
  let next = backup_attachment_fold_parts(reader,
    policy,
    source_position,
    scope_position,
    scope,
    record,
    parts,
    0,
    observed_now,
    before)?
  backup_attachment_fold_records(reader,
    policy,
    source_position,
    scope_position,
    scope,
    records,
    index + 1,
    observed_now,
    next)
end

fn backup_attachment_fold_sources(reader :: borrow D4BackupAttachmentReader,
  selection :: List<D4BackupSelection>,
  sources :: List<D4BackupRawSource>,
  scopes :: List<BackupArchiveScope>,
  policy :: BackupAttachmentPolicy,
  source_position :: Int,
  scope_position :: Int,
  observed_now :: U64,
  before :: D4BackupAttachmentFold) -> D4BackupAttachmentFold!String do
  if source_position >= List.length(sources) do
    if scope_position != List.length(scopes) do
      return Err("backup_attachment_preflight_refused")
    end
    return Ok(before)
  end
  let raw = List.get(sources, source_position)
  if !backup_attachment_same_selection(raw.source.selection,
    List.get(selection, source_position)) do
    return Err("backup_attachment_preflight_refused")
  end
  let records = backup_attachment_record_sources(raw)?
  if List.length(records) == 0 do
    return backup_attachment_fold_sources(reader,
      selection,
      sources,
      scopes,
      policy,
      source_position + 1,
      scope_position,
      observed_now,
      before)
  end
  if scope_position >= List.length(scopes) do
    return Err("backup_attachment_preflight_refused")
  end
  let scope = List.get(scopes, scope_position)
  if scope.kind != raw.source.selection.kind
    || !Bytes.secure_equals(scope.id, raw.source.selection.scope_id)
    || !Bytes.secure_equals(scope.peer, raw.source.peer) do
    return Err("backup_attachment_preflight_refused")
  end
  let next = backup_attachment_fold_records(reader,
    policy,
    source_position,
    scope_position,
    scope,
    records,
    0,
    observed_now,
    before)?
  backup_attachment_fold_sources(reader,
    selection,
    sources,
    scopes,
    policy,
    source_position + 1,
    scope_position + 1,
    observed_now,
    next)
end

fn backup_prepare_attachment_plan(reader :: borrow D4BackupAttachmentReader,
  selection :: List<D4BackupSelection>,
  sources :: List<D4BackupRawSource>,
  policy :: BackupAttachmentPolicy,
  observed_now :: U64) -> D4BackupAttachmentReadyPlan!String do
  if U64.compare(observed_now, reader.authority.captured_at) < 0
    || U64.compare(observed_now, reader.authority.fresh_through) > 0 do
    return Err("backup_attachment_preflight_refused")
  end
  let selected = backup_validate_selection(selection)?
  if List.length(selected) != List.length(sources) do
    return Err("backup_attachment_preflight_refused")
  end
  let prepared = prepare_backup_text_raw(reader.authority, selected, sources)?
  let initial = backup_attachment_extent_add(prepared.encoded_extent, 25)?
  let folded = backup_attachment_fold_sources(reader,
    selected,
    sources,
    prepared.content.scopes,
    policy,
    0,
    0,
    observed_now,
    D4BackupAttachmentFold { reversed_slots: [], extent: initial, files: 0, requests: 0 })?
  Ok(D4BackupAttachmentReadyPlan {
    policy: policy,
    sources: sources,
    content: prepared.content,
    slots: List.reverse(folded.reversed_slots),
    encoded_extent: folded.extent,
    request_count: folded.requests
  })
end

# D4_ATTACHMENT_CAPTURE_ORCHESTRATION_V1: private whole-operation state only.
# The actual retained reader survives completion for the next publication unit;
# its caller continues to own the original platform wrapping key.
resource struct D4BackupCapturedContent do
  reader :: D4BackupAttachmentReader
  content :: Plaintext<PortableBackupContentArchive>
  min_expiry :: Plaintext<Option<U64>>
  encoded_extent :: Plaintext<Int>
  observed_at :: Plaintext<U64>
end

type D4BackupRetrievalAction do
  D4BackupRetrievalRefuse
  D4BackupRetrievalFetch(object_id :: Bytes, capability :: Bytes, part :: Int)
  D4BackupRetrievalDone
  D4BackupRetrievalPublishReady
end

struct D4BackupCaptureCursor do
  plan :: D4BackupAttachmentReadyPlan
  slot :: Int
  part :: Int
  reversed_chunks :: List<Plaintext<Bytes>>
  partial_size :: Int
  reversed_files :: List<BackupArchiveAttachment>
  min_expiry :: Option<U64>
  observed_at :: U64
end

struct D4BackupCaptureComplete do
  content :: Plaintext<PortableBackupContentArchive>
  min_expiry :: Plaintext<Option<U64>>
  encoded_extent :: Plaintext<Int>
  observed_at :: Plaintext<U64>
end

type D4BackupCaptureState do
  D4BackupCaptureInvalid
  D4BackupCaptureReading(cursor :: D4BackupCaptureCursor)
  D4BackupCaptureReady(value :: D4BackupCaptureComplete)
end

# This is the only reviewed observation of private retrieval state. It does not
# clear caller control, release a reference or make a caller-supplied plan valid.
fn backup_observe_retrieval_action(action :: Plaintext<D4BackupRetrievalAction>) -> D4BackupRetrievalAction do
  let closed :: Plaintext<D4BackupRetrievalAction> = case action do
    D4BackupRetrievalFetch(id, capability, part) ->
      if Bytes.length(id) == 32 && Bytes.length(capability) == 32 && part >= 1 && part <= 256 do
        D4BackupRetrievalFetch(id, capability, part)
      else
        D4BackupRetrievalRefuse
      end
    D4BackupRetrievalRefuse -> D4BackupRetrievalRefuse
    D4BackupRetrievalDone
    D4BackupRetrievalPublishReady
  end
  declassify(closed,
    "Explicit user-requested attachment backup exposes only closed refusal, retrieval completion or publication eligibility, and each authenticated fixed-origin request's exact 32-byte object ID, exact 32-byte download capability and bounded part index; request count/order is inherent in this sequence. Source and slot identities, EAM/wrapped-key bytes, filename/MIME, file digests, exact plaintext lengths and expiry timestamps, content, raw errors and prior caller control are not released by this projection.")
end

fn backup_capture_minimum(before :: Option<U64>, next :: U64) -> Option<U64> do
  case before do
    None -> Some(next)
    Some(value) -> Some(if U64.compare(next, value) < 0 do
      next
    else
      value
    end)
  end
end

fn backup_capture_observed_time(authority :: D4BackupAuthority,
  previous :: U64,
  now :: U64) -> Unit!String do
  if U64.compare(now, previous) < 0 || U64.compare(now, authority.captured_at) < 0 do
    Err("backup_clock_rollback")
  else if U64.compare(now, authority.fresh_through) > 0 do
    Err("backup_authority_expired")
  else
    Ok(nil)
  end
end

fn backup_capture_live_included(minimum :: Option<U64>, now :: U64) -> Bool do
  case minimum do
    None -> true
    Some(expiry) -> U64.compare(now, expiry) < 0
  end
end

fn backup_capture_content(plan :: D4BackupAttachmentReadyPlan,
  files :: List<BackupArchiveAttachment>) -> PortableBackupContentArchive!String do
  if List.length(files) != List.length(plan.slots) do
    return Err("backup_archive_refused")
  end
  let scopes = for position in 0..List.length(plan.content.scopes) do
    let scope = List.get(plan.content.scopes, position)
    let entries = for row in scope.entries do
      let attachments = List.flatten(for index in 0..List.length(plan.slots) do
        let slot = List.get(plan.slots, index)
        if slot.scope_position == position && slot.record_ordinal == row.ordinal do
          [List.get(files, index)]
        else
          []
        end
      end)
      BackupContentRecord {
        ordinal: row.ordinal,
        direction: row.direction,
        message_id: row.message_id,
        sender_account: row.sender_account,
        sender_device: row.sender_device,
        timestamp: row.timestamp,
        text: row.text,
        attachments: attachments
      }
    end
    BackupContentScope {
      kind: scope.kind,
      id: scope.id,
      peer: scope.peer,
      name: scope.name,
      entries: entries
    }
  end
  Ok(PortableBackupContentArchive {
    policy: plan.policy,
    owner_account: plan.content.owner_account,
    owner_authorization_key: plan.content.owner_authorization_key,
    service_realm: plan.content.service_realm,
    candidate_count: plan.content.candidate_count,
    omitted_timed: plan.content.omitted_timed,
    omitted_unknown: plan.content.omitted_unknown,
    omitted_nontext: plan.content.omitted_nontext,
    omitted_empty: plan.content.omitted_empty,
    attachment_messages: plan.content.attachment_messages,
    scopes: scopes
  })
end

fn backup_capture_encoded_extent(authority :: D4BackupAuthority,
  content :: Plaintext<PortableBackupContentArchive>) -> Plaintext<Int>!String do
  let encoded = case encode_content_archive(BackupContentArchive {
    policy: content.policy,
    backup_id: mobile_zeroes(32)?,
    owner_account: content.owner_account,
    owner_authorization_key: content.owner_authorization_key,
    service_realm: content.service_realm,
    created_at: authority.captured_at,
    candidate_count: content.candidate_count,
    omitted_timed: content.omitted_timed,
    omitted_unknown: content.omitted_unknown,
    omitted_nontext: content.omitted_nontext,
    omitted_empty: content.omitted_empty,
    attachment_messages: content.attachment_messages,
    scopes: content.scopes
  }) do
    Err(_) -> return Err("backup_archive_refused")
    Ok(value) -> value
  end
  Ok(Bytes.length(encoded))
end

# Pure settling skips only already authenticated omissions and assembles a file
# once all its bounded chunks have opened. The original source/ordinal/slot
# sequence never leaves this private state.
fn backup_capture_settle(reader :: borrow D4BackupAttachmentReader,
  state :: D4BackupCaptureState) -> D4BackupCaptureState!String do
  case state do
    D4BackupCaptureReading(cursor) -> do
      if cursor.slot < 0 || cursor.slot > List.length(cursor.plan.slots) do
        return Err("backup_archive_refused")
      end
      if cursor.slot == List.length(cursor.plan.slots) do
        let content = backup_capture_content(cursor.plan, List.reverse(cursor.reversed_files))?
        let extent = backup_capture_encoded_extent(reader.authority, content)?
        if extent > cursor.plan.encoded_extent do
          return Err("backup_archive_refused")
        end
        return Ok(D4BackupCaptureReady(D4BackupCaptureComplete {
          content: content,
          min_expiry: cursor.min_expiry,
          encoded_extent: extent,
          observed_at: cursor.observed_at
        }))
      end
      let slot = List.get(cursor.plan.slots, cursor.slot)
      case slot.admission do
        D4BackupAttachmentOmitted(reason) ->
          backup_capture_settle(reader,
            D4BackupCaptureReading(%{cursor |
              slot: cursor.slot + 1,
              part: 0,
              reversed_chunks: [],
              partial_size: 0,
              reversed_files: [ArchiveAttachmentOmitted(reason)] ++ cursor.reversed_files
            }))
        D4BackupAttachmentReadable -> do
          let manifest = case slot.manifest do
            None -> return Err("backup_archive_refused")
            Some(value) -> value
          end
          if cursor.part < 0 || cursor.part > manifest.chunk_count do
            return Err("backup_archive_refused")
          end
          if cursor.part < manifest.chunk_count do
            return Ok(state)
          end
          if cursor.partial_size != manifest.plaintext_size do
            return Err("backup_archive_refused")
          end
          let bytes = case Bytes.concat_many(List.reverse(cursor.reversed_chunks),
            manifest.plaintext_size) do
            Err(_) -> return Err("backup_archive_refused")
            Ok(value) -> value
          end
          backup_capture_settle(reader,
            D4BackupCaptureReading(%{cursor |
              slot: cursor.slot + 1,
              part: 0,
              reversed_chunks: [],
              partial_size: 0,
              reversed_files: [
                ArchiveAttachmentIncluded(manifest.filename, manifest.mime_type, bytes)
              ]
                ++ cursor.reversed_files,
              min_expiry: backup_capture_minimum(cursor.min_expiry, manifest.expires_at)
            }))
        end
      end
    end
    _ -> Ok(state)
  end
end

fn backup_capture_totalized(raw :: D4BackupCaptureState!String) -> Plaintext<D4BackupCaptureState> do
  case raw do
    Err(_) -> D4BackupCaptureInvalid
    Ok(value) -> value
  end
end

fn backup_capture_initial(reader :: borrow D4BackupAttachmentReader,
  selection :: List<D4BackupSelection>,
  raw_sources :: List<D4BackupRawSource>!String,
  policy :: BackupAttachmentPolicy,
  sampled :: U64!String) -> D4BackupCaptureState!String do
  let now = sampled?
  let plan = backup_prepare_attachment_plan(reader, selection, raw_sources?, policy, now)?
  backup_capture_settle(reader,
    D4BackupCaptureReading(D4BackupCaptureCursor {
      plan: plan,
      slot: 0,
      part: 0,
      reversed_chunks: [],
      partial_size: 0,
      reversed_files: [],
      min_expiry: None,
      observed_at: now
    }))
end

fn backup_capture_omit(reader :: borrow D4BackupAttachmentReader,
  cursor :: D4BackupCaptureCursor,
  reason :: BackupAttachmentOmission,
  now :: U64) -> D4BackupCaptureState!String do
  if cursor.plan.policy != AllowArchiveAttachmentOmissions do
    return Err("backup_archive_refused")
  end
  backup_capture_settle(reader,
    D4BackupCaptureReading(%{cursor |
      slot: cursor.slot + 1,
      part: 0,
      reversed_chunks: [],
      partial_size: 0,
      reversed_files: [ArchiveAttachmentOmitted(reason)] ++ cursor.reversed_files,
      observed_at: now
    }))
end

fn backup_capture_before(reader :: borrow D4BackupAttachmentReader,
  state :: D4BackupCaptureState,
  now :: U64) -> D4BackupCaptureState!String do
  case state do
    D4BackupCaptureReading(cursor) -> do
      if cursor.slot < 0 || cursor.slot >= List.length(cursor.plan.slots) do
        return Err("backup_archive_refused")
      end
      backup_capture_observed_time(reader.authority, cursor.observed_at, now)?
      if !backup_capture_live_included(cursor.min_expiry, now) do
        return Err("backup_archive_refused")
      end
      let slot = List.get(cursor.plan.slots, cursor.slot)
      let manifest = case slot.manifest do
        None -> return Err("backup_archive_refused")
        Some(value) -> value
      end
      if U64.compare(now, manifest.expires_at) >= 0 do
        let updated = backup_capture_omit(reader, cursor, ArchiveAttachmentExpired, now)?
        backup_capture_before(reader, updated, now)
      else
        Ok(D4BackupCaptureReading(%{cursor | observed_at: now}))
      end
    end
    D4BackupCaptureReady(value) -> do
      backup_capture_observed_time(reader.authority, value.observed_at, now)?
      if !backup_capture_live_included(value.min_expiry, now) do
        return Err("backup_archive_refused")
      end
      Ok(D4BackupCaptureReady(%{value | observed_at: now}))
    end
    D4BackupCaptureInvalid -> Ok(D4BackupCaptureInvalid)
  end
end

fn backup_capture_fetch_action(state :: D4BackupCaptureState) -> D4BackupRetrievalAction!String do
  case state do
    D4BackupCaptureReading(cursor) -> do
      if cursor.slot < 0 || cursor.slot >= List.length(cursor.plan.slots) do
        return Err("backup_archive_refused")
      end
      let slot = List.get(cursor.plan.slots, cursor.slot)
      let reference = case slot.reference do
        None -> return Err("backup_archive_refused")
        Some(value) -> decode_reference(value)?
      end
      let manifest = case slot.manifest do
        None -> return Err("backup_archive_refused")
        Some(value) -> value
      end
      if cursor.part < 0 || cursor.part >= manifest.chunk_count || cursor.part >= 256 do
        return Err("backup_archive_refused")
      end
      Ok(D4BackupRetrievalFetch(reference.object_id,
        reference.download_capability,
        cursor.part + 1))
    end
    D4BackupCaptureReady(_) -> Ok(D4BackupRetrievalDone)
    D4BackupCaptureInvalid -> Err("backup_archive_refused")
  end
end

fn backup_capture_action(state :: D4BackupCaptureState) -> Plaintext<D4BackupRetrievalAction> do
  case backup_capture_fetch_action(state) do
    Err(_) -> D4BackupRetrievalRefuse
    Ok(action) -> action
  end
end

fn backup_capture_accept(reader :: borrow D4BackupAttachmentReader,
  state :: D4BackupCaptureState,
  id :: Bytes,
  capability :: Bytes,
  part :: Int,
  response :: AttachmentHttpResponse!String,
  before :: U64,
  now :: U64) -> D4BackupCaptureState!String do
  let cursor = case state do
    D4BackupCaptureReading(value) -> value
    _ -> return Err("backup_archive_refused")
  end
  case backup_capture_fetch_action(state)? do
    D4BackupRetrievalFetch(expected_id, expected_capability, expected_part) ->
      if !Bytes.secure_equals(id, expected_id)
        || !Bytes.secure_equals(capability, expected_capability)
        || part != expected_part do
        return Err("backup_archive_refused")
      end
    _ -> return Err("backup_archive_refused")
  end
  let slot = List.get(cursor.plan.slots, cursor.slot)
  let reference = case slot.reference do
    None -> return Err("backup_archive_refused")
    Some(value) -> value
  end
  let manifest = case slot.manifest do
    None -> return Err("backup_archive_refused")
    Some(value) -> value
  end
  let received = response?
  let opened = if received.status == 200 do
    Some(open_attachment_chunk_with_device(reader.device, reference, cursor.part, received.body)?)
  else if received.status == 404 || received.status == 410 do
    None
  else
    return Err("backup_archive_refused")
  end
  let live = backup_attachment_read_completion(reader.authority.captured_at,
    reader.authority.fresh_through,
    manifest.expires_at,
    before,
    now)?
  if !live do
    return backup_capture_omit(reader, cursor, ArchiveAttachmentExpired, now)
  end
  let bytes = case opened do
    None -> return backup_capture_omit(reader, cursor, ArchiveAttachmentUnavailable, now)
    Some(value) -> value
  end
  if Bytes.length(bytes) < 1
    || Bytes.length(bytes) > 65536
    || Bytes.length(bytes) > manifest.plaintext_size - cursor.partial_size do
    return Err("backup_archive_refused")
  end
  backup_capture_settle(reader,
    D4BackupCaptureReading(%{cursor |
      part: cursor.part + 1,
      reversed_chunks: [bytes] ++ cursor.reversed_chunks,
      partial_size: cursor.partial_size + Bytes.length(bytes),
      observed_at: now
    }))
end

# Pure payload selection only. The public Done observation selects the outer
# Result tag; private state never chooses Ok versus Err after that observation.
fn backup_capture_completed_payload(state :: Plaintext<D4BackupCaptureState>,
  zero_time :: U64) -> Plaintext<D4BackupCaptureComplete> do
  case state do
    D4BackupCaptureReady(value) -> value
    _ -> D4BackupCaptureComplete {
      content: PortableBackupContentArchive {
        policy: RequireArchiveAttachments,
        owner_account: Bytes.empty(),
        owner_authorization_key: Bytes.empty(),
        service_realm: Bytes.empty(),
        candidate_count: 0,
        omitted_timed: 0,
        omitted_unknown: 0,
        omitted_nontext: 0,
        omitted_empty: 0,
        attachment_messages: 0,
        scopes: []
      },
      min_expiry: None,
      encoded_extent: 0,
      observed_at: zero_time
    }
  end
end

fn backup_capture_drive(path :: String,
  key :: borrow StorageKey,
  reader :: borrow D4BackupAttachmentReader,
  state :: Plaintext<D4BackupCaptureState>) -> D4BackupCaptureComplete!String do
  require_backup_attachment_reader_current(path, key, reader)?
  let before = current_time()?
  let prepared = backup_capture_totalized(backup_capture_before(reader, state, before))
  let action = backup_observe_retrieval_action(backup_capture_action(prepared))
  case action do
    D4BackupRetrievalRefuse -> Err("backup_archive_refused")
    D4BackupRetrievalFetch(id, capability, part) -> do
      let response = legacy_attachment_download_response(reader.authority.context.pins.network,
        id,
        capability,
        part)
      # Every response, including transport refusal, crosses the same original
      # ciphertext/native/TLS fence before its private result is inspected.
      require_backup_attachment_reader_current(path, key, reader)?
      let now = current_time()?
      let next = backup_capture_totalized(backup_capture_accept(reader,
        prepared,
        id,
        capability,
        part,
        response,
        before,
        now))
      backup_capture_drive(path, key, reader, next)
    end
    D4BackupRetrievalDone -> do
      # D4_CAPTURE_DONE_FINAL_FENCE_V1
      require_backup_attachment_reader_current(path, key, reader)?
      let now = current_time()?
      let final_state = backup_capture_totalized(backup_capture_before(reader, prepared, now))
      let final_action = backup_observe_retrieval_action(backup_capture_action(final_state))
      case final_action do
        D4BackupRetrievalDone -> do
          # Checked public literal; this is not a caller-supplied clock.
          let zero_time = U64.parse("0")?
          Ok(backup_capture_completed_payload(final_state, zero_time))
        end
        _ -> Err("backup_archive_refused")
      end
    end
    D4BackupRetrievalPublishReady -> Err("backup_archive_refused")
  end
end

fn backup_capture_open_sources(history :: D4BackupHistoryCapture,
  key :: borrow StorageKey) -> List<D4BackupRawSource>!String do
  Ok(for source in history.refs do
    backup_open_raw(history.authority.sources, source, key)?
  end)
end

fn backup_capture_result(reader :: consume D4BackupAttachmentReader,
  raw :: D4BackupCaptureComplete!String) -> D4BackupCapturedContent!String do
  case raw do
    Err(_) -> Err("backup_archive_refused")
    Ok(value) -> Ok(D4BackupCapturedContent {
      reader: reader,
      content: value.content,
      min_expiry: value.min_expiry,
      encoded_extent: value.encoded_extent,
      observed_at: value.observed_at
    })
  end
end

# Production passes the original authority after capturing both pending-slot
# absences. Discovery extends that same bounded snapshot; it never refreshes it.
fn backup_capture_attachment_content_for_authority(path :: String,
  authority :: D4BackupAuthority,
  selection :: List<D4BackupSelection>,
  policy :: BackupAttachmentPolicy,
  key :: borrow StorageKey) -> D4BackupCapturedContent!String do
  let selected = backup_validate_selection(selection)?
  let history = backup_capture_create_sources(path, authority, selected, key)?
  let reader = capture_backup_attachment_reader(path, history.authority, key)?
  let sources = backup_capture_open_sources(history, key)
  let sampled = current_time()
  let state = backup_capture_totalized(backup_capture_initial(reader,
    selected,
    sources,
    policy,
    sampled))
  let completed = backup_capture_drive(path, key, reader, state)
  backup_capture_result(reader, completed)
end

# Test/CLI convenience only. Pending content creation uses the seeded-authority
# entry above and generates its sole final portable file after capture.
fn backup_capture_attachment_content_with_key(path :: String,
  expected_profile :: Bytes,
  selection :: List<D4BackupSelection>,
  policy :: BackupAttachmentPolicy,
  key :: borrow StorageKey) -> D4BackupCapturedContent!String do
  let authority = capture_backup_authority_with_key(path, expected_profile, key)?
  backup_capture_attachment_content_for_authority(path, authority, selection, policy, key)
end

# BEGIN GUARDED_ARCHIVE_VIEW_ADDITION_V1
from Mobile.BackupArchiveViewDispatch import (
  BackupReadonlyOverview,
  BackupReadonlyPage,
  BackupReadonlyPageRequest,
  backup_readonly_overview,
  backup_readonly_page
)

struct D4BackupPreparedViewRead do
  authority :: D4BackupAuthority
  sources :: FanoutSnapshot
  payload :: Plaintext<Bytes>
  revision_tag :: Bytes
end

fn backup_view_identity(path :: String, expected_profile :: Bytes) -> Bool do
  backup_valid_identity(path, expected_profile)
    && Bytes.length(Bytes.from_utf8(path)) <= 4096
    && !String.contains(path, "\0")
end

fn backup_view_selection(request :: BackupReadonlyPageRequest) -> Bool do
  case request do
    ReadonlyMessagePage(page) -> (page.kind == 1 || page.kind == 2)
      && (if page.kind == 1 do
        Bytes.length(page.scope_id) == 16
      else
        Bytes.length(page.scope_id) == 32
      end)
      && page.offset >= 0
      && page.offset <= 256
      && page.limit >= 1
      && page.limit <= 16
    ReadonlyFileChunk(chunk) -> (chunk.kind == 1 || chunk.kind == 2)
      && Bytes.length(chunk.token) == 32
      && chunk.ordinal >= 0
      && chunk.ordinal <= 255
      && chunk.slot_index >= 0
      && chunk.slot_index <= 9
      && chunk.chunk_index >= 0
      && chunk.chunk_index <= 255
  end
end

# Exactly one key effect, before any private index/schema/record traversal.
# Only public request data and captured ciphertext/native frames enter this tag.
fn backup_view_revision(path :: String,
  expected_profile :: Bytes,
  id :: Bytes,
  authority :: D4BackupAuthority,
  captured :: FanoutSnapshot,
  row :: String,
  index :: String,
  key :: borrow StorageKey) -> Bytes!String do
  let frame = mobile_join([
      mobile_byte(1)?,
      mobile_vector(Bytes.from_utf8(path))?,
      mobile_vector(expected_profile)?,
      mobile_vector(id)?,
      mobile_vector(Crypto.sha256(backup_blob(captured, row)?))?,
      mobile_vector(Crypto.sha256(backup_blob(captured, index)?))?,
      mobile_vector(Crypto.sha256(authority.context.network_frame))?,
      mobile_vector(Crypto.sha256(authority.context.security_frame))?,
      mobile_vector(Crypto.sha256(authority.context.companion_frame))?
    ],
    0,
    Bytes.empty())?
  if Bytes.length(frame) > 40455 do
    return Err("invalid_backup_request")
  end
  case StorageKey.index_tag(key, Bytes.from_utf8("morse/backup-view-revision/v1"), frame) do
    Err(_) -> Err("backup_archive_refused")
    Ok(tag) -> if Bytes.length(tag) == 32 do
      Ok(tag)
    else
      Err("backup_archive_refused")
    end
  end
end

fn backup_prepare_view_read(path :: String,
  expected_profile :: Bytes,
  id :: Bytes,
  key :: borrow StorageKey) -> D4BackupPreparedViewRead!String do
  let authority = capture_backup_authority_with_key(path, expected_profile, key)?
  let row = backup_archive_label(authority.profile.account_id, id)?
  let index = backup_archive_index_label(authority.profile.account_id)?
  let captured = capture_backup_snapshot_with_key(path, authority.sources, [row, index], key)?
  let revision = backup_view_revision(path,
    expected_profile,
    id,
    authority,
    captured,
    row,
    index,
    key)?
  let plan = backup_totalized_read(backup_prepare_read_raw(authority,
    id,
    backup_index_source(captured, index, key),
    backup_archive_source(captured, row, key),
    Bytes.length(backup_blob(captured, index)?) == 0))
  if backup_observe_admission(plan.admission) != 1 do
    return Err("backup_archive_refused")
  end
  Ok(D4BackupPreparedViewRead {
    authority: authority,
    sources: captured,
    payload: plan.payload,
    revision_tag: revision
  })
end

fn backup_view_overview_with_key(path :: String,
  expected_profile :: Bytes,
  id :: Bytes,
  key :: borrow StorageKey) -> Result<Plaintext<BackupReadonlyOverview>, String> do
  let ready = backup_prepare_view_read(path, expected_profile, id, key)?
  let projected = backup_readonly_overview(ready.payload)
  backup_finalize(path, key, BackupFinalFence(%{ready.authority | sources: ready.sources}))?
  projected
end

pub fn read_backup_archive_view_overview(path :: String,
  expected_profile :: Bytes,
  backup_id :: Bytes) -> Result<Plaintext<BackupReadonlyOverview>, String> do
  if !backup_view_identity(path, expected_profile) || Bytes.length(backup_id) != 32 do
    return Err("invalid_backup_request")
  end
  let key = platform_key()?
  let result = backup_view_overview_with_key(path, expected_profile, backup_id, key)
  Secret.destroy(key)
  result
end

fn backup_view_page_with_key(path :: String,
  expected_profile :: Bytes,
  id :: Bytes,
  request :: BackupReadonlyPageRequest,
  key :: borrow StorageKey) -> Result<Plaintext<BackupReadonlyPage>, String> do
  let ready = backup_prepare_view_read(path, expected_profile, id, key)?
  let projected = backup_readonly_page(ready.payload, ready.revision_tag, request)
  backup_finalize(path, key, BackupFinalFence(%{ready.authority | sources: ready.sources}))?
  projected
end

pub fn read_backup_archive_view_page(path :: String,
  expected_profile :: Bytes,
  backup_id :: Bytes,
  request :: BackupReadonlyPageRequest) -> Result<Plaintext<BackupReadonlyPage>, String> do
  if !backup_view_identity(path, expected_profile)
    || Bytes.length(backup_id) != 32
    || !backup_view_selection(request) do
    return Err("invalid_backup_request")
  end
  let key = platform_key()?
  let result = backup_view_page_with_key(path, expected_profile, backup_id, request, key)
  Secret.destroy(key)
  result
end

fn backup_view_preview_with_key(path :: String,
  expected_profile :: Bytes,
  wire :: Bytes,
  code :: String,
  key :: borrow StorageKey) -> Result<Plaintext<BackupReadonlyOverview>, String> do
  let authority = capture_backup_authority_with_key(path, expected_profile, key)?
  let plan = backup_prepare_preview(authority, wire, code)
  if backup_observe_admission(plan.admission) != 1 do
    return Err("backup_archive_refused")
  end
  let projected = backup_readonly_overview(plan.payload)
  backup_finalize(path, key, BackupFinalFence(authority))?
  projected
end

pub fn preview_backup_archive_view_overview(path :: String,
  expected_profile :: Bytes,
  wire :: Bytes,
  recovery_code :: String) -> Result<Plaintext<BackupReadonlyOverview>, String> do
  if !backup_view_identity(path, expected_profile)
    || Bytes.length(wire) < 1
    || Bytes.length(wire) > 16796864
    || String.length(recovery_code) < 1
    || String.length(recovery_code) > 1024 do
    return Err("invalid_backup_request")
  end
  let key = platform_key()?
  let result = backup_view_preview_with_key(path, expected_profile, wire, recovery_code, key)
  Secret.destroy(key)
  result
end

# END GUARDED_ARCHIVE_VIEW_ADDITION_V1

from Mobile.Codec import mobile_vector

# D4_PENDING_CONTENT_PUBLICATION_COMPOSED_V2
from Backups.PortableV2 import create_portable_content_backup_v2

struct D4BackupPreparedContentPending do
  before :: PendingCipherBasis
  created :: D4BackupPendingCreated
  descriptor :: Bytes
end

fn backup_prepare_pending_content(captured :: borrow D4BackupCapturedContent,
  before :: PendingCipherBasis,
  key :: borrow StorageKey) -> D4BackupPreparedContentPending!String do
  let authority = captured.reader.authority
  let created = case create_portable_content_backup_v2(captured.content, authority.captured_at) do
    Err(_) -> return Err("backup_archive_refused")
    Ok(value) -> value
  end
  let draft = case Crypto.random_bytes(32) do
    Err(_) -> return Err("pending_export_refused")
    Ok(value) -> value
  end
  let descriptor = D4PendingDescriptor {
    account: authority.profile.account_id,
    authorization: authority.profile.account.authorization_public_key,
    realm: authority.service_realm,
    device: authority.profile.device_id,
    draft_id: draft,
    backup_id: backup_pending_wire_id(created.wire)?,
    wire_digest: Crypto.sha256(created.wire),
    wire_size: Bytes.length(created.wire),
    created_at: authority.captured_at
  }
  let sealed = seal_local(backup_pending_descriptor_wire(descriptor)?,
    key,
    backup_pending_context(authority)?)?
  Ok(D4BackupPreparedContentPending {
    before: before,
    created: D4BackupPendingCreated {
      draft_id: draft,
      wire: created.wire,
      recovery_code: created.recovery_code
    },
    descriptor: sealed
  })
end

fn backup_pending_content_action(captured_at :: U64,
  fresh_through :: U64,
  min_expiry :: Plaintext<Option<U64>>,
  previous :: Plaintext<U64>,
  now :: U64) -> Plaintext<D4BackupRetrievalAction> do
  if U64.compare(now, previous) < 0
    || U64.compare(now, captured_at) < 0
    || U64.compare(now, fresh_through) > 0 do
    return D4BackupRetrievalRefuse
  end
  case min_expiry do
    None -> D4BackupRetrievalPublishReady
    Some(expiry) -> if U64.compare(now, expiry) < 0 do
      D4BackupRetrievalPublishReady
    else
      D4BackupRetrievalRefuse
    end
  end
end

fn backup_publish_pending_content_on(database :: SqliteConn,
  key :: borrow StorageKey,
  captured :: borrow D4BackupCapturedContent,
  prepared :: D4BackupPreparedContentPending) -> Unit!String do
  require_backup_attachment_reader_current_on(database, key, captured.reader)?
  require_pending_cipher_basis_with_key(database, key, prepared.before)?
  let before = current_time()?
  case backup_observe_retrieval_action(backup_pending_content_action(captured.reader.authority.captured_at,
    captured.reader.authority.fresh_through,
    captured.min_expiry,
    captured.observed_at,
    before)) do
    D4BackupRetrievalPublishReady -> nil
    _ -> return Err("backup_archive_refused")
  end
  publish_pending_cipher_pair_with_key(database,
    key,
    prepared.before,
    prepared.created.wire,
    prepared.descriptor)?
  let finished = current_time()?
  case backup_observe_retrieval_action(backup_pending_content_action(captured.reader.authority.captured_at,
    captured.reader.authority.fresh_through,
    captured.min_expiry,
    before,
    finished)) do
    D4BackupRetrievalPublishReady -> Ok(nil)
    _ -> Err("backup_archive_refused")
  end
end

fn backup_publish_pending_content(path :: String,
  key :: borrow StorageKey,
  captured :: borrow D4BackupCapturedContent,
  prepared :: D4BackupPreparedContentPending) -> Unit!String do
  let database = case Sqlite.open(path) do
    Err(_) -> return Err("database_open_failed")
    Ok(value) -> value
  end
  let started = case Sqlite.execute(database, "PRAGMA busy_timeout = 1000", []) do
    Err(error)
    Ok(_) -> Sqlite.execute(database, "BEGIN IMMEDIATE", [])
  end
  let result = case started do
    Err(_) -> Err("database_write_failed")
    Ok(_) -> case backup_publish_pending_content_on(database, key, captured, prepared) do
      Err(_) -> Err("backup_archive_refused")
      Ok(_) -> case Sqlite.commit(database) do
        Err(_) -> Err("database_write_failed")
        Ok(_) -> Ok(nil)
      end
    end
  end
  case result do
    Err(_) -> do
      Sqlite.rollback(database)
      nil
    end
    Ok(_) -> nil
  end
  Sqlite.close(database)
  result
end

fn backup_retire_pending_content(captured :: consume D4BackupCapturedContent) do
  nil
end

fn backup_pending_content_with_key(path :: String,
  expected_profile :: Bytes,
  selection :: List<D4BackupSelection>,
  policy :: BackupAttachmentPolicy,
  key :: borrow StorageKey) -> D4BackupPendingCreated!String do
  let authority = capture_backup_authority_with_key(path, expected_profile, key)?
  let before = backup_pending_capture(path, authority, key)?
  if before.wire.present || before.descriptor.present do
    return Err("pending_export_exists")
  end
  # Both original absences share the 192-label/32 MiB source budget before any
  # discovery or network retrieval. The capture entry extends this authority.
  let sources = capture_backup_snapshot_with_key(path,
    FanoutSnapshot {
      bases: List.append(authority.sources.bases,
        AccountBasis {
          profile: before.profile,
          labels: [before.wire_label, before.descriptor_label],
          records: [Bytes.empty(), Bytes.empty()]
        })
    },
    [],
    key)?
  let captured = backup_capture_attachment_content_for_authority(path,
    %{authority | sources: sources},
    selection,
    policy,
    key)?
  # Do not propagate after acquiring the resource: every preparation/writer
  # result first flows through the single explicit retirement below.
  let result = case backup_prepare_pending_content(captured, before, key) do
    Err(error)
    Ok(prepared) -> case backup_publish_pending_content(path, key, captured, prepared) do
      Err(error)
      Ok(_) -> Ok(prepared.created)
    end
  end
  backup_retire_pending_content(captured)
  result
end

pub fn create_pending_content_backup_export(path :: String,
  expected_profile :: Bytes,
  selection :: List<D4BackupSelection>,
  policy :: BackupAttachmentPolicy) -> D4BackupPendingCreated!String do
  let selected = backup_validate_selection(selection)?
  if !backup_valid_identity(path, expected_profile) do
    return Err("invalid_backup_request")
  end
  let key = platform_key()?
  let result = backup_pending_content_with_key(path, expected_profile, selected, policy, key)
  Secret.destroy(key)
  result
end
