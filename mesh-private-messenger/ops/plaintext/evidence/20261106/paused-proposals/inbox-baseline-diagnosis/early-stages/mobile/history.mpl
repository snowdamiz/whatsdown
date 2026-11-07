from Mobile.HistoryExpiry import (
  prepare_direct_history_expiry,
  commit_history_expiry,
  unexpired_history
)
from Mobile.ConversationPolicy import prepare_conversation_policy, commit_conversation_policy
from Mobile.ReceiveSources import ReceiveSources
from Session.State import RatchetState
from Mobile.SafetyVerification import prepare_safety_verification, commit_safety_verification
from Mobile.HistoryWire import (
  encode_history,
  decode_history
)
from Storage.HistoryBlobs import (
  seal_history_blob,
  open_history_blob
)
from Mobile.Attachments import attachment_summary
from Mobile.Delivery import DeliveryRecord, delivery_state, load_delivery
from Mobile.Presentation import presented_message_writes, presented_body
from Binary.Reader import BinaryReader, finish, reader
from Identity.Device import DeviceKeys
from Mobile.Codec import (
  current_time,
  encode_output_list,
  mobile_append,
  mobile_byte,
  mobile_join,
  mobile_read_byte,
  mobile_read_u32,
  mobile_utf8,
  mobile_vector,
  mobile_write_u32,
  mobile_write_u64,
  take_vector
)
from Mobile.Profile import load_profile, open_device, peer_account_id
from Mobile.Sessions import (
  contains_session_id,
  find_peer_session,
  inner_bytes,
  load_session_ids,
  load_session_record,
  parse_session_record,
  updated_session_record
)
from Mobile.Types import (
  ConversationSummary,
  MobileHistoryEntry,
  MobileHistoryAttachment,
  MobileHistoryMatch,
  MobileLoadedSession,
  MobilePeerRequest,
  MobilePolicyRequest,
  MobileReadBytes,
  MobileSessionRecord
)
from Protocol.EnvelopeWire import decode_inner_envelope
from Protocol.V1 import (
  AccountIdentity,
  DeviceCredential,
  DirectoryEntry,
  InnerEnvelope,
  PrekeyBundle
)
from Session.Snapshot import SnapshotOutcome, snapshot
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import local_context, open_local, platform_key, seal_local
from Storage.AccountGuard import AccountBasis
from Storage.ViewOnce import ViewOnceRecord, decode_view_once_record
from Mobile.ViewOnceAdmission import view_once_row_label
from Transport.Packet import ClientProfile, decode_client_profile

##! Mobile.History implementation.

fn history_label(conversation_id :: Bytes) -> String do
  "history/v1/#{Bytes.to_hex(conversation_id)}"
end

fn load_history(database_path :: String,
  wrapping_key :: borrow StorageKey,
  conversation_id :: Bytes) -> List<MobileHistoryEntry>!String do
  let label = history_label(conversation_id)
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(List.new())
    else
      Err(error)
    end
    Ok(blob) -> decode_history(open_history_blob(blob, wrapping_key, label)?)
  end
end

## Inspect only the already captured history ciphertext. The receive commit
## later checks the same basis, so a concurrent history change cannot be blessed.
fn matched_view_once_history(entries :: List<MobileHistoryEntry>,
  expected :: InnerEnvelope,
  direction :: Int) -> Plaintext<MobileHistoryMatch> do
  let matches = List.filter(entries,
    fn(value) -> Bytes.secure_equals(value.inner.client_message_id, expected.client_message_id) end)
  if List.length(matches) == 0 do
    return HistoryAbsent
  end
  if List.length(matches) != 1 do
    return HistoryConflict
  end
  let existing = List.head(matches)
  let same = existing.attachment_kind == HistoryViewOnce
    && existing.direction == direction
    && Bytes.secure_equals(existing.inner.sender_account_id, expected.sender_account_id)
    && Bytes.secure_equals(existing.inner.sender_device_id, expected.sender_device_id)
    && Bytes.secure_equals(existing.inner.recipient_device_id, expected.recipient_device_id)
    && Bytes.secure_equals(existing.inner.conversation_id, expected.conversation_id)
    && U64.compare(existing.inner.client_timestamp, expected.client_timestamp) == 0
    && existing.inner.message_type == expected.message_type
    && Bytes.secure_equals(existing.inner.body, presented_body(expected.body))
    && Bytes.secure_equals(existing.inner.reply_reference, expected.reply_reference)
    && existing.inner.receipt_policy == expected.receipt_policy
    && existing.inner.disappearing_seconds == expected.disappearing_seconds
  if same do
    HistoryIdentical
  else
    HistoryConflict
  end
end

pub fn captured_history_match(key :: borrow StorageKey,
  before :: AccountBasis,
  expected :: InnerEnvelope,
  direction :: Int) -> Result<Plaintext<MobileHistoryMatch>, String> do
  let label = history_label(expected.conversation_id)
  if List.length(before.labels) != List.length(before.records) do
    return Err("invalid_receive_basis")
  end
  for index in 0..List.length(before.labels) do
    if List.get(before.labels, index) == label do
      let blob = List.get(before.records, index)
      if Bytes.length(blob) == 0 do
        return Ok(HistoryAbsent)
      end
      let entries = decode_history(open_history_blob(blob, key, label)?)?
      return Ok(matched_view_once_history(entries, expected, direction))
    end
  end
  Err("invalid_receive_basis")
end

pub fn updated_history(database_path :: String,
  wrapping_key :: borrow StorageKey,
  inner :: InnerEnvelope,
  direction :: Int) -> Result<(List<String>, List<Bytes>), String> do
  updated_history_with_kind(database_path, wrapping_key, inner, direction, HistoryOrdinary)
end

pub fn updated_history_with_kind(database_path :: String,
  wrapping_key :: borrow StorageKey,
  inner :: InnerEnvelope,
  direction :: Int,
  kind :: MobileHistoryAttachment) -> Result<(List<String>, List<Bytes>), String> do
  let label = history_label(inner.conversation_id)
  let entries = load_history(database_path, wrapping_key, inner.conversation_id)?
  let presentation = if kind == HistoryViewOnce do
    Ok((presented_body(inner.body), Bytes.empty(), [], []))
  else
    presented_message_writes(database_path,
      wrapping_key,
      inner.sender_account_id,
      Bytes.empty(),
      Bytes.empty(),
      inner.body)
  end
  let (body, framed_attachment, presentation_labels, presentation_blobs) = Result.unwrap_or(presentation,
    (inner.body, Bytes.empty(), [], []))
  let updated = if Bytes.length(body) == 0
    && Bytes.length(inner.attachment_manifest) == 0
    && kind == HistoryOrdinary do
    entries
  else
    List.append(entries,
      MobileHistoryEntry {
        direction: direction,
        inner: %{inner | body: body},
        attachment_kind: kind
      })
  end
  let encoded = encode_history(updated)
  let encrypted = seal_history_blob(Result.unwrap_or(encoded, Bytes.empty()), wrapping_key, label)
  # Prepare encryption before observing private outcomes. Preserve the original
  # error priority; a fallback or failed preparation never becomes a write plan.
  let _ = presentation?
  let _ = encoded?
  let blob = encrypted?
  Ok((List.append(presentation_labels, label), List.append(presentation_blobs, blob)))
end

fn conversation_summary(loaded :: MobileLoadedSession) -> Bytes!String do
  mobile_join([
      mobile_vector(loaded.record.conversation_id)?,
      mobile_vector(Bytes.from_utf8(loaded.record.peer_username))?,
      mobile_vector(loaded.record.peer_account_id)?,
      mobile_vector(loaded.record.peer_device_id)?,
      mobile_vector(loaded.record.safety_number)?,
      mobile_vector(mobile_byte(loaded.record.request_state)?)?,
      mobile_vector(mobile_byte(if loaded.record.blocked do
        1
      else
        0
      end)?)?,
      mobile_vector(mobile_byte(if loaded.record.verified do
        1
      else
        0
      end)?)?,
      mobile_vector(mobile_byte(if loaded.record.key_changed do
        1
      else
        0
      end)?)?,
      mobile_vector(mobile_write_u32(loaded.record.disappearing_seconds)?)?
    ],
    0,
    Bytes.empty())
end

pub fn decode_conversation_summary(input :: Bytes) -> ConversationSummary!String do
  case reader(input, 1024) do
    Err(_) -> Err("invalid_conversation_summary")
    Ok(state) -> do
      let count = take_vector(state, 4)?
      let entry_bytes = take_vector(count.state, 512)?
      let entry = case reader(entry_bytes.value, 512) do
        Err(_) -> Err("invalid_conversation_summary")
        Ok(value)
      end?
      let conversation_id = take_vector(entry, 16)?
      let username = take_vector(conversation_id.state, 32)?
      let peer_account_id = take_vector(username.state, 32)?
      let peer_device_id = take_vector(peer_account_id.state, 16)?
      let safety = take_vector(peer_device_id.state, 64)?
      let request_state = take_vector(safety.state, 1)?
      let blocked = take_vector(request_state.state, 1)?
      let verified = take_vector(blocked.state, 1)?
      let key_changed = take_vector(verified.state, 1)?
      let disappearing = take_vector(key_changed.state, 4)?
      let request_value = mobile_read_byte(request_state.value)?
      let blocked_value = mobile_read_byte(blocked.value)?
      let verified_value = mobile_read_byte(verified.value)?
      let changed_value = mobile_read_byte(key_changed.value)?
      let username_value = mobile_utf8(username.value, "invalid_conversation_summary")?
      let valid_safety = Bytes.length(safety.value) == 64
        || (Bytes.length(safety.value) == 0 && verified_value == 0 && changed_value == 1)
      let valid = mobile_read_u32(count.value)? == 1
        && String.length(username_value) > 0
        && Bytes.length(conversation_id.value) == 16
        && Bytes.length(peer_account_id.value) == 32
        && Bytes.length(peer_device_id.value) == 16
        && valid_safety
        && (request_value == 0 || request_value == 1)
        && blocked_value <= 1
        && verified_value <= 1
        && changed_value <= 1
      case finish(entry_bytes.state) do
        Err(_) -> Err("invalid_conversation_summary")
        Ok(_) -> case finish(disappearing.state) do
          Err(_) -> Err("invalid_conversation_summary")
          Ok(_) -> if !valid do
            Err("invalid_conversation_summary")
          else
            Ok(ConversationSummary {
              conversation_id: conversation_id.value,
              username: username_value,
              peer_account_id: peer_account_id.value,
              peer_device_id: peer_device_id.value,
              safety_number: safety.value,
              request_state: request_value,
              blocked: blocked_value == 1,
              verified: verified_value == 1,
              key_changed: changed_value == 1,
              disappearing_seconds: mobile_read_u32(disappearing.value)?
            })
          end
        end
      end
    end
  end
end

fn collect_conversations(database_path :: String,
  wrapping_key :: borrow StorageKey,
  local_account_id :: Bytes,
  session_ids :: List<Bytes>,
  index :: Int,
  seen_accounts :: List<Bytes>,
  values :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(session_ids) do
    Ok(values)
  else
    let loaded = load_session_record(database_path, wrapping_key, List.get(session_ids, index))?
    if Bytes.secure_equals(local_account_id, loaded.record.peer_account_id)
      || contains_session_id(seen_accounts, loaded.record.peer_account_id, 0) do
      collect_conversations(database_path,
        wrapping_key,
        local_account_id,
        session_ids,
        index + 1,
        seen_accounts,
        values)
    else
      let preferred = find_peer_session(database_path,
        wrapping_key,
        loaded.record.peer_account_id,
        session_ids,
        0)?
      let has_history = case load_blob(database_path,
        history_label(preferred.record.conversation_id)) do
        Ok(_) -> Ok(true)
        Err(error) -> if error == "local_state_not_found" do
          Ok(false)
        else
          Err(error)
        end
      end?
      collect_conversations(database_path,
        wrapping_key,
        local_account_id,
        session_ids,
        index + 1,
        List.append(seen_accounts, loaded.record.peer_account_id),
        if has_history do
          List.append(values, conversation_summary(preferred)?)
        else
          values
        end)
    end
  end
end

pub fn list_conversations(database_path :: String) -> Bytes!String do
  ensure_schema(database_path)?
  let wrapping_key = platform_key()?
  let local = decode_client_profile(load_profile(database_path)?)?
  let session_ids = load_session_ids(database_path, wrapping_key)?
  encode_output_list(collect_conversations(database_path,
    wrapping_key,
    local.account_id,
    session_ids,
    0,
    List.new(),
    List.new())?)
end

# The last field says what became of a sent message: 0 sent, 1 still waiting
# to leave, 2 refused for good by every device it was addressed to.

fn history_view_once_kind(value :: MobileHistoryEntry) -> Bool do
  declassify(value.attachment_kind == HistoryViewOnce,
    "Direct history discloses only whether an authenticated message has a view-once placeholder; the reference, object capability, and content remain private.")
end

fn view_once_display_expired(now :: U64, expires :: U64, message :: Option<U64>) -> Bool do
  U64.compare(now, expires) >= 0
    || case message do
      None -> false
      Some(expiry) -> U64.compare(now, expiry) >= 0
    end
end

fn view_once_display_state(opened :: Result<Plaintext<Bytes>, String>,
  now :: U64) -> Plaintext<Int> do
  case opened do
    Err(_) -> 5
    Ok(raw) -> case decode_view_once_record(raw) do
      Err(_) -> 5
      Ok(record) -> case record do
        PendingFetch(value) -> if view_once_display_expired(now,
          value.expires_at,
          value.message_expiry) do
          4
        else
          1
        end
        Ready(value) -> if view_once_display_expired(now,
          value.expires_at,
          value.available.message_expiry) do
          4
        else
          2
        end
        Available(_) -> 2
        Consumed(_) -> 3
        ConsumedV2(_) -> 3
        Expired(_) -> 4
      end
    end
  end
end

fn view_once_history_status(path :: String,
  key :: borrow StorageKey,
  conversation :: Bytes,
  message :: Bytes,
  now :: U64) -> Int!String do
  let v1 = view_once_row_label(1, conversation, message)
  let v2 = view_once_row_label(2, conversation, message)
  let old = Result.unwrap_or(load_blob(path, v1), Bytes.empty())
  let new = Result.unwrap_or(load_blob(path, v2), Bytes.empty())
  let chosen = if Bytes.length(old) > 0 && Bytes.length(new) > 0 do
    Err("view_once_unavailable")
  else if Bytes.length(new) > 0 do
    open_local(new, key, local_context(v2)?)
  else if Bytes.length(old) > 0 do
    open_local(old, key, local_context(v1)?)
  else
    Err("view_once_unavailable")
  end
  let closed = view_once_display_state(chosen, now)
  Ok(declassify(closed,
    "Direct history displays only pending, ready, opened, expired, or unavailable for the selected view-once item; references, capabilities, keys, image metadata, and errors remain private."))
end

fn history_summary(path :: String,
  wrapping_key :: borrow StorageKey,
  conversation :: Bytes,
  now :: U64,
  versioned :: Bool,
  device :: borrow DeviceKeys,
  value :: MobileHistoryEntry,
  delivery :: List<DeliveryRecord>) -> Bytes!String do
  let state = if value.direction == 1 do
    delivery_state(delivery, value.inner.client_message_id)
  else
    0
  end
  let view_once = history_view_once_kind(value)
  let attachment = if view_once do
    Bytes.empty()
  else
    attachment_summary(device, value.inner.attachment_manifest)
  end
  let status = if view_once do
    view_once_history_status(path, wrapping_key, conversation, value.inner.client_message_id, now)?
  else
    0
  end
  mobile_join([
      mobile_vector(mobile_byte(value.direction)?)?,
      mobile_vector(value.inner.client_message_id)?,
      mobile_vector(mobile_write_u64(value.inner.client_timestamp)?)?,
      mobile_vector(value.inner.body)?,
      mobile_vector(mobile_write_u32(value.inner.disappearing_seconds)?)?,
      mobile_vector(attachment)?,
      mobile_vector(mobile_byte(state)?)?
    ]
      ++ if versioned do
        [mobile_vector(mobile_byte(status)?)?]
      else
        []
      end,
    0,
    Bytes.empty())
end

fn history_summaries(path :: String,
  wrapping_key :: borrow StorageKey,
  conversation :: Bytes,
  now :: U64,
  versioned :: Bool,
  device :: borrow DeviceKeys,
  values :: List<MobileHistoryEntry>,
  delivery :: List<DeliveryRecord>,
  index :: Int,
  summaries :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(values) do
    Ok(summaries)
  else
    history_summaries(path,
      wrapping_key,
      conversation,
      now,
      versioned,
      device,
      values,
      delivery,
      index + 1,
      List.append(summaries,
        history_summary(path,
          wrapping_key,
          conversation,
          now,
          versioned,
          device,
          List.get(values, index),
          delivery)?))
  end
end

pub fn load_visible_history(request :: MobilePeerRequest) -> Result<Plaintext<Bytes>, String> do
  ensure_schema(request.database_path)?
  let peer_id = peer_account_id(request.peer_profile)?
  let wrapping_key = platform_key()?
  let local = decode_client_profile(load_profile(request.database_path)?)?
  let loaded = find_peer_session(request.database_path,
    wrapping_key,
    peer_id,
    load_session_ids(request.database_path, wrapping_key)?,
    0)?
  let now = current_time()?
  commit_history_expiry(request.database_path,
    prepare_direct_history_expiry(request.database_path, wrapping_key, loaded.session_id, now)?)?
  let entries = load_history(request.database_path, wrapping_key, loaded.record.conversation_id)?
  let visible = unexpired_history(entries, now)?
  let device = open_device(local, wrapping_key, request.database_path)?
  let versioned = declassify(List.any(visible,
      fn(value) -> value.attachment_kind == HistoryViewOnce end),
    "Direct history selects versioned framing only when a visible view-once placeholder is present; bodies and references remain private.")
  let output = encode_output_list(history_summaries(request.database_path,
    wrapping_key,
    loaded.record.conversation_id,
    now,
    versioned,
    device,
    visible,
    load_delivery(request.database_path, wrapping_key)?,
    0,
    List.new())?)?
  if versioned do
    mobile_append(Bytes.from_hex("02485354")?, output)
  else
    Ok(output)
  end
end

pub fn conversation_safety(request :: MobilePeerRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let peer_id = peer_account_id(request.peer_profile)?
  let wrapping_key = platform_key()?
  let loaded = find_peer_session(request.database_path,
    wrapping_key,
    peer_id,
    load_session_ids(request.database_path, wrapping_key)?,
    0)?
  Ok(loaded.record.safety_number)
end

fn accepted_request_blobs(database_path :: String,
  wrapping_key :: borrow StorageKey,
  peer_account_id :: Bytes,
  session_ids :: List<Bytes>,
  index :: Int,
  labels :: List<String>,
  blobs :: List<Bytes>) -> Result<(List<String>, List<Bytes>), String> do
  if index >= List.length(session_ids) do
    Ok((labels, blobs))
  else
    let loaded = load_session_record(database_path, wrapping_key, List.get(session_ids, index))?
    if Bytes.secure_equals(loaded.record.peer_account_id, peer_account_id)
      && loaded.record.request_state != 1 do
      let record = %{loaded.record | request_state: 1}
      let blob = seal_local(updated_session_record(record.snapshot, record)?,
        wrapping_key,
        local_context(loaded.label)?)?
      accepted_request_blobs(database_path,
        wrapping_key,
        peer_account_id,
        session_ids,
        index + 1,
        List.append(labels, loaded.label),
        List.append(blobs, blob))
    else
      accepted_request_blobs(database_path,
        wrapping_key,
        peer_account_id,
        session_ids,
        index + 1,
        labels,
        blobs)
    end
  end
end

# Historical fixture serializer. Production self-sync receive uses captured
# ciphertexts below: policy and ratchet writers can advance these peer rows
# concurrently, so every rewritten source must survive the final atomic guard.

pub fn accepted_request_writes(database_path :: String,
  wrapping_key :: borrow StorageKey,
  peer_account_id :: Bytes,
  session_ids :: List<Bytes>) -> Result<(List<String>, List<Bytes>), String> do
  accepted_request_blobs(database_path,
    wrapping_key,
    peer_account_id,
    session_ids,
    0,
    List.new(),
    List.new())
end

fn accepted_captured_blobs(wrapping_key :: borrow StorageKey,
  peer_account_id :: Bytes,
  sources :: ReceiveSources,
  batch_index :: Int,
  row_index :: Int,
  labels :: List<String>,
  blobs :: List<Bytes>) -> Result<(List<String>, List<Bytes>), String> do
  if batch_index >= List.length(sources.batches) do
    return Ok((labels, blobs))
  end
  let batch = List.get(sources.batches, batch_index)
  if row_index >= List.length(batch.labels) do
    return accepted_captured_blobs(wrapping_key,
      peer_account_id,
      sources,
      batch_index + 1,
      1,
      labels,
      blobs)
  end
  let label = List.get(batch.labels, row_index)
  if label == sources.alias_label do
    return accepted_captured_blobs(wrapping_key,
      peer_account_id,
      sources,
      batch_index,
      row_index + 1,
      labels,
      blobs)
  end
  let record = parse_session_record(open_local(List.get(batch.records, row_index),
    wrapping_key,
    local_context(label)?)?)?
  if Bytes.secure_equals(record.peer_account_id, peer_account_id) && record.request_state != 1 do
    let blob = seal_local(updated_session_record(record.snapshot, %{record | request_state: 1})?,
      wrapping_key,
      local_context(label)?)?
    accepted_captured_blobs(wrapping_key,
      peer_account_id,
      sources,
      batch_index,
      row_index + 1,
      List.append(labels, label),
      List.append(blobs, blob))
  else
    accepted_captured_blobs(wrapping_key,
      peer_account_id,
      sources,
      batch_index,
      row_index + 1,
      labels,
      blobs)
  end
end

## Production receive serializes the exact captured peer rows. The older
## path-based wrapper above remains only for historical test callers; guarded
## receive commits refuse any session write not covered by their source basis.
pub fn accepted_request_writes_from_sources(wrapping_key :: borrow StorageKey,
  peer_account_id :: Bytes,
  sources :: ReceiveSources) -> Result<(List<String>, List<Bytes>), String> do
  if !Bytes.secure_equals(peer_account_id, sources.peer_account_id) do
    return Err("invalid_receive_sources")
  end
  accepted_captured_blobs(wrapping_key, peer_account_id, sources, 0, 1, [], [])
end

pub fn update_conversation(request :: MobilePolicyRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let peer_id = peer_account_id(request.peer_profile)?
  let wrapping_key = platform_key()?
  if request.action == 6 do
    let prepared = prepare_safety_verification(request.database_path,
      wrapping_key,
      peer_id,
      request.expected_safety)?
    commit_safety_verification(request.database_path, prepared)?
    return Ok(Bytes.from_utf8("ok"))
  end
  let prepared = prepare_conversation_policy(request.database_path,
    wrapping_key,
    peer_id,
    request.action,
    request.value)?
  commit_conversation_policy(request.database_path, prepared)?
  Ok(Bytes.from_utf8("ok"))
end

pub struct PostageMessageRecipient do
  account_id :: Bytes
  username :: String
  conversation_id :: Bytes
end

# Read-only local context for a queued message request. Duplicate message IDs
# across different conversations are ambiguous and never select a recipient.
pub fn postage_message_recipient(path :: String,
  wrapping :: borrow StorageKey,
  message_id :: Bytes) -> PostageMessageRecipient!String do
  let ids = load_session_ids(path, wrapping)?
  if Bytes.length(message_id) != 16 || List.length(ids) > 256 do
    return Err("unsupported_postage_message")
  end
  let sessions = for id in ids do
    load_session_record(path, wrapping, id)?.record
  end
  let matches = for index in 0..List.length(sessions) do
    let record = List.get(sessions, index)
    let seen = List.any(List.take(sessions, index),
      fn(prior) -> Bytes.secure_equals(prior.conversation_id, record.conversation_id) end)
    if seen do
      None
    else
      let entries = load_history(path, wrapping, record.conversation_id)?
      if List.any(entries,
        fn(entry) -> Bytes.secure_equals(entry.inner.client_message_id, message_id)
          && Bytes.secure_equals(entry.inner.sender_account_id, record.local_account_id) end) do
        Some(PostageMessageRecipient {
          account_id: record.peer_account_id,
          username: record.peer_username,
          conversation_id: record.conversation_id
        })
      else
        None
      end
    end
  end
  let found = List.flat_map(matches,
    fn(value) do
      case value do
        None -> []
        Some(value) -> [value]
      end
    end)
  if List.length(found) != 1 do
    return Err("ambiguous_postage_message")
  end
  Ok(List.head(found))
end
