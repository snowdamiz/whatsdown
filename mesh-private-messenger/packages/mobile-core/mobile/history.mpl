from Mobile.Attachments import attachment_summary
from Mobile.ContactAddress import rotated_contact_address_writes
from Mobile.Delivery import DeliveryRecord, delivery_state, load_delivery
from Mobile.Presentation import presented_message_writes
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
  mobile_wide,
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
  updated_session_record
)
from Mobile.Types import (
  ConversationSummary,
  MobileHistoryEntry,
  MobileLoadedSession,
  MobilePeerRequest,
  MobilePolicyRequest,
  MobileReadBytes,
  MobileSessionRecord
)
from Protocol.EnvelopeWire import decode_inner_envelope
from Protocol.V1 import AccountIdentity, DeviceCredential, DirectoryEntry, InnerEnvelope, PrekeyBundle
from Session.Handshake import RatchetState
from Session.Snapshot import SnapshotOutcome, snapshot
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import local_context, open_local, platform_key, seal_local
from Storage.Records import store_updated_blobs, store_updated_session
from Transport.Packet import ClientProfile, decode_client_profile

##! Mobile.History implementation.

fn history_label(conversation_id :: Bytes) -> String do
  "history/v1/#{Bytes.to_hex(conversation_id)}"
end

fn encode_history_entry(value :: MobileHistoryEntry) -> Bytes ! String do
  mobile_join([mobile_vector(mobile_byte(value.direction) ?) ?, mobile_vector(inner_bytes(value.inner) ?) ?],
  0,
  Bytes.empty())
end

fn encode_history_parts(values :: List < MobileHistoryEntry >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_history_parts(values,
    index + 1,
    mobile_append(output, mobile_vector(encode_history_entry(List.get(values, index)) ?) ?) ?)
  end
end

fn encode_history(values :: List < MobileHistoryEntry >) -> Bytes ! String do
  let bounded = if List.length(values) > 256 do
    List.drop(values, List.length(values) - 256)
  else
    values
  end
  encode_history_parts(bounded, 0, mobile_vector(mobile_write_u32(List.length(bounded)) ?) ?)
end

fn parse_history_entry(input :: Bytes) -> MobileHistoryEntry ! String do
  case reader(input, 65600) do
    Err( _) -> Err("invalid_history")
    Ok( state) -> do
      let direction = take_vector(state, 1) ?
      let inner = take_vector(direction.state, 65536) ?
      case finish(inner.state) do
        Err( _) -> Err("invalid_history")
        Ok( _) -> do
          let direction_value = mobile_read_byte(direction.value) ?
          if direction_value != 1 && direction_value != 2 do
            Err("invalid_history")
          else
            case decode_inner_envelope(inner.value) do
              Err( _) -> Err("invalid_history")
              Ok( value) -> Ok(MobileHistoryEntry {
                direction : direction_value,
                inner : value
              })
            end
          end
        end
      end
    end
  end
end

fn parse_history_parts(state :: BinaryReader,
count :: Int,
index :: Int,
values :: List < MobileHistoryEntry >) -> List < MobileHistoryEntry > ! String do
  if index >= count do
    case finish(state) do
      Err( _) -> Err("invalid_history")
      Ok( _) -> Ok(values)
    end
  else
    let entry = take_vector(state, 65600) ?
    parse_history_parts(entry.state,
    count,
    index + 1,
    List.append(values, parse_history_entry(entry.value) ?))
  end
end

fn decode_history(input :: Bytes) -> List < MobileHistoryEntry > ! String do
  case reader(input, 8388608) do
    Err( _) -> Err("invalid_history")
    Ok( state) -> do
      let count = take_vector(state, 4) ?
      let count_value = mobile_read_u32(count.value) ?
      if count_value > 256 do
        Err("invalid_history")
      else
        parse_history_parts(count.state, count_value, 0, List.new())
      end
    end
  end
end

fn load_history(database_path :: String,
wrapping_key :: borrow StorageKey,
conversation_id :: Bytes) -> List < MobileHistoryEntry > ! String do
  let label = history_label(conversation_id)
  case load_blob(database_path, label) do
    Err( error) -> if error == "local_state_not_found" do
      Ok(List.new())
    else
      Err(error)
    end
    Ok( blob) -> decode_history(open_local(blob, wrapping_key, local_context(label) ?) ?)
  end
end

pub fn updated_history(database_path :: String,
wrapping_key :: borrow StorageKey,
inner :: InnerEnvelope,
direction :: Int) -> Result <( List < String >, List < Bytes >), String > do
  let label = history_label(inner.conversation_id)
  let entries = load_history(database_path, wrapping_key, inner.conversation_id) ?
  let ( body, framed_attachment, presentation_labels, presentation_blobs) = presented_message_writes(database_path,
  wrapping_key,
  inner.sender_account_id,
  Bytes.empty(),
  Bytes.empty(),
  inner.body) ?
  let updated = if Bytes.length(body) == 0 && Bytes.length(inner.attachment_manifest) == 0 do
    entries
  else
    List.append(entries,
    MobileHistoryEntry {
      direction : direction,
      inner : % { inner | body : body }
    })
  end
  Ok((List.append(presentation_labels, label),
  List.append(presentation_blobs,
  seal_local(encode_history(updated) ?, wrapping_key, local_context(label) ?) ?)))
end

fn conversation_summary(loaded :: MobileLoadedSession) -> Bytes ! String do
  mobile_join([mobile_vector(loaded.record.conversation_id) ?, mobile_vector(Bytes.from_utf8(loaded.record.peer_username)) ?, mobile_vector(loaded.record.peer_account_id) ?, mobile_vector(loaded.record.peer_device_id) ?, mobile_vector(loaded.record.safety_number) ?, mobile_vector(mobile_byte(loaded.record.request_state) ?) ?, mobile_vector(mobile_byte(if loaded.record.blocked do
    1
  else
    0
  end) ?) ?, mobile_vector(mobile_byte(if loaded.record.verified do
    1
  else
    0
  end) ?) ?, mobile_vector(mobile_byte(if loaded.record.key_changed do
    1
  else
    0
  end) ?) ?, mobile_vector(mobile_write_u32(loaded.record.disappearing_seconds) ?) ?],
  0,
  Bytes.empty())
end

pub fn decode_conversation_summary(input :: Bytes) -> ConversationSummary ! String do
  case reader(input, 1024) do
    Err( _) -> Err("invalid_conversation_summary")
    Ok( state) -> do
      let count = take_vector(state, 4) ?
      let entry_bytes = take_vector(count.state, 512) ?
      let entry = case reader(entry_bytes.value, 512) do
        Err( _) -> Err("invalid_conversation_summary")
        Ok( value) -> Ok(value)
      end ?
      let conversation_id = take_vector(entry, 16) ?
      let username = take_vector(conversation_id.state, 32) ?
      let peer_account_id = take_vector(username.state, 32) ?
      let peer_device_id = take_vector(peer_account_id.state, 16) ?
      let safety = take_vector(peer_device_id.state, 64) ?
      let request_state = take_vector(safety.state, 1) ?
      let blocked = take_vector(request_state.state, 1) ?
      let verified = take_vector(blocked.state, 1) ?
      let key_changed = take_vector(verified.state, 1) ?
      let disappearing = take_vector(key_changed.state, 4) ?
      let request_value = mobile_read_byte(request_state.value) ?
      let blocked_value = mobile_read_byte(blocked.value) ?
      let verified_value = mobile_read_byte(verified.value) ?
      let changed_value = mobile_read_byte(key_changed.value) ?
      let username_value = mobile_utf8(username.value, "invalid_conversation_summary") ?
      let valid_safety = Bytes.length(safety.value) == 64 || (Bytes.length(safety.value) == 0 && verified_value == 0 && changed_value == 1)
      let valid = mobile_read_u32(count.value) ? == 1 && String.length(username_value) > 0 && Bytes.length(conversation_id.value) == 16 && Bytes.length(peer_account_id.value) == 32 && Bytes.length(peer_device_id.value) == 16 && valid_safety && (request_value == 0 || request_value == 1) && blocked_value <= 1 && verified_value <= 1 && changed_value <= 1
      case finish(entry_bytes.state) do
        Err( _) -> Err("invalid_conversation_summary")
        Ok( _) -> case finish(disappearing.state) do
          Err( _) -> Err("invalid_conversation_summary")
          Ok( _) -> if !valid do
            Err("invalid_conversation_summary")
          else
            Ok(ConversationSummary {
              conversation_id : conversation_id.value,
              username : username_value,
              peer_account_id : peer_account_id.value,
              peer_device_id : peer_device_id.value,
              safety_number : safety.value,
              request_state : request_value,
              blocked : blocked_value == 1,
              verified : verified_value == 1,
              key_changed : changed_value == 1,
              disappearing_seconds : mobile_read_u32(disappearing.value) ?
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
session_ids :: List < Bytes >,
index :: Int,
seen_accounts :: List < Bytes >,
values :: List < Bytes >) -> List < Bytes > ! String do
  if index >= List.length(session_ids) do
    Ok(values)
  else
    let loaded = load_session_record(database_path, wrapping_key, List.get(session_ids, index)) ?
    if Bytes.secure_equals(local_account_id, loaded.record.peer_account_id) || contains_session_id(seen_accounts,
    loaded.record.peer_account_id,
    0) do
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
      0) ?
      let has_history = case load_blob(database_path,
      history_label(preferred.record.conversation_id)) do
        Ok( _) -> Ok(true)
        Err( error) -> if error == "local_state_not_found" do
          Ok(false)
        else
          Err(error)
        end
      end ?
      collect_conversations(database_path,
      wrapping_key,
      local_account_id,
      session_ids,
      index + 1,
      List.append(seen_accounts, loaded.record.peer_account_id),
      if has_history do
        List.append(values, conversation_summary(preferred) ?)
      else
        values
      end)
    end
  end
end

pub fn list_conversations(database_path :: String) -> Bytes ! String do
  ensure_schema(database_path) ?
  let wrapping_key = platform_key() ?
  let local = decode_client_profile(load_profile(database_path) ?) ?
  let session_ids = load_session_ids(database_path, wrapping_key) ?
  encode_output_list(collect_conversations(database_path,
  wrapping_key,
  local.account_id,
  session_ids,
  0,
  List.new(),
  List.new()) ?)
end

fn message_visible(value :: MobileHistoryEntry, now :: U64) -> Bool ! String do
  if value.inner.disappearing_seconds == 0 do
    Ok(true)
  else
    let lifetime = mobile_wide(Int.to_string(value.inner.disappearing_seconds * 1000)) ?
    let expires_at = U64.add(value.inner.client_timestamp, lifetime) ?
    Ok(U64.compare(now, expires_at) < 0)
  end
end

fn visible_history(values :: List < MobileHistoryEntry >,
now :: U64,
index :: Int,
visible :: List < MobileHistoryEntry >) -> List < MobileHistoryEntry > ! String do
  if index >= List.length(values) do
    Ok(visible)
  else
    let value = List.get(values, index)
    let next = if message_visible(value, now) ? do
      List.append(visible, value)
    else
      visible
    end
    visible_history(values, now, index + 1, next)
  end
end

# The last field says what became of a sent message: 0 sent, 1 still waiting
# to leave, 2 refused for good by every device it was addressed to.

fn history_summary(device :: borrow DeviceKeys,
value :: MobileHistoryEntry,
delivery :: List < DeliveryRecord >) -> Bytes ! String do
  let state = if value.direction == 1 do
    delivery_state(delivery, value.inner.client_message_id)
  else
    0
  end
  mobile_join([mobile_vector(mobile_byte(value.direction) ?) ?, mobile_vector(value.inner.client_message_id) ?, mobile_vector(mobile_write_u64(value.inner.client_timestamp) ?) ?, mobile_vector(value.inner.body) ?, mobile_vector(mobile_write_u32(value.inner.disappearing_seconds) ?) ?, mobile_vector(attachment_summary(device,
  value.inner.attachment_manifest)) ?, mobile_vector(mobile_byte(state) ?) ?],
  0,
  Bytes.empty())
end

fn history_summaries(device :: borrow DeviceKeys,
values :: List < MobileHistoryEntry >,
delivery :: List < DeliveryRecord >,
index :: Int,
summaries :: List < Bytes >) -> List < Bytes > ! String do
  if index >= List.length(values) do
    Ok(summaries)
  else
    history_summaries(device,
    values,
    delivery,
    index + 1,
    List.append(summaries, history_summary(device, List.get(values, index), delivery) ?))
  end
end

pub fn load_visible_history(request :: MobilePeerRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let peer_id = peer_account_id(request.peer_profile) ?
  let wrapping_key = platform_key() ?
  let local = decode_client_profile(load_profile(request.database_path) ?) ?
  let loaded = find_peer_session(request.database_path,
  wrapping_key,
  peer_id,
  load_session_ids(request.database_path, wrapping_key) ?,
  0) ?
  let entries = load_history(request.database_path, wrapping_key, loaded.record.conversation_id) ?
  let visible = visible_history(entries, current_time() ?, 0, List.new()) ?
  if List.length(visible) != List.length(entries) do
    let label = history_label(loaded.record.conversation_id)
    let blob = seal_local(encode_history(visible) ?, wrapping_key, local_context(label) ?) ?
    store_updated_session(request.database_path, label, blob) ?
  else
    nil
  end
  let device = open_device(local, wrapping_key, request.database_path) ?
  encode_output_list(history_summaries(device,
  visible,
  load_delivery(request.database_path, wrapping_key) ?,
  0,
  List.new()) ?)
end

pub fn conversation_safety(request :: MobilePeerRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let peer_id = peer_account_id(request.peer_profile) ?
  let wrapping_key = platform_key() ?
  let loaded = find_peer_session(request.database_path,
  wrapping_key,
  peer_id,
  load_session_ids(request.database_path, wrapping_key) ?,
  0) ?
  Ok(loaded.record.safety_number)
end

fn updated_policy(record :: MobileSessionRecord, action :: Int, value :: Int) -> MobileSessionRecord ! String do
  if action == 1 do
    Ok(% { record | request_state : 1 })
  else if action == 2 do
    Ok(% { record | blocked : true })
  else if action == 3 do
    Ok(% { record | blocked : false })
  else if action == 4 && Bytes.length(record.safety_number) == 64 do
    Ok(% { record | verified : true, key_changed : false })
  else if action == 5 && value >= 0 && value <= 2592000 do
    Ok(% { record | disappearing_seconds : value })
  else
    Err("invalid_conversation_policy")
  end
end

fn updated_peer_policy_blobs(database_path :: String,
wrapping_key :: borrow StorageKey,
peer_account_id :: Bytes,
session_ids :: List < Bytes >,
action :: Int,
value :: Int,
safety :: Bytes,
index :: Int,
labels :: List < String >,
blobs :: List < Bytes >) -> Result <( List < String >, List < Bytes >), String > do
  if index >= List.length(session_ids) do
    Ok((labels, blobs))
  else
    let loaded = load_session_record(database_path, wrapping_key, List.get(session_ids, index)) ?
    if Bytes.secure_equals(loaded.record.peer_account_id, peer_account_id) do
      let record = if action == 4 && !Bytes.secure_equals(loaded.record.safety_number, safety) do
        Ok(% { loaded.record | verified : false, key_changed : true })
      else
        updated_policy(loaded.record, action, value)
      end ?
      let blob = seal_local(updated_session_record(record.snapshot, record) ?,
      wrapping_key,
      local_context(loaded.label) ?) ?
      updated_peer_policy_blobs(database_path,
      wrapping_key,
      peer_account_id,
      session_ids,
      action,
      value,
      safety,
      index + 1,
      List.append(labels, loaded.label),
      List.append(blobs, blob))
    else
      updated_peer_policy_blobs(database_path,
      wrapping_key,
      peer_account_id,
      session_ids,
      action,
      value,
      safety,
      index + 1,
      labels,
      blobs)
    end
  end
end

pub fn update_conversation(request :: MobilePolicyRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let peer_id = peer_account_id(request.peer_profile) ?
  let wrapping_key = platform_key() ?
  let session_ids = load_session_ids(request.database_path, wrapping_key) ?
  let preferred = find_peer_session(request.database_path, wrapping_key, peer_id, session_ids, 0) ?
  let _ = if request.action == 4 && Bytes.length(preferred.record.safety_number) != 64 do
    Err("safety_number_unavailable")
  else
    Ok(nil)
  end ?
  let ( labels, blobs) = updated_peer_policy_blobs(request.database_path,
  wrapping_key,
  peer_id,
  session_ids,
  request.action,
  request.value,
  preferred.record.safety_number,
  0,
  List.new(),
  List.new()) ?
  # Blocking someone also takes back what they were handed: this device gets a
  # new contact address, the directory retires the old one on the next
  # publication, and everyone else is handed the new one with the next message.
  let ( rotation_labels, rotation_blobs) = if request.action == 2 do
    rotated_contact_address_writes(wrapping_key)
  else
    Ok((List.new(), List.new()))
  end ?
  store_updated_blobs(request.database_path,
  List.concat(labels, rotation_labels),
  List.concat(blobs, rotation_blobs)) ?
  Ok(Bytes.from_utf8("ok"))
end
