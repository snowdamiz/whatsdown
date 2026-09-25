from Binary.Reader import BinaryReader, finish, reader
from Mobile.Codec import (
  mobile_append,
  mobile_byte,
  mobile_join,
  mobile_read_byte,
  mobile_read_u32,
  mobile_read_u64,
  mobile_utf8,
  mobile_vector,
  mobile_wide,
  mobile_write_u32,
  mobile_write_u64,
  mobile_zeroes,
  take_vector,
  take_vector_error
)
from Mobile.Types import (
  MobileLoadedSession,
  MobilePreparedSend,
  MobileReadBytes,
  MobileSessionRecord,
  MobileSyncPayload
)
from Protocol.EnvelopeWire import encode_inner_envelope
from Protocol.HandshakeWire import encode_initial_message
from Protocol.V1 import (
  AccountIdentity,
  DeviceCredential,
  DirectoryEntry,
  InitialMessage,
  InnerEnvelope,
  PrekeyBundle
)
from Session.Handshake import RatchetState
from Session.Ratchet import RatchetError, RatchetMessage, encode_ratchet_message
from Session.Snapshot import SnapshotOutcome, restore, snapshot
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local, seal_local
from Storage.Records import store_new_session
from Transport.Packet import ClientProfile, TransportPacket, decode_packet, open_initial_packet

##! Mobile.Sessions implementation.

pub fn inner_bytes(value :: InnerEnvelope) -> Bytes!String do
  case encode_inner_envelope(value) do
    Err(_) -> Err("inner_encoding_failed")
    Ok(encoded)
  end
end

pub fn encode_sync_payload(local :: ClientProfile, peer :: ClientProfile, inner :: InnerEnvelope) -> Bytes!String do
  mobile_join([
      mobile_vector(Bytes.from_utf8(peer.username))?,
      mobile_vector(peer.account_id)?,
      mobile_vector(inner.conversation_id)?,
      mobile_vector(inner.client_message_id)?,
      mobile_vector(mobile_write_u64(inner.client_timestamp)?)?,
      mobile_vector(inner.body)?,
      mobile_vector(mobile_write_u32(inner.disappearing_seconds)?)?,
      mobile_vector(safety_number(local, peer)?)?
    ],
    0,
    Bytes.empty())
end

pub fn parse_sync_payload(input :: Bytes) -> MobileSyncPayload!String do
  case reader(input, 32500) do
    Err(_) -> Err("invalid_sync_payload")
    Ok(state) -> do
      let peer_username = take_vector_error(state, 64, "invalid_sync_payload")?
      let peer_account_id = take_vector_error(peer_username.state, 32, "invalid_sync_payload")?
      let conversation_id = take_vector_error(peer_account_id.state, 16, "invalid_sync_payload")?
      let client_message_id = take_vector_error(conversation_id.state, 16, "invalid_sync_payload")?
      let client_timestamp = take_vector_error(client_message_id.state, 8, "invalid_sync_payload")?
      let body = take_vector_error(client_timestamp.state, 32000, "invalid_sync_payload")?
      let disappearing_seconds = take_vector_error(body.state, 4, "invalid_sync_payload")?
      let safety = optional_safety_number(disappearing_seconds.state)?
      case finish(safety.state) do
        Err(_) -> Err("invalid_sync_payload")
        Ok(_) -> do
          let username = mobile_utf8(peer_username.value, "invalid_sync_payload")?
          if String.length(username) == 0 || Bytes.length(peer_account_id.value) != 32 || Bytes.length(conversation_id.value) != 16 || Bytes.length(client_message_id.value) != 16 || Bytes.length(client_timestamp.value) != 8 || Bytes.length(disappearing_seconds.value) != 4 do
            Err("invalid_sync_payload")
          else
            let timestamp = case mobile_read_u64(client_timestamp.value) do
              Err(_) -> Err("invalid_sync_payload")
              Ok(value)
            end?
            let disappearing = case mobile_read_u32(disappearing_seconds.value) do
              Err(_) -> Err("invalid_sync_payload")
              Ok(value)
            end?
            Ok(MobileSyncPayload {
              peer_username: username,
              peer_account_id: peer_account_id.value,
              conversation_id: conversation_id.value,
              client_message_id: client_message_id.value,
              client_timestamp: timestamp,
              body: body.value,
              disappearing_seconds: disappearing,
              safety_number: safety.value
            })
          end
        end
      end
    end
  end
end

## The sync envelope's attachment field already targets this device, so it is stored as-is.

pub fn sync_history_inner(local :: ClientProfile, value :: MobileSyncPayload, attachment :: Bytes) -> InnerEnvelope!String do
  Ok(InnerEnvelope {
    version: 1,
    sender_account_id: local.account_id,
    sender_device_id: local.device_id,
    recipient_device_id: mobile_zeroes(16)?,
    conversation_id: value.conversation_id,
    client_message_id: value.client_message_id,
    client_timestamp: value.client_timestamp,
    message_type: 1,
    body: value.body,
    reply_reference: Bytes.empty(),
    attachment_manifest: attachment,
    receipt_policy: 0,
    disappearing_seconds: value.disappearing_seconds,
    extensions: List.new()
  })
end

pub fn initial_bytes(value :: InitialMessage) -> Bytes!String do
  case encode_initial_message(value) do
    Err(_) -> Err("initial_encoding_failed")
    Ok(encoded)
  end
end

pub fn parse_initial_packet(input :: Bytes, recipient :: borrow X25519PrivateKey) -> Result<(Bytes, Bytes), String> do
  case open_initial_packet(input, recipient) do
    Err(error) -> if error == "initial_crypto_failed" do
      Err(error)
    else
      Err("invalid_initial_packet")
    end
    Ok(RatchetPacket(_)) -> Err("invalid_initial_packet")
    Ok(InitialPacket(account_identity, message)) -> Ok((account_identity, message))
  end
end

fn session_label(session_id :: Bytes) -> String do
  "session/v1/#{Bytes.to_hex(session_id)}"
end

fn encode_session_record(snapshot_blob :: Bytes,
  local :: ClientProfile,
  peer :: ClientProfile,
  conversation_id :: Bytes,
  request_state :: Int,
  key_changed :: Bool,
  strongest_suite :: Int) -> Bytes!String do
  mobile_join([
      mobile_vector(snapshot_blob)?,
      mobile_vector(local.account_id)?,
      mobile_vector(local.device_id)?,
      mobile_vector(peer.account_id)?,
      mobile_vector(peer.device_id)?,
      mobile_vector(Bytes.from_utf8(peer.username))?,
      mobile_vector(peer.entry.mailbox_token)?,
      mobile_vector(conversation_id)?,
      mobile_vector(mobile_byte(request_state)?)?,
      mobile_vector(mobile_byte(0)?)?,
      mobile_vector(mobile_byte(0)?)?,
      mobile_vector(mobile_byte(if key_changed do
        1
      else
        0
      end)?)?,
      mobile_vector(mobile_write_u32(0)?)?,
      mobile_vector(mobile_byte(strongest_suite)?)?,
      mobile_vector(safety_number(local, peer)?)?
    ],
    0,
    Bytes.empty())
end

fn optional_safety_number(state :: BinaryReader) -> MobileReadBytes!String do
  if state.offset == Bytes.length(state.input) do
    Ok(MobileReadBytes {
      state: state,
      value: Bytes.empty()
    })
  else
    let value = take_vector(state, 64)?
    if Bytes.length(value.value) != 0 && Bytes.length(value.value) != 64 do
      Err("invalid_safety_number")
    else
      Ok(value)
    end
  end
end

fn parse_session_record(input :: Bytes) -> MobileSessionRecord!String do
  case reader(input, 70600) do
    Err(_) -> Err("invalid_session_record")
    Ok(state) -> do
      let snapshot_blob = take_vector(state, 68900)?
      let local_account_id = take_vector(snapshot_blob.state, 32)?
      let local_device_id = take_vector(local_account_id.state, 16)?
      let peer_account_id = take_vector(local_device_id.state, 32)?
      let peer_device_id = take_vector(peer_account_id.state, 16)?
      let peer_username = take_vector(peer_device_id.state, 64)?
      let peer_mailbox = take_vector(peer_username.state, 32)?
      let conversation_id = take_vector(peer_mailbox.state, 16)?
      let request_state = take_vector(conversation_id.state, 1)?
      let blocked = take_vector(request_state.state, 1)?
      let verified = take_vector(blocked.state, 1)?
      let key_changed = take_vector(verified.state, 1)?
      let disappearing_seconds = take_vector(key_changed.state, 4)?
      let strongest_suite = if disappearing_seconds.state.offset == Bytes.length(disappearing_seconds.state.input) do
        MobileReadBytes {
          state: disappearing_seconds.state,
          value: mobile_byte(1)?
        }
      else
        take_vector(disappearing_seconds.state, 1)?
      end
      let safety = optional_safety_number(strongest_suite.state)?
      case finish(safety.state) do
        Err(_) -> Err("invalid_session_record")
        Ok(_) -> do
          let username = mobile_utf8(peer_username.value, "invalid_session_record")?
          let request_value = mobile_read_byte(request_state.value)?
          let blocked_value = mobile_read_byte(blocked.value)?
          let verified_value = mobile_read_byte(verified.value)?
          let changed_value = mobile_read_byte(key_changed.value)?
          let disappearing_value = mobile_read_u32(disappearing_seconds.value)?
          let strongest_value = mobile_read_byte(strongest_suite.value)?
          let valid = Bytes.length(local_account_id.value) == 32 && Bytes.length(local_device_id.value) == 16 && Bytes.length(peer_account_id.value) == 32 && Bytes.length(peer_device_id.value) == 16 && String.length(username) > 0 && Bytes.length(peer_mailbox.value) == 32 && Bytes.length(conversation_id.value) == 16 && (request_value == 0 || request_value == 1) && blocked_value <= 1 && verified_value <= 1 && changed_value <= 1 && (strongest_value == 1 || strongest_value == 2)
          if !valid do
            Err("invalid_session_record")
          else
            Ok(MobileSessionRecord {
              snapshot: snapshot_blob.value,
              local_account_id: local_account_id.value,
              local_device_id: local_device_id.value,
              peer_account_id: peer_account_id.value,
              peer_device_id: peer_device_id.value,
              peer_username: username,
              peer_mailbox: peer_mailbox.value,
              conversation_id: conversation_id.value,
              request_state: request_value,
              blocked: blocked_value == 1,
              verified: verified_value == 1 && Bytes.length(safety.value) == 64,
              key_changed: changed_value == 1 || Bytes.length(safety.value) == 0,
              disappearing_seconds: disappearing_value,
              strongest_suite: strongest_value,
              safety_number: safety.value
            })
          end
        end
      end
    end
  end
end

fn read_session_ids(encoded :: Bytes, offset :: Int, values :: List<Bytes>) -> List<Bytes>!String do
  if offset >= Bytes.length(encoded) do
    Ok(values)
  else
    case Bytes.slice(encoded, offset, 32) do
      Err(_) -> Err("invalid_session_index")
      Ok(value) -> read_session_ids(encoded, offset + 32, List.append(values, value))
    end
  end
end

fn decode_session_ids(encoded :: Bytes) -> List<Bytes>!String do
  if Bytes.length(encoded) % 32 != 0 do
    Err("invalid_session_index")
  else
    read_session_ids(encoded, 0, List.new())
  end
end

pub fn contains_session_id(values :: List<Bytes>, session_id :: Bytes, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else if Bytes.secure_equals(List.get(values, index), session_id) do
    true
  else
    contains_session_id(values, session_id, index + 1)
  end
end

pub fn load_session_ids(database_path :: String, wrapping_key :: borrow StorageKey) -> List<Bytes>!String do
  case load_blob(database_path, "sessions/v1") do
    Err(error) -> if error == "local_state_not_found" do
      Ok(List.new())
    else
      Err(error)
    end
    Ok(blob) -> decode_session_ids(open_local(blob, wrapping_key, local_context("sessions/v1")?)?)
  end
end

pub fn updated_session_index(database_path :: String,
  wrapping_key :: borrow StorageKey,
  session_id :: Bytes) -> Bytes!String do
  let existing = load_session_ids(database_path, wrapping_key)?
  let encoded = if contains_session_id(existing, session_id, 0) do
    mobile_join(existing, 0, Bytes.empty())?
  else
    mobile_join(List.append(existing, session_id), 0, Bytes.empty())?
  end
  seal_local(encoded, wrapping_key, local_context("sessions/v1")?)
end

pub fn prepared_session_ids(prepared :: List<MobilePreparedSend>,
  index :: Int,
  session_ids :: List<Bytes>) -> List<Bytes> do
  if index >= List.length(prepared) do
    session_ids
  else
    let value = List.get(prepared, index)
    let next = if value.new_session && !contains_session_id(session_ids, value.session_id, 0) do
      List.append(session_ids, value.session_id)
    else
      session_ids
    end
    prepared_session_ids(prepared, index + 1, next)
  end
end

pub fn prepared_envelopes(prepared :: List<MobilePreparedSend>,
  index :: Int,
  envelopes :: List<Bytes>) -> List<Bytes> do
  if index >= List.length(prepared) do
    envelopes
  else
    prepared_envelopes(prepared,
      index + 1,
      List.append(envelopes, List.get(prepared, index).envelope))
  end
end

pub fn seal_session_ids(session_ids :: List<Bytes>, wrapping_key :: borrow StorageKey) -> Bytes!String do
  seal_local(mobile_join(session_ids, 0, Bytes.empty())?,
    wrapping_key,
    local_context("sessions/v1")?)
end

pub fn load_session_record(database_path :: String,
  wrapping_key :: borrow StorageKey,
  session_id :: Bytes) -> MobileLoadedSession!String do
  let label = session_label(session_id)
  let record = open_local(load_blob(database_path, label)?, wrapping_key, local_context(label)?)?
  Ok(MobileLoadedSession {
    session_id: session_id,
    label: label,
    record: parse_session_record(record)?
  })
end

# ponytail: the MVP scans encrypted session IDs; add an encrypted peer index if measured conversation counts make this slow.

fn preferred_session(first :: MobileLoadedSession, second :: MobileLoadedSession) -> MobileLoadedSession do
  let first_active = Bytes.length(first.record.snapshot) > 0
  let second_active = Bytes.length(second.record.snapshot) > 0
  if second_active && !first_active do
    second
  else if first_active && !second_active do
    first
  else if second.record.strongest_suite > first.record.strongest_suite do
    second
  else if second.record.strongest_suite == first.record.strongest_suite && Bytes.length(second.record.safety_number) == 64 && !Bytes.secure_equals(first.record.safety_number,
    second.record.safety_number) do
    second
  else
    first
  end
end

pub fn find_peer_session(database_path :: String,
  wrapping_key :: borrow StorageKey,
  peer_account_id :: Bytes,
  session_ids :: List<Bytes>,
  index :: Int) -> MobileLoadedSession!String do
  if index >= List.length(session_ids) do
    Err("session_not_found")
  else
    let loaded = load_session_record(database_path, wrapping_key, List.get(session_ids, index))?
    if Bytes.secure_equals(loaded.record.peer_account_id, peer_account_id) do
      case find_peer_session(database_path, wrapping_key, peer_account_id, session_ids, index + 1) do
        Err(error) -> if error == "session_not_found" do
          Ok(loaded)
        else
          Err(error)
        end
        Ok(next) -> Ok(preferred_session(loaded, next))
      end
    else
      find_peer_session(database_path, wrapping_key, peer_account_id, session_ids, index + 1)
    end
  end
end

pub fn find_device_session(database_path :: String,
  wrapping_key :: borrow StorageKey,
  peer_account_id :: Bytes,
  peer_device_id :: Bytes,
  session_ids :: List<Bytes>,
  index :: Int) -> MobileLoadedSession!String do
  if index >= List.length(session_ids) do
    Err("session_not_found")
  else
    let loaded = load_session_record(database_path, wrapping_key, List.get(session_ids, index))?
    if Bytes.secure_equals(loaded.record.peer_account_id, peer_account_id) && Bytes.secure_equals(loaded.record.peer_device_id,
      peer_device_id) do
      case find_device_session(database_path,
        wrapping_key,
        peer_account_id,
        peer_device_id,
        session_ids,
        index + 1) do
        Err(error) -> if error == "session_not_found" do
          Ok(loaded)
        else
          Err(error)
        end
        Ok(next) -> Ok(preferred_session(loaded, next))
      end
    else
      find_device_session(database_path,
        wrapping_key,
        peer_account_id,
        peer_device_id,
        session_ids,
        index + 1)
    end
  end
end

pub fn strongest_device_suite(database_path :: String,
  wrapping_key :: borrow StorageKey,
  peer_account_id :: Bytes,
  peer_device_id :: Bytes,
  session_ids :: List<Bytes>,
  index :: Int,
  strongest :: Int) -> Int!String do
  if index >= List.length(session_ids) do
    Ok(strongest)
  else
    let loaded = load_session_record(database_path, wrapping_key, List.get(session_ids, index))?
    let matches = Bytes.secure_equals(loaded.record.peer_account_id, peer_account_id) && Bytes.secure_equals(loaded.record.peer_device_id,
      peer_device_id)
    let next = if matches && loaded.record.strongest_suite > strongest do
      loaded.record.strongest_suite
    else
      strongest
    end
    strongest_device_suite(database_path,
      wrapping_key,
      peer_account_id,
      peer_device_id,
      session_ids,
      index + 1,
      next)
  end
end

pub fn device_needs_prekey(database_path :: String,
  wrapping_key :: borrow StorageKey,
  session_ids :: List<Bytes>,
  profile :: ClientProfile) -> Bool!String do
  case find_device_session(database_path,
    wrapping_key,
    profile.account_id,
    profile.device_id,
    session_ids,
    0) do
    Err(error) -> if error == "session_not_found" do
      Ok(true)
    else
      Err(error)
    end
    Ok(loaded) -> if loaded.record.strongest_suite > profile.bundle.suite do
      Err("peer_keys_changed")
    else
      Ok(loaded.record.strongest_suite < profile.bundle.suite || Bytes.length(loaded.record.safety_number) == 0)
    end
  end
end

fn conversation_alias_id(peer_account_id :: Bytes) -> Bytes!String do
  Ok(Crypto.sha256(mobile_append(Bytes.from_utf8("mesh-msg/mobile/conversation-alias/v1"),
    peer_account_id)?))
end

pub fn self_sync_conversation_id(account_id :: Bytes) -> Bytes!String do
  case Bytes.slice(Crypto.sha256(mobile_append(Bytes.from_utf8("mesh-msg/mobile/self-sync/v1"),
      account_id)?),
    0,
    16) do
    Err(_) -> Err("self_sync_failed")
    Ok(value)
  end
end

## The key this device files a conversation under. Its own records decide: a
## conversation from before names were derived keeps the name it has. Only a
## peer this device knows nothing about takes the name a sibling device sent,
## kept in an alias record so the peer's first message lands in the same place.

pub fn ensure_conversation_alias(database_path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  sync :: MobileSyncPayload,
  session_ids :: List<Bytes>) -> Bytes!String do
  case find_peer_session(database_path, wrapping_key, sync.peer_account_id, session_ids, 0) do
    Ok(existing) -> Ok(existing.record.conversation_id)
    Err(error) -> if error != "session_not_found" do
      Err(error)
    else
      let alias_id = conversation_alias_id(sync.peer_account_id)?
      let label = session_label(alias_id)
      let record = MobileSessionRecord {
        snapshot: Bytes.empty(),
        local_account_id: local.account_id,
        local_device_id: local.device_id,
        peer_account_id: sync.peer_account_id,
        peer_device_id: mobile_zeroes(16)?,
        peer_username: sync.peer_username,
        peer_mailbox: mobile_zeroes(32)?,
        conversation_id: sync.conversation_id,
        request_state: 1,
        blocked: false,
        verified: false,
        key_changed: false,
        disappearing_seconds: sync.disappearing_seconds,
        strongest_suite: 1,
        safety_number: sync.safety_number
      }
      let blob = seal_local(updated_session_record(record.snapshot, record)?,
        wrapping_key,
        local_context(label)?)?
      let index_blob = updated_session_index(database_path, wrapping_key, alias_id)?
      store_new_session(database_path, label, blob, index_blob)?
      Ok(sync.conversation_id)
    end
  end
end

fn bytes_before(left :: Bytes, right :: Bytes, index :: Int) -> Bool!String do
  if Bytes.length(left) != Bytes.length(right) do
    Err("invalid_safety_number")
  else if index >= Bytes.length(left) do
    Ok(false)
  else
    let left_byte = mobile_read_byte(Bytes.slice(left, index, 1)?)?
    let right_byte = mobile_read_byte(Bytes.slice(right, index, 1)?)?
    if left_byte == right_byte do
      bytes_before(left, right, index + 1)
    else
      Ok(left_byte < right_byte)
    end
  end
end

pub fn safety_number(local :: ClientProfile, peer :: ClientProfile) -> Bytes!String do
  let local_identity = mobile_append(local.account_id, local.account.authorization_public_key)?
  let peer_identity = mobile_append(peer.account_id, peer.account.authorization_public_key)?
  let ordered = if bytes_before(local_identity, peer_identity, 0)? do
    [local_identity, peer_identity]
  else
    [peer_identity, local_identity]
  end
  Ok(Bytes.from_utf8(Bytes.to_hex(Crypto.sha256(mobile_join([
      Bytes.from_utf8("mesh-msg/mobile/account-safety/v2"),
      List.get(ordered, 0),
      List.get(ordered, 1)
    ],
    0,
    Bytes.empty())?))))
end

fn reject_session_snapshot(state :: consume RatchetState) -> Result<(Bytes, String, Bytes), String> do
  Err("session_snapshot_failed")
end

fn finish_session_snapshot(state :: consume RatchetState,
  snapshot_blob :: Bytes,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  peer :: ClientProfile,
  conversation_id :: Bytes,
  request_state :: Int,
  key_changed :: Bool,
  session_id :: Bytes,
  label :: String) -> Result<(Bytes, String, Bytes), String> do
  let record = encode_session_record(snapshot_blob,
    local,
    peer,
    conversation_id,
    request_state,
    key_changed,
    state.suite)?
  Ok((session_id, label, seal_local(record, wrapping_key, local_context(label)?)?))
end

pub fn seal_session(state :: consume RatchetState,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  peer :: ClientProfile,
  conversation_id :: Bytes,
  request_state :: Int,
  key_changed :: Bool) -> Result<(Bytes, String, Bytes), String> do
  let session_id = state.session_id
  let label = session_label(session_id)
  case snapshot(state, wrapping_key, local.account_id, local.device_id, mobile_wide("1")?) do
    SnapshotRejected(rejected_state, _) -> reject_session_snapshot(rejected_state)
    SnapshotSealed(next_state, snapshot_blob) -> finish_session_snapshot(next_state,
      snapshot_blob,
      wrapping_key,
      local,
      peer,
      conversation_id,
      request_state,
      key_changed,
      session_id,
      label)
  end
end

fn finish_upgraded_session_snapshot(state :: consume RatchetState,
  snapshot_blob :: Bytes,
  wrapping_key :: borrow StorageKey,
  previous :: MobileLoadedSession,
  local :: ClientProfile,
  peer :: ClientProfile,
  session_id :: Bytes,
  label :: String) -> Result<(Bytes, String, Bytes), String> do
  let safety = safety_number(local, peer)?
  let changed = !Bytes.secure_equals(previous.record.safety_number, safety)
  let record = %{previous.record | snapshot: snapshot_blob, peer_account_id: peer.account_id, peer_device_id: peer.device_id, peer_username: peer.username, peer_mailbox: peer.entry.mailbox_token, strongest_suite: state.suite, safety_number: safety, verified: previous.record.verified && !changed, key_changed: previous.record.key_changed || changed}
  Ok((session_id,
    label,
    seal_local(updated_session_record(record.snapshot, record)?,
      wrapping_key,
      local_context(label)?)?))
end

pub fn seal_upgraded_session(state :: consume RatchetState,
  wrapping_key :: borrow StorageKey,
  previous :: MobileLoadedSession,
  local :: ClientProfile,
  peer :: ClientProfile) -> Result<(Bytes, String, Bytes), String> do
  let session_id = state.session_id
  let label = session_label(session_id)
  case snapshot(state,
    wrapping_key,
    previous.record.local_account_id,
    previous.record.local_device_id,
    mobile_wide("1")?) do
    SnapshotRejected(rejected_state, _) -> reject_session_snapshot(rejected_state)
    SnapshotSealed(next_state, snapshot_blob) -> finish_upgraded_session_snapshot(next_state,
      snapshot_blob,
      wrapping_key,
      previous,
      local,
      peer,
      session_id,
      label)
  end
end

pub fn ratchet_bytes(value :: RatchetMessage) -> Bytes!String do
  case encode_ratchet_message(value) do
    Err(_) -> Err("ratchet_encoding_failed")
    Ok(encoded)
  end
end

## An initial packet already opened from the recipient-sealed transport. A bare
## initial packet is never accepted from an unsealed envelope.

pub fn parse_sealed_initial_packet(input :: Bytes) -> Result<(Bytes, Bytes), String> do
  case decode_packet(input) do
    Ok(InitialPacket(account_identity, message)) -> Ok((account_identity, message))
    _ -> Err("invalid_initial_packet")
  end
end

pub fn parse_ratchet_packet(input :: Bytes) -> Bytes!String do
  case decode_packet(input) do
    Err(_) -> Err("invalid_ratchet_packet")
    Ok(InitialPacket(_, _)) -> Err("invalid_ratchet_packet")
    Ok(RatchetPacket(message)) -> Ok(message)
  end
end

pub fn restore_session(loaded :: MobileLoadedSession, wrapping_key :: borrow StorageKey) -> RatchetState!String do
  case restore(loaded.record.snapshot,
    wrapping_key,
    loaded.record.local_account_id,
    loaded.record.local_device_id,
    mobile_wide("1")?) do
    Err(_) -> Err("session_restore_failed")
    Ok(state)
  end
end

pub fn updated_session_record(snapshot_blob :: Bytes, record :: MobileSessionRecord) -> Bytes!String do
  mobile_join([
      mobile_vector(snapshot_blob)?,
      mobile_vector(record.local_account_id)?,
      mobile_vector(record.local_device_id)?,
      mobile_vector(record.peer_account_id)?,
      mobile_vector(record.peer_device_id)?,
      mobile_vector(Bytes.from_utf8(record.peer_username))?,
      mobile_vector(record.peer_mailbox)?,
      mobile_vector(record.conversation_id)?,
      mobile_vector(mobile_byte(record.request_state)?)?,
      mobile_vector(mobile_byte(if record.blocked do
        1
      else
        0
      end)?)?,
      mobile_vector(mobile_byte(if record.verified do
        1
      else
        0
      end)?)?,
      mobile_vector(mobile_byte(if record.key_changed do
        1
      else
        0
      end)?)?,
      mobile_vector(mobile_write_u32(record.disappearing_seconds)?)?,
      mobile_vector(mobile_byte(record.strongest_suite)?)?,
      mobile_vector(record.safety_number)?
    ],
    0,
    Bytes.empty())
end

fn reject_updated_snapshot(state :: consume RatchetState) -> Bytes!String do
  Err("session_snapshot_failed")
end

fn finish_updated_snapshot(state :: consume RatchetState,
  snapshot_blob :: Bytes,
  record :: MobileSessionRecord,
  wrapping_key :: borrow StorageKey,
  label :: String) -> Bytes!String do
  let strongest_suite = if state.suite > record.strongest_suite do
    state.suite
  else
    record.strongest_suite
  end
  seal_local(updated_session_record(snapshot_blob, %{record | strongest_suite: strongest_suite})?,
    wrapping_key,
    local_context(label)?)
end

pub fn seal_updated_session(state :: consume RatchetState,
  loaded :: MobileLoadedSession,
  wrapping_key :: borrow StorageKey) -> Bytes!String do
  let next_version = U64.add(state.snapshot_version, mobile_wide("1")?)?
  case snapshot(state,
    wrapping_key,
    loaded.record.local_account_id,
    loaded.record.local_device_id,
    next_version) do
    SnapshotRejected(rejected_state, _) -> reject_updated_snapshot(rejected_state)
    SnapshotSealed(next_state, snapshot_blob) -> finish_updated_snapshot(next_state,
      snapshot_blob,
      loaded.record,
      wrapping_key,
      loaded.label)
  end
end
