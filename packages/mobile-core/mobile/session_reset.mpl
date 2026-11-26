##! Mobile.SessionReset: healing a direct session that lost more of one side's
##! messages than a receiver can skip (`protocol/session-reset-v1.md`).
##!
##! The receiver R finds a message from the sender S too far ahead. Once that
##! message proves genuine (it opens under the key its position gives), R asks
##! S for a new session over the direction that still works, R to S: an inner
##! message of type 5 carrying the newest message R holds from S, a one-time
##! prekey R made for this and never published, and R's current profile. Only R
##! can send it, because only R holds that session's keys. S answers by starting
##! a new session to R's bundle with that prekey, an ordinary signed-prekey
##! handshake whose first message (type 6) names the broken session, and sends
##! again, in the new session, what it sent R after that newest message. Both
##! sides retire the broken session: it stays readable for what was already on
##! its way and is never sent on again. R asks once a session; an answer is a
##! handshake, never a request, so nothing loops.

from Identity.Device import DeviceKeys
from Mobile.Attachments import rewrap_reference
from Mobile.Codec import (
  current_time,
  mobile_finish,
  mobile_join,
  mobile_read_u64,
  mobile_reader,
  mobile_vector,
  mobile_wide,
  mobile_write_u64,
  random_bytes,
  take_fixed,
  take_vector_error
)
from Mobile.ContactAddress import deposit_address, outgoing_extensions
from Mobile.Healing import with_session_features
from Mobile.History import history_newest_from, history_sent_after
from Mobile.Outbox import load_outbox_ids, prepare_outbox_writes
from Mobile.Prekeys import reset_prekey_writes
from Mobile.Profile import open_device, policy
from Mobile.Sessions import (
  initial_bytes,
  inner_bytes,
  load_session_ids,
  load_session_record,
  prepared_session_ids,
  ratchet_bytes,
  safety_number,
  seal_replacing_session,
  seal_session_ids,
  seal_updated_session,
  self_sync_conversation_id,
  session_suite_floor,
  strongest_device_suite,
  updated_session_record
)
from Mobile.Transport import sealed_outer_bytes
from Mobile.Types import (
  MobileLoadedSession,
  MobileOneTimePrekey,
  MobilePreparedSend,
  MobileSessionRecord
)
from Prekeys.Bundle import normalize_prekey_bundle
from Protocol.V1 import InitialMessage, InnerEnvelope, ProtocolExtension
from Session.Handshake import (
  RatchetState,
  SessionError,
  initiate_at_floor,
  is_retryable_session_error
)
from Session.Header import ratchet_feature_session_reset, ratchet_has_feature
from Protocol.EnvelopeWire import decode_inner_envelope
from Session.Ratchet import (
  RatchetError,
  RatchetMessage,
  encrypt_sealed,
  ratchet_jump_authentic,
  ratchet_jump_open
)
from Storage.Keys import local_context, seal_local
from Storage.Records import store_outbound, store_updated_session
from Transport.Packet import (
  ClientProfile,
  TransportPacket,
  decode_client_profile,
  direct_conversation_id,
  encode_initial_plaintext,
  encode_packet,
  session_aad
)

pub fn session_reset_request_type() -> Int do
  5
end

pub fn session_reset_answer_type() -> Int do
  6
end

## At most this many earlier messages are sent again after a reset.

fn resend_limit() -> Int do
  32
end

struct ResetRequest do
  last_received :: U64
  prekey :: MobileOneTimePrekey
  requester :: Bytes
end

fn encode_request(last_received :: U64,
  prekey :: MobileOneTimePrekey,
  requester :: Bytes) -> Bytes!String do
  mobile_join([
      Bytes.from_hex("01535251")?,
      mobile_write_u64(last_received)?,
      mobile_write_u64(prekey.id)?,
      prekey.public_key,
      mobile_vector(requester)?
    ],
    0,
    Bytes.empty())
end

fn decode_request(input :: Bytes) -> ResetRequest!String do
  let state = mobile_reader(input, 32768, "invalid_session_reset")?
  let magic = take_fixed(state, 4)?
  let last_received = take_fixed(magic.state, 8)?
  let prekey_id = take_fixed(last_received.state, 8)?
  let prekey = take_fixed(prekey_id.state, 32)?
  let requester = take_vector_error(prekey.state, 32752, "invalid_session_reset")?
  mobile_finish(requester.state, "invalid_session_reset")?
  if Bytes.to_hex(magic.value) != "01535251" do
    Err("invalid_session_reset")
  else
    Ok(ResetRequest {
      last_received: mobile_read_u64(last_received.value)?,
      prekey: MobileOneTimePrekey {
        id: mobile_read_u64(prekey_id.value)?,
        public_key: prekey.value
      },
      requester: requester.value
    })
  end
end

fn encode_answer(broken_session_id :: Bytes, last_received :: U64) -> Bytes!String do
  mobile_join([Bytes.from_hex("01535241")?, broken_session_id, mobile_write_u64(last_received)?],
    0,
    Bytes.empty())
end

# What a reset answer (inner type 6) says: the session it replaces, and the
# newest message its sender holds from the requester.

fn answered(body :: Bytes) -> Result<(Bytes, U64), String> do
  if Bytes.length(body) != 44 || Bytes.to_hex(Bytes.slice(body, 0, 4)?) != "01535241" do
    Err("invalid_session_reset")
  else
    Ok((Bytes.slice(body, 4, 32)?, mobile_read_u64(Bytes.slice(body, 36, 8)?)?))
  end
end

fn wire_conversation(local :: ClientProfile, record :: MobileSessionRecord) -> Bytes!String do
  if Bytes.secure_equals(record.peer_account_id, local.account_id) do
    self_sync_conversation_id(local.account_id)
  else
    direct_conversation_id(local.account_id, record.peer_account_id)
  end
end

fn control_inner(local :: ClientProfile,
  record :: MobileSessionRecord,
  message_type :: Int,
  body :: Bytes,
  extensions :: List<ProtocolExtension>,
  now :: U64) -> InnerEnvelope!String do
  Ok(InnerEnvelope {
    version: 1,
    sender_account_id: local.account_id,
    sender_device_id: local.device_id,
    recipient_device_id: record.peer_device_id,
    conversation_id: wire_conversation(local, record)?,
    client_message_id: random_bytes(16)?,
    client_timestamp: now,
    message_type: message_type,
    body: body,
    reply_reference: Bytes.empty(),
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: extensions
  })
end

## A reset request that is itself too far ahead: when each side lost more
## than it can skip of the other's messages, each side's request is. It is
## read without changing the session, and answered like any other; the
## receiver then asks for nothing itself.

pub fn far_session_reset_request(state :: borrow RatchetState,
  loaded :: MobileLoadedSession,
  local :: ClientProfile,
  blocked :: Bool,
  message :: RatchetMessage,
  associated_data :: Bytes) -> Option<Bytes> do
  if blocked do
    None
  else
    case ratchet_jump_open(state, message, associated_data) do
      Err(_) -> None
      Ok(plaintext) -> case decode_inner_envelope(plaintext) do
        Err(_) -> None
        Ok(inner) -> if inner.message_type == session_reset_request_type()
          && Bytes.secure_equals(inner.sender_account_id, loaded.record.peer_account_id)
          && Bytes.secure_equals(inner.sender_device_id, loaded.record.peer_device_id)
          && Bytes.secure_equals(inner.recipient_device_id, local.device_id) do
          Some(inner.body)
        else
          None
        end
      end
    end
  end
end

## Whether a message refused as too far ahead should make this device ask for
## a new session: the peer reads resets, this session has not asked already
## and is not blocked, and the message is genuine.

pub fn session_reset_wanted(state :: borrow RatchetState,
  loaded :: MobileLoadedSession,
  blocked :: Bool,
  message :: RatchetMessage,
  associated_data :: Bytes) -> Bool do
  loaded.record.reset_state == 0
    && !blocked
    && Bytes.length(loaded.record.peer_identity_key) == 32
    && ratchet_has_feature(state.peer_features, ratchet_feature_session_reset())
    && ratchet_jump_authentic(state, message, associated_data)
end

## R: asks the peer for a new session, in the session that broke, and marks it
## asked. The request leaves through the outbox like any message.

pub fn request_session_reset(database_path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  local_profile :: Bytes,
  loaded :: MobileLoadedSession,
  state :: consume RatchetState) -> Result<(), String> do
  let now = current_time()?
  let record = loaded.record
  let pending_ids = load_outbox_ids(database_path, wrapping_key)?
  let session_ids = load_session_ids(database_path, wrapping_key)?
  let last_received = history_newest_from(database_path,
    wrapping_key,
    record.conversation_id,
    record.peer_account_id,
    record.peer_device_id)?
  let (prekey, prekey_labels, prekey_blobs) = reset_prekey_writes(local,
    wrapping_key,
    database_path)?
  let body = encode_request(last_received, prekey, local_profile)?
  let extensions = with_session_features(outgoing_extensions(database_path, wrapping_key)?)?
  let inner = control_inner(local, record, session_reset_request_type(), body, extensions, now)?
  case encrypt_sealed(state, inner_bytes(inner)?, session_aad(loaded.session_id)?) do
    Err(_) -> Err("message_encryption_failed")
    Ok(value) -> do
      let (next_state, message) = value
      let asked = %{loaded | record: %{record | reset_state: 1, reset_at: now}}
      let session_blob = seal_updated_session(next_state, asked, wrapping_key)?
      let outer = sealed_outer_bytes(deposit_address(database_path,
          wrapping_key,
          record.peer_mailbox)?,
        encode_packet(RatchetPacket(ratchet_bytes(message)?))?,
        record.peer_identity_key,
        now)?
      let (outbox_labels, outbox_blobs, outbox_index_blob) = prepare_outbox_writes(wrapping_key,
        pending_ids,
        [outer],
        database_path,
        Bytes.empty(),
        0,
        0)?
      store_outbound(database_path,
        [
          MobilePreparedSend {
            envelope: outer,
            session_id: loaded.session_id,
            session_label: loaded.label,
            session_blob: session_blob,
            new_session: false
          }
        ],
        List.new(),
        seal_session_ids(session_ids, wrapping_key)?,
        prekey_labels,
        prekey_blobs,
        outbox_labels,
        outbox_blobs,
        outbox_index_blob)
    end
  end
end

# S: the requester must be the device at the other end of the session, under
# the same account key; its bundle gets the prekey it sent.

fn requester_profile(local :: ClientProfile,
  record :: MobileSessionRecord,
  request :: ResetRequest) -> ClientProfile!String do
  let requester = decode_client_profile(request.requester)?
  let same_account_key = Bytes.length(record.safety_number) == 0
    || Bytes.secure_equals(record.safety_number, safety_number(local, requester)?)
  if !Bytes.secure_equals(requester.account_id, record.peer_account_id)
    || !Bytes.secure_equals(requester.device_id, record.peer_device_id)
    || !same_account_key
    || Bytes.length(request.prekey.public_key) != 32 do
    Err("session_reset_mismatch")
  else
    let base = case normalize_prekey_bundle(requester.bundle) do
      Err(_) -> Err("session_reset_mismatch")
      Ok(value)
    end?
    Ok(%{requester |
      bundle: %{base |
        one_time_prekey_id: request.prekey.id,
        one_time_prekey: request.prekey.public_key
      }
    })
  end
end

fn resent_inner(local :: ClientProfile,
  local_device :: borrow DeviceKeys,
  requester :: ClientProfile,
  record :: MobileSessionRecord,
  original :: InnerEnvelope,
  extensions :: List<ProtocolExtension>) -> InnerEnvelope!String do
  let attachment = if Bytes.length(original.attachment_manifest) == 0 do
    Ok(Bytes.empty())
  else
    rewrap_reference(local_device, original.attachment_manifest, requester.credential.dh_public_key)
  end?
  Ok(%{original |
    sender_account_id: local.account_id,
    sender_device_id: local.device_id,
    recipient_device_id: requester.device_id,
    conversation_id: wire_conversation(local, record)?,
    attachment_manifest: attachment,
    extensions: extensions
  })
end

fn reject_resend(state :: consume RatchetState,
  error :: String) -> Result<(RatchetState, List<Bytes>), String> do
  Err(error)
end

# The earlier messages, one after another in the new session.

fn resent(state :: consume RatchetState,
  database_path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  local_device :: borrow DeviceKeys,
  requester :: ClientProfile,
  record :: MobileSessionRecord,
  originals :: List<InnerEnvelope>,
  extensions :: List<ProtocolExtension>,
  now :: U64,
  index :: Int,
  outers :: List<Bytes>) -> Result<(RatchetState, List<Bytes>), String> do
  if index >= List.length(originals) do
    Ok((state, outers))
  else
    case resent_inner(local,
      local_device,
      requester,
      record,
      List.get(originals, index),
      extensions) do
      Err(error) -> reject_resend(state, error)
      Ok(inner) -> case inner_bytes(inner) do
        Err(error) -> reject_resend(state, error)
        Ok(plaintext) -> case session_aad(state.session_id) do
          Err(error) -> reject_resend(state, error)
          Ok(aad) -> resend_one(encrypt_sealed(state, plaintext, aad),
            database_path,
            wrapping_key,
            local,
            local_device,
            requester,
            record,
            originals,
            extensions,
            now,
            index,
            outers)
        end
      end
    end
  end
end

fn resend_one(sealed :: Result<(RatchetState, RatchetMessage), RatchetError>,
  database_path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  local_device :: borrow DeviceKeys,
  requester :: ClientProfile,
  record :: MobileSessionRecord,
  originals :: List<InnerEnvelope>,
  extensions :: List<ProtocolExtension>,
  now :: U64,
  index :: Int,
  outers :: List<Bytes>) -> Result<(RatchetState, List<Bytes>), String> do
  case sealed do
    Err(_) -> Err("message_encryption_failed")
    Ok(value) -> do
      let (next_state, message) = value
      case outbound(database_path, wrapping_key, requester, message, now) do
        Err(error) -> reject_resend(next_state, error)
        Ok(outer) -> resent(next_state,
          database_path,
          wrapping_key,
          local,
          local_device,
          requester,
          record,
          originals,
          extensions,
          now,
          index + 1,
          List.append(outers, outer))
      end
    end
  end
end

fn outbound(database_path :: String,
  wrapping_key :: borrow StorageKey,
  requester :: ClientProfile,
  message :: RatchetMessage,
  now :: U64) -> Bytes!String do
  sealed_outer_bytes(deposit_address(database_path, wrapping_key, requester.entry.mailbox_token)?,
    encode_packet(RatchetPacket(ratchet_bytes(message)?))?,
    requester.credential.dh_public_key,
    now)
end

fn started_session(local :: ClientProfile,
  local_profile :: Bytes,
  local_device :: borrow DeviceKeys,
  requester :: ClientProfile,
  answer :: InnerEnvelope,
  strongest_suite :: Int,
  now :: U64) -> Result<(RatchetState, InitialMessage), String> do
  let plaintext = case encode_initial_plaintext(local_profile, inner_bytes(answer)?) do
    Err(_) -> Err("invalid_initial_plaintext")
    Ok(value)
  end?
  case initiate_at_floor(local_device,
    local.credential,
    requester.account,
    requester.bundle,
    policy(requester, now),
    strongest_suite,
    session_suite_floor(),
    plaintext) do
    Err(SuiteBelowFloor) -> Err("session_reset_refused")
    Err(error) -> if is_retryable_session_error(error) do
      Err("session_start_failed")
    else
      Err("session_reset_refused")
    end
    Ok(value)
  end
end

fn reject_answer(state :: consume RatchetState, error :: String) -> Bytes!String do
  Err(error)
end

## S: answers a reset request that arrived in `loaded`, whose state after
## opening it is `state`: retires that session, starts a new one to the
## requester and sends again what the requester is missing.

pub fn answer_session_reset(database_path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  local_profile :: Bytes,
  loaded :: MobileLoadedSession,
  state :: consume RatchetState,
  body :: Bytes) -> Bytes!String do
  let now = current_time()?
  let record = loaded.record
  let retired = %{loaded | record: %{record | reset_state: 2, reset_at: now}}
  if record.reset_state == 2 do
    # Already answered: a second request for the same session changes nothing.
    let session_blob = seal_updated_session(state, loaded, wrapping_key)?
    store_updated_session(database_path, loaded.label, session_blob)?
    Ok(Bytes.empty())
  else
    case decode_request(body) do
      Err(error) -> reject_answer(state, error)
      Ok(request) -> case requester_profile(local, record, request) do
        Err(error) -> reject_answer(state, error)
        Ok(requester) -> do
          let retired_blob = seal_updated_session(state, retired, wrapping_key)?
          answer_with_session(database_path,
            wrapping_key,
            local,
            local_profile,
            loaded,
            retired_blob,
            requester,
            request,
            now)
        end
      end
    end
  end
end

fn answer_with_session(database_path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  local_profile :: Bytes,
  loaded :: MobileLoadedSession,
  retired_blob :: Bytes,
  requester :: ClientProfile,
  request :: ResetRequest,
  now :: U64) -> Bytes!String do
  let record = loaded.record
  let session_ids = load_session_ids(database_path, wrapping_key)?
  let pending_ids = load_outbox_ids(database_path, wrapping_key)?
  let local_device = open_device(local, wrapping_key, database_path)?
  let extensions = with_session_features(outgoing_extensions(database_path, wrapping_key)?)?
  # The requester sends again what it sent after this, as this side does.
  let newest_held = history_newest_from(database_path,
    wrapping_key,
    record.conversation_id,
    record.peer_account_id,
    record.peer_device_id)?
  let answer = control_inner(local,
    record,
    session_reset_answer_type(),
    encode_answer(loaded.session_id, newest_held)?,
    extensions,
    now)?
  let strongest_suite = strongest_device_suite(database_path,
    wrapping_key,
    requester.account_id,
    requester.device_id,
    session_ids,
    0,
    0)?
  let originals = history_sent_after(database_path,
    wrapping_key,
    record.conversation_id,
    request.last_received,
    resend_limit())?
  let (state, initial) = started_session(local,
    local_profile,
    local_device,
    requester,
    answer,
    strongest_suite,
    now)?
  let initial_outer = sealed_outer_bytes(deposit_address(database_path,
      wrapping_key,
      requester.entry.mailbox_token)?,
    encode_packet(InitialPacket(local.entry.account_identity, initial_bytes(initial)?))?,
    requester.credential.dh_public_key,
    now)?
  let (state, resends) = resent(state,
    database_path,
    wrapping_key,
    local,
    local_device,
    requester,
    record,
    originals,
    extensions,
    now,
    0,
    List.new())?
  let (session_id, label, session_blob) = seal_replacing_session(state,
    wrapping_key,
    loaded,
    local,
    requester,
    now)?
  let prepared = [
    MobilePreparedSend {
      envelope: initial_outer,
      session_id: session_id,
      session_label: label,
      session_blob: session_blob,
      new_session: true
    },
    MobilePreparedSend {
      envelope: Bytes.empty(),
      session_id: loaded.session_id,
      session_label: loaded.label,
      session_blob: retired_blob,
      new_session: false
    }
  ]
  let (outbox_labels, outbox_blobs, outbox_index_blob) = prepare_outbox_writes(wrapping_key,
    pending_ids,
    List.concat([initial_outer], resends),
    database_path,
    Bytes.empty(),
    0,
    0)?
  store_outbound(database_path,
    prepared,
    List.new(),
    seal_session_ids(prepared_session_ids(prepared, 0, session_ids), wrapping_key)?,
    List.new(),
    List.new(),
    outbox_labels,
    outbox_blobs,
    outbox_index_blob)?
  Ok(Bytes.empty())
end

fn reject_answered(state :: consume RatchetState,
  error :: String) -> Result<(RatchetState, List<String>, List<Bytes>, U64), String> do
  Err(error)
end

## R: the answer's first message opened a new session, whose state is `state`.
## The broken session it names is retired if it is this peer device's, and what
## this side sent after the newest message the peer holds goes again in the new
## session. Returns the new session's state, the writes (the retired record and
## the outbox) and when the reset was asked for.

pub fn answered_session_reset(database_path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  peer :: ClientProfile,
  state :: consume RatchetState,
  body :: Bytes) -> Result<(RatchetState, List<String>, List<Bytes>, U64), String> do
  let now = current_time()?
  let (broken, newest_held) = answered(body)?
  case load_session_record(database_path, wrapping_key, broken) do
    Err(_) -> Ok((state, List.new(), List.new(), now))
    Ok(loaded) -> if !Bytes.secure_equals(loaded.record.peer_account_id, peer.account_id)
      || !Bytes.secure_equals(loaded.record.peer_device_id, peer.device_id) do
      reject_answered(state, "session_reset_mismatch")
    else
      resend_answered(database_path, wrapping_key, local, peer, state, loaded, newest_held, now)
    end
  end
end

fn resend_answered(database_path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  peer :: ClientProfile,
  state :: consume RatchetState,
  loaded :: MobileLoadedSession,
  newest_held :: U64,
  now :: U64) -> Result<(RatchetState, List<String>, List<Bytes>, U64), String> do
  let reset_at = if U64.compare(loaded.record.reset_at, mobile_wide("0")?) == 0 do
    now
  else
    loaded.record.reset_at
  end
  let record = %{loaded.record | reset_state: 2, reset_at: reset_at}
  let retired = seal_local(updated_session_record(record.snapshot, record)?,
    wrapping_key,
    local_context(loaded.label)?)?
  let originals = history_sent_after(database_path,
    wrapping_key,
    record.conversation_id,
    newest_held,
    resend_limit())?
  let local_device = open_device(local, wrapping_key, database_path)?
  let extensions = with_session_features(outgoing_extensions(database_path, wrapping_key)?)?
  let pending_ids = load_outbox_ids(database_path, wrapping_key)?
  let (next_state, resends) = resent(state,
    database_path,
    wrapping_key,
    local,
    local_device,
    peer,
    record,
    originals,
    extensions,
    now,
    0,
    List.new())?
  let (outbox_labels, outbox_blobs, outbox_index_blob) = prepare_outbox_writes(wrapping_key,
    pending_ids,
    resends,
    database_path,
    Bytes.empty(),
    0,
    0)?
  Ok((next_state,
    List.concat([loaded.label, "outbox/v1"], outbox_labels),
    List.concat([retired, outbox_index_blob], outbox_blobs),
    reset_at))
end
