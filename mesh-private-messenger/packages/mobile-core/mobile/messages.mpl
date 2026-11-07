from Mobile.SessionPolicy import capture_native_session_policy, native_session_minimum
from Mobile.ReceiveSources import (
  ReceiveSources,
  capture_receive_sources,
  capture_receive_sessions,
  capture_receive_alias,
  receive_captured_peer,
  receive_captured_strongest
)
from Storage.AccountGuard import AccountBasis
from Mobile.HeaderAdmission import (
  capture_header_initial,
  capture_legacy_receive,
  commit_legacy_receive_with_sources,
  capture_header_history,
  capture_header_record,
  commit_initial_admission_at_policy,
  prepared_header_initial_alias
)
from Mobile.HeaderRouting import (
  HeaderRoute,
  route_header_guarded,
  commit_header_receive_with_sources
)
from Mobile.HeaderCapabilities import require_direct_headers, require_new_header_capacity
from Session.State import RatchetState, DecryptOutcome, RatchetError, RatchetMessage
from Mobile.AttachmentCapabilities import require_direct_attachment
from Mobile.AttachmentSendState import (
  capture_direct_attachment,
  commit_direct_attachment,
  commit_direct_attachment_at_policy
)
from Mobile.Attachments import (
  rewrap_reference,
  view_once_carrier_kind,
  view_once_carrier_present,
  contains_view_once_material
)
from Mobile.Presentation import presented_body, view_once_presentation_valid
from Identity.Device import DeviceKeys, VerificationPolicy
from Mobile.Codec import (
  canonical_outer,
  current_time,
  random_bytes,
  mobile_join,
  mobile_byte,
  mobile_write_u32,
  mobile_write_u64
)
from Mobile.ContactAddress import (
  deposit_address,
  learned_contact_address_writes
)
from Mobile.Outgoing import direct_extensions
from Mobile.Gossip import observe_gossip
from Mobile.TransparencySafety import require_log_changes_allowed
from Mobile.FanoutPrekeys import matching_fanout_prekey_state_labels
from Mobile.History import (
  accepted_request_writes_from_sources,
  updated_history,
  updated_history_with_kind,
  captured_history_match
)
from Mobile.ViewOnceAdmission import (
  prepare_view_once_pending,
  prepare_view_once_write,
  view_once_row_label,
  view_once_identity_label,
  view_once_logical_label,
  view_once_epoch_label,
  require_view_once_epoch,
  captured_view_once_exists
)
from Attachments.ViewOnce import ViewOnceBinding, decode_view_once_reference
from Mobile.GroupInvitesState import received_invitation_writes
from Mobile.Outbox import load_outbox_ids, outbox_capacity, prepare_outbox_writes
from Mobile.Prekeys import (
  find_prekey,
  last_resort_replayed,
  load_active_prekey_pool,
  find_last_resort_prekey,
  load_prekey_pool,
  remove_prekey,
  remove_prekey_id,
  seal_active_prekey_pool,
  seal_last_resort_replay,
  seal_prekey_pool
)
from Mobile.Profile import load_profile, open_device, policy
from Mobile.Renewal import open_bundle_prekeys, own_bundle_policy, responder_prekey_bundle
from Mobile.Transport import MobileOpenedPacket, open_outer_packet, sealed_outer_bytes
from Mobile.Sessions import (
  prepared_conversation_alias,
  find_peer_session,
  initial_bytes,
  inner_bytes,
  load_session_ids,
  load_session_record,
  parse_initial_packet,
  parse_ratchet_packet,
  parse_sealed_initial_packet,
  parse_sync_payload,
  prepared_session_ids,
  ratchet_bytes,
  restore_session,
  session_uses_headers,
  safety_number,
  seal_session,
  seal_session_ids,
  seal_updated_session,
  seal_upgraded_session,
  self_sync_conversation_id,
  strongest_device_suite,
  sync_history_inner,
  updated_session_index
)
from Mobile.Types import (
  MobileLoadedSession,
  MobileOneTimePrekey,
  MobilePreparedSend,
  MobileReceiveRequest,
  MobileHistoryAttachment,
  MobileSessionRecord,
  MobileStartRequest,
  MobileSyncPayload
)
from Prekeys.Bundle import (
  OneTimePrekeySecrets,
  PostQuantumPrekeySecrets,
  PrekeyError,
  SignedPrekeySecrets
)
from Protocol.EnvelopeWire import decode_inner_envelope
from Protocol.HandshakeWire import decode_initial_message
from Protocol.IdentityWire import decode_account_identity, decode_device_credential
from Protocol.V1 import (
  AccountIdentity,
  DeviceCredential,
  DirectoryEntry,
  InitialMessage,
  InnerEnvelope,
  OuterEnvelope,
  PrekeyBundle
)
from Session.Handshake import (
  SessionError,
  initiate_at_minimum_suite,
  is_retryable_session_error,
  receive_initial_at_minimum_suite
)
from Session.Ratchet import (
  decode_ratchet_message,
  decrypt,
  encrypt_sealed,
  is_retryable_ratchet_error,
  ratchet_transport_matches
)
from Storage.Blobs import ensure_schema
from Storage.Keys import one_time_prekey_label, platform_key
from Storage.Records import (
  store_record_changes,
  store_updated_session,
  store_updated_session_and_history
)
from Transport.Packet import (
  ClientProfile,
  TransportPacket,
  decode_client_profile,
  decode_initial_plaintext,
  direct_conversation_id,
  encode_initial_plaintext,
  encode_packet,
  session_aad
)

##! Mobile.Messages implementation.

struct PreparedReceivedHistory do
  basis :: AccountBasis
  kind :: MobileHistoryAttachment
  pending_labels :: List<String>
  pending_blobs :: List<Bytes>
  duplicate :: Bool
end

fn view_once_body_safe(wire :: Bytes, body :: Bytes) -> Plaintext<Bool> do
  if !view_once_presentation_valid(body) do
    return false
  end
  let visible = presented_body(body)
  case decode_view_once_reference(wire) do
    Err(_) -> false
    Ok(reference) -> !contains_view_once_material(visible, wire)
      && !contains_view_once_material(visible, reference.object_id)
      && !contains_view_once_material(visible, reference.download_capability)
      && !contains_view_once_material(visible, reference.encrypted_manifest)
      && !contains_view_once_material(visible, reference.wrapped_key)
  end
end

## Local aliases and ignored contact extensions are not message identity.
fn view_once_message_digest(inner :: InnerEnvelope,
  direction :: Int) -> Result<Plaintext<Bytes>, String> do
  let input = mobile_join([
      Bytes.from_utf8("morse/view-once/content/v2\n"),
      mobile_byte(direction)?,
      inner.sender_account_id,
      inner.sender_device_id,
      inner.recipient_device_id,
      inner.client_message_id,
      mobile_write_u64(inner.client_timestamp)?,
      mobile_write_u32(inner.message_type)?,
      mobile_write_u32(inner.receipt_policy)?,
      mobile_write_u32(inner.disappearing_seconds)?,
      Crypto.sha256(presented_body(inner.body)),
      Crypto.sha256(inner.reply_reference)
    ],
    0,
    Bytes.empty())?
  Ok(Crypto.sha256(input))
end

fn sync_side_effects(key :: borrow StorageKey,
  peer :: Bytes,
  sources :: ReceiveSources,
  duplicate :: Bool,
  alias_labels :: List<String>,
  alias_blobs :: List<Bytes>) -> Result<(List<String>, List<Bytes>), String> do
  if duplicate do
    Ok(([], []))
  else
    let (labels, blobs) = accepted_request_writes_from_sources(key, peer, sources)?
    Ok((labels ++ alias_labels, blobs ++ alias_blobs))
  end
end

fn sync_initial_index(path :: String,
  key :: borrow StorageKey,
  session :: Bytes,
  duplicate :: Bool,
  prepared_index :: Bytes) -> Bytes!String do
  if duplicate do
    updated_session_index(path, key, session)
  else
    Ok(prepared_index)
  end
end

fn required_receive_basis(value :: Option<AccountBasis>) -> AccountBasis!String do
  case value do
    None -> Err("invalid_receive_basis")
    Some(basis) -> Ok(basis)
  end
end

fn prepare_received_history(path :: String,
  key :: borrow StorageKey,
  device :: borrow DeviceKeys,
  local :: ClientProfile,
  before :: AccountBasis,
  authenticated_sender :: InnerEnvelope,
  wire_conversation :: Bytes,
  peer_context :: Bytes,
  history :: InnerEnvelope,
  direction :: Int) -> PreparedReceivedHistory!String do
  let attachment = history.attachment_manifest
  let expected_marker = Bytes.from_hex("01564f52")?
  let batch_marker = Bytes.from_hex("01415442")?
  let kind = declassify(view_once_carrier_kind(attachment, expected_marker, batch_marker),
    "Authenticated receive distinguishes only ordinary attachments, a standalone view-once reference, and a refused mixed or malformed batch; reference contents and message body remain private.")
  if kind == 2 do
    return Err("view_once_reference_refused")
  end
  let legacy_label = view_once_row_label(1, history.conversation_id, history.client_message_id)
  let label = view_once_row_label(2, history.conversation_id, history.client_message_id)
  let expected = ViewOnceBinding {
    sender_account_id: authenticated_sender.sender_account_id,
    sender_device_id: authenticated_sender.sender_device_id,
    receiver_account_id: local.account_id,
    receiver_device_id: local.device_id,
    conversation_id: wire_conversation,
    message_id: history.client_message_id
  }
  let identity_label = view_once_identity_label(expected)?
  let logical_label = view_once_logical_label(local.account_id,
    peer_context,
    history.client_message_id)?
  let captured = capture_header_record(path, Some(before), legacy_label)?
  let captured = capture_header_record(path, captured, label)?
  let captured = capture_header_record(path, captured, identity_label)?
  let captured = capture_header_record(path, captured, logical_label)?
  let basis = required_receive_basis(captured)?
  if kind == 0 do
    if captured_view_once_exists(basis, legacy_label, label, identity_label, logical_label)? do
      return Err("view_once_reference_refused")
    end
    return Ok(PreparedReceivedHistory {
      basis: basis,
      kind: HistoryOrdinary,
      pending_labels: [],
      pending_blobs: [],
      duplicate: false
    })
  end
  let captured = capture_header_record(path, Some(basis), view_once_epoch_label())?
  let basis = required_receive_basis(captured)?
  require_view_once_epoch(key, basis, local.account_id, local.device_id)?
  let expiry = if history.disappearing_seconds == 0 do
    None
  else if history.disappearing_seconds < 0 do
    return Err("view_once_reference_refused")
  else
    Some(U64.add(history.client_timestamp,
      U64.parse(Int.to_string(history.disappearing_seconds * 1000))?)?)
  end
  let now = current_time()?
  let pending = prepare_view_once_pending(device, expected, attachment, expiry, now)?
  if !declassify(view_once_body_safe(attachment, history.body),
    "Authenticated view-once receive exposes only whether its caption is valid and excludes the selected reference material; caption, reference, key, capability and errors remain private.") do
    return Err("view_once_reference_refused")
  end
  let history_match = captured_history_match(key, basis, history, direction)
  let content_digest = view_once_message_digest(history, direction)
  let write = prepare_view_once_write(key,
    basis,
    history.conversation_id,
    wire_conversation,
    history.client_message_id,
    local.account_id,
    peer_context,
    identity_label,
    logical_label,
    pending,
    history_match,
    content_digest,
    now)?
  Ok(PreparedReceivedHistory {
    basis: basis,
    kind: HistoryViewOnce,
    pending_labels: if write.duplicate do
      []
    else
      [write.label, write.identity_label, write.logical_label]
    end,
    pending_blobs: if write.duplicate do
      []
    else
      [write.blob, write.identity_blob, write.logical_blob]
    end,
    duplicate: write.duplicate
  })
end

fn received_history_writes(path :: String,
  key :: borrow StorageKey,
  prepared :: PreparedReceivedHistory,
  history :: InnerEnvelope,
  direction :: Int) -> Result<(List<String>, List<Bytes>), String> do
  if prepared.duplicate do
    Ok(([], []))
  else
    let inner = if prepared.kind == HistoryViewOnce do
      %{history | attachment_manifest: Bytes.empty(), extensions: List.new()}
    else
      history
    end
    let (labels, blobs) = updated_history_with_kind(path, key, inner, direction, prepared.kind)?
    Ok((labels ++ prepared.pending_labels, blobs ++ prepared.pending_blobs))
  end
end

fn received_history_body(prepared :: PreparedReceivedHistory,
  body :: Plaintext<Bytes>) -> Plaintext<Bytes> do
  if prepared.duplicate do
    Bytes.empty()
  else
    presented_body(body)
  end
end

pub fn start_conversation(request :: MobileStartRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let local_encode_client_profile = load_profile(request.database_path)?
  let local = decode_client_profile(local_encode_client_profile)?
  let peer = decode_client_profile(request.peer_profile)?
  let session_policy = capture_native_session_policy()?
  let wrapping_key = platform_key()?
  require_direct_headers(request.database_path, wrapping_key, local, peer)?
  require_log_changes_allowed(request.database_path, wrapping_key)?
  let attachment_before = Some(capture_direct_attachment(request.database_path,
    wrapping_key,
    local_encode_client_profile,
    peer)?)
  if Bytes.length(request.attachment) > 0 do
    require_direct_attachment(request.database_path, wrapping_key, local, peer, request.attachment)?
  end
  let pending_ids = load_outbox_ids(request.database_path, wrapping_key)?
  if List.length(pending_ids) >= outbox_capacity() do
    Err("outbox_full")
  else
    Ok(nil)
  end?
  let session_ids = load_session_ids(request.database_path, wrapping_key)?
  require_new_header_capacity(List.length(session_ids), 1)?
  let local_device = open_device(local, wrapping_key, request.database_path)?
  let now = current_time()?
  let conversation_id = direct_conversation_id(local.account_id, peer.account_id)?
  # The peer copy re-addresses the attachment key to the peer device; history keeps the local copy.
  let history_inner = InnerEnvelope {
    version: 1,
    sender_account_id: local.account_id,
    sender_device_id: local.device_id,
    recipient_device_id: peer.device_id,
    conversation_id: conversation_id,
    client_message_id: random_bytes(16)?,
    client_timestamp: now,
    message_type: 1,
    body: request.body,
    reply_reference: Bytes.empty(),
    attachment_manifest: request.attachment,
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: List.new()
  }
  # What goes to the peer differs from what history keeps: the attachment key is
  # re-addressed, and the message hands over this device's contact address.
  let rewrapped = rewrap_reference(local_device, request.attachment, peer.credential.dh_public_key)?
  let handed_over = direct_extensions(request.database_path, wrapping_key)?
  let inner = %{history_inner | attachment_manifest: rewrapped, extensions: handed_over}
  let plaintext = case encode_initial_plaintext(local_encode_client_profile, inner_bytes(inner)?) do
    Err(_) -> Err("invalid_initial_plaintext")
    Ok(value)
  end?
  let strongest_suite = strongest_device_suite(request.database_path,
    wrapping_key,
    peer.account_id,
    peer.device_id,
    session_ids,
    0,
    0)?
  let (state, initial) = case initiate_at_minimum_suite(local_device,
    local.credential,
    peer.account,
    peer.bundle,
    policy(peer, now),
    strongest_suite,
    native_session_minimum(session_policy)?,
    plaintext) do
    Err(MinimumSessionSuiteRequired) -> Err("session_suite_below_minimum")
    Err(_) -> Err("session_start_failed")
    Ok(value)
  end?
  let packet = encode_packet(InitialPacket(local.entry.account_identity, initial_bytes(initial)?))?
  let outer = sealed_outer_bytes(deposit_address(request.database_path,
      wrapping_key,
      peer.entry.mailbox_token)?,
    packet,
    peer.credential.dh_public_key,
    now)?
  let (session_id, label, session_blob) = seal_session(state,
    wrapping_key,
    local,
    peer,
    conversation_id,
    1,
    false)?
  let prepared = [
    MobilePreparedSend {
      envelope: outer,
      session_id: session_id,
      session_label: label,
      session_blob: session_blob,
      new_session: true
    }
  ]
  let index_blob = seal_session_ids(prepared_session_ids(prepared, 0, session_ids), wrapping_key)?
  let (history_keys, history_blobs) = updated_history(request.database_path,
    wrapping_key,
    history_inner,
    1)?
  let (outbox_labels, outbox_blobs, outbox_index_blob) = prepare_outbox_writes(wrapping_key,
    pending_ids,
    [outer],
    request.database_path,
    history_inner.client_message_id,
    0,
    1,
    local)?
  commit_direct_attachment_at_policy(request.database_path,
    attachment_before,
    session_policy,
    prepared,
    List.new(),
    index_blob,
    history_keys,
    history_blobs,
    outbox_labels,
    outbox_blobs,
    outbox_index_blob)?
  Ok(outer)
end

# A used one-time prekey is deleted with the session write. The reusable
# last-resort key stays, so its first message is remembered instead.

fn received_prekey_writes(database_path :: String,
  wrapping_key :: borrow StorageKey,
  prekeys :: List<MobileOneTimePrekey>,
  active_prekeys :: List<U64>,
  selected_id :: U64,
  reusable :: Bool,
  transcript_hash :: Bytes,
  fanout_labels :: List<String>) -> Result<(List<String>, List<String>, List<Bytes>), String> do
  if reusable do
    Ok((fanout_labels,
      ["last-resort-replays/v1"],
      [seal_last_resort_replay(database_path, wrapping_key, transcript_hash)?]))
  else
    Ok((List.append(fanout_labels, one_time_prekey_label(selected_id)),
      ["one-time-prekeys/v1", "one-time-prekey-active/v1"],
      [
        seal_prekey_pool(remove_prekey(prekeys, selected_id, 0, List.new()), wrapping_key)?,
        seal_active_prekey_pool(remove_prekey_id(active_prekeys, selected_id, 0, List.new()),
          wrapping_key)?
      ]))
  end
end

# A message that was authenticated and is from the device it claims to be from
# may hand over that device's contact address. It is kept at once, in its own
# write: the message may be delivered again, and the address is as true then.
# A blocked peer is not listened to.

fn require_control_without_view_once(inner :: InnerEnvelope) -> Unit!String do
  let vor = Bytes.from_hex("01564f52")?
  let batch = Bytes.from_hex("01415442")?
  if declassify(view_once_carrier_present(inner.attachment_manifest, vor, batch),
    "Authenticated direct control receive reveals only whether an unsupported view-once carrier is present; attachment and message contents remain private.") do
    Err("view_once_reference_refused")
  else
    Ok(nil)
  end
end

fn keep_contact_address(database_path :: String,
  wrapping_key :: borrow StorageKey,
  blocked :: Bool,
  public_address :: Bytes,
  inner :: InnerEnvelope) -> Result<(), String> do
  if blocked do
    Ok(nil)
  else
    observe_gossip(database_path, wrapping_key, inner, current_time()?)?
    let (labels, blobs, removed) = learned_contact_address_writes(database_path,
      wrapping_key,
      public_address,
      inner.extensions)?
    if List.length(labels) == 0 do
      Ok(nil)
    else
      store_record_changes(database_path, labels, blobs, removed)
    end
  end
end

## View-once admission owns its own durable boundary. Do not apply unrelated
## contact or gossip writes for its new, duplicate, or refused carriers.
fn keep_ordinary_contact(database_path :: String,
  wrapping_key :: borrow StorageKey,
  prepared :: PreparedReceivedHistory,
  public_address :: Bytes,
  inner :: InnerEnvelope) -> Unit!String do
  if prepared.kind == HistoryOrdinary do
    keep_contact_address(database_path, wrapping_key, false, public_address, inner)
  else
    Ok(nil)
  end
end

fn peer_sync_payload(body :: Bytes, local_account_id :: Bytes) -> MobileSyncPayload!String do
  let sync = parse_sync_payload(body)?
  if Bytes.secure_equals(sync.peer_account_id, local_account_id) do
    Err("invalid_sync_payload")
  else
    Ok(sync)
  end
end

pub fn receive_initial_message(request :: MobileReceiveRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let local_encode_client_profile = load_profile(request.database_path)?
  let local = decode_client_profile(local_encode_client_profile)?
  let outer = canonical_outer(request.outer)?
  if !Bytes.secure_equals(outer.mailbox_token, local.entry.mailbox_token) do
    Err("wrong_mailbox")
  else
    let wrapping_key = platform_key()?
    require_log_changes_allowed(request.database_path, wrapping_key)?
    let local_device = open_device(local, wrapping_key, request.database_path)?
    let opened = open_outer_packet(outer, local_device.identity_private_key)?
    let (packet_account_identity, packet_message) = if opened.sealed do
      parse_sealed_initial_packet(opened.packet)
    else
      # Legacy queued initial packets carry their own recipient seal.
      parse_initial_packet(outer.ciphertext, local_device.identity_private_key)
    end?
    let initial = case decode_initial_message(packet_message) do
      Err(_) -> Err("invalid_initial_message")
      Ok(value)
    end?
    # A sealed outer suite names only the transport; the handshake transcript
    # authenticates the real suite.
    if !opened.sealed && outer.suite != initial.suite do
      Err("outer_suite_mismatch")
    else
      let initiator_account = case decode_account_identity(packet_account_identity) do
        Err(_) -> Err("invalid_initiator_account")
        Ok(value)
      end?
      let admission_before = Some(capture_header_initial(request.database_path,
        wrapping_key,
        local_encode_client_profile,
        initial.one_time_prekey_id)?)
      let session_ids = load_session_ids(request.database_path, wrapping_key)?
      let initial_sources = case admission_before do
        None -> Err("invalid_receive_basis")
        Some(before) -> capture_receive_sessions(request.database_path,
          wrapping_key,
          before,
          session_ids)
      end?
      let session_policy = capture_native_session_policy()?
      if initial.version == 2 do
        require_new_header_capacity(List.length(session_ids), 1)?
      end
      let prekeys = load_prekey_pool(local, wrapping_key, request.database_path)?
      let active_prekeys = load_active_prekey_pool(request.database_path, prekeys, wrapping_key)?
      let last_resort = find_last_resort_prekey(request.database_path,
        wrapping_key,
        initial.one_time_prekey_id)?
      let reusable = case last_resort do
        None -> false
        Some(_) -> true
      end
      let selected_prekey = case last_resort do
        Some(value) -> Ok(value)
        None -> find_prekey(prekeys, initial.one_time_prekey_id, 0)
      end?
      if reusable
        && last_resort_replayed(request.database_path, wrapping_key, initial.transcript_hash)? do
        Err("replayed_initial_message")
      else
        Ok(nil)
      end?
      let initiator_credential = case decode_device_credential(initial.initiator_credential) do
        Err(_) -> Err("invalid_initiator_credential")
        Ok(value)
      end?
      let strongest_suite = receive_captured_strongest(initial_sources,
        wrapping_key,
        initiator_account.account_id,
        initiator_credential.device_id)?
      # The bundle this message was sealed to: the current one, or one renewed
      # away from recently enough that its mail may still arrive.
      let responder_bundle = responder_prekey_bundle(request.database_path,
        wrapping_key,
        local,
        selected_prekey,
        strongest_suite,
        packet_message)?
      let (signed, one_time, post_quantum) = open_bundle_prekeys(local,
        wrapping_key,
        request.database_path,
        responder_bundle,
        selected_prekey)?
      let now = current_time()?
      let (state, plaintext) = case receive_initial_at_minimum_suite(local_device,
        local.account,
        responder_bundle,
        signed,
        one_time,
        post_quantum,
        initiator_account,
        own_bundle_policy(local, responder_bundle, now),
        VerificationPolicy {
          current_time: now,
          minimum_directory_sequence: initiator_account.directory_sequence
        },
        strongest_suite,
        native_session_minimum(session_policy)?,
        packet_message) do
        Err(error) -> if is_retryable_session_error(error) do
          Err("initial_crypto_failed")
        else
          Err("initial_receive_failed")
        end
        Ok(value)
      end?
      let decoded = case decode_initial_plaintext(plaintext) do
        Err(_) -> Err("invalid_initial_plaintext")
        Ok(value)
      end?
      let peer = case decode_client_profile(decoded.profile) do
        Err(_) -> Err("invalid_peer_profile")
        Ok(value)
      end?
      let inner = case decode_inner_envelope(decoded.inner) do
        Err(_) -> Err("invalid_inner_envelope")
        Ok(value)
      end?
      let previous = case receive_captured_peer(initial_sources, wrapping_key, peer.account_id) do
        Ok(loaded) -> Ok(Some(loaded))
        Err(error) -> if error == "session_not_found" do
          Ok(None)
        else
          Err(error)
        end
      end?
      let self_sync = inner.message_type == 2
        && Bytes.secure_equals(peer.account_id, local.account_id)
      let valid_kind = self_sync
        || ((inner.message_type == 1 || inner.message_type == 3 || inner.message_type == 4)
          && !Bytes.secure_equals(peer.account_id, local.account_id))
      let expected_conversation = if self_sync do
        self_sync_conversation_id(local.account_id)?
      else
        direct_conversation_id(local.account_id, peer.account_id)?
      end
      # A conversation from before names were derived still goes by the name
      # in this device's record, so what was in flight at an upgrade arrives.
      let conversation_mismatch = !Bytes.secure_equals(inner.conversation_id, expected_conversation)
        && case previous do
          None -> true
          Some(loaded) -> !Bytes.secure_equals(inner.conversation_id, loaded.record.conversation_id)
        end
      # The name this device files the conversation under is its own records'
      # business; a wire name only ever adds to what is already here.
      let conversation_key = case previous do
        None -> inner.conversation_id
        Some(loaded) -> loaded.record.conversation_id
      end
      let mismatch = !valid_kind
        || conversation_mismatch
        || !Bytes.secure_equals(peer.entry.account_identity, packet_account_identity)
        || !Bytes.secure_equals(inner.sender_account_id, peer.account_id)
        || !Bytes.secure_equals(inner.sender_device_id, peer.device_id)
        || !Bytes.secure_equals(peer.device_id, initiator_credential.device_id)
        || !Bytes.secure_equals(inner.recipient_device_id, local.device_id)
      if mismatch do
        Err("initial_identity_mismatch")
      else
        let blocked = case previous do
          None -> false
          Some(loaded) -> loaded.record.blocked
        end
        let (session_id, label, session_blob) = case previous do
          None -> seal_session(state, wrapping_key, local, peer, inner.conversation_id, 0, false)
          Some(loaded) -> seal_upgraded_session(state, wrapping_key, loaded, local, peer)
        end?
        let (removed_labels, prekey_labels, prekey_blobs) = received_prekey_writes(request.database_path,
          wrapping_key,
          prekeys,
          active_prekeys,
          selected_prekey.id,
          reusable,
          initial.transcript_hash,
          matching_fanout_prekey_state_labels(request.database_path,
            wrapping_key,
            peer,
            initial.suite)?)?
        if blocked do
          let index_blob = updated_session_index(request.database_path, wrapping_key, session_id)?
          commit_initial_admission_at_policy(request.database_path,
            admission_before,
            Some(initial_sources),
            session_policy,
            label,
            session_blob,
            index_blob,
            List.new(),
            List.new(),
            removed_labels,
            prekey_labels,
            prekey_blobs)?
          Err("blocked_message")
        else if self_sync do
          let sync = peer_sync_payload(inner.body, local.account_id)?
          let acceptance_sources = capture_receive_alias(request.database_path,
            wrapping_key,
            initial_sources,
            sync.peer_account_id)?
          let (synced_key, index_blob, alias_labels, alias_blobs) = prepared_header_initial_alias(request.database_path,
            wrapping_key,
            local,
            sync,
            session_ids,
            session_id,
            initial.version == 2)?
          let synced = sync_history_inner(local, sync, inner.attachment_manifest)?
          let history_inner = %{synced | conversation_id: synced_key}
          let admission_before = capture_header_history(request.database_path,
            admission_before,
            synced_key)?
          let before = required_receive_basis(admission_before)?
          let prepared = prepare_received_history(request.database_path,
            wrapping_key,
            local_device,
            local,
            before,
            inner,
            sync.conversation_id,
            sync.peer_account_id,
            history_inner,
            1)?
          keep_ordinary_contact(request.database_path,
            wrapping_key,
            prepared,
            peer.entry.mailbox_token,
            inner)?
          let (history_keys, history_blobs) = received_history_writes(request.database_path,
            wrapping_key,
            prepared,
            history_inner,
            1)?
          # A sibling device could only send this once the request was accepted there.
          let (sync_labels, sync_blobs) = sync_side_effects(wrapping_key,
            sync.peer_account_id,
            acceptance_sources,
            prepared.duplicate,
            alias_labels,
            alias_blobs)?
          let index_blob = sync_initial_index(request.database_path,
            wrapping_key,
            session_id,
            prepared.duplicate,
            index_blob)?
          commit_initial_admission_at_policy(request.database_path,
            Some(prepared.basis),
            Some(acceptance_sources),
            session_policy,
            label,
            session_blob,
            index_blob,
            history_keys ++ sync_labels,
            history_blobs ++ sync_blobs,
            removed_labels,
            prekey_labels,
            prekey_blobs)?
          Ok(received_history_body(prepared, history_inner.body))
        else if inner.message_type == 3 || inner.message_type == 4 do
          require_control_without_view_once(inner)?
          keep_contact_address(request.database_path,
            wrapping_key,
            false,
            peer.entry.mailbox_token,
            inner)?
          let (labels, blobs) = received_invitation_writes(request.database_path,
            wrapping_key,
            local,
            peer.username,
            inner)?
          commit_initial_admission_at_policy(request.database_path,
            admission_before,
            Some(initial_sources),
            session_policy,
            label,
            session_blob,
            updated_session_index(request.database_path, wrapping_key, session_id)?,
            labels,
            blobs,
            removed_labels,
            prekey_labels,
            prekey_blobs)?
          Ok(Bytes.empty())
        else
          let index_blob = updated_session_index(request.database_path, wrapping_key, session_id)?
          let admission_before = capture_header_history(request.database_path,
            admission_before,
            conversation_key)?
          let before = required_receive_basis(admission_before)?
          let prepared = prepare_received_history(request.database_path,
            wrapping_key,
            local_device,
            local,
            before,
            inner,
            inner.conversation_id,
            inner.sender_account_id,
            %{inner | conversation_id: conversation_key},
            2)?
          keep_ordinary_contact(request.database_path,
            wrapping_key,
            prepared,
            peer.entry.mailbox_token,
            inner)?
          let (history_keys, history_blobs) = received_history_writes(request.database_path,
            wrapping_key,
            prepared,
            %{inner | conversation_id: conversation_key},
            2)?
          commit_initial_admission_at_policy(request.database_path,
            Some(prepared.basis),
            Some(initial_sources),
            session_policy,
            label,
            session_blob,
            index_blob,
            history_keys,
            history_blobs,
            removed_labels,
            prekey_labels,
            prekey_blobs)?
          Ok(received_history_body(prepared, inner.body))
        end
      end
    end
  end
end

pub fn send_message(request :: MobileStartRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let local_wire = load_profile(request.database_path)?
  let local = decode_client_profile(local_wire)?
  let requested_peer = decode_client_profile(request.peer_profile)?
  let wrapping_key = platform_key()?
  require_direct_headers(request.database_path, wrapping_key, local, requested_peer)?
  let attachment_before = Some(capture_direct_attachment(request.database_path,
    wrapping_key,
    local_wire,
    requested_peer)?)
  if Bytes.length(request.attachment) > 0 do
    require_direct_attachment(request.database_path,
      wrapping_key,
      local,
      requested_peer,
      request.attachment)?
  end
  let pending_ids = load_outbox_ids(request.database_path, wrapping_key)?
  if List.length(pending_ids) >= outbox_capacity() do
    Err("outbox_full")
  else
    Ok(nil)
  end?
  let session_ids = load_session_ids(request.database_path, wrapping_key)?
  let loaded = find_peer_session(request.database_path,
    wrapping_key,
    requested_peer.account_id,
    session_ids,
    0)?
  let changed = !Bytes.secure_equals(loaded.record.peer_device_id, requested_peer.device_id)
    || !Bytes.secure_equals(loaded.record.peer_mailbox, requested_peer.entry.mailbox_token)
    || (Bytes.length(loaded.record.safety_number) == 64
      && !Bytes.secure_equals(loaded.record.safety_number, safety_number(local, requested_peer)?))
  if changed do
    Err("peer_keys_changed")
  else if loaded.record.strongest_suite > requested_peer.bundle.suite do
    Err("peer_keys_changed")
  else if !session_uses_headers(loaded.record.snapshot)
    || loaded.record.strongest_suite < requested_peer.bundle.suite
    || Bytes.length(loaded.record.safety_number) == 0 do
    Err("session_upgrade_required")
  else if loaded.record.blocked do
    Err("conversation_blocked")
  else if loaded.record.request_state != 1 do
    Err("message_request_pending")
  else
    let state = restore_session(loaded, wrapping_key)?
    let now = current_time()?
    let history_inner = InnerEnvelope {
      version: 1,
      sender_account_id: local.account_id,
      sender_device_id: local.device_id,
      recipient_device_id: loaded.record.peer_device_id,
      conversation_id: loaded.record.conversation_id,
      client_message_id: random_bytes(16)?,
      client_timestamp: now,
      message_type: 1,
      body: request.body,
      reply_reference: Bytes.empty(),
      attachment_manifest: request.attachment,
      receipt_policy: 0,
      disappearing_seconds: loaded.record.disappearing_seconds,
      extensions: List.new()
    }
    let inner = if Bytes.length(request.attachment) == 0 do
      Ok(history_inner)
    else
      let local_device = open_device(local, wrapping_key, request.database_path)?
      Ok(%{history_inner |
        attachment_manifest: rewrap_reference(local_device,
          request.attachment,
          requested_peer.credential.dh_public_key)?
      })
    end?
    # The sent copy hands over this device's contact address; history does not keep it.
    let handed_over = direct_extensions(request.database_path, wrapping_key)?
    let wire_conversation_id = direct_conversation_id(local.account_id, requested_peer.account_id)?
    let (next_state, message) = case encrypt_sealed(state,
      inner_bytes(%{inner | conversation_id: wire_conversation_id, extensions: handed_over})?,
      session_aad(loaded.session_id)?) do
      Err(_) -> Err("message_encryption_failed")
      Ok(value)
    end?
    let packet = encode_packet(RatchetPacket(ratchet_bytes(message)?))?
    let outer = sealed_outer_bytes(deposit_address(request.database_path,
        wrapping_key,
        loaded.record.peer_mailbox)?,
      packet,
      requested_peer.credential.dh_public_key,
      now)?
    let session_blob = seal_updated_session(next_state,
      %{loaded |
        record: %{loaded.record | peer_transport_key: requested_peer.credential.dh_public_key}
      },
      wrapping_key)?
    let (history_keys, history_blobs) = updated_history(request.database_path,
      wrapping_key,
      history_inner,
      1)?
    let prepared = [
      MobilePreparedSend {
        envelope: outer,
        session_id: loaded.session_id,
        session_label: loaded.label,
        session_blob: session_blob,
        new_session: false
      }
    ]
    let (outbox_labels, outbox_blobs, outbox_index_blob) = prepare_outbox_writes(wrapping_key,
      pending_ids,
      [outer],
      request.database_path,
      history_inner.client_message_id,
      0,
      1,
      local)?
    commit_direct_attachment(request.database_path,
      attachment_before,
      prepared,
      List.new(),
      seal_session_ids(session_ids, wrapping_key)?,
      history_keys,
      history_blobs,
      outbox_labels,
      outbox_blobs,
      outbox_index_blob)?
    Ok(outer)
  end
end

fn reject_message(state :: consume RatchetState, error :: String) -> Bytes!String do
  Err(error)
end

fn capture_received_history(path :: String,
  selected :: Option<HeaderRoute>,
  legacy_before :: Option<AccountBasis>,
  conversation :: Bytes) -> Result<(Option<HeaderRoute>, Option<AccountBasis>), String> do
  case selected do
    None -> case legacy_before do
      None -> Err("invalid_receive_basis")
      Some(before) -> Ok((None, capture_header_history(path, Some(before), conversation)?))
    end
    Some(route) -> case capture_header_history(path, Some(route.basis), conversation)? do
      None -> Err("invalid_header_receive_basis")
      Some(basis) -> Ok((Some(%{route | basis: basis}), None))
    end
  end
end

fn capture_received_acceptance(path :: String,
  key :: borrow StorageKey,
  selected :: Option<HeaderRoute>,
  legacy_before :: Option<AccountBasis>,
  ids :: List<Bytes>,
  peer :: Bytes) -> ReceiveSources!String do
  let before = case selected do
    Some(route) -> Ok(route.basis)
    None -> case legacy_before do
      Some(value) -> Ok(value)
      None -> Err("invalid_receive_basis")
    end
  end?
  capture_receive_sources(path, key, before, ids, peer)
end

fn selected_receive_basis(selected :: Option<HeaderRoute>,
  legacy_before :: Option<AccountBasis>) -> AccountBasis!String do
  case selected do
    Some(route) -> Ok(route.basis)
    None -> case legacy_before do
      Some(before) -> Ok(before)
      None -> Err("invalid_receive_basis")
    end
  end
end

fn with_received_basis(selected :: Option<HeaderRoute>,
  before :: AccountBasis) -> (Option<HeaderRoute>, Option<AccountBasis>) do
  case selected do
    Some(route) -> (Some(%{route | basis: before}), None)
    None -> (None, Some(before))
  end
end

fn commit_received(path :: String,
  selected :: Option<HeaderRoute>,
  legacy_before :: Option<AccountBasis>,
  labels :: List<String>,
  blobs :: List<Bytes>) -> Result<(), String> do
  commit_received_with_sources(path, selected, legacy_before, None, labels, blobs)
end

fn commit_received_with_sources(path :: String,
  selected :: Option<HeaderRoute>,
  legacy_before :: Option<AccountBasis>,
  sources :: Option<ReceiveSources>,
  labels :: List<String>,
  blobs :: List<Bytes>) -> Result<(), String> do
  case selected do
    None -> case legacy_before do
      None -> Err("invalid_receive_basis")
      Some(before) -> commit_legacy_receive_with_sources(path, before, sources, labels, blobs)
    end
    Some(route) -> commit_header_receive_with_sources(path, route, sources, labels, blobs)
  end
end

pub fn receive_message(request :: MobileReceiveRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let local_wire = load_profile(request.database_path)?
  let local = decode_client_profile(local_wire)?
  let outer = canonical_outer(request.outer)?
  if !Bytes.secure_equals(outer.mailbox_token, local.entry.mailbox_token) do
    Err("wrong_mailbox")
  else
    let wrapping_key = platform_key()?
    let local_device = open_device(local, wrapping_key, request.database_path)?
    let opened = open_outer_packet(outer, local_device.identity_private_key)?
    let packet_message = parse_ratchet_packet(opened.packet)?
    let message = case decode_ratchet_message(packet_message) do
      Err(_) -> Err("invalid_ratchet_message")
      Ok(value)
    end?
    if !ratchet_transport_matches(message, opened.sealed) do
      Err("invalid_ratchet_message")
    else if !opened.sealed && outer.suite != message.suite do
      Err("outer_suite_mismatch")
    else
      Ok(nil)
    end?
    let selected = if message.version == 4 do
      Some(route_header_guarded(request.database_path,
        wrapping_key,
        outer.envelope_id,
        packet_message,
        message,
        local_wire)?)
    else
      None
    end
    let legacy_before = case selected do
      Some(_) -> None
      None -> Some(capture_legacy_receive(request.database_path,
        wrapping_key,
        local_wire,
        message.session_id)?)
    end
    let loaded = case selected do
      Some(route) -> route.loaded
      None -> load_session_record(request.database_path, wrapping_key, message.session_id)?
    end
    let session_ids = load_session_ids(request.database_path, wrapping_key)?
    let peer_policy = find_peer_session(request.database_path,
      wrapping_key,
      loaded.record.peer_account_id,
      session_ids,
      0)?
    let state = restore_session(loaded, wrapping_key)?
    case decrypt(state, message, session_aad(loaded.session_id)?) do
      Rejected(rejected_state, error) -> if is_retryable_ratchet_error(error) do
        reject_message(rejected_state, "ratchet_retryable")
      else
        reject_message(rejected_state, "message_rejected")
      end
      Opened(next_state, plaintext) -> do
        let inner = case decode_inner_envelope(plaintext) do
          Err(_) -> Err("invalid_inner_envelope")
          Ok(value)
        end?
        let self_sync = inner.message_type == 2
          && Bytes.secure_equals(loaded.record.peer_account_id, local.account_id)
        let valid_kind = self_sync
          || inner.message_type == 5
          || ((inner.message_type == 1 || inner.message_type == 3 || inner.message_type == 4)
            && !Bytes.secure_equals(loaded.record.peer_account_id, local.account_id))
        let expected_conversation = if Bytes.secure_equals(loaded.record.peer_account_id,
          local.account_id) do
          self_sync_conversation_id(local.account_id)?
        else
          direct_conversation_id(local.account_id, loaded.record.peer_account_id)?
        end
        let mismatch = !valid_kind
          || !Bytes.secure_equals(inner.sender_account_id, loaded.record.peer_account_id)
          || !Bytes.secure_equals(inner.sender_device_id, loaded.record.peer_device_id)
          || !Bytes.secure_equals(inner.recipient_device_id, local.device_id)
          || (!Bytes.secure_equals(inner.conversation_id, expected_conversation)
            && !Bytes.secure_equals(inner.conversation_id, loaded.record.conversation_id))
        if mismatch do
          reject_message(next_state, "message_rejected")
        else
          let session_blob = seal_updated_session(next_state, loaded, wrapping_key)?
          if peer_policy.record.blocked do
            commit_received(request.database_path,
              selected,
              legacy_before,
              [loaded.label],
              [session_blob])?
            Err("blocked_message")
          else if inner.message_type == 5 do
            require_control_without_view_once(inner)?
            keep_contact_address(request.database_path,
              wrapping_key,
              false,
              loaded.record.peer_mailbox,
              inner)?
            commit_received(request.database_path,
              selected,
              legacy_before,
              [loaded.label],
              [session_blob])?
            Ok(Bytes.empty())
          else if inner.message_type == 3 || inner.message_type == 4 do
            require_control_without_view_once(inner)?
            keep_contact_address(request.database_path,
              wrapping_key,
              false,
              loaded.record.peer_mailbox,
              inner)?
            let (labels, blobs) = received_invitation_writes(request.database_path,
              wrapping_key,
              local,
              loaded.record.peer_username,
              inner)?
            commit_received(request.database_path,
              selected,
              legacy_before,
              List.append(labels, loaded.label),
              List.append(blobs, session_blob))?
            Ok(Bytes.empty())
          else if self_sync do
            let sync = peer_sync_payload(inner.body, local.account_id)?
            let acceptance_sources = capture_received_acceptance(request.database_path,
              wrapping_key,
              selected,
              legacy_before,
              session_ids,
              sync.peer_account_id)?
            let (synced_key, alias_labels, alias_blobs) = prepared_conversation_alias(request.database_path,
              wrapping_key,
              local,
              sync,
              session_ids)?
            let synced = sync_history_inner(local, sync, inner.attachment_manifest)?
            let history_inner = %{synced | conversation_id: synced_key}
            let (selected, legacy_before) = capture_received_history(request.database_path,
              selected,
              legacy_before,
              synced_key)?
            let prepared = prepare_received_history(request.database_path,
              wrapping_key,
              local_device,
              local,
              selected_receive_basis(selected, legacy_before)?,
              inner,
              sync.conversation_id,
              sync.peer_account_id,
              history_inner,
              1)?
            keep_ordinary_contact(request.database_path,
              wrapping_key,
              prepared,
              loaded.record.peer_mailbox,
              inner)?
            let (selected, legacy_before) = with_received_basis(selected, prepared.basis)
            let (history_keys, history_blobs) = received_history_writes(request.database_path,
              wrapping_key,
              prepared,
              history_inner,
              1)?
            # A sibling device could only send this once the request was accepted there.
            let (sync_labels, sync_blobs) = sync_side_effects(wrapping_key,
              sync.peer_account_id,
              acceptance_sources,
              prepared.duplicate,
              alias_labels,
              alias_blobs)?
            commit_received_with_sources(request.database_path,
              selected,
              legacy_before,
              Some(acceptance_sources),
              [loaded.label] ++ history_keys ++ sync_labels,
              [session_blob] ++ history_blobs ++ sync_blobs)?
            Ok(received_history_body(prepared, history_inner.body))
          else
            let (selected, legacy_before) = capture_received_history(request.database_path,
              selected,
              legacy_before,
              loaded.record.conversation_id)?
            let prepared = prepare_received_history(request.database_path,
              wrapping_key,
              local_device,
              local,
              selected_receive_basis(selected, legacy_before)?,
              inner,
              inner.conversation_id,
              inner.sender_account_id,
              %{inner | conversation_id: loaded.record.conversation_id},
              2)?
            keep_ordinary_contact(request.database_path,
              wrapping_key,
              prepared,
              loaded.record.peer_mailbox,
              inner)?
            let (selected, legacy_before) = with_received_basis(selected, prepared.basis)
            let (history_keys, history_blobs) = received_history_writes(request.database_path,
              wrapping_key,
              prepared,
              %{inner | conversation_id: loaded.record.conversation_id},
              2)?
            commit_received(request.database_path,
              selected,
              legacy_before,
              [loaded.label] ++ history_keys,
              [session_blob] ++ history_blobs)?
            Ok(received_history_body(prepared, inner.body))
          end
        end
      end
    end
  end
end
