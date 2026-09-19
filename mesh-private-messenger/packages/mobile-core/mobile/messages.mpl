from Identity.Device import DeviceKeys, VerificationPolicy
from Mobile.Codec import canonical_outer, current_time, outer_bytes, random_bytes
from Mobile.FanoutPrekeys import matching_fanout_prekey_state_labels
from Mobile.History import updated_history
from Mobile.GroupInvitesState import received_invitation_writes
from Mobile.Outbox import load_outbox_ids, prepare_outbox_writes
from Mobile.Prekeys import (
  find_prekey,
  load_active_prekey_pool,
  load_prekey_pool,
  remove_prekey,
  remove_prekey_id,
  seal_active_prekey_pool,
  seal_prekey_pool
)
from Mobile.Profile import load_profile, open_device, open_prekeys, policy
from Mobile.Sessions import (
  ensure_conversation_alias,
  find_peer_session,
  initial_bytes,
  inner_bytes,
  load_session_ids,
  load_session_record,
  parse_initial_packet,
  parse_ratchet_packet,
  parse_sync_payload,
  prepared_session_ids,
  ratchet_bytes,
  restore_session,
  safety_number,
  seal_session,
  seal_session_ids,
  seal_updated_session,
  seal_upgraded_session,
  strongest_device_suite,
  sync_history_inner,
  updated_session_index
)
from Mobile.Types import (
  MobileLoadedSession,
  MobileOneTimePrekey,
  MobilePreparedSend,
  MobileReceiveRequest,
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
  RatchetState,
  SessionError,
  initiate,
  is_retryable_session_error,
  receive_initial
)
from Session.Ratchet import (
  DecryptOutcome,
  RatchetError,
  RatchetMessage,
  decode_ratchet_message,
  decrypt,
  encrypt,
  is_retryable_ratchet_error
)
from Storage.Blobs import ensure_schema
from Storage.Keys import one_time_prekey_label, platform_key
from Storage.Records import (
  store_outbound,
  store_received_session,
  store_updated_session,
  store_updated_blobs,
  store_updated_session_and_history
)
from Transport.Packet import (
  ClientProfile,
  TransportPacket,
  decode_client_profile,
  decode_initial_plaintext,
  encode_initial_plaintext,
  encode_packet,
  seal_initial_packet,
  session_aad
)

##! Mobile.Messages implementation.

pub fn start_conversation(request :: MobileStartRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local_encode_client_profile = load_profile(request.database_path) ?
  let local = decode_client_profile(local_encode_client_profile) ?
  let peer = decode_client_profile(request.peer_profile) ?
  let wrapping_key = platform_key() ?
  let pending_ids = load_outbox_ids(request.database_path, wrapping_key) ?
  let _ = if List.length(pending_ids) >= 64 do
    Err("outbox_full")
  else
    Ok(nil)
  end ?
  let session_ids = load_session_ids(request.database_path, wrapping_key) ?
  let local_device = open_device(local, wrapping_key, request.database_path) ?
  let now = current_time() ?
  let conversation_id = random_bytes(16) ?
  let inner = InnerEnvelope {
    version : 1,
    sender_account_id : local.account_id,
    sender_device_id : local.device_id,
    recipient_device_id : peer.device_id,
    conversation_id : conversation_id,
    client_message_id : random_bytes(16) ?,
    client_timestamp : now,
    message_type : 1,
    body : request.body,
    reply_reference : Bytes.empty(),
    attachment_manifest : Bytes.empty(),
    receipt_policy : 0,
    disappearing_seconds : 0,
    extensions : List.new()
  }
  let plaintext = case encode_initial_plaintext(local_encode_client_profile, inner_bytes(inner) ?) do
    Err( _) -> Err("invalid_initial_plaintext")
    Ok( value) -> Ok(value)
  end ?
  let strongest_suite = strongest_device_suite(request.database_path,
  wrapping_key,
  peer.account_id,
  peer.device_id,
  session_ids,
  0,
  0) ?
  let ( state, initial) = case initiate(local_device,
  local.credential,
  peer.account,
  peer.bundle,
  policy(peer, now),
  strongest_suite,
  plaintext) do
    Err( _) -> Err("session_start_failed")
    Ok( value) -> Ok(value)
  end ?
  let packet = seal_initial_packet(local.entry.account_identity,
  initial_bytes(initial) ?,
  X25519PublicKey { bytes : peer.credential.dh_public_key }) ?
  let outer = outer_bytes(peer.entry.mailbox_token, initial.suite, packet, now) ?
  let ( session_id, label, session_blob) = seal_session(state,
  wrapping_key,
  local,
  peer,
  conversation_id,
  1,
  false) ?
  let prepared = [MobilePreparedSend {
    envelope : outer,
    session_id : session_id,
    session_label : label,
    session_blob : session_blob,
    new_session : true
  }]
  let index_blob = seal_session_ids(prepared_session_ids(prepared, 0, session_ids), wrapping_key) ?
  let ( history_key, history_blob) = updated_history(request.database_path, wrapping_key, inner, 1) ?
  let ( outbox_labels, outbox_blobs, outbox_index_blob) = prepare_outbox_writes(wrapping_key,
  pending_ids,
  [outer]) ?
  store_outbound(request.database_path,
  prepared,
  List.new(),
  index_blob,
  [history_key],
  [history_blob],
  outbox_labels,
  outbox_blobs,
  outbox_index_blob) ?
  Ok(outer)
end

pub fn receive_initial_message(request :: MobileReceiveRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local_encode_client_profile = load_profile(request.database_path) ?
  let local = decode_client_profile(local_encode_client_profile) ?
  let outer = canonical_outer(request.outer) ?
  if !Bytes.secure_equals(outer.mailbox_token, local.entry.mailbox_token) do
    Err("wrong_mailbox")
  else
    let wrapping_key = platform_key() ?
    let local_device = open_device(local, wrapping_key, request.database_path) ?
    let ( packet_account_identity, packet_message) = parse_initial_packet(outer.ciphertext,
    local_device.identity_private_key) ?
    let initial = case decode_initial_message(packet_message) do
      Err( _) -> Err("invalid_initial_message")
      Ok( value) -> Ok(value)
    end ?
    if outer.suite != initial.suite do
      Err("outer_suite_mismatch")
    else
      let initiator_account = case decode_account_identity(packet_account_identity) do
        Err( _) -> Err("invalid_initiator_account")
        Ok( value) -> Ok(value)
      end ?
      let session_ids = load_session_ids(request.database_path, wrapping_key) ?
      let prekeys = load_prekey_pool(local, wrapping_key, request.database_path) ?
      let active_prekeys = load_active_prekey_pool(request.database_path, prekeys, wrapping_key) ?
      let selected_prekey = find_prekey(prekeys, initial.one_time_prekey_id, 0) ?
      let responder_bundle = % { local.bundle | one_time_prekey_id : selected_prekey.id, one_time_prekey : selected_prekey.public_key }
      let initiator_credential = case decode_device_credential(initial.initiator_credential) do
        Err( _) -> Err("invalid_initiator_credential")
        Ok( value) -> Ok(value)
      end ?
      let strongest_suite = strongest_device_suite(request.database_path,
      wrapping_key,
      initiator_account.account_id,
      initiator_credential.device_id,
      session_ids,
      0,
      0) ?
      let ( signed, one_time, post_quantum) = open_prekeys(local,
      wrapping_key,
      request.database_path,
      selected_prekey) ?
      let now = current_time() ?
      let ( state, plaintext) = case receive_initial(local_device,
      local.account,
      responder_bundle,
      signed,
      one_time,
      post_quantum,
      initiator_account,
      policy(local, now),
      VerificationPolicy {
        current_time : now,
        minimum_directory_sequence : initiator_account.directory_sequence
      },
      strongest_suite,
      packet_message) do
        Err( error) -> if is_retryable_session_error(error) do
          Err("initial_crypto_failed")
        else
          Err("initial_receive_failed")
        end
        Ok( value) -> Ok(value)
      end ?
      let decoded = case decode_initial_plaintext(plaintext) do
        Err( _) -> Err("invalid_initial_plaintext")
        Ok( value) -> Ok(value)
      end ?
      let peer = case decode_client_profile(decoded.profile) do
        Err( _) -> Err("invalid_peer_profile")
        Ok( value) -> Ok(value)
      end ?
      let inner = case decode_inner_envelope(decoded.inner) do
        Err( _) -> Err("invalid_inner_envelope")
        Ok( value) -> Ok(value)
      end ?
      let previous = case find_peer_session(request.database_path,
      wrapping_key,
      peer.account_id,
      session_ids,
      0) do
        Ok( loaded) -> Ok(Some(loaded))
        Err( error) -> if error == "session_not_found" do
          Ok(None)
        else
          Err(error)
        end
      end ?
      let self_sync = inner.message_type == 2 && Bytes.secure_equals(peer.account_id,
      local.account_id)
      let valid_kind = self_sync || ((inner.message_type == 1 || inner.message_type == 3 || inner.message_type == 4) && !Bytes.secure_equals(peer.account_id,
      local.account_id))
      let conversation_mismatch = case previous do
        None -> false
        Some( loaded) -> !Bytes.secure_equals(inner.conversation_id, loaded.record.conversation_id)
      end
      let mismatch = !valid_kind || conversation_mismatch || !Bytes.secure_equals(peer.entry.account_identity,
      packet_account_identity) || !Bytes.secure_equals(inner.sender_account_id, peer.account_id) || !Bytes.secure_equals(inner.sender_device_id,
      peer.device_id) || !Bytes.secure_equals(peer.device_id, initiator_credential.device_id) || !Bytes.secure_equals(inner.recipient_device_id,
      local.device_id)
      if mismatch do
        Err("initial_identity_mismatch")
      else
        let blocked = case previous do
          None -> false
          Some( loaded) -> loaded.record.blocked
        end
        let ( session_id, label, session_blob) = case previous do
          None -> seal_session(state, wrapping_key, local, peer, inner.conversation_id, 0, false)
          Some( loaded) -> seal_upgraded_session(state, wrapping_key, loaded, local, peer)
        end ?
        let remaining_prekeys = remove_prekey(prekeys, selected_prekey.id, 0, List.new())
        let prekey_index_blob = seal_prekey_pool(remaining_prekeys, wrapping_key) ?
        let prekey_active_blob = seal_active_prekey_pool(remove_prekey_id(active_prekeys,
        selected_prekey.id,
        0,
        List.new()),
        wrapping_key) ?
        let prekey_label = one_time_prekey_label(selected_prekey.id)
        let removed_labels = List.append(matching_fanout_prekey_state_labels(request.database_path,
        wrapping_key,
        peer,
        initial.suite) ?,
        prekey_label)
        if blocked do
          let index_blob = updated_session_index(request.database_path, wrapping_key, session_id) ?
          store_received_session(request.database_path,
          label,
          session_blob,
          index_blob,
          List.new(),
          List.new(),
          removed_labels,
          prekey_index_blob,
          prekey_active_blob) ?
          Err("blocked_message")
        else if self_sync do
          let sync = parse_sync_payload(inner.body) ?
          if Bytes.secure_equals(sync.peer_account_id, local.account_id) do
            Err("invalid_sync_payload")
          else
            let history_inner = sync_history_inner(local, sync) ?
            ensure_conversation_alias(request.database_path, wrapping_key, local, sync) ?
            let index_blob = updated_session_index(request.database_path, wrapping_key, session_id) ?
            let ( history_key, history_blob) = updated_history(request.database_path,
            wrapping_key,
            history_inner,
            1) ?
            store_received_session(request.database_path,
            label,
            session_blob,
            index_blob,
            [history_key],
            [history_blob],
            removed_labels,
            prekey_index_blob,
            prekey_active_blob) ?
            Ok(history_inner.body)
          end
        else if inner.message_type == 3 || inner.message_type == 4 do
          let (labels, blobs) = received_invitation_writes(request.database_path, wrapping_key,
            local, peer.username, inner) ?
          store_received_session(request.database_path, label, session_blob,
            updated_session_index(request.database_path, wrapping_key, session_id) ?,
            labels, blobs, removed_labels, prekey_index_blob, prekey_active_blob) ?
          Ok(Bytes.empty())
        else
          let index_blob = updated_session_index(request.database_path, wrapping_key, session_id) ?
          let ( history_key, history_blob) = updated_history(request.database_path,
          wrapping_key,
          inner,
          2) ?
          store_received_session(request.database_path,
          label,
          session_blob,
          index_blob,
          [history_key],
          [history_blob],
          removed_labels,
          prekey_index_blob,
          prekey_active_blob) ?
          Ok(inner.body)
        end
      end
    end
  end
end

pub fn send_message(request :: MobileStartRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local = decode_client_profile(load_profile(request.database_path) ?) ?
  let requested_peer = decode_client_profile(request.peer_profile) ?
  let wrapping_key = platform_key() ?
  let pending_ids = load_outbox_ids(request.database_path, wrapping_key) ?
  let _ = if List.length(pending_ids) >= 64 do
    Err("outbox_full")
  else
    Ok(nil)
  end ?
  let session_ids = load_session_ids(request.database_path, wrapping_key) ?
  let loaded = find_peer_session(request.database_path,
  wrapping_key,
  requested_peer.account_id,
  session_ids,
  0) ?
  let changed = !Bytes.secure_equals(loaded.record.peer_device_id, requested_peer.device_id) || !Bytes.secure_equals(loaded.record.peer_mailbox,
  requested_peer.entry.mailbox_token) || (Bytes.length(loaded.record.safety_number) == 64 && !Bytes.secure_equals(loaded.record.safety_number,
  safety_number(local, requested_peer) ?))
  if changed do
    Err("peer_keys_changed")
  else if loaded.record.strongest_suite > requested_peer.bundle.suite do
    Err("peer_keys_changed")
  else if loaded.record.strongest_suite < requested_peer.bundle.suite || Bytes.length(loaded.record.safety_number) == 0 do
    Err("session_upgrade_required")
  else if loaded.record.blocked do
    Err("conversation_blocked")
  else if loaded.record.request_state != 1 do
    Err("message_request_pending")
  else
    let state = restore_session(loaded, wrapping_key) ?
    let now = current_time() ?
    let inner = InnerEnvelope {
      version : 1,
      sender_account_id : local.account_id,
      sender_device_id : local.device_id,
      recipient_device_id : loaded.record.peer_device_id,
      conversation_id : loaded.record.conversation_id,
      client_message_id : random_bytes(16) ?,
      client_timestamp : now,
      message_type : 1,
      body : request.body,
      reply_reference : Bytes.empty(),
      attachment_manifest : Bytes.empty(),
      receipt_policy : 0,
      disappearing_seconds : loaded.record.disappearing_seconds,
      extensions : List.new()
    }
    let ( next_state, message) = case encrypt(state,
    inner_bytes(inner) ?,
    session_aad(loaded.session_id) ?) do
      Err( _) -> Err("message_encryption_failed")
      Ok( value) -> Ok(value)
    end ?
    let packet = encode_packet(RatchetPacket(ratchet_bytes(message) ?)) ?
    let outer = outer_bytes(loaded.record.peer_mailbox, message.suite, packet, now) ?
    let session_blob = seal_updated_session(next_state, loaded, wrapping_key) ?
    let ( history_key, history_blob) = updated_history(request.database_path,
    wrapping_key,
    inner,
    1) ?
    let prepared = [MobilePreparedSend {
      envelope : outer,
      session_id : loaded.session_id,
      session_label : loaded.label,
      session_blob : session_blob,
      new_session : false
    }]
    let ( outbox_labels, outbox_blobs, outbox_index_blob) = prepare_outbox_writes(wrapping_key,
    pending_ids,
    [outer]) ?
    store_outbound(request.database_path,
    prepared,
    List.new(),
    seal_session_ids(session_ids, wrapping_key) ?,
    [history_key],
    [history_blob],
    outbox_labels,
    outbox_blobs,
    outbox_index_blob) ?
    Ok(outer)
  end
end

fn reject_message(state :: consume RatchetState, error :: String) -> Bytes ! String do
  Err(error)
end

pub fn receive_message(request :: MobileReceiveRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local = decode_client_profile(load_profile(request.database_path) ?) ?
  let outer = canonical_outer(request.outer) ?
  if !Bytes.secure_equals(outer.mailbox_token, local.entry.mailbox_token) do
    Err("wrong_mailbox")
  else
    let packet_message = parse_ratchet_packet(outer.ciphertext) ?
    let message = case decode_ratchet_message(packet_message) do
      Err( _) -> Err("invalid_ratchet_message")
      Ok( value) -> Ok(value)
    end ?
    let _ = if outer.suite != message.suite do
      Err("outer_suite_mismatch")
    else
      Ok(nil)
    end ?
    let wrapping_key = platform_key() ?
    let loaded = load_session_record(request.database_path, wrapping_key, message.session_id) ?
    let peer_policy = find_peer_session(request.database_path,
    wrapping_key,
    loaded.record.peer_account_id,
    load_session_ids(request.database_path, wrapping_key) ?,
    0) ?
    let state = restore_session(loaded, wrapping_key) ?
    case decrypt(state, message, session_aad(loaded.session_id) ?) do
      Rejected( rejected_state, error) -> if is_retryable_ratchet_error(error) do
        reject_message(rejected_state, "ratchet_retryable")
      else
        reject_message(rejected_state, "message_rejected")
      end
      Opened( next_state, plaintext) -> do
        let inner = case decode_inner_envelope(plaintext) do
          Err( _) -> Err("invalid_inner_envelope")
          Ok( value) -> Ok(value)
        end ?
        let self_sync = inner.message_type == 2 && Bytes.secure_equals(loaded.record.peer_account_id,
        local.account_id)
        let valid_kind = self_sync || ((inner.message_type == 1 || inner.message_type == 3 || inner.message_type == 4) && !Bytes.secure_equals(loaded.record.peer_account_id,
        local.account_id))
        let mismatch = !valid_kind || !Bytes.secure_equals(inner.sender_account_id,
        loaded.record.peer_account_id) || !Bytes.secure_equals(inner.sender_device_id,
        loaded.record.peer_device_id) || !Bytes.secure_equals(inner.recipient_device_id,
        local.device_id) || !Bytes.secure_equals(inner.conversation_id,
        loaded.record.conversation_id)
        if mismatch do
          reject_message(next_state, "message_rejected")
        else
          let session_blob = seal_updated_session(next_state, loaded, wrapping_key) ?
          if peer_policy.record.blocked do
            store_updated_session(request.database_path, loaded.label, session_blob) ?
            Err("blocked_message")
          else if inner.message_type == 3 || inner.message_type == 4 do
            let (labels, blobs) = received_invitation_writes(request.database_path, wrapping_key,
              local, loaded.record.peer_username, inner) ?
            store_updated_blobs(request.database_path, List.append(labels, loaded.label),
              List.append(blobs, session_blob)) ?
            Ok(Bytes.empty())
          else if self_sync do
            let sync = parse_sync_payload(inner.body) ?
            if Bytes.secure_equals(sync.peer_account_id, local.account_id) do
              Err("invalid_sync_payload")
            else
              let history_inner = sync_history_inner(local, sync) ?
              ensure_conversation_alias(request.database_path, wrapping_key, local, sync) ?
              let ( history_key, history_blob) = updated_history(request.database_path,
              wrapping_key,
              history_inner,
              1) ?
              store_updated_session_and_history(request.database_path,
              loaded.label,
              session_blob,
              history_key,
              history_blob) ?
              Ok(history_inner.body)
            end
          else
            let ( history_key, history_blob) = updated_history(request.database_path,
            wrapping_key,
            inner,
            2) ?
            store_updated_session_and_history(request.database_path,
            loaded.label,
            session_blob,
            history_key,
            history_blob) ?
            Ok(inner.body)
          end
        end
      end
    end
  end
end
