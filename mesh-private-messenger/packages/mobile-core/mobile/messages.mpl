from Mobile.Attachments import rewrap_reference
from Mobile.Presentation import presented_body
from Identity.Device import DeviceKeys, VerificationPolicy
from Mobile.Codec import canonical_outer, current_time, random_bytes
from Mobile.ContactAddress import deposit_address, learned_contact_address_writes, outgoing_extensions
from Mobile.FanoutPrekeys import matching_fanout_prekey_state_labels
from Mobile.History import accepted_request_writes, updated_history
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
from Mobile.Profile import load_profile, open_device, open_prekeys, policy
from Mobile.Transport import MobileOpenedPacket, open_outer_packet, sealed_outer_bytes
from Mobile.Sessions import (
  direct_conversation_id,
  ensure_conversation_alias,
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
  encrypt_sealed,
  is_retryable_ratchet_error,
  ratchet_transport_matches
)
from Storage.Blobs import ensure_schema
from Storage.Keys import one_time_prekey_label, platform_key
from Storage.Records import (
  store_outbound,
  store_received_session,
  store_record_changes,
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
  session_aad
)

##! Mobile.Messages implementation.

pub fn start_conversation(request :: MobileStartRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let local_encode_client_profile = load_profile(request.database_path)?
  let local = decode_client_profile(local_encode_client_profile)?
  let peer = decode_client_profile(request.peer_profile)?
  let wrapping_key = platform_key()?
  let pending_ids = load_outbox_ids(request.database_path, wrapping_key)?
  if List.length(pending_ids) >= outbox_capacity() do
    Err("outbox_full")
  else
    Ok(nil)
  end?
  let session_ids = load_session_ids(request.database_path, wrapping_key)?
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
  let handed_over = outgoing_extensions(request.database_path, wrapping_key)?
  let inner = % { history_inner | attachment_manifest: rewrapped, extensions: handed_over }
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
  let (state, initial) = case initiate(local_device,
    local.credential,
    peer.account,
    peer.bundle,
    policy(peer, now),
    strongest_suite,
    plaintext) do
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
    1)?
  store_outbound(request.database_path,
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

fn keep_contact_address(database_path :: String,
  wrapping_key :: borrow StorageKey,
  blocked :: Bool,
  public_address :: Bytes,
  inner :: InnerEnvelope) -> Result<(), String> do
  if blocked do
    Ok(nil)
  else
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

pub fn receive_initial_message(request :: MobileReceiveRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let local_encode_client_profile = load_profile(request.database_path)?
  let local = decode_client_profile(local_encode_client_profile)?
  let outer = canonical_outer(request.outer)?
  if !Bytes.secure_equals(outer.mailbox_token, local.entry.mailbox_token) do
    Err("wrong_mailbox")
  else
    let wrapping_key = platform_key()?
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
      let session_ids = load_session_ids(request.database_path, wrapping_key)?
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
      if reusable && last_resort_replayed(request.database_path,
        wrapping_key,
        initial.transcript_hash)? do
        Err("replayed_initial_message")
      else
        Ok(nil)
      end?
      let responder_bundle = % { local.bundle | one_time_prekey_id: selected_prekey.id, one_time_prekey: selected_prekey.public_key }
      let initiator_credential = case decode_device_credential(initial.initiator_credential) do
        Err(_) -> Err("invalid_initiator_credential")
        Ok(value)
      end?
      let strongest_suite = strongest_device_suite(request.database_path,
        wrapping_key,
        initiator_account.account_id,
        initiator_credential.device_id,
        session_ids,
        0,
        0)?
      let (signed, one_time, post_quantum) = open_prekeys(local,
        wrapping_key,
        request.database_path,
        selected_prekey)?
      let now = current_time()?
      let (state, plaintext) = case receive_initial(local_device,
        local.account,
        responder_bundle,
        signed,
        one_time,
        post_quantum,
        initiator_account,
        policy(local, now),
        VerificationPolicy {
          current_time: now,
          minimum_directory_sequence: initiator_account.directory_sequence
        },
        strongest_suite,
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
      let previous = case find_peer_session(request.database_path,
        wrapping_key,
        peer.account_id,
        session_ids,
        0) do
        Ok(loaded) -> Ok(Some(loaded))
        Err(error) -> if error == "session_not_found" do
          Ok(None)
        else
          Err(error)
        end
      end?
      let self_sync = inner.message_type == 2 && Bytes.secure_equals(peer.account_id,
        local.account_id)
      let valid_kind = self_sync || ((inner.message_type == 1 || inner.message_type == 3 || inner.message_type == 4) && !Bytes.secure_equals(peer.account_id,
        local.account_id))
      let expected_conversation = if self_sync do
        self_sync_conversation_id(local.account_id)?
      else
        direct_conversation_id(local.account_id, peer.account_id)?
      end
      # A conversation from before names were derived still goes by the name
      # in this device's record, so what was in flight at an upgrade arrives.
      let conversation_mismatch = !Bytes.secure_equals(inner.conversation_id, expected_conversation) && case previous do
        None -> true
        Some(loaded) -> !Bytes.secure_equals(inner.conversation_id, loaded.record.conversation_id)
      end
      # The name this device files the conversation under is its own records'
      # business; a wire name only ever adds to what is already here.
      let conversation_key = case previous do
        None -> inner.conversation_id
        Some(loaded) -> loaded.record.conversation_id
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
          Some(loaded) -> loaded.record.blocked
        end
        keep_contact_address(request.database_path,
          wrapping_key,
          blocked,
          peer.entry.mailbox_token,
          inner)?
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
          store_received_session(request.database_path,
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
          let sync = parse_sync_payload(inner.body)?
          if Bytes.secure_equals(sync.peer_account_id, local.account_id) do
            Err("invalid_sync_payload")
          else
            let synced_key = ensure_conversation_alias(request.database_path,
              wrapping_key,
              local,
              sync,
              session_ids)?
            let synced = sync_history_inner(local, sync, inner.attachment_manifest)?
            let history_inner = % { synced | conversation_id: synced_key }
            let index_blob = updated_session_index(request.database_path, wrapping_key, session_id)?
            let (history_keys, history_blobs) = updated_history(request.database_path,
              wrapping_key,
              history_inner,
              1)?
            # A sibling device could only send this once the request was accepted there.
            let (accepted_labels, accepted_blobs) = accepted_request_writes(request.database_path,
              wrapping_key,
              sync.peer_account_id,
              session_ids)?
            store_received_session(request.database_path,
              label,
              session_blob,
              index_blob,
              List.concat(history_keys, accepted_labels),
              List.concat(history_blobs, accepted_blobs),
              removed_labels,
              prekey_labels,
              prekey_blobs)?
            Ok(presented_body(history_inner.body))
          end
        else if inner.message_type == 3 || inner.message_type == 4 do
          let (labels, blobs) = received_invitation_writes(request.database_path,
            wrapping_key,
            local,
            peer.username,
            inner)?
          store_received_session(request.database_path,
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
          let (history_keys, history_blobs) = updated_history(request.database_path,
            wrapping_key,
            % { inner | conversation_id: conversation_key },
            2)?
          store_received_session(request.database_path,
            label,
            session_blob,
            index_blob,
            history_keys,
            history_blobs,
            removed_labels,
            prekey_labels,
            prekey_blobs)?
          Ok(presented_body(inner.body))
        end
      end
    end
  end
end

pub fn send_message(request :: MobileStartRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let local = decode_client_profile(load_profile(request.database_path)?)?
  let requested_peer = decode_client_profile(request.peer_profile)?
  let wrapping_key = platform_key()?
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
  let changed = !Bytes.secure_equals(loaded.record.peer_device_id, requested_peer.device_id) || !Bytes.secure_equals(loaded.record.peer_mailbox,
    requested_peer.entry.mailbox_token) || (Bytes.length(loaded.record.safety_number) == 64 && !Bytes.secure_equals(loaded.record.safety_number,
    safety_number(local, requested_peer)?))
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
      Ok(% { history_inner | attachment_manifest: rewrap_reference(local_device,
        request.attachment,
        requested_peer.credential.dh_public_key)? })
    end?
    # The sent copy hands over this device's contact address; history does not keep it.
    let handed_over = outgoing_extensions(request.database_path, wrapping_key)?
    let wire_conversation_id = direct_conversation_id(local.account_id, requested_peer.account_id)?
    let (next_state, message) = case encrypt_sealed(state,
      inner_bytes(% { inner | conversation_id: wire_conversation_id, extensions: handed_over })?,
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
    let session_blob = seal_updated_session(next_state, loaded, wrapping_key)?
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
      1)?
    store_outbound(request.database_path,
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

pub fn receive_message(request :: MobileReceiveRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let local = decode_client_profile(load_profile(request.database_path)?)?
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
    let loaded = load_session_record(request.database_path, wrapping_key, message.session_id)?
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
        let self_sync = inner.message_type == 2 && Bytes.secure_equals(loaded.record.peer_account_id,
          local.account_id)
        let valid_kind = self_sync || ((inner.message_type == 1 || inner.message_type == 3 || inner.message_type == 4) && !Bytes.secure_equals(loaded.record.peer_account_id,
          local.account_id))
        let expected_conversation = if self_sync do
          self_sync_conversation_id(local.account_id)?
        else
          direct_conversation_id(local.account_id, loaded.record.peer_account_id)?
        end
        let mismatch = !valid_kind || !Bytes.secure_equals(inner.sender_account_id,
          loaded.record.peer_account_id) || !Bytes.secure_equals(inner.sender_device_id,
          loaded.record.peer_device_id) || !Bytes.secure_equals(inner.recipient_device_id,
          local.device_id) || (!Bytes.secure_equals(inner.conversation_id, expected_conversation) && !Bytes.secure_equals(inner.conversation_id,
          loaded.record.conversation_id))
        if mismatch do
          reject_message(next_state, "message_rejected")
        else
          let session_blob = seal_updated_session(next_state, loaded, wrapping_key)?
          keep_contact_address(request.database_path,
            wrapping_key,
            peer_policy.record.blocked,
            loaded.record.peer_mailbox,
            inner)?
          if peer_policy.record.blocked do
            store_updated_session(request.database_path, loaded.label, session_blob)?
            Err("blocked_message")
          else if inner.message_type == 3 || inner.message_type == 4 do
            let (labels, blobs) = received_invitation_writes(request.database_path,
              wrapping_key,
              local,
              loaded.record.peer_username,
              inner)?
            store_updated_blobs(request.database_path,
              List.append(labels, loaded.label),
              List.append(blobs, session_blob))?
            Ok(Bytes.empty())
          else if self_sync do
            let sync = parse_sync_payload(inner.body)?
            if Bytes.secure_equals(sync.peer_account_id, local.account_id) do
              Err("invalid_sync_payload")
            else
              let synced_key = ensure_conversation_alias(request.database_path,
                wrapping_key,
                local,
                sync,
                session_ids)?
              let synced = sync_history_inner(local, sync, inner.attachment_manifest)?
              let history_inner = % { synced | conversation_id: synced_key }
              let (history_keys, history_blobs) = updated_history(request.database_path,
                wrapping_key,
                history_inner,
                1)?
              # A sibling device could only send this once the request was accepted there.
              let (accepted_labels, accepted_blobs) = accepted_request_writes(request.database_path,
                wrapping_key,
                sync.peer_account_id,
                session_ids)?
              store_updated_session_and_history(request.database_path,
                loaded.label,
                session_blob,
                List.concat(history_keys, accepted_labels),
                List.concat(history_blobs, accepted_blobs))?
              Ok(presented_body(history_inner.body))
            end
          else
            let (history_keys, history_blobs) = updated_history(request.database_path,
              wrapping_key,
              % { inner | conversation_id: loaded.record.conversation_id },
              2)?
            store_updated_session_and_history(request.database_path,
              loaded.label,
              session_blob,
              history_keys,
              history_blobs)?
            Ok(presented_body(inner.body))
          end
        end
      end
    end
  end
end
