from Mobile.SessionPolicy import capture_native_session_policy, native_session_minimum
from Mobile.HeaderCapabilities import require_header_sets, require_new_header_capacity
from Session.State import RatchetState, RatchetError, RatchetMessage
from Mobile.AttachmentCapabilities import require_attachment_format_sets
from Mobile.FanoutState import capture_fanout_sources
from Storage.FanoutCommit import (
  FanoutSnapshot,
  capture_fanout_snapshot,
  capture_fanout_history,
  combine_fanout_snapshots,
  commit_fanout_snapshot_at_policy,
  commit_fanout_records
)
from Mobile.Attachments import rewrap_reference
from Mobile.Presentation import present_message
from Identity.Device import DeviceKeys, VerificationPolicy
from Mobile.Codec import current_time, encode_output_list, random_bytes
from Mobile.ContactAddress import deposit_address
from Mobile.Outgoing import direct_extensions
from Mobile.TransparencySafety import require_log_changes_allowed
from Mobile.DeviceSet import verified_device_set
from Mobile.FanoutPrekeys import (
  claimed_prekey_profile,
  fanout_prekey_reservation_labels,
  invalid_fanout_sets,
  load_fanout_prekey_reservation
)
from Mobile.History import updated_history
from Mobile.Outbox import load_outbox_ids, outbox_capacity, prepare_outbox_writes
from Mobile.Profile import load_profile, open_device, policy
from Mobile.Transport import sealed_outer_bytes
from Mobile.Sessions import (
  device_needs_prekey,
  encode_sync_payload,
  find_device_session,
  find_peer_session,
  initial_bytes,
  inner_bytes,
  load_session_ids,
  prepared_envelopes,
  prepared_session_ids,
  ratchet_bytes,
  restore_session,
  session_uses_headers,
  safety_number,
  seal_session,
  seal_session_ids,
  seal_updated_session,
  seal_upgraded_session,
  self_sync_conversation_id
)
from Mobile.Transparency import require_transparency_device_set
from Mobile.Types import (
  MobileClaimedPrekey,
  MobileFanoutRequest,
  MobileLoadedSession,
  MobilePreparedSend,
  MobileSessionRecord,
  MobileVerifiedDeviceSet
)
from Prekeys.Bundle import PrekeyError
from Protocol.V1 import (
  AccountIdentity,
  DeviceCredential,
  DeviceSet,
  DirectoryEntry,
  InitialMessage,
  InnerEnvelope,
  PrekeyBundle
)
from Session.Handshake import SessionError, initiate_at_minimum_suite
from Session.Ratchet import encrypt_sealed
from Session.Snapshot import SnapshotOutcome, snapshot
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import platform_key, open_local, local_context
from Transport.Packet import (
  ClientProfile,
  TransportPacket,
  decode_client_profile,
  direct_conversation_id,
  encode_initial_plaintext,
  encode_packet,
  session_aad
)

##! Mobile.Fanout implementation.

fn append_needed_prekeys(database_path :: String,
  wrapping_key :: borrow StorageKey,
  session_ids :: List<Bytes>,
  profiles :: List<ClientProfile>,
  local_device_id :: Bytes,
  skip_local_device :: Bool,
  now :: U64,
  claims :: List<MobileClaimedPrekey>,
  index :: Int) -> List<MobileClaimedPrekey>!String do
  if index >= List.length(profiles) do
    Ok(claims)
  else
    let profile = List.get(profiles, index)
    if skip_local_device && Bytes.secure_equals(profile.device_id, local_device_id) do
      append_needed_prekeys(database_path,
        wrapping_key,
        session_ids,
        profiles,
        local_device_id,
        skip_local_device,
        now,
        claims,
        index + 1)
    else if !(device_needs_prekey(database_path, wrapping_key, session_ids, profile)?) do
      append_needed_prekeys(database_path,
        wrapping_key,
        session_ids,
        profiles,
        local_device_id,
        skip_local_device,
        now,
        claims,
        index + 1)
    else
      require_log_changes_allowed(database_path, wrapping_key)?
      case load_fanout_prekey_reservation(database_path, wrapping_key, profile, now) do
        Err(error)
        Ok(None) -> Err("invalid_fanout_prekeys")
        Ok(Some(claim)) -> append_needed_prekeys(database_path,
          wrapping_key,
          session_ids,
          profiles,
          local_device_id,
          skip_local_device,
          now,
          List.append(claims, claim),
          index + 1)
      end
    end
  end
end

fn start_device_session(claimed_prekeys :: List<MobileClaimedPrekey>,
  minimum_session_suite :: Int,
  local_device :: borrow DeviceKeys,
  local_encode_client_profile :: Bytes,
  local :: ClientProfile,
  peer :: ClientProfile,
  inner :: InnerEnvelope,
  conversation_id :: Bytes,
  wrapping_key :: borrow StorageKey,
  previous :: Option<MobileLoadedSession>,
  strongest_suite :: Int,
  deposit :: Bytes) -> MobilePreparedSend!String do
  let claimed_peer = claimed_prekey_profile(claimed_prekeys, peer.entry.prekey_bundle, 0)?
  let plaintext = case encode_initial_plaintext(local_encode_client_profile, inner_bytes(inner)?) do
    Err(_) -> Err("invalid_initial_plaintext")
    Ok(value)
  end?
  let (state, initial) = case initiate_at_minimum_suite(local_device,
    local.credential,
    claimed_peer.account,
    claimed_peer.bundle,
    policy(claimed_peer, inner.client_timestamp),
    strongest_suite,
    minimum_session_suite,
    plaintext) do
    Err(MinimumSessionSuiteRequired) -> Err("session_suite_below_minimum")
    Err(_) -> Err("session_start_failed")
    Ok(value)
  end?
  let packet = encode_packet(InitialPacket(local.entry.account_identity, initial_bytes(initial)?))?
  let outer = sealed_outer_bytes(deposit,
    packet,
    peer.credential.dh_public_key,
    inner.client_timestamp)?
  let (session_id, label, session_blob) = case previous do
    None -> seal_session(state, wrapping_key, local, claimed_peer, conversation_id, 1, false)
    Some(loaded) -> seal_upgraded_session(state, wrapping_key, loaded, local, claimed_peer)
  end?
  Ok(MobilePreparedSend {
    envelope: outer,
    session_id: session_id,
    session_label: label,
    session_blob: session_blob,
    new_session: true
  })
end

fn send_to_device(database_path :: String,
  wrapping_key :: borrow StorageKey,
  session_ids :: List<Bytes>,
  claimed_prekeys :: List<MobileClaimedPrekey>,
  minimum_session_suite :: Int,
  local_device :: borrow DeviceKeys,
  local_encode_client_profile :: Bytes,
  local :: ClientProfile,
  peer :: ClientProfile,
  inner :: InnerEnvelope,
  conversation_id :: Bytes) -> MobilePreparedSend!String do
  case find_device_session(database_path,
    wrapping_key,
    peer.account_id,
    peer.device_id,
    session_ids,
    0) do
    Ok(loaded) -> do
      let changed = !Bytes.secure_equals(loaded.record.peer_mailbox, peer.entry.mailbox_token)
        || (Bytes.length(loaded.record.safety_number) == 64
          && !Bytes.secure_equals(loaded.record.safety_number, safety_number(local, peer)?))
      if changed do
        Err("peer_keys_changed")
      else if loaded.record.strongest_suite > peer.bundle.suite do
        Err("peer_keys_changed")
      else if !session_uses_headers(loaded.record.snapshot)
        || loaded.record.strongest_suite < peer.bundle.suite
        || Bytes.length(loaded.record.safety_number) == 0 do
        require_log_changes_allowed(database_path, wrapping_key)?
        let strongest_suite = loaded.record.strongest_suite
        start_device_session(claimed_prekeys,
          minimum_session_suite,
          local_device,
          local_encode_client_profile,
          local,
          peer,
          inner,
          conversation_id,
          wrapping_key,
          Some(loaded),
          strongest_suite,
          deposit_address(database_path, wrapping_key, peer.entry.mailbox_token)?)
      else
        let state = restore_session(loaded, wrapping_key)?
        let (next_state, message) = case encrypt_sealed(state,
          inner_bytes(inner)?,
          session_aad(loaded.session_id)?) do
          Err(_) -> Err("message_encryption_failed")
          Ok(value)
        end?
        let packet = encode_packet(RatchetPacket(ratchet_bytes(message)?))?
        let outer = sealed_outer_bytes(deposit_address(database_path,
            wrapping_key,
            peer.entry.mailbox_token)?,
          packet,
          peer.credential.dh_public_key,
          inner.client_timestamp)?
        let session_blob = seal_updated_session(next_state,
          %{loaded | record: %{loaded.record | peer_transport_key: peer.credential.dh_public_key}},
          wrapping_key)?
        Ok(MobilePreparedSend {
          envelope: outer,
          session_id: loaded.session_id,
          session_label: loaded.label,
          session_blob: session_blob,
          new_session: false
        })
      end
    end
    Err(error) -> if error != "session_not_found" do
      Err(error)
    else
      require_log_changes_allowed(database_path, wrapping_key)?
      start_device_session(claimed_prekeys,
        minimum_session_suite,
        local_device,
        local_encode_client_profile,
        local,
        peer,
        inner,
        conversation_id,
        wrapping_key,
        None,
        0,
        deposit_address(database_path, wrapping_key, peer.entry.mailbox_token)?)
    end
  end
end

fn peer_fanout(database_path :: String,
  wrapping_key :: borrow StorageKey,
  session_ids :: List<Bytes>,
  claimed_prekeys :: List<MobileClaimedPrekey>,
  minimum_session_suite :: Int,
  local_device :: borrow DeviceKeys,
  local_encode_client_profile :: Bytes,
  local :: ClientProfile,
  profiles :: List<ClientProfile>,
  conversation_id :: Bytes,
  client_message_id :: Bytes,
  now :: U64,
  body :: Bytes,
  attachment :: Bytes,
  message_type :: Int,
  disappearing_seconds :: Int,
  index :: Int,
  output :: List<MobilePreparedSend>) -> List<MobilePreparedSend>!String do
  if index >= List.length(profiles) do
    Ok(output)
  else
    let peer = List.get(profiles, index)
    let handed_over = direct_extensions(database_path, wrapping_key)?
    let inner = InnerEnvelope {
      version: 1,
      sender_account_id: local.account_id,
      sender_device_id: local.device_id,
      recipient_device_id: peer.device_id,
      conversation_id: direct_conversation_id(local.account_id, peer.account_id)?,
      client_message_id: client_message_id,
      client_timestamp: now,
      message_type: message_type,
      body: body,
      reply_reference: Bytes.empty(),
      attachment_manifest: rewrap_reference(local_device,
        attachment,
        peer.credential.dh_public_key)?,
      receipt_policy: 0,
      disappearing_seconds: disappearing_seconds,
      extensions: handed_over
    }
    let prepared = send_to_device(database_path,
      wrapping_key,
      session_ids,
      claimed_prekeys,
      minimum_session_suite,
      local_device,
      local_encode_client_profile,
      local,
      peer,
      inner,
      conversation_id)?
    peer_fanout(database_path,
      wrapping_key,
      session_ids,
      claimed_prekeys,
      minimum_session_suite,
      local_device,
      local_encode_client_profile,
      local,
      profiles,
      conversation_id,
      client_message_id,
      now,
      body,
      attachment,
      message_type,
      disappearing_seconds,
      index + 1,
      List.append(output, prepared))
  end
end

fn self_fanout(database_path :: String,
  wrapping_key :: borrow StorageKey,
  session_ids :: List<Bytes>,
  claimed_prekeys :: List<MobileClaimedPrekey>,
  minimum_session_suite :: Int,
  local_device :: borrow DeviceKeys,
  local_encode_client_profile :: Bytes,
  local :: ClientProfile,
  local_profiles :: List<ClientProfile>,
  client_message_id :: Bytes,
  now :: U64,
  sync_body :: Bytes,
  attachment :: Bytes,
  index :: Int,
  output :: List<MobilePreparedSend>) -> List<MobilePreparedSend>!String do
  if index >= List.length(local_profiles) do
    Ok(output)
  else
    let peer = List.get(local_profiles, index)
    if Bytes.secure_equals(peer.device_id, local.device_id) do
      self_fanout(database_path,
        wrapping_key,
        session_ids,
        claimed_prekeys,
        minimum_session_suite,
        local_device,
        local_encode_client_profile,
        local,
        local_profiles,
        client_message_id,
        now,
        sync_body,
        attachment,
        index + 1,
        output)
    else
      let handed_over = direct_extensions(database_path, wrapping_key)?
      let inner = InnerEnvelope {
        version: 1,
        sender_account_id: local.account_id,
        sender_device_id: local.device_id,
        recipient_device_id: peer.device_id,
        conversation_id: self_sync_conversation_id(local.account_id)?,
        client_message_id: client_message_id,
        client_timestamp: now,
        message_type: 2,
        body: sync_body,
        reply_reference: Bytes.empty(),
        attachment_manifest: rewrap_reference(local_device,
          attachment,
          peer.credential.dh_public_key)?,
        receipt_policy: 0,
        disappearing_seconds: 0,
        extensions: handed_over
      }
      let prepared = send_to_device(database_path,
        wrapping_key,
        session_ids,
        claimed_prekeys,
        minimum_session_suite,
        local_device,
        local_encode_client_profile,
        local,
        peer,
        inner,
        inner.conversation_id)?
      self_fanout(database_path,
        wrapping_key,
        session_ids,
        claimed_prekeys,
        minimum_session_suite,
        local_device,
        local_encode_client_profile,
        local,
        local_profiles,
        client_message_id,
        now,
        sync_body,
        attachment,
        index + 1,
        List.append(output, prepared))
    end
  end
end

pub fn send_fanout(request :: MobileFanoutRequest) -> Bytes!String do
  send_fanout_at_profile(request, load_blob(request.database_path, "profile/v1")?)
end

pub fn send_fanout_at_profile(request :: MobileFanoutRequest, profile :: Bytes) -> Bytes!String do
  let key = platform_key()?
  let local = decode_client_profile(open_local(profile, key, local_context("profile/v1")?)?)?
  let before = capture_fanout_snapshot(request.database_path,
    profile,
    ["presentation/v1/user/#{Bytes.to_hex(local.account_id)}"])?
  send_fanout_control_after_snapshot(%{request |
      body: present_message(request.database_path, Bytes.empty(), request.body)?
    },
    1,
    [],
    [],
    before)
end

pub fn send_fanout_control(request :: MobileFanoutRequest,
  message_type :: Int,
  extra_labels :: List<String>,
  extra_blobs :: List<Bytes>) -> Bytes!String do
  let captured_profile = load_blob(request.database_path, "profile/v1")?
  let before = capture_fanout_snapshot(request.database_path, captured_profile, extra_labels)?
  send_fanout_control_after_snapshot(request, message_type, extra_labels, extra_blobs, before)
end

pub fn send_fanout_control_after_snapshot(request :: MobileFanoutRequest,
  message_type :: Int,
  extra_labels :: List<String>,
  extra_blobs :: List<Bytes>,
  initial :: FanoutSnapshot) -> Bytes!String do
  ensure_schema(request.database_path)?
  commit_fanout_records(request.database_path, initial, [], [], [])?
  let session_policy = capture_native_session_policy()?
  let captured_profile = List.head(initial.bases).profile
  let wrapping_key = platform_key()?
  let local_encode_client_profile = open_local(captured_profile,
    wrapping_key,
    local_context("profile/v1")?)?
  let local = decode_client_profile(local_encode_client_profile)?
  let peers = verified_device_set(request.peer_device_set)?
  let local_devices = verified_device_set(request.local_device_set)?
  if invalid_fanout_sets(local, peers, local_devices) do
    Err("invalid_fanout_device_set")
  else
    let wrapping_key = platform_key()?
    require_transparency_device_set(request.database_path, wrapping_key, peers)?
    require_transparency_device_set(request.database_path, wrapping_key, local_devices)?
    let before = combine_fanout_snapshots(initial,
      capture_fanout_sources(request.database_path,
        wrapping_key,
        captured_profile,
        local,
        peers.profiles,
        local_devices.profiles,
        extra_labels)?)?
    require_transparency_device_set(request.database_path, wrapping_key, peers)?
    require_transparency_device_set(request.database_path, wrapping_key, local_devices)?
    require_header_sets(peers, local_devices)?
    if Bytes.length(request.attachment) > 0 do
      require_attachment_format_sets(peers, local_devices, request.attachment)?
    end
    let session_ids = load_session_ids(request.database_path, wrapping_key)?
    let needed = needed_header_sessions(request.database_path,
      wrapping_key,
      session_ids,
      peers.profiles
        ++ List.filter(local_devices.profiles,
          fn(profile) do message_type == 1
            && !Bytes.secure_equals(profile.device_id, local.device_id) end),
      0,
      0)?
    require_new_header_capacity(List.length(session_ids), needed)?
    let now = current_time()?
    let peer_prekeys = append_needed_prekeys(request.database_path,
      wrapping_key,
      session_ids,
      peers.profiles,
      local.device_id,
      false,
      now,
      List.new(),
      0)?
    let claimed_prekeys = if message_type != 1 do
      Ok(peer_prekeys)
    else
      append_needed_prekeys(request.database_path,
        wrapping_key,
        session_ids,
        local_devices.profiles,
        local.device_id,
        true,
        now,
        peer_prekeys,
        0)
    end?
    let pending_ids = load_outbox_ids(request.database_path, wrapping_key)?
    let anchor = case find_peer_session(request.database_path,
      wrapping_key,
      peers.account.account_id,
      session_ids,
      0) do
      Err(error) -> if error == "session_not_found" do
        let representative = List.head(peers.profiles)
        Ok(MobileSessionRecord {
          snapshot: Bytes.empty(),
          local_account_id: local.account_id,
          local_device_id: local.device_id,
          peer_account_id: representative.account_id,
          peer_device_id: representative.device_id,
          peer_username: representative.username,
          peer_mailbox: representative.entry.mailbox_token,
          conversation_id: direct_conversation_id(local.account_id, representative.account_id)?,
          request_state: 1,
          blocked: false,
          verified: false,
          key_changed: false,
          disappearing_seconds: 0,
          strongest_suite: 1,
          safety_number: safety_number(local, representative)?,
          peer_transport_key: representative.credential.dh_public_key
        })
      else
        Err(error)
      end
      Ok(loaded) -> Ok(loaded.record)
    end?
    let added_count = List.length(peers.profiles)
      + if message_type == 1 do
        List.length(local_devices.profiles) - 1
      else
        0
      end
    if List.length(pending_ids) + added_count > outbox_capacity() do
      Err("outbox_full")
    else if anchor.blocked do
      Err("conversation_blocked")
    else if anchor.request_state != 1 && message_type != 4 do
      Err("message_request_pending")
    else
      let before = if message_type == 1 do
        capture_fanout_history(request.database_path, before, anchor.conversation_id)
      else
        Ok(before)
      end?
      let client_message_id = random_bytes(16)?
      let local_device = open_device(local, wrapping_key, request.database_path)?
      let minimum_session_suite = native_session_minimum(session_policy)?
      let prepared_peers = peer_fanout(request.database_path,
        wrapping_key,
        session_ids,
        claimed_prekeys,
        minimum_session_suite,
        local_device,
        local_encode_client_profile,
        local,
        peers.profiles,
        anchor.conversation_id,
        client_message_id,
        now,
        request.body,
        request.attachment,
        message_type,
        if message_type == 1 do
          anchor.disappearing_seconds
        else
          0
        end,
        0,
        List.new())?
      let history_inner = InnerEnvelope {
        version: 1,
        sender_account_id: local.account_id,
        sender_device_id: local.device_id,
        recipient_device_id: List.head(peers.profiles).device_id,
        conversation_id: anchor.conversation_id,
        client_message_id: client_message_id,
        client_timestamp: now,
        message_type: 1,
        body: request.body,
        reply_reference: Bytes.empty(),
        attachment_manifest: request.attachment,
        receipt_policy: 0,
        disappearing_seconds: anchor.disappearing_seconds,
        extensions: List.new()
      }
      let (history_keys, history_blobs) = if message_type != 1 do
        Ok((extra_labels, extra_blobs))
      else
        let (history_keys, history_blobs) = updated_history(request.database_path,
          wrapping_key,
          history_inner,
          1)?
        Ok((history_keys, history_blobs))
      end?
      let sync_body = encode_sync_payload(local, List.head(peers.profiles), history_inner)?
      let prepared = if message_type != 1 do
        Ok(prepared_peers)
      else
        self_fanout(request.database_path,
          wrapping_key,
          session_ids,
          claimed_prekeys,
          minimum_session_suite,
          local_device,
          local_encode_client_profile,
          local,
          local_devices.profiles,
          client_message_id,
          now,
          sync_body,
          request.attachment,
          0,
          prepared_peers)
      end?
      let envelopes = prepared_envelopes(prepared, 0, List.new())
      let session_index_blob = seal_session_ids(prepared_session_ids(prepared, 0, session_ids),
        wrapping_key)?
      # The peer's devices come first; envelopes for this account's own devices
      # follow and say nothing about whether the message arrived.
      let tracked = if message_type == 1 do
        List.length(prepared_peers)
      else
        0
      end
      let (outbox_labels, outbox_blobs, outbox_index_blob) = prepare_outbox_writes(wrapping_key,
        pending_ids,
        envelopes,
        request.database_path,
        client_message_id,
        0,
        tracked,
        local)?
      commit_fanout_snapshot_at_policy(request.database_path,
        before,
        session_policy,
        prepared,
        fanout_prekey_reservation_labels(claimed_prekeys, 0, List.new()),
        session_index_blob,
        history_keys,
        history_blobs,
        outbox_labels,
        outbox_blobs,
        outbox_index_blob)?
      encode_output_list(envelopes)
    end
  end
end

fn needed_header_sessions(path :: String,
  key :: borrow StorageKey,
  ids :: List<Bytes>,
  profiles :: List<ClientProfile>,
  index :: Int,
  total :: Int) -> Int!String do
  if index >= List.length(profiles) do
    Ok(total)
  else
    let needed = device_needs_prekey(path, key, ids, List.get(profiles, index))?
    needed_header_sessions(path,
      key,
      ids,
      profiles,
      index + 1,
      total
        + if needed do
          1
        else
          0
        end)
  end
end
