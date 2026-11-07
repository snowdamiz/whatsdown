from Mobile.SiblingMembership import (
  sibling_source_labels,
  sibling_proof_label,
  sibling_captured_member,
  sibling_captured_blob,
  require_sibling_observation
)
from Mobile.SessionPolicy import NativeSessionPolicy, capture_native_session_policy
from Mobile.ReceiveSources import (
  ReceiveSources,
  capture_receive_sessions,
  receive_captured_peer,
  require_receive_sources
)
from Mobile.HeaderAdmission import capture_header_record
from Storage.AccountGuard import AccountBasis, load_account_basis
from Session.State import RatchetState
from Mobile.Codec import current_time, random_bytes
from Mobile.ContactAddress import deposit_address
from Mobile.Gossip import pending_gossip, clear_gossip_writes
from Mobile.GroupGossip import flush_group_gossip
from Mobile.GossipState import queued_group_peers, decode_gossip_state, queued_gossip_writes
from Mobile.Outbox import load_outbox_ids, outbox_capacity, prepare_outbox_writes
from Mobile.Outgoing import direct_extensions
from Mobile.Profile import load_profile
from Mobile.Sessions import (
  parse_session_record,
  load_session_ids,
  load_session_record,
  find_device_session,
  find_peer_session,
  restore_session,
  session_uses_headers,
  inner_bytes,
  ratchet_bytes,
  seal_updated_session,
  seal_session_ids,
  self_sync_conversation_id
)
from Mobile.Transport import sealed_outer_bytes
from Mobile.Types import MobileLoadedSession, MobileSessionRecord, MobilePreparedSend
from Protocol.V1 import InnerEnvelope
from Session.Ratchet import encrypt_sealed
from Storage.Blobs import ensure_schema
from Storage.Keys import platform_key, open_local, seal_local, local_context
from Storage.Records import store_outbound, store_outbound_after_guard
from Transport.Packet import (
  ClientProfile,
  TransportPacket,
  decode_client_profile,
  direct_conversation_id,
  encode_packet,
  session_aad
)

fn sibling_marker_label(id :: Bytes) -> String do
  "sibling-session/v1/#{Bytes.to_hex(id)}"
end

fn sibling_marker_plaintext(local :: ClientProfile,
  peer :: ClientProfile,
  id :: Bytes,
  snapshot_blob :: Bytes) -> Bytes!String do
  case Bytes.concat_many([
      Bytes.from_utf8("morse/sibling-session/v1\n"),
      id,
      local.account_id,
      local.device_id,
      local.account.authorization_public_key,
      local.credential.signing_public_key,
      local.credential.dh_public_key,
      peer.device_id,
      peer.credential.signing_public_key,
      peer.credential.dh_public_key,
      Crypto.sha256(snapshot_blob)
    ],
    1024) do
    Err(_) -> Err("sibling_marker_encoding_failed")
    Ok(value)
  end
end

fn sibling_marker_write(key :: borrow StorageKey,
  local :: ClientProfile,
  peer :: ClientProfile,
  id :: Bytes,
  session_label :: String,
  session_blob :: Bytes) -> Bytes!String do
  let record = parse_session_record(open_local(session_blob, key, local_context(session_label)?)?)?
  seal_local(sibling_marker_plaintext(local, peer, id, record.snapshot)?,
    key,
    local_context(sibling_marker_label(id))?)
end

fn require_sibling_marker(basis :: AccountBasis,
  key :: borrow StorageKey,
  local :: ClientProfile,
  peer :: ClientProfile,
  loaded :: MobileLoadedSession) -> Unit!String do
  let label = sibling_marker_label(loaded.session_id)
  let blob = sibling_captured_blob([basis], label)?
  if Bytes.length(blob) == 0 do
    return Err("sibling_session_unproven")
  end
  if !Bytes.secure_equals(loaded.record.local_account_id, local.account_id)
    || !Bytes.secure_equals(loaded.record.local_device_id, local.device_id)
    || !Bytes.secure_equals(loaded.record.peer_account_id, local.account_id)
    || !Bytes.secure_equals(loaded.record.peer_device_id, peer.device_id)
    || !Bytes.secure_equals(loaded.record.peer_transport_key, peer.credential.dh_public_key)
    || !Bytes.secure_equals(open_local(blob, key, local_context(label)?)?,
      sibling_marker_plaintext(local, peer, loaded.session_id, loaded.record.snapshot)?) do
    Err("sibling_session_unproven")
  else
    Ok(nil)
  end
end

struct SiblingSend do
  basis :: AccountBasis
  sources :: ReceiveSources
  member :: ClientProfile
  policy :: NativeSessionPolicy
  fresh_through :: U64
  clear_labels :: List<String>
  clear_blobs :: List<Bytes>
end

fn extend_sibling_basis(path :: String,
  before :: AccountBasis,
  label :: String) -> AccountBasis!String do
  case capture_header_record(path, Some(before), label)? do
    None -> Err("invalid_receive_basis")
    Some(value) -> Ok(value)
  end
end

fn captured_sibling_send(path :: String,
  key :: borrow StorageKey,
  local :: ClientProfile,
  ids :: List<Bytes>,
  device :: Bytes) -> Option<(MobileLoadedSession, Bytes, SiblingSend)>!String do
  let gossip_label = "checkpoint-gossip/v1/#{Bytes.to_hex(local.account_id)}"
  let before = load_account_basis(path,
    [
      "sessions/v1",
      "outbox/v1",
      gossip_label,
      "checkpoint-gossip/group-pending/v1",
      "contact-address/v1"
    ]
      ++ sibling_source_labels(local.account_id))?
  if !Bytes.secure_equals(open_local(before.profile, key, local_context("profile/v1")?)?,
    local.encoded) do
    return Err("account_state_changed")
  end
  let sources = capture_receive_sessions(path, key, before, ids)?
  let selected = find_device_session(path, key, local.account_id, device, ids, 0)?
  let captured = sibling_captured_blob([before] ++ sources.batches, selected.label)?
  let loaded = %{selected |
    record: parse_session_record(open_local(captured, key, local_context(selected.label)?)?)?
  }
  if !Bytes.secure_equals(loaded.record.peer_account_id, local.account_id)
    || !Bytes.secure_equals(loaded.record.peer_device_id, device) do
    return Err("account_state_changed")
  end
  let peer_policy = receive_captured_peer(sources, key, local.account_id)?
  if !session_uses_headers(loaded.record.snapshot)
    || peer_policy.record.blocked
    || loaded.record.key_changed
    || Bytes.length(loaded.record.peer_transport_key) != 32 do
    return Ok(None)
  end
  let gossip_blob = sibling_captured_blob([before], gossip_label)?
  if Bytes.length(gossip_blob) == 0 do
    return Ok(None)
  end
  let gossip = decode_gossip_state(open_local(gossip_blob, key, local_context(gossip_label)?)?)?
  if Bytes.length(gossip.pending_group) != 0
    || Bytes.length(gossip.pending_body) == 0
    || !Bytes.secure_equals(gossip.pending_device, device) do
    return Ok(None)
  end
  let before = extend_sibling_basis(path, before, sibling_marker_label(loaded.session_id))?
  let before = extend_sibling_basis(path,
    before,
    "peer-contact-address/v1/#{Bytes.to_hex(Crypto.sha256(loaded.record.peer_mailbox))}")?
  let proof = sibling_proof_label([before], key, local.account_id)?
  let before = if proof == "" do
    before
  else
    extend_sibling_basis(path, before, proof)?
  end
  let policy = capture_native_session_policy()?
  let (member, deadline) = sibling_captured_member([before],
    key,
    local,
    device,
    policy,
    current_time()?)?
  require_sibling_marker(before, key, local, member, loaded)?
  let (labels, blobs) = queued_gossip_writes(path,
    key,
    local.account_id,
    %{gossip |
      pending_body: Bytes.empty(),
      pending_device: Bytes.empty(),
      pending_group: Bytes.empty()
    })?
  Ok(Some((loaded,
    gossip.pending_body,
    SiblingSend {
      basis: before,
      sources: sources,
      member: member,
      policy: policy,
      fresh_through: deadline,
      clear_labels: labels,
      clear_blobs: blobs
    })))
end

fn send_pending(path :: String,
  key :: borrow StorageKey,
  local :: ClientProfile,
  ids :: List<Bytes>,
  loaded :: MobileLoadedSession,
  body :: Bytes,
  sibling :: Option<SiblingSend>) -> Result<(), String> do
  let pending_ids = load_outbox_ids(path, key)?
  let now = current_time()?
  let inner = InnerEnvelope {
    version: 1,
    sender_account_id: local.account_id,
    sender_device_id: local.device_id,
    recipient_device_id: loaded.record.peer_device_id,
    conversation_id: if Bytes.secure_equals(local.account_id, loaded.record.peer_account_id) do
      self_sync_conversation_id(local.account_id)?
    else
      direct_conversation_id(local.account_id, loaded.record.peer_account_id)?
    end,
    client_message_id: random_bytes(16)?,
    client_timestamp: now,
    message_type: 5,
    body: body,
    reply_reference: Bytes.empty(),
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: direct_extensions(path, key)?
  }
  let state = restore_session(loaded, key)?
  let (next, message) = case encrypt_sealed(state,
    inner_bytes(inner)?,
    session_aad(loaded.session_id)?) do
    Err(_) -> return Err("message_encryption_failed")
    Ok(value) -> value
  end
  let packet = encode_packet(RatchetPacket(ratchet_bytes(message)?))?
  let outer = sealed_outer_bytes(deposit_address(path, key, loaded.record.peer_mailbox)?,
    packet,
    loaded.record.peer_transport_key,
    now)?
  let prepared = [
    MobilePreparedSend {
      envelope: outer,
      session_id: loaded.session_id,
      session_label: loaded.label,
      session_blob: seal_updated_session(next, loaded, key)?,
      new_session: false
    }
  ]
  let (clear_labels, clear_blobs) = case sibling do
    None -> clear_gossip_writes(path, key, loaded.record.peer_account_id)
    Some(value) -> Ok((value.clear_labels, value.clear_blobs))
  end?
  let (labels, blobs, index) = prepare_outbox_writes(key,
    pending_ids,
    [outer],
    path,
    Bytes.empty(),
    0,
    0,
    local)?
  case sibling do
    None -> store_outbound(path,
      prepared,
      List.new(),
      seal_session_ids(ids, key)?,
      clear_labels,
      clear_blobs,
      labels,
      blobs,
      index)
    Some(value) -> do
      let marker = sibling_marker_write(key,
        local,
        value.member,
        loaded.session_id,
        loaded.label,
        List.head(prepared).session_blob)?
      store_outbound_after_guard(path,
        prepared,
        List.new(),
        seal_session_ids(ids, key)?,
        List.append(clear_labels, sibling_marker_label(loaded.session_id)),
        List.append(clear_blobs, marker),
        labels,
        blobs,
        index,
        fn(database) do
          require_receive_sources(database, value.basis, Some(value.sources))?
          require_sibling_observation(Some((value.policy, value.fresh_through)))
        end)
    end
  end
end

fn flush_sessions(path :: String,
  key :: borrow StorageKey,
  local :: ClientProfile,
  ids :: List<Bytes>,
  index :: Int,
  sent :: Int) -> Result<(), String> do
  if index >= List.length(ids)
    || sent >= 8
    || List.length(load_outbox_ids(path, key)?) >= outbox_capacity() do
    return Ok(nil)
  end
  let candidate = load_session_record(path, key, List.get(ids, index))?
  let peer = candidate.record.peer_account_id
  if Bytes.secure_equals(peer, local.account_id) do
    let captured = captured_sibling_send(path, key, local, ids, candidate.record.peer_device_id)?
    let did_send = case captured do
      None -> false
      Some((loaded, body, admission)) -> do
        send_pending(path, key, local, ids, loaded, body, Some(admission))?
        true
      end
    end
    return flush_sessions(path,
      key,
      local,
      ids,
      index + 1,
      sent
        + if did_send do
          1
        else
          0
        end)
  end
  let (device, body) = pending_gossip(path, key, peer)?
  if Bytes.length(body) == 0 || !Bytes.secure_equals(device, candidate.record.peer_device_id) do
    return flush_sessions(path, key, local, ids, index + 1, sent)
  end
  let policy = find_peer_session(path, key, peer, ids, 0)?
  let loaded = find_device_session(path, key, peer, device, ids, 0)?
  # Controls never start a session or accept a message request. Older sealed
  # session records learn their transport key after the next ordinary send.
  if !session_uses_headers(loaded.record.snapshot)
    || policy.record.blocked
    || (policy.record.request_state != 1 && !Bytes.secure_equals(peer, local.account_id))
    || loaded.record.key_changed
    || Bytes.length(loaded.record.peer_transport_key) != 32 do
    return flush_sessions(path, key, local, ids, index + 1, sent)
  end
  send_pending(path, key, local, ids, loaded, body, None)?
  flush_sessions(path, key, local, ids, index + 1, sent + 1)
end

pub fn flush_gossip(path :: String) -> Result<(), String> do
  ensure_schema(path)?
  let key = platform_key()?
  let ids = load_session_ids(path, key)?
  if List.length(ids) == 0 && List.length(queued_group_peers(path, key)?) == 0 do
    return Ok(nil)
  end
  let local = decode_client_profile(load_profile(path)?)?
  flush_sessions(path, key, local, ids, 0, 0)?
  flush_group_gossip(path, key, local)
end
