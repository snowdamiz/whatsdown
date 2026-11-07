from Session.State import RatchetState
from Mobile.Codec import current_time, random_bytes
from Mobile.ContactAddress import deposit_address
from Mobile.Gossip import pending_gossip, clear_gossip_writes
from Mobile.GroupGossip import flush_group_gossip
from Mobile.GossipState import queued_group_peers
from Mobile.Outbox import load_outbox_ids, outbox_capacity, prepare_outbox_writes
from Mobile.Outgoing import direct_extensions
from Mobile.Profile import load_profile
from Mobile.Sessions import (
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
from Storage.Keys import platform_key
from Storage.Records import store_outbound
from Transport.Packet import (
  ClientProfile,
  TransportPacket,
  decode_client_profile,
  direct_conversation_id,
  encode_packet,
  session_aad
)

fn send_pending(path :: String,
  key :: borrow StorageKey,
  local :: ClientProfile,
  ids :: List<Bytes>,
  loaded :: MobileLoadedSession,
  body :: Bytes) -> Result<(), String> do
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
  let (clear_labels, clear_blobs) = clear_gossip_writes(path, key, loaded.record.peer_account_id)?
  let (labels, blobs, index) = prepare_outbox_writes(key,
    pending_ids,
    [outer],
    path,
    Bytes.empty(),
    0,
    0,
    local)?
  store_outbound(path,
    prepared,
    List.new(),
    seal_session_ids(ids, key)?,
    clear_labels,
    clear_blobs,
    labels,
    blobs,
    index)
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
  send_pending(path, key, local, ids, loaded, body)?
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
