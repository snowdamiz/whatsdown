from Groups.GroupCodec import delivery_targets
from Groups.GroupMessages import encrypt_group_payload_for_transport, encode_group_message
from Groups.GroupPayload import GroupPayload
from Groups.CommitWire import encode_group_commit
from Groups.Membership import commit_update
from Groups.Mls import GroupState, GroupRemoveOutcome, GroupEncryptOutcome, GroupDeliveryTarget
from Groups.Tree import find_member_index
from Identity.Device import DeviceKeys
from Mobile.Codec import current_time
from Mobile.Gossip import clear_gossip_writes, gossip_peer_blocked
from Mobile.GossipState import GossipState, load_gossip_state, queued_group_peers
from Mobile.GroupState import (
  load_group,
  consume_group_state,
  group_snapshot_blob,
  group_target_envelopes,
  encode_group_packet
)
from Mobile.Outbox import load_outbox_ids, outbox_capacity, prepare_outbox_writes
from Mobile.Profile import open_device
from Storage.Records import store_updated_blobs
from Storage.GroupRecords import store_group_outbound
from Transport.Packet import ClientProfile

fn discard_pending(path :: String, key :: borrow StorageKey, peer :: Bytes) -> Result<(), String> do
  let (labels, blobs) = clear_gossip_writes(path, key, peer)?
  store_updated_blobs(path, labels, blobs)
end

fn refresh_control(path :: String,
  key :: borrow StorageKey,
  state :: consume GroupState,
  signing :: borrow SigningPrivateKey,
  targets :: List<GroupDeliveryTarget>,
  now :: U64) -> Result<(GroupState, List<Bytes>), String> do
  if state.version == 2 && state.next_generation < 256 do
    return Ok((state, []))
  end
  # This advances keys for the already admitted roster; it cannot change the
  # witness policy or admit a member while a signed fork has paused new trust.
  case commit_update(state, signing) do
    GroupRemoveRejected(rejected, _) -> do
      consume_group_state(rejected)
      Err("group_refresh_rejected")
    end
    GroupMemberRemoved(next, commit) -> do
      let wire = case encode_group_commit(commit) do
        Err(_) -> return Err("group_commit_encoding_failed")
        Ok(value) -> value
      end
      let envelopes = group_target_envelopes(path,
        key,
        targets,
        encode_group_packet(2, wire)?,
        now,
        0,
        [])?
      Ok((next, envelopes))
    end
  end
end

fn send_control(path :: String,
  key :: borrow StorageKey,
  local :: ClientProfile,
  peer :: Bytes,
  pending :: GossipState) -> Bool!String do
  if Bytes.length(pending.pending_group) == 0
    || Bytes.length(pending.pending_body) == 0
    || gossip_peer_blocked(path, key, peer)? do
    discard_pending(path, key, peer)?
    return Ok(false)
  end
  let state = case load_group(path, local, key, pending.pending_group) do
    Err(error) -> if error == "local_state_not_found" do
      discard_pending(path, key, peer)?
      return Ok(false)
    else
      return Err(error)
    end
    Ok(value) -> value
  end
  let recipient = find_member_index(state.tree, peer, pending.pending_device)
  if recipient < 0 || recipient == state.local_leaf do
    consume_group_state(state)
    discard_pending(path, key, peer)?
    return Ok(false)
  end
  let targets = case delivery_targets(state.tree, state.local_leaf) do
    Err(_) -> return Err("group_delivery_failed")
    Ok(value) -> value
  end
  let pending_ids = load_outbox_ids(path, key)?
  let copies = if state.version == 2 && state.next_generation < 256 do
    1
  else
    2
  end
  if List.length(pending_ids) + copies * List.length(targets) > outbox_capacity() do
    consume_group_state(state)
    return Ok(false)
  end
  let device = open_device(local, key, path)?
  let now = current_time()?
  let (state, updates) = refresh_control(path,
    key,
    state,
    device.signing_private_key,
    targets,
    now)?
  case encrypt_group_payload_for_transport(state,
    device.signing_private_key,
    GroupPayload {
      kind: 5,
      body: pending.pending_body,
      hint: Bytes.empty(),
      recipient_account: peer,
      recipient_device: pending.pending_device
    },
    Bytes.from_utf8("mesh-mobile-group/v1")) do
    GroupEncryptRejected(rejected, _) -> do
      consume_group_state(rejected)
      Err("group_message_rejected")
    end
    GroupMessageEncrypted(next, message) -> do
      let wire = case encode_group_message(message) do
        Err(_) -> return Err("group_message_encoding_failed")
        Ok(value) -> value
      end
      # All members advance the sender generation, but only the addressed
      # device may answer. Controls never enter any member's visible history.
      let envelopes = group_target_envelopes(path,
        key,
        targets,
        encode_group_packet(3, wire)?,
        now,
        0,
        updates)?
      let (labels, blobs, index) = prepare_outbox_writes(key,
        pending_ids,
        envelopes,
        path,
        Bytes.empty(),
        0,
        0,
        local)?
      let (state_label, state_blob) = group_snapshot_blob(next, local, key)?
      let (clear_labels, clear_blobs) = clear_gossip_writes(path, key, peer)?
      store_group_outbound(path,
        state_label,
        state_blob,
        labels,
        blobs,
        index,
        clear_labels,
        clear_blobs)?
      Ok(true)
    end
  end
end

fn flush_peers(path :: String,
  key :: borrow StorageKey,
  local :: ClientProfile,
  peers :: List<Bytes>,
  index :: Int,
  sent :: Int) -> Result<(), String> do
  if index >= List.length(peers) || sent >= 8 do
    return Ok(nil)
  end
  let peer = List.get(peers, index)
  let queued = case send_control(path, key, local, peer, load_gossip_state(path, key, peer)?) do
    Err(error) -> if error == "transparency_stale"
      || error == "group_transparency_unverified"
      || error == "device_set_transparency_unverified"
      || error == "transparency_trust_mismatch"
      || error == "group_member_not_found"
      || error == "group_membership_changed"
      || error == "invalid_transparency_view" do
      false
    else
      return Err(error)
    end
    Ok(value) -> value
  end
  flush_peers(path,
    key,
    local,
    peers,
    index + 1,
    sent
      + if queued do
        1
      else
        0
      end)
end

pub fn flush_group_gossip(path :: String,
  key :: borrow StorageKey,
  local :: ClientProfile) -> Result<(), String> do
  flush_peers(path, key, local, queued_group_peers(path, key)?, 0, 0)
end
