from Groups.Mls import GroupDeliveryTarget
from Groups.SenderAnnouncement import (
  GroupSenderAnnouncement,
  decode_group_sender_announcement,
  encode_group_sender_announcement
)
from Groups.Tree import find_member_index
from Mobile.Codec import (
  mobile_byte,
  mobile_finish,
  mobile_join,
  mobile_read_byte,
  mobile_read_u64,
  mobile_reader,
  mobile_vector,
  mobile_write_u64,
  random_bytes,
  take_fixed
)
from Mobile.ContactAddress import deposit_address, outgoing_extensions
from Mobile.GroupState import (
  GroupSigningRecord,
  consume_group_state,
  group_profile,
  group_signers_label,
  group_signing_label,
  load_group,
  load_group_signing
)
from Mobile.Healing import with_session_features
from Mobile.Sessions import (
  find_device_session,
  inner_bytes,
  load_session_ids,
  ratchet_bytes,
  restore_session,
  safety_number,
  seal_updated_session,
  self_sync_conversation_id,
  with_peer_identity
)
from Mobile.Transparency import fresh_account_device_set
from Mobile.Transport import sealed_outer_bytes
from Mobile.Types import MobileLoadedSession
from Protocol.V1 import InnerEnvelope, ProtocolExtension
from Session.Handshake import RatchetState
from Session.Header import ratchet_feature_deniable_groups, ratchet_has_feature
from Session.Ratchet import encrypt_sealed
from Storage.Blobs import load_blob
from Storage.Keys import context, local_context, open_local, open_signing, seal_local, seal_signing
from Transport.Packet import (
  ClientProfile,
  TransportPacket,
  direct_conversation_id,
  encode_packet,
  session_aad
)

##! Mobile.GroupSigning: deniable sender authentication in groups
##! (`protocol/mls-groups-v1.md`, "Deniable sender authentication").
##!
##! A device signs its group messages of an epoch with a key it made for that
##! epoch (group message version 6) once every other member device can read
##! them: each has a session with this device whose peer said so (session
##! feature 8). It tells each of them the key over that session, in inner
##! message type 9, ahead of the message. A receiver accepts a version 6
##! message only under the key the sender's device told it for that epoch, and
##! then refuses that device's long-term-signed messages in the same epoch.
##! The first message of an epoch fixes how the device signs in it.

pub fn group_signer_announcement_type() -> Int do
  9
end

## What a send does before its update commit: whether every other member
## device can read version 6 (`checked` false when the current epoch is
## already deniable, so nothing was looked at), and whether this send must
## start a new epoch to begin signing deniably (its current epoch was fixed as
## long-term).

pub struct GroupSigningStart do
  record :: GroupSigningRecord
  checked :: Bool
  supported :: Bool
  upgrade :: Bool
end

## How a send signs, and what goes with it: the announcements (to lead the
## message's envelopes) and the session and record writes, all stored in the
## send's transaction.

pub struct GroupSigningPlan do
  deniable :: Bool
  public_key :: Bytes
  sealed_key :: Bytes
  key_label :: String
  envelopes :: List<Bytes>
  labels :: List<String>
  blobs :: List<Bytes>
end

fn sealed_signing_record(value :: GroupSigningRecord,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes) -> Result<(String, Bytes), String> do
  let label = group_signing_label(group_id)
  let encoded = mobile_join([
      mobile_byte(1)?,
      mobile_write_u64(value.epoch)?,
      mobile_byte(value.mode)?,
      mobile_vector(value.public_key)?,
      mobile_vector(value.sealed_key)?
    ],
    0,
    Bytes.empty())?
  Ok((label, seal_local(encoded, wrapping_key, local_context(label)?)?))
end

fn key_label(group_id :: Bytes, epoch :: U64) -> String do
  "group-signing/v1/#{Bytes.to_hex(group_id)}/#{U64.to_string(epoch)}"
end

fn drop_state(state :: consume RatchetState) do
  nil
end

fn session_features(loaded :: MobileLoadedSession,
  wrapping_key :: borrow StorageKey) -> Int!String do
  let state = restore_session(loaded, wrapping_key)?
  let features = state.peer_features
  drop_state(state)
  Ok(features)
end

# The session a send to this device would use as it is, without a new
# handshake: the same keys and suite it was verified with.

fn steady_session(local :: ClientProfile,
  peer :: ClientProfile,
  loaded :: MobileLoadedSession) -> Bool!String do
  Ok(Bytes.length(loaded.record.snapshot) > 0
    && loaded.record.reset_state != 2
    && Bytes.secure_equals(loaded.record.peer_mailbox, peer.entry.mailbox_token)
    && Bytes.length(loaded.record.safety_number) == 64
    && Bytes.secure_equals(loaded.record.safety_number, safety_number(local, peer)?)
    && loaded.record.strongest_suite == peer.bundle.suite)
end

fn target_profile(database_path :: String,
  wrapping_key :: borrow StorageKey,
  target :: GroupDeliveryTarget) -> ClientProfile!String do
  let devices = fresh_account_device_set(database_path, wrapping_key, target.account_id)?
  group_profile(devices.profiles, target.account_id, target.device_id, 0)
end

fn target_session(database_path :: String,
  wrapping_key :: borrow StorageKey,
  session_ids :: List<Bytes>,
  target :: GroupDeliveryTarget) -> Option<MobileLoadedSession>!String do
  case find_device_session(database_path,
    wrapping_key,
    target.account_id,
    target.device_id,
    session_ids,
    0) do
    Ok(loaded) -> Ok(Some(loaded))
    Err(error) -> if error == "session_not_found" do
      Ok(None)
    else
      Err(error)
    end
  end
end

fn target_supported(database_path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  session_ids :: List<Bytes>,
  target :: GroupDeliveryTarget) -> Bool!String do
  case target_session(database_path, wrapping_key, session_ids, target)? do
    None -> Ok(false)
    Some(loaded) -> do
      let peer = target_profile(database_path, wrapping_key, target)?
      if steady_session(local, peer, loaded)? do
        Ok(ratchet_has_feature(session_features(loaded, wrapping_key)?,
          ratchet_feature_deniable_groups()))
      else
        Ok(false)
      end
    end
  end
end

# ponytail: finding each target's session scans every session record, and a
# group that stays long-term repeats the scan on each send until the first
# target without support; index sessions by device if that shows.

fn targets_supported(database_path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  session_ids :: List<Bytes>,
  targets :: List<GroupDeliveryTarget>,
  index :: Int) -> Bool!String do
  if index >= List.length(targets) do
    Ok(true)
  else if target_supported(database_path,
    wrapping_key,
    local,
    session_ids,
    List.get(targets, index))? do
    targets_supported(database_path, wrapping_key, local, session_ids, targets, index + 1)
  else
    Ok(false)
  end
end

pub fn group_signing_start(database_path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  group_id :: Bytes,
  epoch :: U64,
  targets :: List<GroupDeliveryTarget>) -> GroupSigningStart!String do
  let record = load_group_signing(database_path, wrapping_key, group_id)?
  let current = record.mode != 0 && U64.compare(record.epoch, epoch) == 0
  let checked = !(current && record.mode == 2)
  let supported = if checked do
    targets_supported(database_path,
      wrapping_key,
      local,
      load_session_ids(database_path, wrapping_key)?,
      targets,
      0)
  else
    Ok(true)
  end?
  Ok(GroupSigningStart {
    record: record,
    checked: checked,
    supported: supported,
    upgrade: current && record.mode == 1 && supported
  })
end

fn announcement_inner(local :: ClientProfile,
  peer :: ClientProfile,
  extensions :: List<ProtocolExtension>,
  body :: Bytes,
  now :: U64) -> InnerEnvelope!String do
  let conversation_id = if Bytes.secure_equals(peer.account_id, local.account_id) do
    self_sync_conversation_id(local.account_id)?
  else
    direct_conversation_id(local.account_id, peer.account_id)?
  end
  Ok(InnerEnvelope {
    version: 1,
    sender_account_id: local.account_id,
    sender_device_id: local.device_id,
    recipient_device_id: peer.device_id,
    conversation_id: conversation_id,
    client_message_id: random_bytes(16)?,
    client_timestamp: now,
    message_type: group_signer_announcement_type(),
    body: body,
    reply_reference: Bytes.empty(),
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: extensions
  })
end

fn announce_to(database_path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  session_ids :: List<Bytes>,
  target :: GroupDeliveryTarget,
  body :: Bytes,
  now :: U64) -> Result<(Bytes, String, Bytes), String> do
  let loaded = case target_session(database_path, wrapping_key, session_ids, target)? do
    None -> Err("group_signer_session_missing")
    Some(value) -> Ok(value)
  end?
  let peer = target_profile(database_path, wrapping_key, target)?
  let extensions = with_session_features(outgoing_extensions(database_path, wrapping_key)?)?
  let inner = announcement_inner(local, peer, extensions, body, now)?
  let state = restore_session(loaded, wrapping_key)?
  let (next_state, message) = case encrypt_sealed(state,
    inner_bytes(inner)?,
    session_aad(loaded.session_id)?) do
    Err(_) -> Err("message_encryption_failed")
    Ok(value)
  end?
  let packet = encode_packet(RatchetPacket(ratchet_bytes(message)?))?
  let envelope = sealed_outer_bytes(deposit_address(database_path,
      wrapping_key,
      peer.entry.mailbox_token)?,
    packet,
    peer.credential.dh_public_key,
    now)?
  let blob = seal_updated_session(next_state,
    with_peer_identity(loaded, peer.credential.dh_public_key),
    wrapping_key)?
  Ok((envelope, loaded.label, blob))
end

fn announcements(database_path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  session_ids :: List<Bytes>,
  targets :: List<GroupDeliveryTarget>,
  body :: Bytes,
  now :: U64,
  index :: Int,
  output :: GroupSigningPlan) -> GroupSigningPlan!String do
  if index >= List.length(targets) do
    Ok(output)
  else
    let (envelope, label, blob) = announce_to(database_path,
      wrapping_key,
      local,
      session_ids,
      List.get(targets, index),
      body,
      now)?
    announcements(database_path,
      wrapping_key,
      local,
      session_ids,
      targets,
      body,
      now,
      index + 1,
      %{output |
        envelopes: List.append(output.envelopes, envelope),
        labels: List.append(output.labels, label),
        blobs: List.append(output.blobs, blob)
      })
  end
end

fn signing_pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("group_key_generation_failed")
    Ok(value)
  end
end

fn deniable_plan(database_path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  group_id :: Bytes,
  epoch :: U64,
  targets :: List<GroupDeliveryTarget>,
  now :: U64) -> GroupSigningPlan!String do
  let pair = signing_pair()?
  let label = key_label(group_id, epoch)
  let sealed_key = seal_signing(pair.private_key,
    wrapping_key,
    context(local.account_id, local.device_id, label, 7)?)?
  let body = case encode_group_sender_announcement(GroupSenderAnnouncement {
    group_id: group_id,
    epoch: epoch,
    signing_public_key: pair.public_key
  }) do
    Err(_) -> Err("invalid_group_signer")
    Ok(value)
  end?
  let record = GroupSigningRecord {
    epoch: epoch,
    mode: 2,
    public_key: pair.public_key.bytes,
    sealed_key: sealed_key
  }
  let (record_label, record_blob) = sealed_signing_record(record, wrapping_key, group_id)?
  announcements(database_path,
    wrapping_key,
    local,
    load_session_ids(database_path, wrapping_key)?,
    targets,
    body,
    now,
    0,
    GroupSigningPlan {
      deniable: true,
      public_key: record.public_key,
      sealed_key: sealed_key,
      key_label: label,
      envelopes: [],
      labels: [record_label],
      blobs: [record_blob]
    })
end

## How this send signs, once its epoch is final. An epoch this device already
## sent in keeps its mode; a new one is deniable when every other member
## device can read it, and long-term otherwise. A deniable epoch that the send
## just refreshed (after 256 messages, or to move witness sets) is checked
## again here: a session may have changed since.

pub fn group_signing_plan(database_path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  start :: GroupSigningStart,
  group_id :: Bytes,
  epoch :: U64,
  targets :: List<GroupDeliveryTarget>,
  now :: U64) -> GroupSigningPlan!String do
  let record = start.record
  if record.mode != 0 && U64.compare(record.epoch, epoch) == 0 do
    Ok(GroupSigningPlan {
      deniable: record.mode == 2,
      public_key: record.public_key,
      sealed_key: record.sealed_key,
      key_label: key_label(group_id, epoch),
      envelopes: [],
      labels: [],
      blobs: []
    })
  else if start.supported
    && (start.checked
      || targets_supported(database_path,
        wrapping_key,
        local,
        load_session_ids(database_path, wrapping_key)?,
        targets,
        0)?) do
    deniable_plan(database_path, wrapping_key, local, group_id, epoch, targets, now)
  else
    let (label, blob) = sealed_signing_record(GroupSigningRecord {
        epoch: epoch,
        mode: 1,
        public_key: Bytes.empty(),
        sealed_key: Bytes.empty()
      },
      wrapping_key,
      group_id)?
    Ok(GroupSigningPlan {
      deniable: false,
      public_key: Bytes.empty(),
      sealed_key: Bytes.empty(),
      key_label: "",
      envelopes: [],
      labels: [label],
      blobs: [blob]
    })
  end
end

## The private half of a deniable plan's key, for signing this send.

pub fn group_signing_key(plan :: GroupSigningPlan,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile) -> SigningPrivateKey!String do
  open_signing(plan.sealed_key,
    wrapping_key,
    context(local.account_id, local.device_id, plan.key_label, 7)?)
end

# Receiving. The record `group-signers/v1/<group>` holds `u8 1` and then
# entries of `u64 epoch || account32 || device16 || key32`, each a key a member
# device announced for an epoch this device has not left.

struct GroupSigner do
  epoch :: U64
  account_id :: Bytes
  device_id :: Bytes
  public_key :: Bytes
end

fn signer_entry(value :: Bytes) -> GroupSigner!String do
  let state = mobile_reader(value, 88, "invalid_group_signers")?
  let epoch = take_fixed(state, 8)?
  let account = take_fixed(epoch.state, 32)?
  let device = take_fixed(account.state, 16)?
  let key = take_fixed(device.state, 32)?
  mobile_finish(key.state, "invalid_group_signers")?
  Ok(GroupSigner {
    epoch: mobile_read_u64(epoch.value)?,
    account_id: account.value,
    device_id: device.value,
    public_key: key.value
  })
end

fn decode_signers(value :: Bytes) -> List<GroupSigner>!String do
  let count = (Bytes.length(value) - 1) / 88
  if Bytes.length(value) < 1
    || (Bytes.length(value) - 1) % 88 != 0
    || mobile_read_byte(Bytes.slice(value, 0, 1)?)? != 1 do
    return Err("invalid_group_signers")
  end
  decode_entries(value, 0, count, [])
end

fn decode_entries(value :: Bytes,
  index :: Int,
  count :: Int,
  output :: List<GroupSigner>) -> List<GroupSigner>!String do
  if index >= count do
    Ok(output)
  else
    let signer = signer_entry(Bytes.slice(value, 1 + index * 88, 88)?)?
    decode_entries(value, index + 1, count, List.append(output, signer))
  end
end

fn signer_parts(values :: List<GroupSigner>,
  index :: Int,
  output :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(values) do
    Ok(output)
  else
    let value = List.get(values, index)
    signer_parts(values,
      index + 1,
      List.concat(output,
        [mobile_write_u64(value.epoch)?, value.account_id, value.device_id, value.public_key]))
  end
end

fn load_signers(database_path :: String,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes) -> List<GroupSigner>!String do
  let label = group_signers_label(group_id)
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok([])
    else
      Err(error)
    end
    Ok(blob) -> decode_signers(open_local(blob, wrapping_key, local_context(label)?)?)
  end
end

fn sealed_signers(values :: List<GroupSigner>,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes) -> Result<(String, Bytes), String> do
  let label = group_signers_label(group_id)
  let parts = signer_parts(values, 0, [mobile_byte(1)?])?
  Ok((label,
    seal_local(mobile_join(parts, 0, Bytes.empty())?, wrapping_key, local_context(label)?)?))
end

fn same_device(value :: GroupSigner, account_id :: Bytes, device_id :: Bytes) -> Bool do
  Bytes.secure_equals(value.account_id, account_id)
    && Bytes.secure_equals(value.device_id, device_id)
end

## The key the device (`account_id`, `device_id`) announced to this one for
## the group's `epoch`; empty when it announced none.

pub fn group_signer_key(database_path :: String,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes,
  epoch :: U64,
  account_id :: Bytes,
  device_id :: Bytes) -> Bytes!String do
  let found = List.find(load_signers(database_path, wrapping_key, group_id)?,
    fn(value) do U64.compare(value.epoch, epoch) == 0
      && same_device(value, account_id, device_id) end)
  case found do
    Some(value) -> Ok(value.public_key)
    None -> Ok(Bytes.empty())
  end
end

# A member device holds at most four announced epochs at once (the current
# one and commits still on their way); more are ignored.

fn signer_writes(database_path :: String,
  wrapping_key :: borrow StorageKey,
  announcement :: GroupSenderAnnouncement,
  current :: U64,
  account_id :: Bytes,
  device_id :: Bytes) -> Result<(List<String>, List<Bytes>), String> do
  let kept = List.filter(load_signers(database_path, wrapping_key, announcement.group_id)?,
    fn(value) do U64.compare(value.epoch, current) >= 0
      && !(U64.compare(value.epoch, announcement.epoch) == 0
        && same_device(value, account_id, device_id)) end)
  let own = List.length(List.filter(kept,
    fn(value) do same_device(value, account_id, device_id) end))
  if own >= 4 do
    Ok(([], []))
  else
    let (label, blob) = sealed_signers(List.append(kept,
        GroupSigner {
          epoch: announcement.epoch,
          account_id: account_id,
          device_id: device_id,
          public_key: announcement.signing_public_key.bytes
        }),
      wrapping_key,
      announcement.group_id)?
    Ok(([label], [blob]))
  end
end

## What an announcement (inner message type 9) from the session peer
## (`account_id`, `device_id`) writes. The peer is its sender: the frame names
## no one. A malformed frame, an epoch this device has left, or a device that
## is not a member there changes nothing. A group this device has not joined
## yet, or a device that is not a member yet of a later epoch, is retried
## (`group_signer_pending`): the welcome or commit is on its way.

pub fn group_signer_received_writes(database_path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  account_id :: Bytes,
  device_id :: Bytes,
  body :: Bytes) -> Result<(List<String>, List<Bytes>), String> do
  let announcement = case decode_group_sender_announcement(body) do
    Err(_) -> return Ok(([], []))
    Ok(value) -> value
  end
  let state = case load_group(database_path, local, wrapping_key, announcement.group_id) do
    Err(error) -> if error == "local_state_not_found" do
      Err("group_signer_pending")
    else
      Err(error)
    end
    Ok(value)
  end?
  let current = state.epoch
  let member = find_member_index(state.tree, account_id, device_id) >= 0
  consume_group_state(state)
  let order = U64.compare(announcement.epoch, current)
  if order < 0 || (order == 0 && !member) do
    Ok(([], []))
  else if !member do
    Err("group_signer_pending")
  else
    signer_writes(database_path, wrapping_key, announcement, current, account_id, device_id)
  end
end
