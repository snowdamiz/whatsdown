from Mobile.Attachments import attachment_summary, group_attachment_reference
from Mobile.ContactAddress import deposit_address
from Mobile.Delivery import DeliveryRecord, delivery_state, load_delivery
from Mobile.Transparency import fresh_account_device_set
from Mobile.Transport import sealed_outer_bytes
from Mobile.Presentation import presented_message_writes
from Binary.Reader import BinaryReader, finish, reader
from Groups.CommitWire import decode_group_commit, encode_group_commit
from Groups.GroupMessages import decode_group_message, encode_group_message
from Groups.GroupSnapshot import group_snapshot, restore_group
from Groups.Mls import (
  GroupCommit,
  GroupDeliveryTarget,
  GroupError,
  GroupMessage,
  GroupProposal,
  GroupSnapshotOutcome,
  GroupState,
  GroupTransparencyPolicy,
  GroupWelcome
)
from Groups.WelcomeWire import decode_group_welcome, encode_group_welcome
from Groups.Tree import GroupMember, IndexedGroupMember, indexed_members
from Identity.Device import DeviceKeys
from Mobile.Codec import (
  encode_output_list,
  mobile_append,
  mobile_byte,
  mobile_join,
  mobile_read_byte,
  mobile_read_u32,
  mobile_read_u64,
  mobile_vector,
  mobile_wide,
  mobile_write_u32,
  mobile_write_u64,
  take_fixed,
  take_vector
)
from Mobile.Profile import load_profile, open_device
from Mobile.Transparency import (
  canonical_transparency_checkpoint,
  load_transparency_view,
  transparency_checkpoint_bytes,
  transparency_checkpoint_in_view,
  transparency_checkpoint_precedes
)
from Mobile.Types import (
  MobileAttachmentRecipient,
  MobileGroupHistoryEntry,
  MobileGroupKeyPackage,
  MobileGroupPacket,
  MobileGroupReferenceRequest,
  MobileGroupWelcomePacket,
  MobileReadBytes,
  MobileTransparencyView,
  MobileVerifiedDeviceSet
)
from Protocol.V1 import AccountIdentity, DeviceCredential, DeviceSet, DirectoryEntry, PrekeyBundle
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import context, local_context, open_local, platform_key, seal_local, seal_x25519
from Storage.Records import store_blobs
from Transparency.Merkle import TransparencyCheckpoint, checkpoint_hash
from Transparency.Wire import decode_checkpoint, encode_checkpoint
from Transport.Packet import ClientProfile, decode_client_profile

##! Mobile.GroupState implementation.

pub fn consume_group_state(value :: consume GroupState) do
  nil
end

pub fn consume_group_private(value :: consume X25519PrivateKey) do
  nil
end

pub fn group_state_label(group_id :: Bytes) -> String!String do
  if Bytes.length(group_id) != 32 do
    Err("invalid_group_id")
  else
    Ok("group-state/v1/#{Bytes.to_hex(group_id)}")
  end
end

pub fn group_baseline_label(group_id :: Bytes) -> String!String do
  if Bytes.length(group_id) != 32 do
    Err("invalid_group_id")
  else
    Ok("group-baseline/v1/#{Bytes.to_hex(group_id)}")
  end
end

pub fn group_baseline_blob(checkpoint :: Bytes,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes) -> Bytes!String do
  canonical_transparency_checkpoint(checkpoint)?
  let label = group_baseline_label(group_id)?
  seal_local(checkpoint, wrapping_key, local_context(label)?)
end

pub fn load_group_baseline(database_path :: String,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes) -> Bytes!String do
  let label = group_baseline_label(group_id)?
  let checkpoint = open_local(load_blob(database_path, label)?, wrapping_key, local_context(label)?)?
  canonical_transparency_checkpoint(checkpoint)?
  Ok(checkpoint)
end

fn contains_group_id(values :: List<Bytes>, group_id :: Bytes, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else if Bytes.secure_equals(List.get(values, index), group_id) do
    true
  else
    contains_group_id(values, group_id, index + 1)
  end
end

fn decode_group_ids_parts(state :: BinaryReader, count :: Int, index :: Int, ids :: List<Bytes>) -> List<Bytes>!String do
  if index >= count do
    case finish(state) do
      Err(_) -> Err("invalid_group_index")
      Ok(_) -> Ok(ids)
    end
  else
    let id = take_vector(state, 32)?
    if Bytes.length(id.value) != 32 || contains_group_id(ids, id.value, 0) do
      Err("invalid_group_index")
    else
      decode_group_ids_parts(id.state, count, index + 1, List.append(ids, id.value))
    end
  end
end

fn decode_group_ids(input :: Bytes) -> List<Bytes>!String do
  case reader(input, 4616) do
    Err(_) -> Err("invalid_group_index")
    Ok(state) -> do
      let count = take_vector(state, 4)?
      let count_value = mobile_read_u32(count.value)?
      if count_value > 128 do
        Err("invalid_group_index")
      else
        decode_group_ids_parts(count.state, count_value, 0, List.new())
      end
    end
  end
end

fn load_group_ids(database_path :: String, wrapping_key :: borrow StorageKey) -> List<Bytes>!String do
  let label = "groups/v1"
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(List.new())
    else
      Err(error)
    end
    Ok(blob) -> decode_group_ids(open_local(blob, wrapping_key, local_context(label)?)?)
  end
end

pub fn updated_group_index_blob(database_path :: String,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes) -> Bytes!String do
  let ids = load_group_ids(database_path, wrapping_key)?
  let updated = if contains_group_id(ids, group_id, 0) do
    ids
  else if List.length(ids) >= 128 do
    Err("group_limit_reached")?
  else
    List.append(ids, group_id)
  end
  seal_local(encode_output_list(updated)?, wrapping_key, local_context("groups/v1")?)
end

pub fn group_history_label(group_id :: Bytes) -> String do
  "group-history/v1/#{Bytes.to_hex(group_id)}"
end

fn valid_group_history_entry(value :: MobileGroupHistoryEntry) -> Bool do
  (Bytes.length(value.message_id) == 0 || Bytes.length(value.message_id) == 32) && (value.direction == 1 || value.direction == 2) && Bytes.length(value.sender_account_id) == 32 && Bytes.length(value.sender_device_id) == 16 && Bytes.length(value.body) <= 65346 && Bytes.length(value.attachment) <= 16384
end

fn encode_group_history_entry(value :: MobileGroupHistoryEntry) -> Bytes!String do
  if !valid_group_history_entry(value) do
    Err("invalid_group_history")
  else
    encode_output_list([
      mobile_byte(1)?,
      mobile_byte(value.direction)?,
      mobile_write_u64(value.epoch)?,
      value.sender_account_id,
      value.sender_device_id,
      mobile_write_u64(value.timestamp)?,
      value.body,
      value.attachment,
      value.message_id
    ])
  end
end

# Exported entries replace the opaque local reference with its opened manifest summary.
# The last field says what became of a sent message: 0 sent, 1 still waiting
# to leave, 2 refused for good by every device it was addressed to.

fn encode_group_history_summary(device :: borrow DeviceKeys,
  value :: MobileGroupHistoryEntry,
  delivery :: List<DeliveryRecord>) -> Bytes!String do
  if !valid_group_history_entry(value) do
    Err("invalid_group_history")
  else
    let state = if value.direction == 1 && Bytes.length(value.message_id) == 32 do
      delivery_state(delivery, value.message_id)
    else
      0
    end
    encode_output_list([
      mobile_byte(1)?,
      mobile_byte(value.direction)?,
      mobile_write_u64(value.epoch)?,
      value.sender_account_id,
      value.sender_device_id,
      mobile_write_u64(value.timestamp)?,
      value.body,
      attachment_summary(device, value.attachment),
      value.message_id,
      mobile_byte(state)?
    ])
  end
end

fn decode_group_history_entry(input :: Bytes) -> MobileGroupHistoryEntry!String do
  case reader(input, 81872) do
    Err(_) -> Err("invalid_group_history")
    Ok(state) -> do
      let count = take_vector(state, 4)?
      let count_value = mobile_read_u32(count.value)?
      let version = take_vector(count.state, 1)?
      let direction = take_vector(version.state, 1)?
      let epoch = take_vector(direction.state, 8)?
      let account_id = take_vector(epoch.state, 32)?
      let device_id = take_vector(account_id.state, 16)?
      let timestamp = take_vector(device_id.state, 8)?
      let body = take_vector(timestamp.state, 65346)?
      # Entries written before attachments shipped carry seven fields.
      let attachment = if count_value >= 8 do
        take_vector(body.state, 16384)?
      else
        MobileReadBytes { state: body.state, value: Bytes.empty() }
      end
      # Legacy histories remain readable; their missing wire IDs cannot be reconstructed.
      let message_id = if count_value == 9 do
        take_vector(attachment.state, 32)?
      else
        MobileReadBytes { state: attachment.state, value: Bytes.empty() }
      end
      case finish(message_id.state) do
        Err(_) -> Err("invalid_group_history")
        Ok(_) -> do
          let direction_value = mobile_read_byte(direction.value)?
          if (count_value != 7 && count_value != 8 && count_value != 9) || (Bytes.length(message_id.value) != 0 && Bytes.length(message_id.value) != 32) || mobile_read_byte(version.value)? != 1 || (direction_value != 1 && direction_value != 2) || Bytes.length(account_id.value) != 32 || Bytes.length(device_id.value) != 16 do
            Err("invalid_group_history")
          else
            Ok(MobileGroupHistoryEntry {
              message_id: message_id.value,
              direction: direction_value,
              epoch: mobile_read_u64(epoch.value)?,
              sender_account_id: account_id.value,
              sender_device_id: device_id.value,
              timestamp: mobile_read_u64(timestamp.value)?,
              body: body.value,
              attachment: attachment.value
            })
          end
        end
      end
    end
  end
end

fn decode_group_history_parts(state :: BinaryReader,
  count :: Int,
  index :: Int,
  entries :: List<MobileGroupHistoryEntry>) -> List<MobileGroupHistoryEntry>!String do
  if index >= count do
    case finish(state) do
      Err(_) -> Err("invalid_group_history")
      Ok(_) -> Ok(entries)
    end
  else
    let entry = take_vector(state, 81872)?
    decode_group_history_parts(entry.state,
      count,
      index + 1,
      List.append(entries, decode_group_history_entry(entry.value)?))
  end
end

fn decode_group_history(input :: Bytes) -> List<MobileGroupHistoryEntry>!String do
  case reader(input, 65536) do
    Err(_) -> Err("invalid_group_history")
    Ok(state) -> do
      let count = take_vector(state, 4)?
      let count_value = mobile_read_u32(count.value)?
      if count_value > 256 do
        Err("invalid_group_history")
      else
        decode_group_history_parts(count.state, count_value, 0, List.new())
      end
    end
  end
end

fn encode_group_history(values :: List<MobileGroupHistoryEntry>) -> Bytes!String do
  let bounded = if List.length(values) > 256 do
    List.drop(values, List.length(values) - 256)
  else
    values
  end
  encode_bounded_group_history(bounded)
end

fn encode_bounded_group_history(values :: List<MobileGroupHistoryEntry>) -> Bytes!String do
  let encoded = encode_group_history_entries(values, 0, List.new())?
  let output = encode_output_list(encoded)?
  if Bytes.length(output) <= 65536 do
    Ok(output)
  else if List.length(values) == 0 do
    Err("invalid_group_history")
  else
    encode_bounded_group_history(List.drop(values, 1))
  end
end

fn encode_group_history_entries(values :: List<MobileGroupHistoryEntry>,
  index :: Int,
  encoded :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(values) do
    Ok(encoded)
  else
    encode_group_history_entries(values,
      index + 1,
      List.append(encoded, encode_group_history_entry(List.get(values, index))?))
  end
end

fn encode_group_history_summaries(device :: borrow DeviceKeys,
  values :: List<MobileGroupHistoryEntry>,
  delivery :: List<DeliveryRecord>,
  index :: Int,
  encoded :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(values) do
    Ok(encoded)
  else
    encode_group_history_summaries(device,
      values,
      delivery,
      index + 1,
      List.append(encoded, encode_group_history_summary(device, List.get(values, index), delivery)?))
  end
end

fn load_group_history(database_path :: String, wrapping_key :: borrow StorageKey, group_id :: Bytes) -> List<MobileGroupHistoryEntry>!String do
  let label = group_history_label(group_id)
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(List.new())
    else
      Err(error)
    end
    Ok(blob) -> decode_group_history(open_local(blob, wrapping_key, local_context(label)?)?)
  end
end

pub fn updated_group_history_blob(database_path :: String,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes,
  creator_id :: Bytes,
  entry :: MobileGroupHistoryEntry) -> Result<(List<String>, List<Bytes>), String> do
  let label = group_history_label(group_id)
  let (body, envelope, presentation_labels, presentation_blobs) = presented_message_writes(database_path,
    wrapping_key,
    entry.sender_account_id,
    group_id,
    creator_id,
    entry.body)?
  # Senders pass their own local reference; receivers pick theirs out of the group envelope.
  # A malformed envelope must not block the text body, so it degrades to "no attachment".
  let attachment = if Bytes.length(entry.attachment) > 0 do
    entry.attachment
  else
    let local = decode_client_profile(load_profile(database_path)?)?
    case group_attachment_reference(envelope, local.account_id, local.device_id) do
      Err(_) -> Bytes.empty()
      Ok(value) -> value
    end
  end
  let previous = load_group_history(database_path, wrapping_key, group_id)?
  let entries = if Bytes.length(body) == 0 && Bytes.length(attachment) == 0 do
    previous
  else
    List.append(previous, %{entry | body: body, attachment: attachment})
  end
  Ok((List.append(presentation_labels, label),
    List.append(presentation_blobs,
      seal_local(encode_group_history(entries)?, wrapping_key, local_context(label)?)?)))
end

pub fn group_join_label(kind :: String) -> String do
  "group-join-#{kind}/v1"
end

pub fn group_join_scoped_label(scope :: String, kind :: String) -> String do
  if scope == "" do
    group_join_label(kind)
  else
    "group-invitation/#{scope}/#{kind}/v1"
  end
end

pub fn group_checkpoint(database_path :: String, wrapping_key :: borrow StorageKey) -> Bytes!String do
  let encoded = transparency_checkpoint_bytes(database_path, wrapping_key)?
  if Bytes.length(encoded) == 0 do
    Err("group_transparency_unverified")
  else
    let view = load_transparency_view(database_path, wrapping_key)?
    if transparency_checkpoint_in_view(encoded, view)? do
      Ok(encoded)
    else
      Err("group_transparency_unverified")
    end
  end
end

pub fn group_member(profile :: ClientProfile,
  init_public_key :: X25519PublicKey,
  leaf_public_key :: X25519PublicKey,
  directory_sequence :: U64,
  checkpoint :: Bytes,
  witness_count :: Int) -> GroupMember do
  GroupMember {
    version: 1,
    account_id: profile.account_id,
    device_id: profile.device_id,
    signing_public_key: SigningPublicKey { bytes: profile.credential.signing_public_key },
    init_public_key: init_public_key,
    leaf_public_key: leaf_public_key,
    mailbox_token: profile.entry.mailbox_token,
    directory_sequence: directory_sequence,
    transparency_checkpoint_hash: checkpoint,
    witness_count: witness_count,
    extensions: [1]
  }
end

pub fn group_key_package_unsigned(value :: MobileGroupKeyPackage) -> Bytes!String do
  mobile_join([
      mobile_byte(1)?,
      Bytes.from_utf8("GKP"),
      value.account_id,
      value.device_id,
      value.init_public_key.bytes,
      value.leaf_public_key.bytes,
      value.checkpoint,
      mobile_byte(value.witness_count)?
    ],
    0,
    Bytes.empty())
end

fn encode_group_key_package(value :: MobileGroupKeyPackage) -> Bytes!String do
  let unsigned = group_key_package_unsigned(value)?
  if Bytes.length(unsigned) != 305 || Bytes.length(value.signature.bytes) != 64 do
    Err("invalid_group_key_package")
  else
    mobile_append(unsigned, value.signature.bytes)
  end
end

pub fn decode_group_key_package(input :: Bytes) -> MobileGroupKeyPackage!String do
  if Bytes.length(input) != 369 do
    Err("invalid_group_key_package")
  else
    let state = case reader(input, 369) do
      Err(_) -> Err("invalid_group_key_package")
      Ok(value)
    end?
    let version = take_fixed(state, 1)?
    let magic = take_fixed(version.state, 3)?
    let account_id = take_fixed(magic.state, 32)?
    let device_id = take_fixed(account_id.state, 16)?
    let init_public = take_fixed(device_id.state, 32)?
    let leaf_public = take_fixed(init_public.state, 32)?
    let checkpoint = take_fixed(leaf_public.state, 188)?
    let witness = take_fixed(checkpoint.state, 1)?
    let signature = take_fixed(witness.state, 64)?
    case finish(signature.state) do
      Err(_) -> Err("invalid_group_key_package")
      Ok(_) -> do
        let value = MobileGroupKeyPackage {
          account_id: account_id.value,
          device_id: device_id.value,
          init_public_key: X25519PublicKey { bytes: init_public.value },
          leaf_public_key: X25519PublicKey { bytes: leaf_public.value },
          checkpoint: checkpoint.value,
          witness_count: mobile_read_byte(witness.value)?,
          signature: Signature { bytes: signature.value }
        }
        if mobile_read_byte(version.value)? != 1 || !Bytes.secure_equals(magic.value,
          Bytes.from_utf8("GKP")) || Bytes.secure_equals(init_public.value, leaf_public.value) || value.witness_count != 2 || !Bytes.secure_equals(encode_checkpoint(decode_checkpoint(checkpoint.value)?)?,
          checkpoint.value) || !Bytes.secure_equals(encode_group_key_package(value)?, input) do
          Err("invalid_group_key_package")
        else
          Ok(value)
        end
      end
    end
  end
end

pub fn group_profile(profiles :: List<ClientProfile>,
  account_id :: Bytes,
  device_id :: Bytes,
  index :: Int) -> ClientProfile!String do
  if index >= List.length(profiles) do
    Err("group_member_not_found")
  else
    let value = List.get(profiles, index)
    if Bytes.secure_equals(value.account_id, account_id) && Bytes.secure_equals(value.device_id,
      device_id) do
      Ok(value)
    else
      group_profile(profiles, account_id, device_id, index + 1)
    end
  end
end

pub fn verified_group_member(devices :: MobileVerifiedDeviceSet,
  encoded_package :: Bytes,
  proof_checkpoint :: Bytes,
  baseline_checkpoint :: Bytes,
  view :: MobileTransparencyView) -> GroupMember!String do
  let package = decode_group_key_package(encoded_package)?
  let profile = group_profile(devices.profiles, package.account_id, package.device_id, 0)?
  let valid_signature = case Crypto.verify(SigningPublicKey {
      bytes: profile.credential.signing_public_key
    },
    group_key_package_unsigned(package)?,
    package.signature) do
    Err(_) -> false
    Ok(value) -> value
  end
  if !valid_signature || !(transparency_checkpoint_precedes(baseline_checkpoint,
    package.checkpoint,
    view)?) || !(transparency_checkpoint_precedes(package.checkpoint, proof_checkpoint, view)?) do
    Err("invalid_group_key_package")
  else
    let baseline_hash = checkpoint_hash(canonical_transparency_checkpoint(baseline_checkpoint)?)?
    Ok(group_member(profile,
      package.init_public_key,
      package.leaf_public_key,
      devices.value.sequence,
      baseline_hash,
      package.witness_count))
  end
end

pub fn create_group_key_package(database_path :: String) -> Bytes!String do
  create_group_key_package_scoped(database_path, "")
end

pub fn create_group_key_package_scoped(database_path :: String, scope :: String) -> Bytes!String do
  ensure_schema(database_path)?
  let profile = decode_client_profile(load_profile(database_path)?)?
  let wrapping_key = platform_key()?
  let checkpoint = group_checkpoint(database_path, wrapping_key)?
  let view = load_transparency_view(database_path, wrapping_key)?
  let package_label = group_join_scoped_label(scope, "package")
  case load_blob(database_path, package_label) do
    Ok(blob) -> do
      let encoded = open_local(blob, wrapping_key, local_context(package_label)?)?
      let package = decode_group_key_package(encoded)?
      let signature_valid = case Crypto.verify(SigningPublicKey {
          bytes: profile.credential.signing_public_key
        },
        group_key_package_unsigned(package)?,
        package.signature) do
        Err(_) -> false
        Ok(value) -> value
      end
      if signature_valid && Bytes.secure_equals(package.account_id, profile.account_id) && Bytes.secure_equals(package.device_id,
        profile.device_id) && transparency_checkpoint_precedes(package.checkpoint, checkpoint, view)? do
        Ok(encoded)
      else
        Err("group_key_package_pending")
      end
    end
    Err(error) -> if error != "local_state_not_found" do
      Err(error)
    else
      let init_keys = case Crypto.x25519_generate() do
        Err(_) -> Err("group_key_generation_failed")
        Ok(value)
      end?
      let leaf_keys = case Crypto.x25519_generate() do
        Err(_) -> Err("group_key_generation_failed")
        Ok(value)
      end?
      let unsigned = MobileGroupKeyPackage {
        account_id: profile.account_id,
        device_id: profile.device_id,
        init_public_key: init_keys.public_key,
        leaf_public_key: leaf_keys.public_key,
        checkpoint: checkpoint,
        witness_count: 2,
        signature: Signature { bytes: Bytes.empty() }
      }
      let device = open_device(profile, wrapping_key, database_path)?
      let signature = case Crypto.sign(device.signing_private_key,
        group_key_package_unsigned(unsigned)?) do
        Err(_) -> Err("group_key_generation_failed")
        Ok(value)
      end?
      let encoded = encode_group_key_package(%{unsigned | signature: signature})?
      let init_label = group_join_scoped_label(scope, "init")
      let leaf_label = group_join_scoped_label(scope, "leaf")
      let package_blob = seal_local(encoded, wrapping_key, local_context(package_label)?)?
      let init_blob = seal_x25519(init_keys.private_key,
        wrapping_key,
        context(profile.account_id, profile.device_id, init_label, 17)?)?
      let leaf_blob = seal_x25519(leaf_keys.private_key,
        wrapping_key,
        context(profile.account_id, profile.device_id, leaf_label, 17)?)?
      consume_group_private(init_keys.private_key)
      consume_group_private(leaf_keys.private_key)
      store_blobs(database_path,
        [package_label, init_label, leaf_label],
        [package_blob, init_blob, leaf_blob])?
      Ok(encoded)
    end
  end
end

pub fn group_snapshot_blob(state :: consume GroupState,
  profile :: ClientProfile,
  wrapping_key :: borrow StorageKey) -> Result<(String, Bytes), String> do
  let label = group_state_label(state.group_id)?
  let version = U64.add(state.snapshot_version, mobile_wide("1")?)?
  case group_snapshot(state, wrapping_key, profile.account_id, profile.device_id, version) do
    GroupSnapshotRejected(rejected, _) -> do
      consume_group_state(rejected)
      Err("group_snapshot_failed")
    end
    GroupSnapshotSealed(next, snapshot_blob) -> do
      let stored = seal_local(snapshot_blob, wrapping_key, local_context(label)?)?
      consume_group_state(next)
      Ok((label, stored))
    end
  end
end

pub fn load_group(database_path :: String,
  profile :: ClientProfile,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes) -> GroupState!String do
  let label = group_state_label(group_id)?
  let snapshot_blob = open_local(load_blob(database_path, label)?,
    wrapping_key,
    local_context(label)?)?
  case restore_group(snapshot_blob,
    wrapping_key,
    profile.account_id,
    profile.device_id,
    mobile_wide("1")?) do
    Err(_) -> Err("group_state_invalid")
    Ok(state) -> if Bytes.secure_equals(state.group_id, group_id) do
      Ok(state)
    else
      consume_group_state(state)
      Err("group_state_invalid")
    end
  end
end

fn group_summary(state :: borrow GroupState) -> Bytes!String do
  encode_output_list([
    mobile_byte(1)?,
    state.group_id,
    mobile_write_u64(state.epoch)?,
    mobile_write_u32(List.length(indexed_members(state.tree)))?
  ])
end

fn group_member_summary(database_path :: String,
  wrapping_key :: borrow StorageKey,
  value :: IndexedGroupMember,
  local_leaf :: Int) -> Bytes!String do
  # Display names are not addresses. Only expose a username bound to this account.
  let username = case fresh_account_device_set(database_path, wrapping_key, value.member.account_id) do
    Ok(devices) -> Bytes.from_utf8(devices.value.username)
    Err(_) -> Bytes.empty()
  end
  encode_output_list([
    mobile_byte(1)?,
    mobile_write_u32(value.leaf_index)?,
    mobile_byte(if value.leaf_index == local_leaf do
      1
    else
      0
    end)?,
    value.member.account_id,
    value.member.device_id,
    mobile_write_u64(value.member.directory_sequence)?,
    mobile_byte(value.member.witness_count)?,
    username
  ])
end

fn group_member_summaries(database_path :: String,
  wrapping_key :: borrow StorageKey,
  values :: List<IndexedGroupMember>,
  local_leaf :: Int,
  index :: Int,
  summaries :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(values) do
    Ok(summaries)
  else
    group_member_summaries(database_path,
      wrapping_key,
      values,
      local_leaf,
      index + 1,
      List.append(summaries,
        group_member_summary(database_path, wrapping_key, List.get(values, index), local_leaf)?))
  end
end

pub fn inspect_mobile_group(request :: MobileGroupReferenceRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let profile = decode_client_profile(load_profile(request.database_path)?)?
  let wrapping_key = platform_key()?
  let state = load_group(request.database_path, profile, wrapping_key, request.group_id)?
  let members = group_member_summaries(request.database_path,
    wrapping_key,
    indexed_members(state.tree),
    state.local_leaf,
    0,
    List.new())?
  let encoded = encode_output_list([
    mobile_byte(1)?,
    state.group_id,
    mobile_write_u64(state.epoch)?,
    mobile_write_u32(state.local_leaf)?,
    state.tree_hash_cache,
    state.policy.checkpoint_hash,
    encode_output_list(members)?
  ])?
  consume_group_state(state)
  Ok(encoded)
end

fn collect_group_summaries(database_path :: String,
  profile :: ClientProfile,
  wrapping_key :: borrow StorageKey,
  group_ids :: List<Bytes>,
  index :: Int,
  summaries :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(group_ids) do
    Ok(summaries)
  else
    let state = load_group(database_path, profile, wrapping_key, List.get(group_ids, index))?
    let summary = group_summary(state)?
    consume_group_state(state)
    collect_group_summaries(database_path,
      profile,
      wrapping_key,
      group_ids,
      index + 1,
      List.append(summaries, summary))
  end
end

pub fn list_mobile_groups(database_path :: String) -> Bytes!String do
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    ensure_schema(database_path)?
    let profile = decode_client_profile(load_profile(database_path)?)?
    let wrapping_key = platform_key()?
    encode_output_list(collect_group_summaries(database_path,
      profile,
      wrapping_key,
      load_group_ids(database_path, wrapping_key)?,
      0,
      List.new())?)
  end
end

pub fn mobile_group_history(request :: MobileGroupReferenceRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let profile = decode_client_profile(load_profile(request.database_path)?)?
  let wrapping_key = platform_key()?
  let state = load_group(request.database_path, profile, wrapping_key, request.group_id)?
  consume_group_state(state)
  let entries = load_group_history(request.database_path, wrapping_key, request.group_id)?
  let device = open_device(profile, wrapping_key, request.database_path)?
  encode_output_list(encode_group_history_summaries(device,
    entries,
    load_delivery(request.database_path, wrapping_key)?,
    0,
    List.new())?)
end

pub fn encode_group_welcome_packet(value :: MobileGroupWelcomePacket) -> Bytes!String do
  if Bytes.length(value.baseline_checkpoint) != 188 || Bytes.length(value.welcome) == 0 || Bytes.length(value.welcome) > 65327 do
    Err("invalid_group_welcome")
  else
    canonical_transparency_checkpoint(value.baseline_checkpoint)?
    mobile_join([
        mobile_byte(1)?,
        Bytes.from_utf8("GWB"),
        mobile_vector(value.baseline_checkpoint)?,
        mobile_vector(value.welcome)?
      ],
      0,
      Bytes.empty())
  end
end

fn decode_group_welcome_packet_inner(input :: Bytes) -> MobileGroupWelcomePacket!String do
  case reader(input, 65527) do
    Err(_) -> Err("invalid_group_welcome")
    Ok(state) -> do
      let version = take_fixed(state, 1)?
      let magic = take_fixed(version.state, 3)?
      let baseline = take_vector(magic.state, 188)?
      let welcome = take_vector(baseline.state, 65327)?
      case finish(welcome.state) do
        Err(_) -> Err("invalid_group_welcome")
        Ok(_) -> do
          let value = MobileGroupWelcomePacket {
            baseline_checkpoint: baseline.value,
            welcome: welcome.value
          }
          if mobile_read_byte(version.value)? != 1 || !Bytes.secure_equals(magic.value,
            Bytes.from_utf8("GWB")) || Bytes.length(baseline.value) != 188 || Bytes.length(welcome.value) == 0 || !Bytes.secure_equals(encode_group_welcome_packet(value)?,
            input) do
            Err("invalid_group_welcome")
          else
            Ok(value)
          end
        end
      end
    end
  end
end

pub fn decode_group_welcome_packet(input :: Bytes) -> MobileGroupWelcomePacket!String do
  case decode_group_welcome_packet_inner(input) do
    Err(_) -> Err("invalid_group_welcome")
    Ok(value)
  end
end

pub fn encode_group_packet(kind :: Int, payload :: Bytes) -> Bytes!String do
  if kind < 1 || kind > 3 || Bytes.length(payload) == 0 || Bytes.length(payload) > 65527 do
    Err("invalid_group_packet")
  else
    let encoded = mobile_join([
        mobile_byte(1)?,
        Bytes.from_utf8("GRP"),
        mobile_byte(kind)?,
        mobile_vector(payload)?
      ],
      0,
      Bytes.empty())?
    if Bytes.length(encoded) > 65536 do
      Err("group_message_too_large")
    else
      Ok(encoded)
    end
  end
end

fn decode_group_packet_inner(input :: Bytes) -> MobileGroupPacket!String do
  case reader(input, 65536) do
    Err(_) -> Err("invalid_group_packet")
    Ok(state) -> do
      let version = take_fixed(state, 1)?
      let magic = take_fixed(version.state, 3)?
      let kind = take_fixed(magic.state, 1)?
      let payload = take_vector(kind.state, 65527)?
      case finish(payload.state) do
        Err(_) -> Err("invalid_group_packet")
        Ok(_) -> do
          let kind_value = mobile_read_byte(kind.value)?
          let value = MobileGroupPacket { kind: kind_value, payload: payload.value }
          if mobile_read_byte(version.value)? != 1 || !Bytes.secure_equals(magic.value,
            Bytes.from_utf8("GRP")) || kind_value < 1 || kind_value > 3 || Bytes.length(payload.value) == 0 || !Bytes.secure_equals(encode_group_packet(kind_value,
              payload.value)?,
            input) do
            Err("invalid_group_packet")
          else
            Ok(value)
          end
        end
      end
    end
  end
end

pub fn decode_group_packet(input :: Bytes) -> MobileGroupPacket!String do
  case decode_group_packet_inner(input) do
    Err(_) -> Err("invalid_group_packet")
    Ok(value)
  end
end

pub fn canonical_group_commit(input :: Bytes) -> GroupCommit!String do
  let value = case decode_group_commit(input) do
    Err(_) -> Err("invalid_group_commit")
    Ok(decoded)
  end?
  let encoded = case encode_group_commit(value) do
    Err(_) -> Err("invalid_group_commit")
    Ok(output)
  end?
  if Bytes.secure_equals(encoded, input) do
    Ok(value)
  else
    Err("invalid_group_commit")
  end
end

pub fn canonical_group_welcome(input :: Bytes) -> GroupWelcome!String do
  let value = case decode_group_welcome(input) do
    Err(_) -> Err("invalid_group_welcome")
    Ok(decoded)
  end?
  let encoded = case encode_group_welcome(value) do
    Err(_) -> Err("invalid_group_welcome")
    Ok(output)
  end?
  if Bytes.secure_equals(encoded, input) do
    Ok(value)
  else
    Err("invalid_group_welcome")
  end
end

pub fn canonical_group_message(input :: Bytes) -> GroupMessage!String do
  let value = case decode_group_message(input) do
    Err(_) -> Err("invalid_group_message")
    Ok(decoded)
  end?
  let encoded = case encode_group_message(value) do
    Err(_) -> Err("invalid_group_message")
    Ok(output)
  end?
  if Bytes.secure_equals(encoded, input) do
    Ok(value)
  else
    Err("invalid_group_message")
  end
end

fn group_recipient_envelope(path :: String,
  key :: borrow StorageKey,
  target :: GroupDeliveryTarget,
  packet :: Bytes,
  now :: U64) -> Bytes!String do
  let devices = fresh_account_device_set(path, key, target.account_id)?
  let recipient = group_profile(devices.profiles, target.account_id, target.device_id, 0)?
  # A member who is also a contact has handed over a better address than the public one.
  sealed_outer_bytes(deposit_address(path, key, recipient.entry.mailbox_token)?,
    packet,
    recipient.credential.dh_public_key,
    now)
end

# Attachment keys wrap to each member's stable identity key, not to rotating TreeKEM leaves.

pub fn group_attachment_recipients(path :: String,
  key :: borrow StorageKey,
  targets :: List<GroupDeliveryTarget>,
  index :: Int,
  output :: List<MobileAttachmentRecipient>) -> List<MobileAttachmentRecipient>!String do
  if index >= List.length(targets) do
    Ok(output)
  else
    let target = List.get(targets, index)
    let devices = fresh_account_device_set(path, key, target.account_id)?
    let recipient = group_profile(devices.profiles, target.account_id, target.device_id, 0)?
    group_attachment_recipients(path,
      key,
      targets,
      index + 1,
      List.append(output,
        MobileAttachmentRecipient {
          account_id: target.account_id,
          device_id: target.device_id,
          public_key: recipient.credential.dh_public_key
        }))
  end
end

pub fn group_target_envelopes(path :: String,
  key :: borrow StorageKey,
  targets :: List<GroupDeliveryTarget>,
  packet :: Bytes,
  now :: U64,
  index :: Int,
  output :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(targets) do
    Ok(output)
  else
    group_target_envelopes(path,
      key,
      targets,
      packet,
      now,
      index + 1,
      List.append(output,
        group_recipient_envelope(path, key, List.get(targets, index), packet, now)?))
  end
end

pub fn group_add_envelopes(path :: String,
  key :: borrow StorageKey,
  targets :: List<GroupDeliveryTarget>,
  recipient_leaf :: Int,
  commit_packet :: Bytes,
  welcome_packet :: Bytes,
  now :: U64,
  index :: Int,
  output :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(targets) do
    Ok(output)
  else
    let target = List.get(targets, index)
    let packet = if target.leaf_index == recipient_leaf do
      welcome_packet
    else
      commit_packet
    end
    group_add_envelopes(path,
      key,
      targets,
      recipient_leaf,
      commit_packet,
      welcome_packet,
      now,
      index + 1,
      List.append(output, group_recipient_envelope(path, key, target, packet, now)?))
  end
end
