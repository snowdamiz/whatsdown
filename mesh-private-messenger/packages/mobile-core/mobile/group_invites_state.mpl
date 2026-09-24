from Binary.Reader import BinaryReader
from Groups.Mls import GroupWelcome, GroupCommit
from Groups.Tree import IndexedGroupMember, GroupMember
from Mobile.Codec import (
  current_time,
  encode_output_list,
  mobile_append,
  mobile_byte,
  mobile_finish,
  mobile_read_byte,
  mobile_read_u32,
  mobile_read_u64,
  mobile_reader,
  mobile_utf8,
  mobile_wide,
  mobile_write_u64,
  take_vector
)
from Mobile.GroupState import decode_group_key_package, group_join_label
from Mobile.Types import MobileGroupKeyPackage
from Protocol.V1 import InnerEnvelope
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local, seal_local
from Storage.Records import store_record_changes
from Transport.Packet import ClientProfile

## Invitations are authenticated direct-message controls, never chat text.
## States: 0 sent, 1 received, 2 accepted, 3 ready to add, 4 completed, 5 declined.

pub struct GroupInvitation do
  id :: Bytes
  group_id :: Bytes
  inviter_account :: Bytes
  inviter_device :: Bytes
  recipient_account :: Bytes
  recipient_device :: Bytes
  username :: String
  baseline :: Bytes
  expires_at :: U64
  state :: Int
  key_package :: Bytes
  inviter_signing_key :: Bytes
end

fn read_parts(state :: BinaryReader, remaining :: Int, maximum :: Int, values :: List<Bytes>) -> List<Bytes>!String do
  if remaining == 0 do
    mobile_finish(state, "invalid_group_invitation")?
    Ok(values)
  else
    let part = take_vector(state, maximum)?
    read_parts(part.state, remaining - 1, maximum, List.append(values, part.value))
  end
end

pub fn invitation_parts(input :: Bytes, count :: Int, maximum :: Int) -> List<Bytes>!String do
  let reader = mobile_reader(input, 8 + count * (4 + maximum), "invalid_group_invitation")?
  let encoded_count = take_vector(reader, 4)?
  if mobile_read_u32(encoded_count.value)? != count do
    Err("invalid_group_invitation")
  else
    read_parts(encoded_count.state, count, maximum, [])
  end
end

pub fn invitation_reference(value :: GroupInvitation) -> Bytes!String do
  mobile_append(value.id, value.recipient_device)
end

pub fn invitation_key_label(id :: Bytes, kind :: String) -> String do
  "group-invitation/#{Bytes.to_hex(id)}/#{kind}/v1"
end

fn encode_record(value :: GroupInvitation) -> Bytes!String do
  encode_output_list([
    value.id,
    value.group_id,
    value.inviter_account,
    value.inviter_device,
    value.recipient_account,
    value.recipient_device,
    Bytes.from_utf8(value.username),
    value.baseline,
    mobile_write_u64(value.expires_at)?,
    mobile_byte(value.state)?,
    value.key_package,
    value.inviter_signing_key
  ])
end

fn decode_record(input :: Bytes) -> GroupInvitation!String do
  let p = invitation_parts(input, 12, 369)?
  let value = GroupInvitation {
    id: List.get(p, 0),
    group_id: List.get(p, 1),
    inviter_account: List.get(p, 2),
    inviter_device: List.get(p, 3),
    recipient_account: List.get(p, 4),
    recipient_device: List.get(p, 5),
    username: mobile_utf8(List.get(p, 6), "invalid_group_invitation")?,
    baseline: List.get(p, 7),
    expires_at: mobile_read_u64(List.get(p, 8))?,
    state: mobile_read_byte(List.get(p, 9))?,
    key_package: List.get(p, 10),
    inviter_signing_key: List.get(p, 11)
  }
  if Bytes.length(value.id) != 16 || Bytes.length(value.group_id) != 32 || Bytes.length(value.inviter_account) != 32 || Bytes.length(value.inviter_device) != 16 || Bytes.length(value.recipient_account) != 32 || Bytes.length(value.recipient_device) != 16 || String.length(value.username) == 0 || String.length(value.username) > 64 || Bytes.length(value.baseline) != 188 || value.state > 5 || (Bytes.length(value.inviter_signing_key) != 0 && Bytes.length(value.inviter_signing_key) != 32) || (value.state == 2 && Bytes.length(value.inviter_signing_key) != 32) || (Bytes.length(value.key_package) != 0 && Bytes.length(value.key_package) != 369) do
    Err("invalid_group_invitation")
  else
    Ok(value)
  end
end

pub fn invitation_blob(values :: List<GroupInvitation>, key :: borrow StorageKey) -> Bytes!String do
  if List.length(values) > 128 do
    return Err("group_invitation_limit")
  end
  let records = for value in values do
    encode_record(value)?
  end
  seal_local(encode_output_list(records)?, key, local_context("group-invitations/v1")?)
end

pub fn load_invitations(path :: String, key :: borrow StorageKey) -> List<GroupInvitation>!String do
  let encoded = case load_blob(path, "group-invitations/v1") do
    Ok(blob) -> open_local(blob, key, local_context("group-invitations/v1")?)?
    Err(error) -> if error == "local_state_not_found" do
      return Ok([])
    else
      return Err(error)
    end
  end
  let reader = mobile_reader(encoded, 131072, "invalid_group_invitation")?
  let count = take_vector(reader, 4)?
  let length = mobile_read_u32(count.value)?
  if length > 128 do
    return Err("group_invitation_limit")
  end
  let parts = read_parts(count.state, length, 1024, [])?
  let records = for part in parts do
    decode_record(part)?
  end
  let now = current_time()?
  let live = List.filter(records, fn (value) do U64.compare(value.expires_at, now) > 0 end)
  if List.length(live) != List.length(records) do
    let expired = List.filter(records, fn (value) do U64.compare(value.expires_at, now) <= 0 end)
    let removed = List.flat_map(expired,
      fn (value) do [
        invitation_key_label(value.id, "package"),
        invitation_key_label(value.id, "init"),
        invitation_key_label(value.id, "leaf")
      ] end)
    store_record_changes(path, ["group-invitations/v1"], [invitation_blob(live, key)?], removed)?
  end
  Ok(live)
end

pub fn find_invitation(values :: List<GroupInvitation>, reference :: Bytes) -> GroupInvitation!String do
  if Bytes.length(reference) != 32 do
    return Err("invalid_group_invitation")
  end
  let id = Bytes.slice(reference, 0, 16)?
  let device = Bytes.slice(reference, 16, 16)?
  case List.find(values,
    fn (value) do Bytes.secure_equals(value.id, id) && Bytes.secure_equals(value.recipient_device,
      device) end) do
    Some(value) -> Ok(value)
    None -> Err("group_invitation_not_found")
  end
end

pub fn replace_invitation(values :: List<GroupInvitation>, next :: GroupInvitation) -> List<GroupInvitation> do
  List.map(values,
    fn (value) do
      if Bytes.secure_equals(value.id, next.id) && Bytes.secure_equals(value.recipient_device,
        next.recipient_device) do
        next
      else
        value
      end
    end)
end

fn receive_control(path :: String,
  key :: borrow StorageKey,
  local :: ClientProfile,
  username :: String,
  inner :: InnerEnvelope) -> List<GroupInvitation>!String do
  let values = load_invitations(path, key)?
  let now = current_time()?
  if inner.message_type == 3 do
    let p = invitation_parts(inner.body, 4, 188)?
    let id = List.get(p, 0)
    let group_id = List.get(p, 1)
    let expires_at = mobile_read_u64(List.get(p, 2))?
    let baseline = List.get(p, 3)
    if Bytes.length(id) != 16 || Bytes.length(group_id) != 32 || Bytes.length(baseline) != 188 || U64.compare(expires_at,
      now) <= 0 || U64.compare(expires_at, U64.add(now, mobile_wide("604800000")?)?) > 0 do
      return Ok(values)
    end
    let reference = mobile_append(id, local.device_id)?
    case find_invitation(values, reference) do
      Ok(_) -> return Ok(values)
      Err(_) -> nil
    end
    if List.length(values) >= 128 do
      return Ok(values)
    end
    Ok(List.append(values,
      GroupInvitation {
        id: id,
        group_id: group_id,
        inviter_account: inner.sender_account_id,
        inviter_device: inner.sender_device_id,
        recipient_account: local.account_id,
        recipient_device: local.device_id,
        username: username,
        baseline: baseline,
        expires_at: expires_at,
        state: 1,
        key_package: Bytes.empty(),
        inviter_signing_key: Bytes.empty()
      }))
  else
    let p = invitation_parts(inner.body, 3, 369)?
    let id = List.get(p, 0)
    let group_id = List.get(p, 1)
    let package = decode_group_key_package(List.get(p, 2))?
    let reference = mobile_append(id, inner.sender_device_id)?
    let previous = case find_invitation(values, reference) do
      Ok(value) -> value
      Err(_) -> return Ok(values)
    end
    if previous.state != 0 || !Bytes.secure_equals(previous.group_id, group_id) || !Bytes.secure_equals(previous.inviter_account,
      local.account_id) || !Bytes.secure_equals(previous.inviter_device, local.device_id) || !Bytes.secure_equals(previous.recipient_account,
      inner.sender_account_id) || !Bytes.secure_equals(package.account_id, inner.sender_account_id) || !Bytes.secure_equals(package.device_id,
      inner.sender_device_id) do
      return Ok(values)
    end
    Ok(replace_invitation(values, %{previous | state: 3, key_package: List.get(p, 2)}))
  end
end

## Invalid authenticated controls are ignored while their ratchet still advances.

fn validate_control(inner :: InnerEnvelope) -> Bool!String do
  let count = if inner.message_type == 3 do
    4
  else
    3
  end
  let parts = invitation_parts(inner.body, count, 369)?
  if Bytes.length(List.get(parts, 0)) != 16 || Bytes.length(List.get(parts, 1)) != 32 do
    return Ok(false)
  end
  if inner.message_type == 3 do
    mobile_read_u64(List.get(parts, 2))?
    Ok(Bytes.length(List.get(parts, 3)) == 188)
  else
    decode_group_key_package(List.get(parts, 2))?
    Ok(true)
  end
end

pub fn received_invitation_writes(path :: String,
  key :: borrow StorageKey,
  local :: ClientProfile,
  username :: String,
  inner :: InnerEnvelope) -> Result<(List<String>, List<Bytes>), String> do
  let valid = case validate_control(inner) do
    Ok(value) -> value
    Err(_) -> false
  end
  if !valid do
    return Ok(([], []))
  end
  let values = receive_control(path, key, local, username, inner)?
  Ok((["group-invitations/v1"], [invitation_blob(values, key)?]))
end

pub fn accepted_invitation_scope(path :: String,
  key :: borrow StorageKey,
  welcome :: GroupWelcome,
  baseline :: Bytes) -> String!String do
  let values = load_invitations(path, key)?
  accepted_scope(values, welcome, baseline, 0)
end

fn accepted_scope(values :: List<GroupInvitation>,
  welcome :: GroupWelcome,
  baseline :: Bytes,
  index :: Int) -> String!String do
  if index >= List.length(values) do
    return Ok("")
  end
  let value = List.get(values, index)
  if value.state == 2 && Bytes.secure_equals(value.group_id, welcome.commit.group_id) do
    let package = decode_group_key_package(value.key_package)?
    let recipient = List.find(welcome.members,
      fn (member) do member.leaf_index == welcome.recipient_leaf end)
    let committer = List.find(welcome.members,
      fn (member) do member.leaf_index == welcome.commit.committer_leaf end)
    case (recipient, committer) do
      (Some(target), Some(sender)) -> if Bytes.secure_equals(target.member.init_public_key.bytes,
        package.init_public_key.bytes) && Bytes.secure_equals(target.member.leaf_public_key.bytes,
        package.leaf_public_key.bytes) do
        if !Bytes.secure_equals(sender.member.signing_public_key.bytes, value.inviter_signing_key) do
          Err("group_welcome_rejected")
        else if !Bytes.secure_equals(baseline, value.baseline) || !Bytes.secure_equals(sender.member.account_id,
          value.inviter_account) || !Bytes.secure_equals(sender.member.device_id,
          value.inviter_device) do
          Err("group_welcome_rejected")
        else
          Ok(Bytes.to_hex(value.id))
        end
      else
        accepted_scope(values, welcome, baseline, index + 1)
      end
      _ -> Err("group_welcome_rejected")
    end
  else
    accepted_scope(values, welcome, baseline, index + 1)
  end
end
