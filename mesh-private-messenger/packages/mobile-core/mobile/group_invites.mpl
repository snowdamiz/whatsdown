from Groups.Mls import GroupState, GroupTransparencyPolicy
from Groups.Tree import GroupTree, GroupMember, member_at
from Mobile.Codec import current_time, encode_output_list, mobile_byte, mobile_wide, mobile_write_u64, random_bytes
from Mobile.DeviceSet import verified_device_set
from Mobile.Fanout import send_fanout_control
from Mobile.GroupInvitesState import (
  GroupInvitation,
  find_invitation,
  invitation_blob,
  invitation_reference,
  load_invitations,
  replace_invitation
)
from Mobile.GroupState import (
  consume_group_state,
  create_group_key_package_scoped,
  group_profile,
  group_state_label,
  load_group,
  load_group_baseline
)
from Mobile.Groups import add_mobile_group_member_with_updates
from Mobile.Profile import load_profile
from Mobile.Sessions import find_peer_session, load_session_ids
from Mobile.Transparency import require_transparency_device_set
from Mobile.Types import MobileFanoutRequest, MobileGroupAddRequest, MobilePayloadRequest, MobileTriplePayloadRequest, MobileVerifiedDeviceSet, MobileLoadedSession, MobileSessionRecord
from Protocol.V1 import AccountIdentity, DeviceCredential, DeviceSet, DirectoryEntry, PrekeyBundle
from Storage.Blobs import load_blob
from Storage.Keys import platform_key
from Storage.Records import store_updated_blobs
from Transport.Packet import ClientProfile, decode_client_profile

pub fn invite_to_group(request :: MobileFanoutRequest) -> Bytes ! String do
  if Bytes.length(request.body) != 32 do
    return Err("invalid_group_invitation")
  end
  let path = request.database_path
  let key = platform_key() ?
  let local = decode_client_profile(load_profile(path) ?) ?
  let peers = verified_device_set(request.peer_device_set) ?
  let _ = require_transparency_device_set(path, key, peers) ?
  let group = load_group(path, local, key, request.body) ?
  let member = member_at(group.tree, group.local_leaf)
  consume_group_state(group)
  case member do
    Err( _) -> do
      return Err("group_member_not_found")
    end
    Ok( _) -> nil
  end
  let existing = load_invitations(path, key) ?
  let pending = List.find(existing,
  fn (value) do (value.state == 0 || value.state == 3) && Bytes.secure_equals(value.group_id,
  request.body) && Bytes.secure_equals(value.recipient_account, peers.account.account_id) end)
  case pending do
    Some( _) -> do
      return encode_output_list([])
    end
    None -> nil
  end
  let baseline = load_group_baseline(path, key, request.body) ?
  let id = random_bytes(16) ?
  let expires_at = U64.add(current_time() ?, mobile_wide("604800000") ?) ?
  let pending = for peer in peers.profiles do
    GroupInvitation {
      id : id,
      group_id : request.body,
      inviter_account : local.account_id,
      inviter_device : local.device_id,
      recipient_account : peer.account_id,
      recipient_device : peer.device_id,
      username : peer.username,
      baseline : baseline,
      expires_at : expires_at,
      state : 0,
      key_package : Bytes.empty(),
      inviter_signing_key : local.credential.signing_public_key
    }
  end
  let blob = invitation_blob(existing ++ pending, key) ?
  let body = encode_output_list([id, request.body, mobile_write_u64(expires_at) ?, baseline]) ?
  send_fanout_control(% { request | body : body }, 3, ["group-invitations/v1"], [blob])
end

pub fn accept_group_invitation(request :: MobileFanoutRequest) -> Bytes ! String do
  let path = request.database_path
  let key = platform_key() ?
  let local = decode_client_profile(load_profile(path) ?) ?
  let values = load_invitations(path, key) ?
  let invitation = find_invitation(values, request.body) ?
  if !Bytes.secure_equals(invitation.recipient_account, local.account_id) || !Bytes.secure_equals(invitation.recipient_device,
  local.device_id) do
    return Err("invalid_group_invitation")
  end
  if invitation.state == 2 do
    return encode_output_list([])
  end
  if invitation.state != 1 do
    return Err("invalid_group_invitation")
  end
  let peers = verified_device_set(request.peer_device_set) ?
  let _ = require_transparency_device_set(path, key, peers) ?
  let inviter = group_profile(peers.profiles,
  invitation.inviter_account,
  invitation.inviter_device,
  0) ?
  let peer = find_peer_session(path,
  key,
  invitation.inviter_account,
  load_session_ids(path, key) ?,
  0) ?
  if peer.record.blocked do
    return Err("conversation_blocked")
  end
  let package = create_group_key_package_scoped(path, Bytes.to_hex(invitation.id)) ?
  # A welcome committed before the invitation deadline may spend 30 days in delivery.
  let retain_until = U64.add(invitation.expires_at, mobile_wide("2592000000") ?) ?
  let updated = replace_invitation(values,
  % { invitation | state : 2, key_package : package, inviter_signing_key : inviter.credential.signing_public_key, expires_at : retain_until })
  let body = encode_output_list([invitation.id, invitation.group_id, package]) ?
  send_fanout_control(% { request | body : body },
  4,
  ["group-invitations/v1"],
  [invitation_blob(updated, key) ?])
end

pub fn complete_group_invitation(request :: MobileTriplePayloadRequest) -> Bytes ! String do
  let path = request.database_path
  let key = platform_key() ?
  let local = decode_client_profile(load_profile(path) ?) ?
  let values = load_invitations(path, key) ?
  let invitation = find_invitation(values, request.second) ?
  if !Bytes.secure_equals(invitation.inviter_account, local.account_id) || !Bytes.secure_equals(invitation.inviter_device,
  local.device_id) do
    return Err("invalid_group_invitation")
  end
  if invitation.state == 4 do
    return encode_output_list([])
  end
  if invitation.state != 3 do
    return Err("group_invitation_not_accepted")
  end
  let peers = verified_device_set(request.first) ?
  let _ = require_transparency_device_set(path, key, peers) ?
  let _ = group_profile(peers.profiles,
  invitation.recipient_account,
  invitation.recipient_device,
  0) ?
  let peer = find_peer_session(path,
  key,
  invitation.recipient_account,
  load_session_ids(path, key) ?,
  0) ?
  if peer.record.blocked do
    return Err("conversation_blocked")
  end
  let blob = invitation_blob(replace_invitation(values, % { invitation | state : 4 }), key) ?
  add_mobile_group_member_with_updates(MobileGroupAddRequest {
    database_path : path,
    group_id : invitation.group_id,
    device_set : request.first,
    key_package : invitation.key_package
  },
  ["group-invitations/v1"],
  [blob])
end

pub fn decline_group_invitation(request :: MobilePayloadRequest) -> Bytes ! String do
  let key = platform_key() ?
  let values = load_invitations(request.database_path, key) ?
  let invitation = find_invitation(values, request.payload) ?
  if invitation.state == 5 do
    return Ok(Bytes.empty())
  end
  if invitation.state != 1 do
    return Err("invalid_group_invitation")
  end
  let blob = invitation_blob(replace_invitation(values, % { invitation | state : 5 }), key) ?
  store_updated_blobs(request.database_path, ["group-invitations/v1"], [blob]) ?
  Ok(Bytes.empty())
end

pub fn list_group_invitations(path :: String) -> Bytes ! String do
  let key = platform_key() ?
  let values = load_invitations(path, key) ?
  let sessions = load_session_ids(path, key) ?
  let summaries = for value in values do
    invitation_summary(path, key, sessions, value) ?
  end
  encode_output_list(List.filter(summaries, fn (value) do Bytes.length(value) > 0 end))
end

fn invitation_summary(path :: String,
key :: borrow StorageKey,
sessions :: List < Bytes >,
value :: GroupInvitation) -> Bytes ! String do
  if value.state > 3 do
    return Ok(Bytes.empty())
  end
  let incoming = value.state == 1 || value.state == 2
  let account = if incoming do
    value.inviter_account
  else
    value.recipient_account
  end
  let peer = find_peer_session(path, key, account, sessions, 0) ?
  if peer.record.blocked do
    return Ok(Bytes.empty())
  end
  if incoming do
    case load_blob(path, group_state_label(value.group_id) ?) do
      Ok( _) -> do
        return Ok(Bytes.empty())
      end
      Err( error) -> if error != "local_state_not_found" do
        return Err(error)
      end
    end
  end
  encode_output_list([invitation_reference(value) ?, value.group_id, Bytes.from_utf8(value.username), account, mobile_byte(value.state) ?])
end
