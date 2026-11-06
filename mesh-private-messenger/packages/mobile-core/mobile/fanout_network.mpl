from Mobile.AttachmentCapabilities import require_attachment_format_sets
from Mobile.AttachmentRecipients import attachment_authorization, attachment_target_accounts
from Mobile.Account import inspect_device_set_result_at_profile
from Mobile.AccountState import BoundAccount, load_bound_account, account_snapshot_current
from Mobile.Attachments import validate_attachment
from Mobile.Codec import (
  mobile_reader,
  mobile_finish,
  take_vector_error,
  mobile_utf8,
  mobile_read_byte,
  mobile_byte
)
from Mobile.DeviceSet import verified_device_set
from Mobile.DirectoryResolve import resolve_directory_device_set_at_profile
from Mobile.Fanout import send_fanout_at_profile
from Mobile.FanoutPrekeys import prepare_fanout_prekeys_at_profile
from Mobile.GroupInvites import invite_to_group_at_profile, accept_group_invitation_at_profile
from Mobile.NetworkPins import native_network_pins
from Mobile.Platform import native_security_config
from Mobile.TransparencySafety import require_log_changes_allowed
from Mobile.Types import MobileFanoutRequest, MobileFanoutTargetsRequest, MobilePayloadRequest
from Storage.Keys import platform_key
from Transparency.Config import encode_security_config

pub struct FanoutAction do
  path :: String
  expected_profile :: Bytes
  username :: String
  kind :: Int
  payload :: Bytes
  expected_peer :: Bytes
  attachment :: Bytes
end

## Ordinary vectors, no count prefix. Peer sets, origins, claim signatures,
## envelopes and ratchets never cross this compact action boundary.
pub fn parse_fanout_action(input :: Bytes) -> FanoutAction!String do
  let state = mobile_reader(input, 88740, "invalid_fanout_action")?
  let path = take_vector_error(state, 4096, "invalid_fanout_action")?
  let profile = take_vector_error(path.state, 36134, "invalid_fanout_action")?
  let username = take_vector_error(profile.state, 65, "invalid_fanout_action")?
  let kind = take_vector_error(username.state, 1, "invalid_fanout_action")?
  let payload = take_vector_error(kind.state, 32000, "invalid_fanout_action")?
  let expected_peer = take_vector_error(payload.state, 32, "invalid_fanout_action")?
  let attachment = take_vector_error(expected_peer.state, 16384, "invalid_fanout_action")?
  mobile_finish(attachment.state, "invalid_fanout_action")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  let peer = mobile_utf8(username.value, "invalid_username")?
  if Bytes.length(path.value) == 0
    || String.contains(database_path, "\0")
    || Bytes.length(profile.value) == 0
    || Bytes.length(kind.value) != 1
    || !Regex.is_match(~r/^(@[0-9a-f]{64}|[a-z0-9_.-]{1,64})$/, peer)
    || (Bytes.length(expected_peer.value) != 0 && Bytes.length(expected_peer.value) != 32) do
    return Err("invalid_fanout_action")
  end
  let mode = mobile_read_byte(kind.value)?
  if mode < 1
    || mode > 5
    || ((mode == 2 || mode == 3)
      && (Bytes.length(payload.value) != 32 || Bytes.length(attachment.value) != 0))
    || (mode == 4 && (Bytes.length(payload.value) != 0 || Bytes.length(attachment.value) != 0))
    || (mode == 5
      && (Bytes.length(payload.value) < 32
        || Bytes.length(payload.value) > 2048
        || Bytes.length(payload.value) % 32 != 0
        || Bytes.length(attachment.value) != 0
        || Bytes.length(expected_peer.value) != 0))
    || (mode == 1 && Bytes.length(payload.value) == 0 && Bytes.length(attachment.value) == 0) do
    return Err("invalid_fanout_action")
  end
  validate_attachment(attachment.value)?
  Ok(FanoutAction {
    path: database_path,
    expected_profile: profile.value,
    username: peer,
    kind: mode,
    payload: payload.value,
    expected_peer: expected_peer.value,
    attachment: attachment.value
  })
end

fn current(action :: FanoutAction,
  who :: BoundAccount,
  origin :: String,
  security :: Bytes) -> Result<(), String> do
  if !account_snapshot_current(action.path, who.before.profile)
    || native_network_pins()?.core_origin != origin
    || !Bytes.secure_equals(encode_security_config(native_security_config()?)?, security) do
    return Err("account_state_changed")
  end
  let key = platform_key()?
  require_log_changes_allowed(action.path, key)
end

pub fn native_fanout_send(input :: Bytes) -> Bytes!String do
  let action = parse_fanout_action(input)?
  let who = load_bound_account(action.path, action.expected_profile, false)?
  let pins = native_network_pins()?
  let security = encode_security_config(native_security_config()?)?
  current(action, who, pins.core_origin, security)?
  if action.kind == 5 do
    let accounts = attachment_target_accounts(action.path, who.profile, 5, action.payload)?
    for account in accounts do
      resolve_directory_device_set_at_profile(action.path,
        "@" <> Bytes.to_hex(account),
        who.before.profile)?
      current(action, who, pins.core_origin, security)?
    end
    let ticket = attachment_authorization(action.path, who.public_profile, 5, action.payload)?
    current(action, who, pins.core_origin, security)?
    return Ok(ticket)
  end
  let peer_set = resolve_directory_device_set_at_profile(action.path,
    action.username,
    who.before.profile)?
  current(action, who, pins.core_origin, security)?
  let peers = verified_device_set(peer_set)?
  if Bytes.length(action.expected_peer) > 0
    && !Bytes.secure_equals(action.expected_peer, peers.account.account_id) do
    return Err("fanout_contact_identity_changed")
  end
  let local_set = resolve_directory_device_set_at_profile(action.path,
    who.profile.username,
    who.before.profile)?
  current(action, who, pins.core_origin, security)?
  let peer_view = inspect_device_set_result_at_profile(MobilePayloadRequest {
      database_path: action.path,
      payload: peer_set
    },
    who.before.profile)?
  inspect_device_set_result_at_profile(MobilePayloadRequest {
      database_path: action.path,
      payload: local_set
    },
    who.before.profile)?
  current(action, who, pins.core_origin, security)?
  if action.kind == 4 do
    let ticket = attachment_authorization(action.path,
      who.public_profile,
      4,
      peers.account.account_id)?
    current(action, who, pins.core_origin, security)?
    return Ok(ticket)
  end
  if Bytes.length(action.attachment) > 0 do
    require_attachment_format_sets(peers, verified_device_set(local_set)?, action.attachment)?
  end
  prepare_fanout_prekeys_at_profile(MobileFanoutTargetsRequest {
      database_path: action.path,
      peer_device_set: peer_set,
      local_device_set: local_set
    },
    who.before.profile)?
  current(action, who, pins.core_origin, security)?
  let request = MobileFanoutRequest {
    database_path: action.path,
    peer_device_set: peer_set,
    local_device_set: local_set,
    body: action.payload,
    attachment: action.attachment
  }
  if action.kind == 1 do
    send_fanout_at_profile(request, who.before.profile)?
  else if action.kind == 2 do
    invite_to_group_at_profile(request, who.before.profile)?
  else
    accept_group_invitation_at_profile(request, who.before.profile)?
  end
  current(action, who, pins.core_origin, security)?
  case Bytes.concat(Bytes.from_utf8("\u{1}FNO"),
    mobile_byte(if peer_view.changed do
      1
    else
      0
    end)?) do
    Err(_) -> Err("fanout_output_failed")
    Ok(value)
  end
end
