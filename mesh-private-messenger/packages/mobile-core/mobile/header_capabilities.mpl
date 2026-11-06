##! New HE writes require the precise authenticated reader capability on all actual devices.
from Mobile.Transparency import fresh_account_device_set
from Mobile.Types import MobileVerifiedDeviceSet
from Protocol.Capabilities import supports_header_encryption
from Protocol.IdentityWire import encode_device_credential
from Transport.Packet import ClientProfile

pub fn require_header_profile(profile :: ClientProfile) -> Unit!String do
  if !supports_header_encryption(profile.credential.capabilities) do
    Err("header_recipient_upgrade_required")
  else
    Ok(nil)
  end
end

pub fn require_header_profiles(profiles :: List<ClientProfile>) -> Unit!String do
  if List.length(profiles) == 0 do
    return Err("header_recipient_unavailable")
  end
  for profile in profiles do
    require_header_profile(profile)?
  end
  Ok(nil)
end

pub fn require_header_sets(peers :: MobileVerifiedDeviceSet,
  own :: MobileVerifiedDeviceSet) -> Unit!String do
  require_header_profiles(peers.profiles)?
  require_header_profiles(own.profiles)
end

fn credential_bytes(profile :: ClientProfile) -> Bytes do
  case encode_device_credential(profile.credential) do
    Err(_) -> Bytes.empty()
    Ok(value) -> value
  end
end

fn included(set :: MobileVerifiedDeviceSet, profile :: ClientProfile) -> Bool do
  let credential = credential_bytes(profile)
  Bytes.length(credential) > 0
    && List.any(set.profiles,
      fn(current) do Bytes.secure_equals(current.account_id, profile.account_id)
        && Bytes.secure_equals(current.device_id, profile.device_id)
        && Bytes.secure_equals(credential_bytes(current), credential) end)
end

pub fn require_direct_headers(path :: String,
  key :: borrow StorageKey,
  local :: ClientProfile,
  peer :: ClientProfile) -> Unit!String do
  let peers = fresh_account_device_set(path, key, peer.account_id)?
  let own = fresh_account_device_set(path, key, local.account_id)?
  if !included(peers, peer) || !included(own, local) do
    return Err("header_recipient_changed")
  end
  require_header_profile(local)?
  require_header_profile(peer)?
  require_header_sets(peers, own)
end

pub fn header_session_capacity() -> Int do
  4096
end

## This is writer admission, never a read-time retirement of existing sessions.
pub fn require_new_header_capacity(count :: Int, additional :: Int) -> Unit!String do
  if additional < 0
    || count < 0
    || (additional > 0
      && (additional > header_session_capacity()
        || count > header_session_capacity() - additional)) do
    Err("header_session_capacity")
  else
    Ok(nil)
  end
end
