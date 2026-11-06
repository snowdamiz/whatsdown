from Mobile.Transparency import fresh_account_device_set
from Mobile.TransparencySafety import require_log_changes_allowed
from Mobile.Types import MobileVerifiedDeviceSet
from Protocol.Capabilities import supports_ach3, supports_attachment_buckets
from Mobile.Attachments import attachment_requires_buckets
from Transport.Packet import ClientProfile

##! Capabilities are account-signed credential fields. Callers supply profiles
##! only after credential, bundle and transparency verification. Group extension
##! claims and host/UI flags never authorize an attachment recipient.

pub fn require_attachment_profile(profile :: ClientProfile) -> Unit!String do
  if supports_ach3(profile.credential.capabilities) do
    Ok(nil)
  else
    Err("attachment_recipient_upgrade_required")
  end
end

pub fn require_attachment_profiles(profiles :: List<ClientProfile>) -> Unit!String do
  if List.length(profiles) == 0 do
    return Err("attachment_recipient_unavailable")
  end
  for profile in profiles do
    require_attachment_profile(profile)?
  end
  Ok(nil)
end

pub fn require_attachment_sets(peers :: MobileVerifiedDeviceSet,
  own :: MobileVerifiedDeviceSet) -> Unit!String do
  require_attachment_profiles(peers.profiles)?
  require_attachment_profiles(own.profiles)
end

fn matching_device(devices :: MobileVerifiedDeviceSet, profile :: ClientProfile) -> Bool do
  List.any(devices.profiles,
    fn(current) do Bytes.secure_equals(current.device_id, profile.device_id)
      && Bytes.secure_equals(current.credential.signing_public_key,
        profile.credential.signing_public_key)
      && Bytes.secure_equals(current.credential.dh_public_key,
        profile.credential.dh_public_key) end)
end

pub fn require_attachment_local(local :: ClientProfile,
  own :: MobileVerifiedDeviceSet) -> Unit!String do
  if !matching_device(own, local) do
    return Err("attachment_recipient_changed")
  end
  require_attachment_profiles(own.profiles)
end

## Legacy one-device send exports still have to check the complete current
## recipient and local device sets before wrapping an attachment key.
pub fn require_direct_attachment(path :: String,
  key :: borrow StorageKey,
  local :: ClientProfile,
  peer :: ClientProfile,
  attachment :: Bytes) -> Unit!String do
  require_log_changes_allowed(path, key)?
  let peers = fresh_account_device_set(path, key, peer.account_id)?
  let own = fresh_account_device_set(path, key, local.account_id)?
  if !matching_device(peers, peer) || !matching_device(own, local) do
    return Err("attachment_recipient_changed")
  end
  require_attachment_format_sets(peers, own, attachment)
end

pub fn require_padded_attachment_profile(profile :: ClientProfile) -> Unit!String do
  require_attachment_profile(profile)?
  if !supports_attachment_buckets(profile.credential.capabilities) do
    return Err("attachment_recipient_upgrade_required")
  end
  Ok(nil)
end

pub fn require_padded_attachment_profiles(profiles :: List<ClientProfile>) -> Unit!String do
  if List.length(profiles) == 0 do
    return Err("attachment_recipient_unavailable")
  end
  for profile in profiles do
    require_padded_attachment_profile(profile)?
  end
  Ok(nil)
end

pub fn require_attachment_format_sets(peers :: MobileVerifiedDeviceSet,
  own :: MobileVerifiedDeviceSet,
  attachment :: Bytes) -> Unit!String do
  require_attachment_sets(peers, own)?
  if attachment_requires_buckets(attachment)? do
    require_padded_attachment_profiles(peers.profiles)?
    require_padded_attachment_profiles(own.profiles)?
  end
  Ok(nil)
end
