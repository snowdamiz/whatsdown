from Storage.AccountGuard import AccountBasis, load_account_basis
from Storage.Blobs import load_blob
from Storage.Keys import platform_key, open_local, local_context
from Mobile.NetworkPins import native_network_pins
from Transport.Packet import ClientProfile, decode_client_profile

pub struct BoundAccount do
  before :: AccountBasis
  profile :: ClientProfile
  public_profile :: Bytes
end

## Public profile input identifies the account/device a UI action was shown for.
## Credential and prekey renewal may change its directory entry; identity keys
## must stay equal. Every eventual write compares the exact captured ciphertext.
pub fn load_bound_account(path :: String,
  expected :: Bytes,
  exact :: Bool) -> BoundAccount!String do
  let requested = decode_client_profile(expected)?
  let before = load_account_basis(path, [])?
  let key = platform_key()?
  let wire = open_local(before.profile, key, local_context("profile/v1")?)?
  let profile = decode_client_profile(wire)?
  let same = Bytes.secure_equals(requested.account_id, profile.account_id)
    && Bytes.secure_equals(requested.device_id, profile.device_id)
    && Bytes.secure_equals(requested.account.authorization_public_key,
      profile.account.authorization_public_key)
    && Bytes.secure_equals(requested.credential.signing_public_key,
      profile.credential.signing_public_key)
    && Bytes.secure_equals(requested.credential.dh_public_key, profile.credential.dh_public_key)
  if !same || (exact && !Bytes.secure_equals(expected, wire)) do
    return Err("account_state_changed")
  end
  Ok(BoundAccount { before: before, profile: profile, public_profile: wire })
end

pub fn account_snapshot_current(path :: String, profile :: Bytes) -> Bool do
  case load_blob(path, "profile/v1") do
    Err(_) -> false
    Ok(value) -> Bytes.secure_equals(value, profile)
  end
end

pub fn account_network_current(path :: String, profile :: Bytes, origin :: String) -> Bool do
  let pins = case native_network_pins() do
    Err(_) -> return false
    Ok(value) -> value
  end
  pins.core_origin == origin && account_snapshot_current(path, profile)
end
