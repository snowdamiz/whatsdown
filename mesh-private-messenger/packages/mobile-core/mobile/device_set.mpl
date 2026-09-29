from Mobile.Codec import current_time
from Mobile.Types import MobileVerifiedDeviceSet
from Prekeys.Bundle import PrekeyError, verify_prekey_bundle
from Protocol.DirectoryWire import decode_device_set, encode_device_set
from Protocol.IdentityWire import decode_account_identity, decode_device_credential
from Protocol.PrekeyWire import decode_prekey_bundle
from Protocol.V1 import AccountIdentity, DeviceCredential, DeviceSet, DirectoryEntry, PrekeyBundle
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local
from Transport.Packet import ClientProfile, decode_client_profile, encode_client_profile

##! Mobile.DeviceSet implementation.

fn device_set_bytes(value :: DeviceSet) -> Bytes!String do
  case encode_device_set(value) do
    Err(_) -> Err("device_set_encoding_failed")
    Ok(encoded)
  end
end

fn canonical_device_set(input :: Bytes) -> DeviceSet!String do
  case decode_device_set(input) do
    Err(_) -> Err("invalid_device_set")
    Ok(value) -> if Bytes.secure_equals(device_set_bytes(value)?, input) do
      Ok(value)
    else
      Err("noncanonical_device_set")
    end
  end
end

pub fn contains_device_id(profiles :: List<ClientProfile>,
  device_id :: Bytes,
  index :: Int) -> Bool do
  if index >= List.length(profiles) do
    false
  else if Bytes.secure_equals(List.get(profiles, index).device_id, device_id) do
    true
  else
    contains_device_id(profiles, device_id, index + 1)
  end
end

fn contains_revoked_id(values :: List<Bytes>, device_id :: Bytes, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else if Bytes.secure_equals(List.get(values, index), device_id) do
    true
  else
    contains_revoked_id(values, device_id, index + 1)
  end
end

fn bundle_verifies(account :: AccountIdentity, bundle :: PrekeyBundle, at :: U64) -> Bool do
  case verify_prekey_bundle(account, bundle, 1, at, account.directory_sequence) do
    Err(_) -> false
    Ok(result) -> result
  end
end

# When a device's bundle stopped being usable: its signed prekey or its
# credential ran out, whichever came first.

pub fn bundle_lapses_at(bundle :: PrekeyBundle, credential :: DeviceCredential) -> U64 do
  if U64.compare(bundle.expires_at, credential.expires_at) < 0 do
    bundle.expires_at
  else
    credential.expires_at
  end
end

struct SortedProfiles do
  profiles :: List<ClientProfile>
  expired :: List<ClientProfile>
end

fn verified_device_profiles(value :: DeviceSet,
  account :: AccountIdentity,
  now :: U64,
  index :: Int,
  profiles :: List<ClientProfile>,
  expired :: List<ClientProfile>) -> SortedProfiles!String do
  if index >= List.length(value.devices) do
    Ok(SortedProfiles { profiles: profiles, expired: expired })
  else
    let entry = List.get(value.devices, index)
    let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
      Err(_) -> Err("invalid_device_set")
      Ok(decoded)
    end?
    let credential = case decode_device_credential(bundle.device_credential) do
      Err(_) -> Err("invalid_device_set")
      Ok(decoded)
    end?
    let current = bundle_verifies(account, bundle, now)
    # Signed by the account and valid until it ran out: still the account's
    # device, just not one to encrypt to.
    let lapse = bundle_lapses_at(bundle, credential)
    let lapsed = !current && U64.compare(lapse, now) < 0 && bundle_verifies(account, bundle, lapse)
    let profile = decode_client_profile(encode_client_profile(entry,
      account.account_id,
      credential.device_id)?)?
    let invalid = (!current && !lapsed)
      || contains_device_id(profiles, profile.device_id, 0)
      || contains_device_id(expired, profile.device_id, 0)
      || contains_revoked_id(value.revoked_device_ids, profile.device_id, 0)
    if invalid do
      Err("invalid_device_set")
    else if current do
      verified_device_profiles(value,
        account,
        now,
        index + 1,
        List.append(profiles, profile),
        expired)
    else
      verified_device_profiles(value,
        account,
        now,
        index + 1,
        profiles,
        List.append(expired, profile))
    end
  end
end

pub fn verified_device_set(input :: Bytes) -> MobileVerifiedDeviceSet!String do
  let value = canonical_device_set(input)?
  let account = case decode_account_identity(value.account_identity) do
    Err(_) -> Err("invalid_device_set")
    Ok(decoded)
  end?
  if U64.compare(value.sequence, account.directory_sequence) < 0 do
    Err("device_set_rollback")
  else
    let sorted = verified_device_profiles(value,
      account,
      current_time()?,
      0,
      List.new(),
      List.new())?
    Ok(MobileVerifiedDeviceSet {
      wire: input,
      value: value,
      account: account,
      profiles: sorted.profiles,
      expired: sorted.expired
    })
  end
end

## Every device signed into the account, reachable or expired.

pub fn account_device_profiles(value :: MobileVerifiedDeviceSet) -> List<ClientProfile> do
  List.concat(value.profiles, value.expired)
end

# What a person reviewing an account's devices cares about: which devices,
# with which identity keys, and which were removed. Renewing a credential,
# signed prekey or ML-KEM prekey changes none of it.

fn device_identity(device :: DirectoryEntry) -> Bytes!String do
  let bundle = case decode_prekey_bundle(device.prekey_bundle) do
    Err(_) -> Err("invalid_device_set")
    Ok(decoded)
  end?
  let credential = case decode_device_credential(bundle.device_credential) do
    Err(_) -> Err("invalid_device_set")
    Ok(decoded)
  end?
  case Bytes.concat(credential.device_id, credential.signing_public_key) do
    Err(_) -> Err("invalid_device_set")
    Ok(prefix) -> case Bytes.concat(prefix, credential.dh_public_key) do
      Err(_) -> Err("invalid_device_set")
      Ok(identity)
    end
  end
end

fn device_identities(values :: List<DirectoryEntry>,
  index :: Int,
  output :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(values) do
    Ok(output)
  else
    device_identities(values,
      index + 1,
      List.append(output, device_identity(List.get(values, index))?))
  end
end

fn same_identities(previous :: List<Bytes>, next :: List<Bytes>, index :: Int) -> Bool do
  if List.length(previous) != List.length(next) do
    false
  else if index >= List.length(previous) do
    true
  else if !Bytes.secure_equals(List.get(previous, index), List.get(next, index)) do
    false
  else
    same_identities(previous, next, index + 1)
  end
end

fn devices_changed(previous :: DeviceSet, next :: DeviceSet) -> Bool!String do
  let same_devices = same_identities(device_identities(previous.devices, 0, List.new())?,
    device_identities(next.devices, 0, List.new())?,
    0)
  let same_revoked = same_identities(previous.revoked_device_ids, next.revoked_device_ids, 0)
  Ok(!same_devices || !same_revoked)
end

pub fn device_set_label(account_id :: Bytes) -> String do
  "device-set/v1/#{Bytes.to_hex(account_id)}"
end

pub fn cached_device_set_changed(database_path :: String,
  wrapping_key :: borrow StorageKey,
  next :: MobileVerifiedDeviceSet,
  label :: String) -> Bool!String do
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(false)
    else
      Err(error)
    end
    Ok(blob) -> do
      let previous_wire = open_local(blob, wrapping_key, local_context(label)?)?
      let previous = canonical_device_set(previous_wire)?
      let same_identity = previous.username == next.value.username
        && Bytes.secure_equals(previous.account_identity, next.value.account_identity)
      let sequence = U64.compare(next.value.sequence, previous.sequence)
      if !same_identity || sequence < 0 do
        Err("device_set_rollback")
      else if sequence == 0 && !Bytes.secure_equals(previous_wire, next.wire) do
        Err("device_set_equivocation")
      else if sequence == 0 do
        Ok(false)
      else
        devices_changed(previous, next.value)
      end
    end
  end
end

pub fn local_device_set(local :: ClientProfile, value :: MobileVerifiedDeviceSet) -> Bool do
  local.username == value.value.username
    && Bytes.secure_equals(local.account_id, value.account.account_id)
    && Bytes.secure_equals(local.entry.account_identity, value.value.account_identity)
    && contains_device_id(account_device_profiles(value), local.device_id, 0)
end
