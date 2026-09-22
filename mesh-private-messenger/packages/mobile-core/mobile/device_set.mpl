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

fn device_set_bytes(value :: DeviceSet) -> Bytes ! String do
  case encode_device_set(value) do
    Err(_) -> Err("device_set_encoding_failed")
    Ok(encoded) -> Ok(encoded)
  end
end

fn canonical_device_set(input :: Bytes) -> DeviceSet ! String do
  case decode_device_set(input) do
    Err(_) -> Err("invalid_device_set")
    Ok(value) -> if Bytes.secure_equals(device_set_bytes(value) ?, input) do
      Ok(value)
    else
      Err("noncanonical_device_set")
    end
  end
end

pub fn contains_device_id(profiles :: List < ClientProfile >, device_id :: Bytes, index :: Int) -> Bool do
  if index >= List.length(profiles) do
    false
  else if Bytes.secure_equals(List.get(profiles, index).device_id, device_id) do
    true
  else
    contains_device_id(profiles, device_id, index + 1)
  end
end

fn contains_revoked_id(values :: List < Bytes >, device_id :: Bytes, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else if Bytes.secure_equals(List.get(values, index), device_id) do
    true
  else
    contains_revoked_id(values, device_id, index + 1)
  end
end

fn verified_device_profiles(value :: DeviceSet,
account :: AccountIdentity,
now :: U64,
index :: Int,
profiles :: List < ClientProfile >) -> List < ClientProfile > ! String do
  if index >= List.length(value.devices) do
    Ok(profiles)
  else
    let entry = List.get(value.devices, index)
    let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
      Err(_) -> Err("invalid_device_set")
      Ok(decoded) -> Ok(decoded)
    end ?
    let credential = case decode_device_credential(bundle.device_credential) do
      Err(_) -> Err("invalid_device_set")
      Ok(decoded) -> Ok(decoded)
    end ?
    let verified = case verify_prekey_bundle(account, bundle, 1, now, account.directory_sequence) do
      Err(_) -> false
      Ok(result) -> result
    end
    let profile = decode_client_profile(encode_client_profile(entry,
    account.account_id,
    credential.device_id) ?) ?
    let invalid = !verified || contains_device_id(profiles, profile.device_id, 0) || contains_revoked_id(value.revoked_device_ids,
    profile.device_id,
    0)
    if invalid do
      Err("invalid_device_set")
    else
      verified_device_profiles(value, account, now, index + 1, List.append(profiles, profile))
    end
  end
end

pub fn verified_device_set(input :: Bytes) -> MobileVerifiedDeviceSet ! String do
  let value = canonical_device_set(input) ?
  let account = case decode_account_identity(value.account_identity) do
    Err(_) -> Err("invalid_device_set")
    Ok(decoded) -> Ok(decoded)
  end ?
  if U64.compare(value.sequence, account.directory_sequence) < 0 do
    Err("device_set_rollback")
  else
    Ok(MobileVerifiedDeviceSet {
      wire : input,
      value : value,
      account : account,
      profiles : verified_device_profiles(value, account, current_time() ?, 0, List.new()) ?
    })
  end
end

pub fn device_set_label(account_id :: Bytes) -> String do
  "device-set/v1/#{Bytes.to_hex(account_id)}"
end

pub fn cached_device_set_changed(database_path :: String,
wrapping_key :: borrow StorageKey,
next :: MobileVerifiedDeviceSet,
label :: String) -> Bool ! String do
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(false)
    else
      Err(error)
    end
    Ok(blob) -> do
      let previous_wire = open_local(blob, wrapping_key, local_context(label) ?) ?
      let previous = canonical_device_set(previous_wire) ?
      let same_identity = previous.username == next.value.username && Bytes.secure_equals(previous.account_identity,
      next.value.account_identity)
      let sequence = U64.compare(next.value.sequence, previous.sequence)
      if !same_identity || sequence < 0 do
        Err("device_set_rollback")
      else if sequence == 0 && !Bytes.secure_equals(previous_wire, next.wire) do
        Err("device_set_equivocation")
      else
        Ok(sequence > 0)
      end
    end
  end
end

pub fn local_device_set(local :: ClientProfile, value :: MobileVerifiedDeviceSet) -> Bool do
  local.username == value.value.username && Bytes.secure_equals(local.account_id,
  value.account.account_id) && Bytes.secure_equals(local.entry.account_identity,
  value.value.account_identity) && contains_device_id(value.profiles, local.device_id, 0)
end
