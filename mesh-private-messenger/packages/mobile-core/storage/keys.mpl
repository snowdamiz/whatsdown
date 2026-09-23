from Mobile.Codec import (
  mobile_byte,
  mobile_join,
  mobile_wide,
  mobile_write_u16,
  mobile_write_u64,
  mobile_zeroes
)
from Protocol.V1 import AccountIdentity, DeviceCredential, DirectoryEntry, PrekeyBundle
from Transport.Packet import ClientProfile

##! Storage.Keys implementation.

pub fn context(account_id :: Bytes, device_id :: Bytes, label :: String, purpose :: Int) -> Bytes!String do
  if Bytes.length(account_id) != 32 || Bytes.length(device_id) != 16 do
    Err("invalid_storage_identity")
  else
    let session_id = if (purpose >= 5 && purpose <= 10) || purpose == 15 do
      mobile_zeroes(32)?
    else
      Crypto.sha256(Bytes.from_utf8("mesh-msg/mobile/storage-session/v1"))
    end
    mobile_join([
        mobile_byte(1)?,
        account_id,
        device_id,
        session_id,
        Crypto.sha256(Bytes.from_utf8(label)),
        mobile_write_u16(purpose)?,
        mobile_write_u64(mobile_wide("1")?)?
      ],
      0,
      Bytes.empty())
  end
end

pub fn local_context(label :: String) -> Bytes!String do
  case Bytes.repeat(0, 32) do
    Err(_) -> Err("storage_context_failed")
    Ok(account_id) -> case Bytes.repeat(0, 16) do
      Err(_) -> Err("storage_context_failed")
      Ok(device_id) -> context(account_id, device_id, label, 14)
    end
  end
end

pub fn pending_context(label :: String, purpose :: Int) -> Bytes!String do
  case Bytes.repeat(0, 32) do
    Err(_) -> Err("storage_context_failed")
    Ok(account_id) -> case Bytes.repeat(0, 16) do
      Err(_) -> Err("storage_context_failed")
      Ok(device_id) -> context(account_id, device_id, label, purpose)
    end
  end
end

pub fn one_time_prekey_label(id :: U64) -> String do
  "one-time-prekey/v1/#{U64.to_string(id)}"
end

pub fn one_time_prekey_context(profile :: ClientProfile, id :: U64) -> Bytes!String do
  let label = one_time_prekey_label(id)
  context(profile.account_id, profile.device_id, label, 10)
end

pub fn platform_key() -> StorageKey!String do
  case StorageKey.platform() do
    Err(_) -> Err("secure_storage_unavailable")
    Ok(key)
  end
end

pub fn seal_signing(key :: borrow SigningPrivateKey,
  wrapping_key :: borrow StorageKey,
  value_context :: Bytes) -> Bytes!String do
  case SigningPrivateKey.seal_for_storage(key, wrapping_key, value_context) do
    Err(_) -> Err("identity_seal_failed")
    Ok(blob)
  end
end

pub fn seal_x25519(key :: borrow X25519PrivateKey,
  wrapping_key :: borrow StorageKey,
  value_context :: Bytes) -> Bytes!String do
  case X25519PrivateKey.seal_for_storage(key, wrapping_key, value_context) do
    Err(_) -> Err("identity_seal_failed")
    Ok(blob)
  end
end

pub fn seal_mlkem(key :: borrow MlKemPrivateKey,
  wrapping_key :: borrow StorageKey,
  value_context :: Bytes) -> Bytes!String do
  case MlKemPrivateKey.seal_for_storage(key, wrapping_key, value_context) do
    Err(_) -> Err("identity_seal_failed")
    Ok(blob)
  end
end

pub fn open_signing(blob :: Bytes, wrapping_key :: borrow StorageKey, value_context :: Bytes) -> SigningPrivateKey!String do
  case SigningPrivateKey.unseal_from_storage(blob, wrapping_key, value_context) do
    Err(_) -> Err("identity_open_failed")
    Ok(key)
  end
end

pub fn open_x25519(blob :: Bytes, wrapping_key :: borrow StorageKey, value_context :: Bytes) -> X25519PrivateKey!String do
  case X25519PrivateKey.unseal_from_storage(blob, wrapping_key, value_context) do
    Err(_) -> Err("identity_open_failed")
    Ok(key)
  end
end

pub fn open_mlkem(blob :: Bytes, wrapping_key :: borrow StorageKey, value_context :: Bytes) -> MlKemPrivateKey!String do
  case MlKemPrivateKey.unseal_from_storage(blob, wrapping_key, value_context) do
    Err(_) -> Err("identity_open_failed")
    Ok(key)
  end
end

pub fn seal_local(value :: Bytes, wrapping_key :: borrow StorageKey, value_context :: Bytes) -> Bytes!String do
  case StorageKey.seal_bytes(value, wrapping_key, value_context) do
    Err(_) -> Err("local_state_seal_failed")
    Ok(blob)
  end
end

pub fn open_local(blob :: Bytes, wrapping_key :: borrow StorageKey, value_context :: Bytes) -> Bytes!String do
  case StorageKey.unseal_bytes(blob, wrapping_key, value_context) do
    Err(_) -> Err("local_state_open_failed")
    Ok(value)
  end
end
