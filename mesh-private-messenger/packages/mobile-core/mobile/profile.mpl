from Identity.Device import (
  AccountKeys,
  DeviceKeys,
  VerificationPolicy,
  generate_account,
  generate_device
)
from Mobile.Codec import mobile_wide
from Mobile.Types import MobileOneTimePrekey
from Prekeys.Bundle import (
  OneTimePrekeySecrets,
  PostQuantumPrekeySecrets,
  PrekeyError,
  SignedPrekeySecrets,
  generate_post_quantum_prekey
)
from Protocol.DirectoryWire import encode_directory_entry
from Protocol.V1 import (
  AccountIdentity,
  DeviceCredential,
  DeviceLinkRequest,
  DirectoryEntry,
  PrekeyBundle
)
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import (
  context,
  local_context,
  one_time_prekey_context,
  one_time_prekey_label,
  open_local,
  open_mlkem,
  open_signing,
  open_x25519,
  pending_context,
  platform_key
)
from Transport.Packet import ClientProfile, decode_client_profile

##! Mobile.Profile implementation.

pub fn account_keys(created_at :: U64) -> Result <( AccountKeys, AccountIdentity), String > do
  case generate_account(created_at, mobile_wide("1") ?) do
    Err( _) -> Err("account_generation_failed")
    Ok( value) -> Ok(value)
  end
end

pub fn device_keys() -> DeviceKeys ! String do
  case generate_device() do
    Err( _) -> Err("device_generation_failed")
    Ok( value) -> Ok(value)
  end
end

pub fn directory_bytes(value :: DirectoryEntry) -> Bytes ! String do
  case encode_directory_entry(value) do
    Err( _) -> Err("directory_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

pub fn load_profile(database_path :: String) -> Bytes ! String do
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    ensure_schema(database_path) ?
    let wrapping_key = platform_key() ?
    open_local(load_blob(database_path, "profile/v1") ?,
    wrapping_key,
    local_context("profile/v1") ?)
  end
end

pub fn peer_account_id(reference :: Bytes) -> Bytes ! String do
  if Bytes.length(reference) == 32 do
    Ok(reference)
  else
    Ok(decode_client_profile(reference) ?.account_id)
  end
end

pub fn policy(profile :: ClientProfile, now :: U64) -> VerificationPolicy do
  VerificationPolicy {
    current_time : now,
    minimum_directory_sequence : profile.account.directory_sequence
  }
end

fn reject_device_open(signing :: consume SigningPrivateKey, error :: String) -> DeviceKeys ! String do
  Err(error)
end

pub fn open_account(profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
database_path :: String) -> AccountKeys ! String do
  let account_blob = load_blob(database_path, "account-signing-key/v1") ?
  case open_signing(account_blob,
  wrapping_key,
  context(profile.account_id, profile.device_id, "account-signing-key/v1", 6) ?) do
    Err( error) -> Err(error)
    Ok( private_key) -> Ok(AccountKeys {
      account_id : profile.account_id,
      private_key : private_key,
      public_key : SigningPublicKey { bytes : profile.account.authorization_public_key }
    })
  end
end

fn reject_prekey_open(signed_private :: consume X25519PrivateKey, error :: String) -> Result <( SignedPrekeySecrets, OneTimePrekeySecrets, PostQuantumPrekeySecrets), String > do
  Err(error)
end

fn reject_post_quantum_open(signed_private :: consume X25519PrivateKey,
one_time_private :: consume X25519PrivateKey,
error :: String) -> Result <( SignedPrekeySecrets, OneTimePrekeySecrets, PostQuantumPrekeySecrets), String > do
  Err(error)
end

pub fn open_post_quantum_prekey(profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
database_path :: String) -> PostQuantumPrekeySecrets ! String do
  let label = "post-quantum-prekey/v1"
  case load_blob(database_path, label) do
    Err( error) -> if error == "local_state_not_found" && profile.bundle.suite == 1 do
      case generate_post_quantum_prekey() do
        Err( _) -> Err("post_quantum_prekey_generation_failed")
        Ok( value) -> Ok(value)
      end
    else
      Err(error)
    end
    Ok( blob) -> do
      let private_key = open_mlkem(blob,
      wrapping_key,
      context(profile.account_id, profile.device_id, label, 15) ?) ?
      Ok(PostQuantumPrekeySecrets {
        private_key : private_key,
        public_key : MlKemPublicKey { bytes : profile.bundle.post_quantum_prekey }
      })
    end
  end
end

pub fn open_device(profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
database_path :: String) -> DeviceKeys ! String do
  let signing_blob = load_blob(database_path, "device-signing-key/v1") ?
  let identity_blob = load_blob(database_path, "device-identity-key/v1") ?
  let signing_context = context(profile.account_id, profile.device_id, "device-signing-key/v1", 7) ?
  let identity_context = context(profile.account_id, profile.device_id, "device-identity-key/v1", 8) ?
  case open_signing(signing_blob, wrapping_key, signing_context) do
    Err( error) -> Err(error)
    Ok( signing) -> case open_x25519(identity_blob, wrapping_key, identity_context) do
      Err( error) -> reject_device_open(signing, error)
      Ok( identity) -> Ok(DeviceKeys {
        device_id : profile.device_id,
        signing_private_key : signing,
        signing_public_key : SigningPublicKey { bytes : profile.credential.signing_public_key },
        identity_private_key : identity,
        identity_public_key : X25519PublicKey { bytes : profile.credential.dh_public_key }
      })
    end
  end
end

pub fn open_pending_device(request :: DeviceLinkRequest,
wrapping_key :: borrow StorageKey,
database_path :: String) -> DeviceKeys ! String do
  let signing_blob = load_blob(database_path, "pending-device-signing-key/v1") ?
  let identity_blob = load_blob(database_path, "pending-device-identity-key/v1") ?
  case open_signing(signing_blob,
  wrapping_key,
  pending_context("pending-device-signing-key/v1", 7) ?) do
    Err( error) -> Err(error)
    Ok( signing) -> case open_x25519(identity_blob,
    wrapping_key,
    pending_context("pending-device-identity-key/v1", 8) ?) do
      Err( error) -> reject_device_open(signing, error)
      Ok( identity) -> Ok(DeviceKeys {
        device_id : request.device_id,
        signing_private_key : signing,
        signing_public_key : SigningPublicKey { bytes : request.signing_public_key },
        identity_private_key : identity,
        identity_public_key : X25519PublicKey { bytes : request.dh_public_key }
      })
    end
  end
end

pub fn open_pending_post_quantum_prekey(request :: DeviceLinkRequest,
wrapping_key :: borrow StorageKey,
database_path :: String) -> PostQuantumPrekeySecrets ! String do
  let label = "pending-post-quantum-prekey/v1"
  let private_key = open_mlkem(load_blob(database_path, label) ?,
  wrapping_key,
  pending_context(label, 15) ?) ?
  Ok(PostQuantumPrekeySecrets {
    private_key : private_key,
    public_key : MlKemPublicKey { bytes : request.post_quantum_public_key }
  })
end

pub fn open_prekeys(profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
database_path :: String,
selected :: MobileOneTimePrekey) -> Result <( SignedPrekeySecrets, OneTimePrekeySecrets, PostQuantumPrekeySecrets), String > do
  let signed_blob = load_blob(database_path, "signed-prekey/v1") ?
  let one_time_label = one_time_prekey_label(selected.id)
  let one_time_blob = load_blob(database_path, one_time_label) ?
  let signed_context = context(profile.account_id, profile.device_id, "signed-prekey/v1", 9) ?
  let one_time_context = one_time_prekey_context(profile, selected.id) ?
  case open_x25519(signed_blob, wrapping_key, signed_context) do
    Err( error) -> Err(error)
    Ok( signed_private) -> case open_x25519(one_time_blob, wrapping_key, one_time_context) do
      Err( error) -> reject_prekey_open(signed_private, error)
      Ok( one_time_private) -> case open_post_quantum_prekey(profile, wrapping_key, database_path) do
        Err( error) -> reject_post_quantum_open(signed_private, one_time_private, error)
        Ok( post_quantum) -> Ok((SignedPrekeySecrets {
          id : profile.bundle.signed_prekey_id,
          private_key : signed_private,
          public_key : X25519PublicKey { bytes : profile.bundle.signed_prekey },
          signature : Signature { bytes : profile.bundle.signed_prekey_signature },
          expires_at : profile.bundle.expires_at
        },
        OneTimePrekeySecrets {
          id : selected.id,
          private_key : one_time_private,
          public_key : X25519PublicKey { bytes : selected.public_key }
        },
        post_quantum))
      end
    end
  end
end
