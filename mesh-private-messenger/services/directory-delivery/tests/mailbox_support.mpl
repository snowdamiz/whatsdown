##! Test fixture: a registered device that can sign mailbox requests.
##!
##! Mailbox reads and acknowledgements are authorized by the device signing key,
##! so tests that fetch must register a real account-signed device.

from Api.Binary import register_device_request
from Identity.Device import AccountKeys, DeviceKeys, generate_account, generate_device, issue_device_credential
from Prekeys.Bundle import build_prekey_bundle, generate_one_time_prekey, generate_signed_prekey
from Protocol.DirectoryWire import encode_directory_entry
from Protocol.IdentityWire import encode_account_identity
from Protocol.MailboxWire import sign_mailbox_ack, sign_mailbox_fetch
from Protocol.PrekeyWire import encode_prekey_bundle
from Protocol.V1 import AccountIdentity, DeviceCredential, DirectoryEntry

fn support_wide(value :: String) -> U64 ! String do
  U64.parse(value)
end

pub fn mailbox_test_now() -> U64 ! String do
  support_wide(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn support_directory_entry(username :: String,
identity :: AccountIdentity,
device_keys :: borrow DeviceKeys,
device_credential :: DeviceCredential,
mailbox_token :: Bytes,
expires_at :: U64) -> DirectoryEntry ! String do
  let signed = case generate_signed_prekey(device_keys,
  device_credential,
  support_wide("1") ?,
  expires_at) do
    Err(_) -> Err("signed prekey generation failed")
    Ok(value) -> Ok(value)
  end ?
  let one_time = case generate_one_time_prekey(support_wide("2") ?) do
    Err(_) -> Err("one-time prekey generation failed")
    Ok(value) -> Ok(value)
  end ?
  let bundle = case build_prekey_bundle(device_credential, signed, one_time) do
    Err(_) -> Err("bundle generation failed")
    Ok(value) -> Ok(value)
  end ?
  let account_identity = case encode_account_identity(identity) do
    Err(_) -> Err("account identity encoding failed")
    Ok(value) -> Ok(value)
  end ?
  let prekey_bundle = case encode_prekey_bundle(bundle) do
    Err(_) -> Err("prekey bundle encoding failed")
    Ok(value) -> Ok(value)
  end ?
  Ok(DirectoryEntry {
    version : 1,
    username : username,
    account_identity : account_identity,
    prekey_bundle : prekey_bundle,
    mailbox_token : mailbox_token
  })
end

fn support_register(pool :: PoolHandle,
username :: String,
mailbox_token :: Bytes,
account_keys :: borrow AccountKeys,
identity :: AccountIdentity,
device_keys :: borrow DeviceKeys,
created_at :: U64) -> Result <(), String > do
  let expires_at = U64.add(created_at, support_wide("31536000000") ?) ?
  let device_credential = case issue_device_credential(account_keys,
  device_keys,
  support_wide("1") ?,
  created_at,
  expires_at,
  support_wide("1") ?) do
    Err(_) -> Err("credential generation failed")
    Ok(value) -> Ok(value)
  end ?
  let entry = support_directory_entry(username,
  identity,
  device_keys,
  device_credential,
  mailbox_token,
  expires_at) ?
  let encoded = case encode_directory_entry(entry) do
    Err(_) -> Err("directory entry encoding failed")
    Ok(value) -> Ok(value)
  end ?
  if register_device_request(pool, encoded).status == 201 do
    Ok(nil)
  else
    Err("test device registration failed")
  end
end

## A complete, valid registration for a fresh account, encoded but not sent.

pub fn test_directory_entry_wire(username :: String, mailbox_token :: Bytes) -> Bytes ! String do
  let created_at = mailbox_test_now() ?
  let expires_at = U64.add(created_at, support_wide("31536000000") ?) ?
  let (account_keys, identity) = case generate_account(created_at, support_wide("1") ?) do
    Err(_) -> Err("account generation failed")
    Ok(value) -> Ok(value)
  end ?
  let device_keys = case generate_device() do
    Err(_) -> Err("device generation failed")
    Ok(value) -> Ok(value)
  end ?
  let device_credential = case issue_device_credential(account_keys,
  device_keys,
  support_wide("1") ?,
  created_at,
  expires_at,
  support_wide("1") ?) do
    Err(_) -> Err("credential generation failed")
    Ok(value) -> Ok(value)
  end ?
  let entry = support_directory_entry(username,
  identity,
  device_keys,
  device_credential,
  mailbox_token,
  expires_at) ?
  case encode_directory_entry(entry) do
    Err(_) -> Err("directory entry encoding failed")
    Ok(value) -> Ok(value)
  end
end

fn reject_registration(device_keys :: consume DeviceKeys, error :: String) -> DeviceKeys ! String do
  Err(error)
end

## Registers a fresh account and device that owns `mailbox_token`; the returned
## keys sign that mailbox's requests.

pub fn register_test_mailbox(pool :: PoolHandle, username :: String, mailbox_token :: Bytes) -> DeviceKeys ! String do
  let created_at = mailbox_test_now() ?
  let (account_keys, identity) = case generate_account(created_at, support_wide("1") ?) do
    Err(_) -> Err("account generation failed")
    Ok(value) -> Ok(value)
  end ?
  let device_keys = case generate_device() do
    Err(_) -> Err("device generation failed")
    Ok(value) -> Ok(value)
  end ?
  case support_register(pool,
  username,
  mailbox_token,
  account_keys,
  identity,
  device_keys,
  created_at) do
    Err(error) -> reject_registration(device_keys, error)
    Ok(_) -> Ok(device_keys)
  end
end

pub fn signed_fetch_at(device_keys :: borrow DeviceKeys,
mailbox_token :: Bytes,
after_sequence :: U64,
issued_at :: U64) -> Bytes ! String do
  case sign_mailbox_fetch(device_keys.signing_private_key,
  Crypto.sha256(mailbox_token),
  after_sequence,
  issued_at) do
    Err(_) -> Err("mailbox fetch signing failed")
    Ok(value) -> Ok(value)
  end
end

pub fn signed_fetch(device_keys :: borrow DeviceKeys, mailbox_token :: Bytes) -> Bytes ! String do
  signed_fetch_at(device_keys, mailbox_token, support_wide("0") ?, mailbox_test_now() ?)
end

pub fn signed_ack_at(device_keys :: borrow DeviceKeys,
mailbox_token :: Bytes,
envelope_ids :: List < Bytes >,
issued_at :: U64) -> Bytes ! String do
  case sign_mailbox_ack(device_keys.signing_private_key,
  Crypto.sha256(mailbox_token),
  issued_at,
  envelope_ids) do
    Err(_) -> Err("mailbox acknowledgement signing failed")
    Ok(value) -> Ok(value)
  end
end

pub fn signed_ack(device_keys :: borrow DeviceKeys,
mailbox_token :: Bytes,
envelope_ids :: List < Bytes >) -> Bytes ! String do
  signed_ack_at(device_keys, mailbox_token, envelope_ids, mailbox_test_now() ?)
end
