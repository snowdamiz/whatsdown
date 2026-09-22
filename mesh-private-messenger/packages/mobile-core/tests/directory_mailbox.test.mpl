from Protocol.V1 import DeviceCredential, DirectoryEntry, MailboxFetch, PrekeyBundle
import File
from MobileCore import (
  create_account_export,
  directory_entry_export,
  directory_lookup_export,
  import_contact_export,
  mailbox_fetch_export
)
from Protocol.DirectoryWire import decode_directory_entry, decode_directory_lookup
from Protocol.IdentityWire import decode_device_credential
from Protocol.MailboxWire import decode_mailbox_fetch, mailbox_fetch_signing_bytes, mailbox_request_is_fresh
from Protocol.PrekeyWire import decode_prekey_bundle
from Tests.Support import append, database_path, vector

fn account_request(path :: String, username :: String) -> Bytes ! String do
  append(vector(Bytes.from_utf8(path)) ?, vector(Bytes.from_utf8(username)) ?)
end

fn zero() -> U64 ! String do
  case U64.parse("0") do
    Err(_) -> Err("test integer conversion failed")
    Ok(value) -> Ok(value)
  end
end

fn now() -> U64 ! String do
  case U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now()))) do
    Err(_) -> Err("test clock conversion failed")
    Ok(value) -> Ok(value)
  end
end

# The key the directory publishes for this device: what the delivery service
# will verify a mailbox request against.

fn published_signing_key(entry :: DirectoryEntry) -> SigningPublicKey ! String do
  let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
    Err(_) -> Err("prekey bundle decode failed")
    Ok(value) -> Ok(value)
  end ?
  let credential = case decode_device_credential(bundle.device_credential) do
    Err(_) -> Err("device credential decode failed")
    Ok(value) -> Ok(value)
  end ?
  Ok(SigningPublicKey { bytes : credential.signing_public_key })
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("directory-mailbox") ?
  let profile = create_account_export(account_request(path, "bob") ?) ?
  assert(Bytes.length(profile) > 0)
  let entry_bytes = directory_entry_export(Bytes.from_utf8(path)) ?
  assert(Bytes.secure_equals(import_contact_export(entry_bytes) ?, profile))
  let entry = case decode_directory_entry(entry_bytes) do
    Err(_) -> Err("directory entry decode failed")
    Ok(value) -> Ok(value)
  end ?
  assert(entry.version == 1)
  assert(entry.username == "bob")
  let lookup = case decode_directory_lookup(directory_lookup_export(Bytes.from_utf8("bob")) ?) do
    Err(_) -> Err("directory lookup decode failed")
    Ok(value) -> Ok(value)
  end ?
  assert(lookup == entry.username)
  let fetch = case decode_mailbox_fetch(mailbox_fetch_export(Bytes.from_utf8(path)) ?) do
    Err(_) -> Err("mailbox fetch decode failed")
    Ok(value) -> Ok(value)
  end ?
  assert(fetch.version == 2)
  assert(Bytes.secure_equals(fetch.mailbox_token_hash, Crypto.sha256(entry.mailbox_token)))
  assert(U64.compare(fetch.after_sequence, zero() ?) == 0)
  assert(mailbox_request_is_fresh(fetch.issued_at, now() ?))
  let signing_bytes = case mailbox_fetch_signing_bytes(fetch) do
    Err(_) -> Err("mailbox fetch signing bytes failed")
    Ok(value) -> Ok(value)
  end ?
  let authorized = case Crypto.verify(published_signing_key(entry) ?,
  signing_bytes,
  Signature { bytes : fetch.signature }) do
    Err(_) -> false
    Ok(valid) -> valid
  end
  assert(authorized)
  File.delete(path) ?
  Ok(true)
end

test("mobile directory and contacts use public codecs and mailbox fetches are device-signed") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
