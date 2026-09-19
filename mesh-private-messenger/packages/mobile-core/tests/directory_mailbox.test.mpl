from Protocol.V1 import DirectoryEntry, MailboxFetch
import File
from MobileCore import (
  create_account_export,
  directory_entry_export,
  directory_lookup_export,
  import_contact_export,
  mailbox_fetch_export
)
from Protocol.DirectoryWire import decode_directory_entry, decode_directory_lookup
from Protocol.MailboxWire import decode_mailbox_fetch
from Tests.Support import append, database_path, vector

fn account_request(path :: String, username :: String) -> Bytes ! String do
  append(vector(Bytes.from_utf8(path)) ?, vector(Bytes.from_utf8(username)) ?)
end

fn zero() -> U64 ! String do
  case U64.parse("0") do
    Err( _) -> Err("test integer conversion failed")
    Ok( value) -> Ok(value)
  end
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("directory-mailbox") ?
  let profile = create_account_export(account_request(path, "bob") ?) ?
  assert(Bytes.length(profile) > 0)
  let entry_bytes = directory_entry_export(Bytes.from_utf8(path)) ?
  assert(Bytes.secure_equals(import_contact_export(entry_bytes) ?, profile))
  let entry = case decode_directory_entry(entry_bytes) do
    Err( _) -> Err("directory entry decode failed")
    Ok( value) -> Ok(value)
  end ?
  assert(entry.version == 1)
  assert(entry.username == "bob")
  let lookup = case decode_directory_lookup(directory_lookup_export(Bytes.from_utf8("bob")) ?) do
    Err( _) -> Err("directory lookup decode failed")
    Ok( value) -> Ok(value)
  end ?
  assert(lookup == entry.username)
  let fetch = case decode_mailbox_fetch(mailbox_fetch_export(Bytes.from_utf8(path)) ?) do
    Err( _) -> Err("mailbox fetch decode failed")
    Ok( value) -> Ok(value)
  end ?
  assert(fetch.version == 1)
  assert(Bytes.secure_equals(fetch.mailbox_token, entry.mailbox_token))
  assert(U64.compare(fetch.after_sequence, zero() ?) == 0)
  File.delete(path) ?
  Ok(true)
end

test("mobile directory, contacts, and mailbox discovery use public Mesh codecs") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
