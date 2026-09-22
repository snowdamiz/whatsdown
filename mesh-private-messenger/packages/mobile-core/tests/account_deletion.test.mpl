from Identity.Device import verify_account_deletion, verify_device_departure
from MobileCore import (
  account_deletion_export,
  create_account_export,
  device_departure_export,
  directory_entry_export,
  erase_account_export,
  forget_on_proof_export,
  load_profile_export
)
from Protocol.DirectoryWire import decode_account_deletion, decode_device_departure, decode_directory_entry
from Protocol.IdentityWire import decode_account_identity, decode_device_credential
from Protocol.PrekeyWire import decode_prekey_bundle
from Protocol.V1 import AccountIdentity
from Tests.Support import append, database_path, vector

fn account_request(path :: String, username :: String) -> Bytes ! String do
  append(vector(Bytes.from_utf8(path)) ?, vector(Bytes.from_utf8(username)) ?)
end

fn identity_of(path :: String) -> AccountIdentity ! String do
  let entry = case decode_directory_entry(directory_entry_export(Bytes.from_utf8(path)) ?) do
    Err( _) -> Err("directory entry decode failed")
    Ok( value) -> Ok(value)
  end ?
  case decode_account_identity(entry.account_identity) do
    Err( _) -> Err("account identity decode failed")
    Ok( value) -> Ok(value)
  end
end

## Writes or removes one record directly, the way an older build, a crash or a
## write racing an erase could leave the table.

fn change_record(path :: String, sql :: String, values :: List < DbValue >) -> Result <(), String > do
  let database = case Sqlite.open(path) do
    Err( _) -> Err("test database open failed")
    Ok( value) -> Ok(value)
  end ?
  let result = Sqlite.execute_values(database, sql, values)
  Sqlite.close(database)
  case result do
    Err( _) -> Err("test record change failed")
    Ok( _) -> Ok(nil)
  end
end

fn record_hash(label :: String) -> DbValue do
  Text(Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(label))))
end

fn loads(path :: String) -> Bool do
  case load_profile_export(Bytes.from_utf8(path)) do
    Err( _) -> false
    Ok( _) -> true
  end
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("account-deletion") ?
  let first = create_account_export(account_request(path, "alice") ?) ?
  let deletion = case decode_account_deletion(account_deletion_export(Bytes.from_utf8(path)) ?) do
    Err( _) -> Err("account deletion decode failed")
    Ok( value) -> Ok(value)
  end ?
  assert(case verify_account_deletion(identity_of(path) ?, deletion) do
    Err( _) -> false
    Ok( valid) -> valid
  end)
  let _ = erase_account_export(Bytes.from_utf8(path)) ?
  assert(!loads(path))
  let _ = erase_account_export(Bytes.from_utf8(path)) ?
  # A record left under one of a new account's labels must not block it.
  change_record(path,
  "INSERT INTO encrypted_blobs (record_hash, ciphertext) VALUES (?, ?)",
  [record_hash("one-time-prekeys/v1"), Binary(Bytes.from_utf8("left behind"))]) ?
  let second = create_account_export(account_request(path, "alice") ?) ?
  assert(!Bytes.secure_equals(second, first))
  assert(loads(path))
  # An account is never replaced by creating another over it.
  assert(case create_account_export(account_request(path, "bob") ?) do
    Err( _) -> true
    Ok( _) -> false
  end)
  # A linked device holds no account key, so it gets no statement to send.
  change_record(path,
  "DELETE FROM encrypted_blobs WHERE record_hash = ?",
  [record_hash("account-signing-key/v1")]) ?
  assert(Bytes.length(account_deletion_export(Bytes.from_utf8(path)) ?) == 0)
  Ok(true)
end

test("an erased account leaves nothing behind that could block the next one") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end

fn device_signing_key(path :: String) -> Bytes ! String do
  let entry = case decode_directory_entry(directory_entry_export(Bytes.from_utf8(path)) ?) do
    Err( _) -> Err("directory entry decode failed")
    Ok( value) -> Ok(value)
  end ?
  let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
    Err( _) -> Err("prekey bundle decode failed")
    Ok( value) -> Ok(value)
  end ?
  case decode_device_credential(bundle.device_credential) do
    Err( _) -> Err("device credential decode failed")
    Ok( value) -> Ok(value.signing_public_key)
  end
end

## Which removal the statement proved, if any: 1 the account deleted, 2 this
## device removed by the account, 3 this device leaving on its own key.

fn forgets(path :: String, statement :: Bytes) -> Int ! String do
  case forget_on_proof_export(append(vector(Bytes.from_utf8(path)) ?, vector(statement) ?) ?) do
    Err( _) -> Ok(0)
    Ok( kind) -> case Bytes.get(kind, 0) do
      Err( _) -> Err("empty removal kind")
      Ok( value) -> Ok(value)
    end
  end
end

fn leaving_proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("account-leaving") ?
  let other = database_path("account-leaving-other") ?
  let _ = create_account_export(account_request(path, "alice") ?) ?
  let _ = create_account_export(account_request(other, "bob") ?) ?
  # Any device can sign itself out of its account, with its own key.
  let departure = case decode_device_departure(device_departure_export(Bytes.from_utf8(path)) ?) do
    Err( _) -> Err("device departure decode failed")
    Ok( value) -> Ok(value)
  end ?
  assert(case verify_device_departure(device_signing_key(path) ?, departure) do
    Err( _) -> false
    Ok( valid) -> valid
  end)
  assert(Bytes.secure_equals(departure.account_id, identity_of(path) ?.account_id))
  # The directory's word that the account was deleted erases nothing unless
  # the account's own key signed it: not garbage, not another account's
  # statement, not a statement changed on the way.
  let theirs = account_deletion_export(Bytes.from_utf8(other)) ?
  let ours = account_deletion_export(Bytes.from_utf8(path)) ?
  let unsigned_part = case Bytes.slice(ours, 0, 107) do
    Err( _) -> Err("test slice failed")
    Ok( value) -> Ok(value)
  end ?
  let changed = case Bytes.concat(unsigned_part, Bytes.from_utf8("x")) do
    Err( _) -> Err("test concat failed")
    Ok( value) -> Ok(value)
  end ?
  let their_departure = device_departure_export(Bytes.from_utf8(other)) ?
  assert(forgets(path, Bytes.from_utf8("garbage")) ? == 0)
  assert(forgets(path, theirs) ? == 0)
  assert(forgets(path, changed) ? == 0)
  assert(forgets(path, their_departure) ? == 0)
  assert(loads(path))
  assert(forgets(path, ours) ? == 1)
  assert(!loads(path))
  # A device whose own departure went through, but whose erase did not.
  assert(loads(other))
  assert(forgets(other, their_departure) ? == 3)
  assert(!loads(other))
  Ok(true)
end

test("a device leaves on its own key, and forgets its account only on a proof that verifies") do
  case leaving_proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
