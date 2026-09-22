import File
from MobileCore import create_account_export, journal_load_export, journal_save_export
from Tests.GroupLifecycleWire import group_vectors
from Tests.Support import database_path, repeated

fn saved(path :: String, key :: String, data :: Bytes) -> Bytes ! String do
  journal_save_export(group_vectors([Bytes.from_utf8(path), Bytes.from_utf8(key), data]) ?)
end

fn loaded(path :: String, key :: String) -> Bytes ! String do
  journal_load_export(group_vectors([Bytes.from_utf8(path), Bytes.from_utf8(key)]) ?)
end

fn refused(path :: String, key :: String) -> Bool do
  let write = case saved(path, key, Bytes.from_utf8("[]")) do
    Err(error) -> error == "invalid_journal_key"
    Ok(_) -> false
  end
  let read = case loaded(path, key) do
    Err(error) -> error == "invalid_journal_key"
    Ok(_) -> false
  end
  write && read
end

# What the app keeps about a chat is nowhere in the database in the clear.

fn stored_in_clear(path :: String, needle :: String) -> Bool ! String do
  let database = Sqlite.open(path) ?
  let rows = Sqlite.query_values(database,
  "SELECT CAST(count(*) AS TEXT) AS found FROM encrypted_blobs WHERE instr(ciphertext, CAST(? AS BLOB)) > 0 OR instr(record_hash, ?) > 0",
  [Text(needle), Text(needle)])
  Sqlite.close(database)
  case Map.get(List.head(rows ?), "found") do
    Text(value) -> Ok(value != "0")
    _ -> Err("count failed")
  end
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("journal") ?
  let _ = create_account_export(group_vectors([Bytes.from_utf8(path), Bytes.from_utf8("alice")]) ?) ?
  let chat = "read-state/chat/" <> Bytes.to_hex(repeated(10, 16) ?)
  let marks = Bytes.from_utf8("[\"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b\"]")
  # Nothing is kept until something is saved.
  assert(Bytes.length(loaded(path, chat) ?) == 0)
  let _ = saved(path, chat, marks) ?
  assert(Bytes.secure_equals(loaded(path, chat) ?, marks))
  assert(!(stored_in_clear(path, "0b0b0b0b0b0b0b0b") ?))
  assert(!(stored_in_clear(path, Bytes.to_hex(repeated(10, 16) ?)) ?))
  # Journals and chats do not share records.
  assert(Bytes.length(loaded(path, "receipt-marks/chat/" <> Bytes.to_hex(repeated(10, 16) ?)) ?) == 0)
  assert(Bytes.length(loaded(path, "read-state/index") ?) == 0)
  let group = "notification-state/group/" <> Bytes.to_hex(repeated(12, 32) ?)
  let _ = saved(path, group, Bytes.from_utf8("[]")) ?
  assert(Bytes.secure_equals(loaded(path, group) ?, Bytes.from_utf8("[]")))
  # A single zero byte removes a record.
  let _ = saved(path, chat, Bytes.from_hex("00") ?) ?
  assert(Bytes.length(loaded(path, chat) ?) == 0)
  # Only a journal's own records can be named: this is no way to read or write
  # over anything else the device keeps.
  assert(refused(path, "contact-address/v1"))
  assert(refused(path, "read-state/../contact-address/v1"))
  assert(refused(path, "read-state/chat/" <> Bytes.to_hex(repeated(10, 15) ?)))
  assert(refused(path, "read-state/chat/" <> String.to_upper(Bytes.to_hex(repeated(10, 16) ?))))
  assert(refused(path, "drafts/chat/" <> Bytes.to_hex(repeated(10, 16) ?)))
  assert(refused(path, chat <> "\n"))
  case saved(path, chat, repeated(91, 262145) ?) do
    Err(error) -> assert(error == "journal_record_too_large")
    Ok(_) -> assert(false)
  end
  File.delete(path) ?
  Ok(true)
end

test("the app's read, notification and receipt journals are sealed, and only they can be named") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
