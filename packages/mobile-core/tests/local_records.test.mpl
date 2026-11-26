import File
from Storage.Keys import local_context, platform_key, seal_local
from Storage.Rows import (
  storage_hmac,
  storage_load,
  storage_open_key,
  storage_prepare,
  storage_put,
  storage_row_for,
  storage_row_key
)
from Tests.Support import database_path, repeated

fn text(row :: Map<String, DbValue>, column :: String) -> String!String do
  case Map.get(row, column) do
    Text(value) -> Ok(value)
    Binary(_) -> Err("expected text")
    Null -> Err("expected text")
  end
end

fn query(path :: String,
  sql :: String,
  values :: List<DbValue>) -> List<Map<String, DbValue>>!String do
  let database = Sqlite.open(path)?
  let rows = Sqlite.query_values(database, sql, values)
  Sqlite.close(database)
  rows
end

fn execute(path :: String, sql :: String) -> Result<(), String> do
  let database = Sqlite.open(path)?
  let result = Sqlite.execute(database, sql, [])
  Sqlite.close(database)
  result?
  Ok(nil)
end

fn legacy_row(label :: String) -> String do
  Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(label)))
end

fn label(index :: Int) -> String do
  "record/v1/" <> Int.to_string(index)
end

# The table as it was before format 2: rows under the labels' plain SHA-256,
# stamped with when they were written.

fn create_legacy(path :: String, value_type :: String) -> Result<(), String> do
  execute(path,
    "CREATE TABLE encrypted_blobs (record_hash TEXT PRIMARY KEY CHECK(length(record_hash) = 64), ciphertext "
      <> value_type
      <> " NOT NULL CHECK(length(ciphertext) > 0), updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP) STRICT")
end

fn sealed(index :: Int) -> Bytes!String do
  let wrapping_key = platform_key()?
  seal_local(Bytes.from_utf8("value " <> Int.to_string(index)),
    wrapping_key,
    local_context(label(index))?)
end

fn fill_legacy(database :: SqliteConn, index :: Int, count :: Int) -> Result<(), String> do
  if index >= count do
    Ok(nil)
  else
    Sqlite.execute_values(database,
      "INSERT INTO encrypted_blobs (record_hash, ciphertext, updated_at) VALUES (?, ?, '2026-01-02 03:04:05')",
      [Text(legacy_row(label(index))), Binary(sealed(index)?)])?
    fill_legacy(database, index + 1, count)
  end
end

# More rows than the move takes at a time.

fn legacy_database(name :: String) -> String!String do
  let path = database_path(name)?
  create_legacy(path, "BLOB")?
  let database = Sqlite.open(path)?
  let filled = fill_legacy(database, 0, 300)
  Sqlite.close(database)
  filled?
  Ok(path)
end

# A sealed value is random each time, so a loaded one is checked by opening it.

fn all_load(path :: String, index :: Int, count :: Int) -> Bool!String do
  if index >= count do
    Ok(true)
  else
    let wrapping_key = platform_key()?
    let loaded = storage_load(path, label(index), wrapping_key)?
    let opened = case StorageKey.unseal_bytes(loaded, wrapping_key, local_context(label(index))?) do
      Err(_) -> Err("record " <> Int.to_string(index) <> " did not open")
      Ok(value)
    end?
    if Bytes.secure_equals(opened, Bytes.from_utf8("value " <> Int.to_string(index))) do
      all_load(path, index + 1, count)
    else
      Ok(false)
    end
  end
end

fn snapshot(path :: String) -> String!String do
  let rows = query(path,
    "SELECT record_hash || ':' || hex(ciphertext) AS row FROM encrypted_blobs ORDER BY record_hash",
    [])?
  Ok(String.join(for row in rows do
      text(row, "row")?
    end,
    ","))
end

# Read in overlapping windows, as File reads at most 64 KiB at a time.

fn in_file_from(path :: String, needle :: Bytes, offset :: Int, size :: Int) -> Bool!String do
  if offset >= size do
    Ok(false)
  else
    let length = if size - offset < 65536 do
      size - offset
    else
      65536
    end
    let window = File.read_bytes(path, offset, length)?
    let rows = query(":memory:",
      "SELECT CAST(instr(?, ?) AS TEXT) AS at",
      [Binary(window), Binary(needle)])?
    if text(List.head(rows), "at")? != "0" do
      Ok(true)
    else
      in_file_from(path, needle, offset + 65536 - 64, size)
    end
  end
end

fn in_file(path :: String, needle :: Bytes) -> Bool!String do
  in_file_from(path, needle, 0, File.size(path)?)
end

fn tables(path :: String) -> String!String do
  let rows = query(path,
    "SELECT group_concat(name, ',') AS names FROM (SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name)",
    [])?
  text(List.head(rows), "names")
end

fn version(path :: String) -> String!String do
  text(List.head(query(path,
      "SELECT CAST(user_version AS TEXT) AS version FROM pragma_user_version",
      [])?),
    "version")
end

fn hmac_proof() -> Bool!String do
  # RFC 4231, test cases 1 and 2.
  let first = storage_hmac(storage_row_key(repeated(11, 20)?)?, Bytes.from_utf8("Hi There"))?
  let second = storage_hmac(storage_row_key(Bytes.from_utf8("Jefe"))?,
    Bytes.from_utf8("what do ya want for nothing?"))?
  Ok(Bytes.to_hex(first) == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    && Bytes.to_hex(second) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
end

fn keyed_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("keyed-rows")?
  let other = database_path("keyed-rows-other")?
  storage_prepare(path)?
  storage_prepare(other)?
  let row = storage_row_for(path, "profile/v1")?
  assert(String.length(row) == 64)
  # Neither the label's own hash nor a fixed function of the label.
  assert(row != legacy_row("profile/v1"))
  assert(row != storage_row_for(other, "profile/v1")?)
  assert(tables(path)? == "encrypted_blobs,storage_label_key")
  assert(version(path)? == "2")
  let columns = query(path,
    "SELECT name FROM pragma_table_info('encrypted_blobs') ORDER BY name",
    [])?
  assert(List.length(columns) == 2)
  assert(text(List.get(columns, 0), "name")? == "ciphertext")
  assert(text(List.get(columns, 1), "name")? == "record_hash")
  # The storage-wrap header of a value, with its counter and the binding of its
  # label's context, is not in the file.
  let value = sealed(7)?
  let database = Sqlite.open(path)?
  let wrapping_key = platform_key()?
  storage_put(database, storage_open_key(database, wrapping_key)?, label(7), value)?
  Sqlite.close(database)
  assert(Bytes.secure_equals(storage_load(path, label(7), wrapping_key)?, value))
  assert(!(in_file(path, Bytes.slice(value, 3, 44)?)?))
  assert(!(in_file(path, Bytes.slice(value, 15, 32)?)?))
  File.delete(path)?
  File.delete(other)?
  Ok(true)
end

fn migration_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = legacy_database("keyed-migration")?
  let binding = Bytes.slice(sealed(0)?, 15, 32)?
  # The first read moves every row, in one go.
  assert(all_load(path, 0, 300)?)
  assert(text(List.head(query(path,
      "SELECT CAST(count(*) AS TEXT) AS count FROM encrypted_blobs",
      [])?),
    "count")? == "300")
  assert(tables(path)? == "encrypted_blobs,storage_label_key")
  assert(version(path)? == "2")
  # What the old rows showed is gone from the file, free pages included.
  assert(!(in_file(path, Bytes.from_utf8(legacy_row(label(0))))?))
  assert(!(in_file(path, Bytes.from_utf8("2026-01-02 03:04:05"))?))
  assert(!(in_file(path, Bytes.from_utf8("updated_at"))?))
  assert(!(in_file(path, binding)?))
  # Opening again changes nothing.
  let moved = snapshot(path)?
  storage_prepare(path)?
  assert(snapshot(path)? == moved)
  assert(all_load(path, 0, 300)?)
  File.delete(path)?
  # The first databases kept base64 text, which moves too; a value that is not
  # canonical base64 stops the move and leaves the database as it was.
  let text_path = database_path("keyed-migration-text")?
  create_legacy(text_path, "TEXT")?
  execute(text_path,
    "INSERT INTO encrypted_blobs (record_hash, ciphertext) VALUES ('"
      <> legacy_row("legacy-text")
      <> "', 'AP+A')")?
  let wrapping_key = platform_key()?
  assert(Bytes.secure_equals(storage_load(text_path, "legacy-text", wrapping_key)?,
    Bytes.from_hex("00ff80")?))
  let invalid_path = database_path("keyed-migration-invalid")?
  create_legacy(invalid_path, "TEXT")?
  execute(invalid_path,
    "INSERT INTO encrypted_blobs (record_hash, ciphertext) VALUES ('"
      <> legacy_row("legacy-text")
      <> "', 'AP+A'), ('"
      <> legacy_row("broken")
      <> "', 'not-base64')")?
  let before = snapshot(invalid_path)?
  assert(case storage_prepare(invalid_path) do
    Err(error) -> error == "database_schema_failed"
    Ok(_) -> false
  end)
  assert(snapshot(invalid_path)? == before)
  assert(tables(invalid_path)? == "encrypted_blobs")
  File.delete(text_path)?
  File.delete(invalid_path)?
  Ok(true)
end

fn interrupted_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = legacy_database("keyed-interrupted")?
  let before = query(path,
    "SELECT group_concat(row, ',') AS rows FROM (SELECT record_hash || ':' || hex(ciphertext) || ':' || updated_at AS row FROM encrypted_blobs ORDER BY record_hash)",
    [])?
  # The move stops in its second batch, as a crash there would.
  let last = text(List.head(query(path,
      "SELECT record_hash FROM encrypted_blobs ORDER BY record_hash LIMIT 1 OFFSET 280",
      [])?),
    "record_hash")?
  execute(path,
    "CREATE TRIGGER mesh_test_interrupt BEFORE DELETE ON encrypted_blobs WHEN OLD.record_hash = '"
      <> last
      <> "' BEGIN SELECT RAISE(ABORT, 'interrupted'); END")?
  assert(case storage_prepare(path) do
    Err(_) -> true
    Ok(_) -> false
  end)
  # Nothing of it stays: the older database opens as it was.
  let left = query(path,
    "SELECT group_concat(row, ',') AS rows FROM (SELECT record_hash || ':' || hex(ciphertext) || ':' || updated_at AS row FROM encrypted_blobs ORDER BY record_hash)",
    [])?
  assert(text(List.head(left), "rows")? == text(List.head(before), "rows")?)
  assert(tables(path)? == "encrypted_blobs")
  assert(version(path)? == "0")
  # The next open moves every row.
  execute(path, "DROP TRIGGER mesh_test_interrupt")?
  assert(all_load(path, 0, 300)?)
  assert(version(path)? == "2")
  File.delete(path)?
  Ok(true)
end

fn passes(result :: Bool!String) -> Bool do
  case result do
    Err(error) -> do
      println(error)
      false
    end
    Ok(value) -> value
  end
end

test("row keys are HMAC-SHA-256") do
  assert(passes(hmac_proof()))
end

test("a label's row can't be told without the database's label key, and values keep no readable header") do
  assert(passes(keyed_proof()))
end

test("an older database moves to keyed rows once, keeping every record and nothing of the old rows") do
  assert(passes(migration_proof()))
end

test("an interrupted move leaves the older database as it was, and the next open finishes it") do
  assert(passes(interrupted_proof()))
end
