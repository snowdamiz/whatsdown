import File
from MobileCore import initialize, persist_envelope, validate_outer
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.V1 import OuterEnvelope
from Storage.Blobs import load_blob
from Storage.Keys import local_context, platform_key, seal_local
from Storage.Records import store_record_changes
from Storage.ViewOnce import ViewOnceRecord, encode_view_once_record
from Tests.Support import append, database_path, repeated, vector

fn outer(ciphertext :: Bytes, padding_bucket :: Int) -> Bytes!String do
  let expiration = case U64.parse("2000000000") do
    Err(_) -> Err("test timestamp conversion failed")
    Ok(value)
  end?
  case encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: repeated(9, 16)?,
    mailbox_token: repeated(7, 32)?,
    suite: 1,
    expiration: expiration,
    padding_bucket: padding_bucket,
    ciphertext: ciphertext
  }) do
    Err(_) -> Err("test outer encoding failed")
    Ok(encoded)
  end
end

fn store_request(database_path :: String, envelope :: Bytes) -> Bytes!String do
  store_request_with_key(database_path, Bytes.from_utf8("record-key"), envelope)
end

fn store_request_with_key(database_path :: String,
  key :: Bytes,
  envelope :: Bytes) -> Bytes!String do
  let path = vector(Bytes.from_utf8(database_path))?
  let record_key = vector(key)?
  append(append(path, record_key)?, vector(envelope)?)
end

fn stored_ciphertext(path :: String, record_hash :: Bytes) -> Bytes!String do
  let database = Sqlite.open(path)?
  let rows = Sqlite.query_values(database,
    "SELECT ciphertext FROM encrypted_blobs WHERE record_hash = ?",
    [Text(Bytes.to_utf8(record_hash)?)])?
  Sqlite.close(database)
  if List.length(rows) != 1 do
    return Err("test_envelope_record_missing")
  end
  case Map.get(List.head(rows), "ciphertext") do
    Binary(value) -> Ok(value)
    _ -> Err("test_envelope_record_missing")
  end
end

fn envelope_namespace_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("envelope-namespace")?
  initialize(Bytes.from_utf8(path))?
  let wrapping = platform_key()?
  let labels = [
    "view-once/v1/00000000000000000000000000000001/00000000000000000000000000000002",
    "view-once/v2/00000000000000000000000000000001/00000000000000000000000000000002",
    "view-once/id/v2/0000000000000000000000000000000000000000000000000000000000000001",
    "profile"
  ]
  for label in labels do
    let native_blob = seal_local(encode_view_once_record(Consumed(repeated(3, 32)?))?,
      wrapping,
      local_context(label)?)?
    let replacement = seal_local(encode_view_once_record(Consumed(repeated(4, 32)?))?,
      wrapping,
      local_context(label)?)?
    store_record_changes(path, [label], [native_blob], List.new())?
    let record_hash = persist_envelope(store_request_with_key(path,
      Bytes.from_utf8(label),
      outer(replacement, 256)?)?)?
    assert(Bytes.secure_equals(load_blob(path, label)?, native_blob))
    assert(Bytes.secure_equals(stored_ciphertext(path, record_hash)?, replacement))
    let second_hash = persist_envelope(store_request_with_key(path,
      Bytes.from_utf8(label),
      outer(native_blob, 256)?)?)?
    assert(Bytes.secure_equals(record_hash, second_hash))
    assert(Bytes.secure_equals(stored_ciphertext(path, second_hash)?, native_blob))
    assert(Bytes.secure_equals(load_blob(path, label)?, native_blob))
  end
  let binary_key = Bytes.from_hex("00ff")?
  let binary_hash = persist_envelope(store_request_with_key(path,
    binary_key,
    outer(repeated(5, 16)?, 256)?)?)?
  assert(Bytes.secure_equals(stored_ciphertext(path, binary_hash)?, repeated(5, 16)?))
  Secret.destroy(wrapping)
  File.delete(path)?
  Ok(true)
end

test("public envelope keys cannot replace native records and retain independent updates") do
  case envelope_namespace_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("api")?
  assert(Bytes.secure_equals(initialize(Bytes.from_utf8(path))?,
    Bytes.from_utf8("mesh-messenger-mobile-v1")))
  case initialize(Bytes.empty()) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "invalid_database_path")
  end
  let encoded_outer = outer(repeated(165, 16)?, 256)?
  assert(Bytes.secure_equals(validate_outer(encoded_outer)?, encoded_outer))
  let boundary_outer = outer(repeated(165, 65536)?, 65536)?
  assert(Bytes.length(boundary_outer) == 65606)
  assert(Bytes.secure_equals(validate_outer(boundary_outer)?, boundary_outer))
  let trailing = append(encoded_outer, Bytes.from_utf8("x"))?
  case validate_outer(trailing) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "invalid_outer_envelope")
  end
  let record_hash = persist_envelope(store_request(path, encoded_outer)?)?
  assert(Bytes.length(record_hash) == 64)
  let database = Sqlite.open(path)?
  let rows = Sqlite.query_values(database,
    "SELECT ciphertext, typeof(ciphertext) AS storage_type FROM encrypted_blobs WHERE record_hash = ?",
    [
      Text(case Bytes.to_utf8(record_hash) do
        Err(_) -> ""
        Ok(value) -> value
      end)
    ])?
  assert(List.length(rows) == 1)
  let row = List.head(rows)
  case Map.get(row, "ciphertext") do
    Binary(value) -> assert(Bytes.secure_equals(value, repeated(165, 16)?))
    Text(_) -> assert(false)
    Null -> assert(false)
  end
  case Map.get(row, "storage_type") do
    Text(value) -> assert(value == "blob")
    Binary(_) -> assert(false)
    Null -> assert(false)
  end
  Sqlite.close(database)
  File.delete(path)?
  Ok(true)
end

test("mobile public boundary validates and persists canonical envelopes") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
