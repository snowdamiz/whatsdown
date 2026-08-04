import File
from MobileCore import initialize, persist_envelope, validate_outer
from Protocol.V1 import OuterEnvelope, encode_outer_envelope
from Tests.Support import append, database_path, repeated, vector

fn outer(ciphertext :: Bytes, padding_bucket :: Int) -> Bytes ! String do
  let expiration = case U64.parse("2000000000") do
    Err( _) -> Err("test timestamp conversion failed")
    Ok( value) -> Ok(value)
  end ?
  case encode_outer_envelope(OuterEnvelope {
    version : 1,
    envelope_id : repeated(9, 16) ?,
    mailbox_token : repeated(7, 32) ?,
    suite : 1,
    expiration : expiration,
    padding_bucket : padding_bucket,
    ciphertext : ciphertext
  }) do
    Err( _) -> Err("test outer encoding failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn store_request(database_path :: String, envelope :: Bytes) -> Bytes ! String do
  let path = vector(Bytes.from_utf8(database_path)) ?
  let record_key = vector(Bytes.from_utf8("record-key")) ?
  append(append(path, record_key) ?, vector(envelope) ?)
end

fn proof() -> Bool ! String do
  let path = database_path("api") ?
  assert(Bytes.secure_equals(initialize(Bytes.from_utf8(path)) ?,
  Bytes.from_utf8("mesh-messenger-mobile-v1")))
  case initialize(Bytes.empty()) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "invalid_database_path")
  end
  let encoded_outer = outer(repeated(165, 16) ?, 256) ?
  assert(Bytes.secure_equals(validate_outer(encoded_outer) ?, encoded_outer))
  let boundary_outer = outer(repeated(165, 65536) ?, 65536) ?
  assert(Bytes.length(boundary_outer) == 65606)
  assert(Bytes.secure_equals(validate_outer(boundary_outer) ?, boundary_outer))
  let trailing = append(encoded_outer, Bytes.from_utf8("x")) ?
  case validate_outer(trailing) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "invalid_outer_envelope")
  end
  let record_hash = persist_envelope(store_request(path, encoded_outer) ?) ?
  assert(Bytes.length(record_hash) == 64)
  let database = Sqlite.open(path) ?
  let rows = Sqlite.query_values(database,
  "SELECT ciphertext, typeof(ciphertext) AS storage_type FROM encrypted_blobs WHERE record_hash = ?",
  [Text(case Bytes.to_utf8(record_hash) do
    Err( _) -> ""
    Ok( value) -> value
  end)]) ?
  assert(List.length(rows) == 1)
  let row = List.head(rows)
  case Map.get(row, "ciphertext") do
    Binary( value) -> assert(Bytes.secure_equals(value, repeated(165, 16) ?))
    Text( _) -> assert(false)
    Null -> assert(false)
  end
  case Map.get(row, "storage_type") do
    Text( value) -> assert(value == "blob")
    Binary( _) -> assert(false)
    Null -> assert(false)
  end
  Sqlite.close(database)
  File.delete(path) ?
  Ok(true)
end

test("mobile public boundary validates and persists canonical envelopes") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
