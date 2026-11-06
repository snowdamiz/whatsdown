##! Content-addressed canonical device records. All mutations run inside the
##! caller's transaction, under the transparency append/maintenance lock.
from Credits.Issuer import decode_issuer_key, encode_issuer_key
from Protocol.DirectoryWire import decode_device_set, encode_device_set, encode_directory_entry
from Protocol.V1 import DeviceSet, DirectoryEntry
from Protocol.WirePrimitives import protocol_vector
from Transparency.Merkle import leaf_hash_for

fn allocated(value :: Result<Bytes, String>) -> Bytes!String do
  case value do
    Err(_) -> Err("transparency allocation failed")
    Ok(bytes)
  end
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(bytes) -> Ok(bytes)
    _ -> Err("invalid transparency record")
  end
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(value) -> Ok(value)
    _ -> Err("invalid transparency record")
  end
end

fn log_version(row :: Map<String, DbValue>) -> Int!String do
  case String.to_int(text(Map.get(row, "log_version"))?) do
    Some(value) -> Ok(value)
    None -> Err("invalid transparency log version")
  end
end

fn canonical(version :: Int, input :: Bytes, expected_hash :: Bytes) -> Result<(), String> do
  if !Bytes.secure_equals(leaf_hash_for(version, input)?, expected_hash) do
    return Err("transparency_entry_hash_mismatch")
  end
  if Bytes.length(input) == 387 && Bytes.to_hex(Bytes.slice(input, 0, 4)?) == "02494b59" do
    let issuer = decode_issuer_key(input)?
    if version != 2 || !Bytes.secure_equals(encode_issuer_key(issuer)?, input) do
      return Err("noncanonical credit issuer entry")
    end
    return Ok(nil)
  end
  let encoded = case decode_device_set(input) do
    Err(_) -> Err("invalid transparency entry")
    Ok(value) -> case encode_device_set(value) do
      Err(_) -> Err("invalid transparency entry")
      Ok(encoded)
    end
  end?
  if Bytes.secure_equals(encoded, input) do
    Ok(nil)
  else
    Err("noncanonical transparency entry")
  end
end

fn join_parts(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    join_parts(parts, index + 1, allocated(Bytes.concat(output, List.get(parts, index)))?)
  end
end

fn reconstruct(conn :: borrow PgConn,
  sequence :: Int,
  header :: Bytes,
  suffix :: Bytes) -> Bytes!String do
  let rows = Pg.query_values(conn,
    "SELECT d.position::text, r.record_hash, r.record_bytes FROM transparency_entry_devices d JOIN transparency_device_records r USING (record_hash) WHERE d.entry_sequence = $1::bigint ORDER BY d.position",
    [Text(Int.to_string(sequence))])?
  if List.length(rows) < 1 || List.length(rows) > 8 do
    return Err("missing transparency records")
  end
  let vectors = for index in 0..List.length(rows) do
    let row = List.get(rows, index)
    let bytes = binary(Map.get(row, "record_bytes"))?
    if text(Map.get(row, "position"))? != Int.to_string(index)
      || !Bytes.secure_equals(Crypto.sha256(bytes), binary(Map.get(row, "record_hash"))?) do
      return Err("invalid transparency record")
    end
    let vector = case protocol_vector(bytes) do
      Err(_) -> Err("invalid transparency record")
      Ok(value)
    end?
    vector
  end
  join_parts(vectors ++ [suffix], 0, header)
end

pub fn entry_bytes_on_connection(conn :: borrow PgConn, sequence :: Int) -> Bytes!String do
  let rows = Pg.query_values(conn,
    "SELECT log_version::text, entry_bytes, entry_header, entry_suffix, leaf_hash FROM transparency_entries WHERE sequence = $1::bigint",
    [Text(Int.to_string(sequence))])?
  if List.length(rows) != 1 do
    return Err("transparency entry not found")
  end
  let row = List.head(rows)
  let bytes = case Map.get(row, "entry_bytes") do
    Binary(value) -> Ok(value)
    _ -> case Map.get(row, "entry_header") do
      Binary(header) -> reconstruct(conn, sequence, header, binary(Map.get(row, "entry_suffix"))?)
      _ -> Err("transparency_entry_pruned")
    end
  end?
  canonical(log_version(row)?, bytes, binary(Map.get(row, "leaf_hash"))?)?
  Ok(bytes)
end

pub fn store_entry_records(conn :: borrow PgConn,
  sequence :: Int,
  bytes :: Bytes,
  expected_hash :: Bytes) -> Result<(), String> do
  let rows = Pg.query_values(conn,
    "SELECT log_version::text FROM transparency_entries WHERE sequence = $1::bigint",
    [Text(Int.to_string(sequence))])?
  if List.length(rows) != 1 do
    return Err("transparency entry not found")
  end
  let version = log_version(List.head(rows))?
  canonical(version, bytes, expected_hash)?
  # Issuer leaves are small immutable public records, never device snapshots.
  if Bytes.length(bytes) == 387 && Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) == "02494b59" do
    return Ok(nil)
  end
  let devices = case decode_device_set(bytes) do
    Err(_) -> Err("invalid transparency entry")
    Ok(value)
  end?
  let header_length = 21
    + Bytes.length(Bytes.from_utf8(devices.username))
    + Bytes.length(devices.account_identity)
  let header = allocated(Bytes.slice(bytes, 0, header_length))?
  let lengths = for index in 0..List.length(devices.devices) do
    let record = case encode_directory_entry(List.get(devices.devices, index)) do
      Err(_) -> Err("invalid transparency record")
      Ok(value)
    end?
    let hash = Crypto.sha256(record)
    Pg.execute_values(conn,
      "INSERT INTO transparency_device_records (record_hash, record_bytes) VALUES ($1, $2) ON CONFLICT DO NOTHING",
      [Binary(hash), Binary(record)])?
    Pg.execute_values(conn,
      "INSERT INTO transparency_entry_devices (entry_sequence, position, record_hash) VALUES ($1::bigint, $2::smallint, $3)",
      [Text(Int.to_string(sequence)), Text(Int.to_string(index)), Binary(hash)])?
    4 + Bytes.length(record)
  end
  let suffix_offset = header_length
    + List.reduce(lengths, 0, fn(total, length) -> total + length end)
  let suffix = allocated(Bytes.slice(bytes, suffix_offset, Bytes.length(bytes) - suffix_offset))?
  let rebuilt = reconstruct(conn, sequence, header, suffix)?
  canonical(version, rebuilt, expected_hash)?
  if !Bytes.secure_equals(bytes, rebuilt) do
    return Err("transparency reconstruction mismatch")
  end
  Pg.execute_values(conn,
    "UPDATE transparency_entries SET entry_bytes = NULL, entry_header = $2, entry_suffix = $3 WHERE sequence = $1::bigint",
    [Text(Int.to_string(sequence)), Binary(header), Binary(suffix)])?
  Ok(nil)
end

pub fn backfill_records_on_connection(conn :: borrow PgConn, limit :: Int) -> Int!String do
  if limit < 1 || limit > 1000 do
    return Err("invalid transparency backfill limit")
  end
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365485)", [])?
  let rows = Pg.query_values(conn,
    "SELECT sequence::text, entry_bytes, leaf_hash FROM transparency_entries WHERE entry_bytes IS NOT NULL AND NOT (octet_length(entry_bytes) = 387 AND substring(entry_bytes FROM 1 FOR 4) = decode('02494b59', 'hex')) ORDER BY sequence LIMIT $1::integer FOR UPDATE",
    [Text(Int.to_string(limit))])?
  for row in rows do
    let sequence = case String.to_int(text(Map.get(row, "sequence"))?) do
      None -> Err("invalid transparency sequence")
      Some(value) -> Ok(value)
    end?
    store_entry_records(conn,
      sequence,
      binary(Map.get(row, "entry_bytes"))?,
      binary(Map.get(row, "leaf_hash"))?)?
  end
  Ok(List.length(rows))
end

pub fn delete_orphan_records(conn :: borrow PgConn, limit :: Int) -> Int!String do
  Pg.execute(conn,
    "DELETE FROM transparency_device_records WHERE record_hash IN (SELECT r.record_hash FROM transparency_device_records r WHERE NOT EXISTS (SELECT 1 FROM transparency_entry_devices d WHERE d.record_hash = r.record_hash) LIMIT $1::integer)",
    [Int.to_string(limit)])
end

pub fn forget_records_on_connection(conn :: borrow PgConn,
  commitment :: Bytes) -> Result<(), String> do
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365485)", [])?
  let records = Pg.query_values(conn,
    "DELETE FROM transparency_entry_devices d USING transparency_entries e WHERE e.sequence = d.entry_sequence AND e.account_commitment = $1 RETURNING d.record_hash",
    [Binary(commitment)])?
  Pg.execute_values(conn,
    "UPDATE transparency_entries SET entry_bytes = NULL, entry_header = NULL, entry_suffix = NULL, pruned_at = now() WHERE account_commitment = $1",
    [Binary(commitment)])?
  for row in records do
    Pg.execute_values(conn,
      "DELETE FROM transparency_device_records r WHERE record_hash = $1 AND NOT EXISTS (SELECT 1 FROM transparency_entry_devices d WHERE d.record_hash = r.record_hash)",
      [Binary(binary(Map.get(row, "record_hash"))?)])?
  end
  Ok(nil)
end
