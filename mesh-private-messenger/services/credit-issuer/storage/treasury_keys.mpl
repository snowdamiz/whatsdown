pub struct TreasuryKeyRecord do
  role :: Int
  public_key :: Bytes
  sealed_key :: Bytes
end

pub fn validate_treasury_key_scope(service_key :: Bytes, purpose :: Int) -> Result<(), String> do
  if Bytes.length(service_key) != 32
    || Bytes.to_hex(service_key) == String.repeat("00", 32)
    || (purpose != 0 && purpose != 1) do
    return Err("invalid_treasury_key_scope")
  end
  Ok(nil)
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(bytes) -> Ok(bytes)
    _ -> Err("invalid_treasury_key_record")
  end
end

pub fn load_treasury_key_records(conn :: borrow PgConn,
  service_key :: Bytes,
  purpose :: Int) -> List<TreasuryKeyRecord>!String do
  validate_treasury_key_scope(service_key, purpose)?
  let rows = Pg.query_values(conn,
    "SELECT role::text, public_key, sealed_key FROM issuer_treasury_keys WHERE service_key=$1 AND purpose=$2::smallint ORDER BY role",
    [Binary(service_key), Text(Int.to_string(purpose))])?
  let records = for row in rows do
    let role = case Map.get(row, "role") do
      Text("0") -> 0
      Text("1") -> 1
      _ -> return Err("invalid_treasury_key_record")
    end
    TreasuryKeyRecord {
      role: role,
      public_key: binary(Map.get(row, "public_key"))?,
      sealed_key: binary(Map.get(row, "sealed_key"))?
    }
  end
  if List.length(records) != 0
    && (List.length(records) != 2
      || List.get(records, 0).role != 0
      || List.get(records, 1).role != 1) do
    return Err("incomplete_treasury_key_pair")
  end
  Ok(records)
end

pub fn insert_treasury_key(conn :: borrow PgConn,
  service_key :: Bytes,
  purpose :: Int,
  record :: TreasuryKeyRecord) -> Result<(), String> do
  validate_treasury_key_scope(service_key, purpose)?
  if (record.role != 0 && record.role != 1)
    || Bytes.length(record.public_key) != 32
    || Bytes.length(record.sealed_key) < 68
    || Bytes.length(record.sealed_key) > 1024 do
    return Err("invalid_treasury_key_record")
  end
  Pg.execute_values(conn,
    "INSERT INTO issuer_treasury_keys(service_key,purpose,role,public_key,sealed_key) VALUES($1,$2::smallint,$3::smallint,$4,$5)",
    [
      Binary(service_key),
      Text(Int.to_string(purpose)),
      Text(Int.to_string(record.role)),
      Binary(record.public_key),
      Binary(record.sealed_key)
    ])?
  Ok(nil)
end
