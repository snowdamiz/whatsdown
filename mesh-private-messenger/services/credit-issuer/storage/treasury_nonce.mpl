# Single payments and multi-payment packets share one nonce reservation fence.
pub fn reserve_treasury_nonce_lane(conn :: borrow PgConn,
  address :: Bytes,
  kind :: Int,
  id :: Bytes) -> Result<(), String> do
  if Bytes.length(address) != 32 || Bytes.length(id) != 32 || (kind != 0 && kind != 1) do
    return Err("invalid_treasury_nonce_lane")
  end
  Pg.execute_values(conn,
    "INSERT INTO issuer_treasury_nonce_lanes(nonce_address,owner_kind,owner_id) VALUES($1,$2::smallint,$3) ON CONFLICT(nonce_address) DO NOTHING",
    [Binary(address), Text(Int.to_string(kind)), Binary(id)])?
  let rows = Pg.query_values(conn,
    "SELECT owner_kind::text,owner_id FROM issuer_treasury_nonce_lanes WHERE nonce_address=$1 FOR UPDATE",
    [Binary(address)])?
  if List.length(rows) != 1 do
    return Err("invalid_treasury_nonce_lane")
  end
  let row = List.head(rows)
  let owner_kind = case Map.get(row, "owner_kind") do
    Text(value) -> value
    _ -> return Err("invalid_treasury_nonce_lane")
  end
  let owner = case Map.get(row, "owner_id") do
    Binary(value) -> value
    _ -> return Err("invalid_treasury_nonce_lane")
  end
  if owner_kind != Int.to_string(kind) || !Bytes.secure_equals(owner, id) do
    return Err("treasury_nonce_lane_busy")
  end
  Ok(nil)
end

pub fn release_treasury_nonce_lane(conn :: borrow PgConn,
  address :: Bytes,
  kind :: Int,
  id :: Bytes) -> Result<(), String> do
  Pg.execute_values(conn,
    "DELETE FROM issuer_treasury_nonce_lanes WHERE nonce_address=$1 AND owner_kind=$2::smallint AND owner_id=$3",
    [Binary(address), Text(Int.to_string(kind)), Binary(id)])?
  Ok(nil)
end
