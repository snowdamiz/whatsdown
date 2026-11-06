# This transaction lock covers absent rows too. Reconciliation must wait for
# a pre-expiry effect to commit before asserting that no action was consumed.
# Domain hashing separates this namespace from the application's other locks.
pub fn lock_credit_operation(conn :: borrow PgConn, id :: Bytes) -> Result<(), String> do
  if Bytes.length(id) != 32 do
    return Err("invalid_credit_operation")
  end
  let key = Crypto.sha256(Bytes.concat(Bytes.from_utf8("morse-credit-operation-lock-v1"), id)?)
  Pg.query_values(conn,
    "SELECT pg_advisory_xact_lock(('x' || substr(encode($1::bytea, 'hex'), 1, 16))::bit(64)::bigint)",
    [Binary(key)])?
  Ok(nil)
end

pub fn ensure_credit_operation_active(conn :: borrow PgConn, id :: Bytes) -> Result<(), String> do
  let rows = Pg.query_values(conn,
    "SELECT hold_id FROM credit_cancellations WHERE hold_id = $1",
    [Binary(id)])?
  if List.length(rows) != 0 do
    Err("credit_operation_conflict")
  else
    Ok(nil)
  end
end
