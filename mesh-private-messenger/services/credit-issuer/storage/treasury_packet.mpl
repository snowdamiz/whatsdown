from Storage.TreasuryNonce import reserve_treasury_nonce_lane, release_treasury_nonce_lane
from Payment.TreasuryOutcome import validate_treasury_outcome
from Solana.TransactionRead import FinalizedTransactionOutcome
from Payment.Treasury import TreasuryChainConfig, treasury_message
from Storage.Treasury import TreasuryMovement, load_treasury_movement
from Solana.Nonce import NonceAccountState
from Solana.Tx import serialize_legacy_message
from Solana.TransactionRead import signed_transaction

fn packet_text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid_treasury_row")
  end
end

fn packet_binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(output) -> Ok(output)
    _ -> Err("invalid_treasury_row")
  end
end

fn lock_movement(conn :: borrow PgConn, id :: Bytes) -> TreasuryMovement!String do
  let rows = Pg.query_values(conn,
    "SELECT movement_id FROM issuer_treasury_movements WHERE movement_id=$1 FOR UPDATE",
    [Binary(id)])?
  if List.length(rows) != 1 do
    return Err("unknown_treasury_movement")
  end
  let movement = load_treasury_movement(conn, id)?
  if Bytes.length(movement.batch_id) != 0 do
    return Err("treasury_movement_batched")
  end
  Ok(movement)
end

# A separately authenticated nonce snapshot is supplied by the privileged worker.
# The complete intended message is durable before it is handed to opaque signers.
pub fn reserve_treasury_message(conn :: borrow PgConn,
  id :: Bytes,
  config :: TreasuryChainConfig,
  nonce :: NonceAccountState,
  now :: U64) -> TreasuryMovement!String do
  let movement = lock_movement(conn, id)?
  let expected = serialize_legacy_message(treasury_message(movement, config, nonce)?)?
  if Bytes.length(movement.message) != 0 do
    if !Bytes.secure_equals(expected, movement.message) do
      return Err("treasury_message_conflict")
    end
    return Ok(movement)
  end
  if movement.state != 0 || U64.compare(now, movement.ready_at) < 0 do
    return Err("treasury_movement_not_ready")
  end
  let old = Pg.query_values(conn,
    "SELECT transaction_signature FROM issuer_treasury_attempts WHERE movement_id=$1 AND nonce_address=$2 AND nonce_value=$3",
    [Binary(id), Binary(config.nonce_address), Binary(nonce.nonce.bytes)])?
  if List.length(old) != 0 do
    return Err("treasury_nonce_already_attempted")
  end
  reserve_treasury_nonce_lane(conn, config.nonce_address, 0, id)?
  Pg.execute_values(conn,
    "UPDATE issuer_treasury_movements SET nonce_address=$2,nonce_value=$3,message=$4 WHERE movement_id=$1 AND state=0",
    [Binary(id), Binary(config.nonce_address), Binary(nonce.nonce.bytes), Binary(expected)])?
  load_treasury_movement(conn, id)
end

# All signatures, signer roles and message bytes are reauthenticated here.
# This commit must complete before any network operation uses the packet.
pub fn commit_treasury_packet(conn :: borrow PgConn,
  id :: Bytes,
  packet :: Bytes,
  signature :: Bytes) -> TreasuryMovement!String do
  let signed = signed_transaction(packet, signature)?
  let movement = lock_movement(conn, id)?
  if !Bytes.secure_equals(signed.message, movement.message) do
    return Err("treasury_packet_mismatch")
  end
  if movement.state != 0 do
    if !Bytes.secure_equals(movement.packet, packet)
      || !Bytes.secure_equals(movement.transaction_signature, signature) do
      return Err("treasury_packet_conflict")
    end
    return Ok(movement)
  end
  let nonce_rows = Pg.query_values(conn,
    "SELECT nonce_address,nonce_value FROM issuer_treasury_movements WHERE movement_id=$1",
    [Binary(id)])?
  let row = List.head(nonce_rows)
  Pg.execute_values(conn,
    "INSERT INTO issuer_treasury_attempts (transaction_signature,movement_id,nonce_address,nonce_value,message,packet,state) VALUES($1,$2,$3,$4,$5,$6,1)",
    [
      Binary(signature),
      Binary(id),
      Binary(packet_binary(Map.get(row, "nonce_address"))?),
      Binary(packet_binary(Map.get(row, "nonce_value"))?),
      Binary(signed.message),
      Binary(packet)
    ])?
  Pg.execute_values(conn,
    "UPDATE issuer_treasury_movements SET packet=$2,transaction_signature=$3,state=1 WHERE movement_id=$1 AND state=0",
    [Binary(id), Binary(packet), Binary(signature)])?
  load_treasury_movement(conn, id)
end

# Absence of history plus a changed nonce is unresolved, never a failed transfer.
# Keep its allocation and active nonce lane reserved indefinitely for recovery.
pub fn block_treasury_history(conn :: borrow PgConn,
  id :: Bytes,
  signature :: Bytes) -> Result<(), String> do
  let movement = lock_movement(conn, id)?
  if !Bytes.secure_equals(movement.transaction_signature, signature)
    || (movement.state != 1 && movement.state != 4) do
    return Err("treasury_attempt_mismatch")
  end
  Pg.execute_values(conn,
    "UPDATE issuer_treasury_movements SET state=4 WHERE movement_id=$1 AND state=1",
    [Binary(id)])?
  Ok(nil)
end

# Explicit retry is legal only after authenticated finalized execution failure.
# All old signed bytes and fees remain in issuer_treasury_attempts. The allocation
# is retained and a new authenticated nonce is required before signing again.
pub fn retry_failed_treasury_movement(conn :: borrow PgConn,
  id :: Bytes) -> TreasuryMovement!String do
  let movement = lock_movement(conn, id)?
  if movement.state != 3 do
    return Err("treasury_failure_not_proved")
  end
  Pg.execute_values(conn,
    "UPDATE issuer_treasury_movements SET state=0,nonce_address=NULL,nonce_value=NULL,message=NULL,packet=NULL,transaction_signature=NULL,finalized_slot=NULL,execution_error=NULL,fee=NULL WHERE movement_id=$1 AND state=3",
    [Binary(id)])?
  load_treasury_movement(conn, id)
end

pub fn finalize_treasury_packet(conn :: borrow PgConn,
  id :: Bytes,
  config :: TreasuryChainConfig,
  outcome :: FinalizedTransactionOutcome) -> TreasuryMovement!String do
  let movement = lock_movement(conn, id)?
  let succeeded = validate_treasury_outcome(movement, config, outcome)?
  let state = if succeeded do
    2
  else
    3
  end
  if movement.state == 2 || movement.state == 3 do
    if movement.state != state do
      return Err("treasury_finality_conflict")
    end
    let rows = Pg.query_values(conn,
      "SELECT finalized_slot::text,fee::text,execution_error FROM issuer_treasury_movements WHERE movement_id=$1",
      [Binary(id)])?
    let row = List.head(rows)
    let same_error = case (Map.get(row, "execution_error"), outcome.execution_error) do
      (Null, None) -> true
      (Text(left), Some(right)) -> left == right
      _ -> false
    end
    if packet_text(Map.get(row, "finalized_slot"))? != U64.to_string(outcome.transaction.slot)
      || packet_text(Map.get(row, "fee"))? != U64.to_string(outcome.transaction.fee)
      || !same_error do
      return Err("treasury_finality_conflict")
    end
    return Ok(movement)
  end
  if movement.state != 1 && movement.state != 4 do
    return Err("treasury_packet_not_committed")
  end
  let error = case outcome.execution_error do
    None -> Null
    Some(value) -> Text(value)
  end
  Pg.execute_values(conn,
    "UPDATE issuer_treasury_attempts SET state=$2::smallint,finalized_slot=$3::numeric,fee=$4::numeric,execution_error=$5 WHERE transaction_signature=$1 AND state=1",
    [
      Binary(movement.transaction_signature),
      Text(Int.to_string(state)),
      Text(U64.to_string(outcome.transaction.slot)),
      Text(U64.to_string(outcome.transaction.fee)),
      error
    ])?
  Pg.execute_values(conn,
    "UPDATE issuer_treasury_movements SET state=$2::smallint,finalized_slot=$3::numeric,fee=$4::numeric,execution_error=$5 WHERE movement_id=$1 AND state IN (1,4)",
    [
      Binary(id),
      Text(Int.to_string(state)),
      Text(U64.to_string(outcome.transaction.slot)),
      Text(U64.to_string(outcome.transaction.fee)),
      error
    ])?
  release_treasury_nonce_lane(conn, config.nonce_address, 0, id)?
  load_treasury_movement(conn, id)
end
