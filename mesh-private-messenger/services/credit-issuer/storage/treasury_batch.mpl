from Payment.Treasury import TreasuryChainConfig, treasury_config_hash
from Payment.TreasuryBatch import (
  canonical_treasury_ids,
  treasury_batch_id,
  treasury_batch_member_hash,
  treasury_batch_message
)
from Payment.TreasuryBatchTypes import TreasuryPaymentBatch
from Storage.Treasury import load_treasury_movement
from Storage.TreasuryNonce import reserve_treasury_nonce_lane, release_treasury_nonce_lane
from Solana.Nonce import NonceAccountState
from Solana.TransactionRead import signed_transaction, FinalizedTransactionOutcome
from Solana.Tx import serialize_legacy_message
from Payment.TreasuryBatchOutcome import treasury_batch_costs, treasury_sum

fn batch_binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(output) -> Ok(output)
    Null -> Ok(Bytes.empty())
    _ -> Err("invalid_treasury_batch_row")
  end
end

fn batch_text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid_treasury_batch_row")
  end
end

fn batch_number(value :: DbValue) -> U64!String do
  case value do
    Null -> U64.parse("0")
    Text(output) -> U64.parse(output)
    _ -> Err("invalid_treasury_batch_row")
  end
end

pub fn load_treasury_batch(conn :: borrow PgConn, id :: Bytes) -> TreasuryPaymentBatch!String do
  let rows = Pg.query_values(conn,
    "SELECT *,state::text,fee::text,rent::text FROM issuer_treasury_batches WHERE batch_id=$1 FOR SHARE",
    [Binary(id)])?
  if List.length(rows) != 1 do
    return Err("unknown_treasury_batch")
  end
  let row = List.head(rows)
  let member_rows = Pg.query_values(conn,
    "SELECT movement_id FROM issuer_treasury_batch_members WHERE batch_id=$1 ORDER BY ordinal",
    [Binary(id)])?
  let members = for entry in member_rows do
    load_treasury_movement(conn, batch_binary(Map.get(entry, "movement_id"))?)?
  end
  let state = case String.to_int(batch_text(Map.get(row, "state"))?) do
    Some(value) -> value
    None -> return Err("invalid_treasury_batch_row")
  end
  let batch = TreasuryPaymentBatch {
    batch_id: id,
    config_hash: batch_binary(Map.get(row, "config_hash"))?,
    member_hash: batch_binary(Map.get(row, "member_hash"))?,
    members: members,
    state: state,
    nonce_address: batch_binary(Map.get(row, "nonce_address"))?,
    nonce_value: batch_binary(Map.get(row, "nonce_value"))?,
    message: batch_binary(Map.get(row, "message"))?,
    packet: batch_binary(Map.get(row, "packet"))?,
    transaction_signature: batch_binary(Map.get(row, "transaction_signature"))?,
    fee: batch_number(Map.get(row, "fee"))?,
    rent: batch_number(Map.get(row, "rent"))?
  }
  if !Bytes.secure_equals(treasury_batch_member_hash(members)?, batch.member_hash) do
    return Err("treasury_batch_membership_corrupt")
  end
  for member in members do
    if member.state != state
      || !Bytes.secure_equals(member.batch_id, id)
      || !Bytes.secure_equals(member.message, batch.message)
      || !Bytes.secure_equals(member.packet, batch.packet)
      || !Bytes.secure_equals(member.transaction_signature, batch.transaction_signature) do
      return Err("treasury_batch_membership_corrupt")
    end
  end
  Ok(batch)
end

fn lock_batch(conn :: borrow PgConn, id :: Bytes) -> TreasuryPaymentBatch!String do
  let rows = Pg.query_values(conn,
    "SELECT batch_id FROM issuer_treasury_batches WHERE batch_id=$1 FOR UPDATE",
    [Binary(id)])?
  if List.length(rows) != 1 do
    return Err("unknown_treasury_batch")
  end
  load_treasury_batch(conn, id)
end

pub fn reserve_treasury_batch(conn :: borrow PgConn,
  config :: TreasuryChainConfig,
  ids :: List<Bytes>,
  nonce :: NonceAccountState,
  now :: U64) -> TreasuryPaymentBatch!String do
  let ordered = canonical_treasury_ids(ids)?
  let id = treasury_batch_id(config, ordered)?
  # Every group operation locks group before members, including initial creation.
  Pg.query_values(conn,
    "SELECT pg_advisory_xact_lock(hashtextextended(encode($1::bytea,'hex'),1835365492))",
    [Binary(id)])?
  let existing = Pg.query_values(conn,
    "SELECT batch_id FROM issuer_treasury_batches WHERE batch_id=$1",
    [Binary(id)])?
  if List.length(existing) != 0 do
    return lock_batch(conn, id)
  end
  let members = for member_id in ordered do
    Pg.query_values(conn,
      "SELECT movement_id FROM issuer_treasury_movements WHERE movement_id=$1 FOR UPDATE",
      [Binary(member_id)])?
    let member = load_treasury_movement(conn, member_id)?
    if member.state != 0
      || Bytes.length(member.batch_id) != 0
      || Bytes.length(member.message) != 0
      || U64.compare(now, member.ready_at) < 0 do
      return Err("treasury_batch_member_not_ready")
    end
    member
  end
  let batch = TreasuryPaymentBatch {
    batch_id: id,
    config_hash: treasury_config_hash(config)?,
    member_hash: treasury_batch_member_hash(members)?,
    members: members,
    state: 0,
    nonce_address: config.nonce_address,
    nonce_value: nonce.nonce.bytes,
    message: Bytes.empty(),
    packet: Bytes.empty(),
    transaction_signature: Bytes.empty(),
    fee: U64.parse("0")?,
    rent: U64.parse("0")?
  }
  let encoded = serialize_legacy_message(treasury_batch_message(batch, config, nonce)?)?
  reserve_treasury_nonce_lane(conn, config.nonce_address, 1, id)?
  Pg.execute_values(conn,
    "INSERT INTO issuer_treasury_batches(batch_id,config_hash,member_hash,member_count,nonce_address,nonce_value,message) VALUES($1,$2,$3,$4::smallint,$5,$6,$7)",
    [
      Binary(id),
      Binary(batch.config_hash),
      Binary(batch.member_hash),
      Text(Int.to_string(List.length(members))),
      Binary(config.nonce_address),
      Binary(nonce.nonce.bytes),
      Binary(encoded)
    ])?
  for ordinal in 0..List.length(members) do
    let member = List.get(members, ordinal)
    Pg.execute_values(conn,
      "UPDATE issuer_treasury_movements SET batch_id=$2,nonce_address=$3,nonce_value=$4,message=$5 WHERE movement_id=$1",
      [
        Binary(member.movement_id),
        Binary(id),
        Binary(config.nonce_address),
        Binary(nonce.nonce.bytes),
        Binary(encoded)
      ])?
    Pg.execute_values(conn,
      "INSERT INTO issuer_treasury_batch_members(movement_id,batch_id,ordinal) VALUES($1,$2,$3::smallint)",
      [Binary(member.movement_id), Binary(id), Text(Int.to_string(ordinal))])?
  end
  load_treasury_batch(conn, id)
end

pub fn commit_treasury_batch(conn :: borrow PgConn,
  id :: Bytes,
  packet :: Bytes,
  signature :: Bytes) -> TreasuryPaymentBatch!String do
  let signed = signed_transaction(packet, signature)?
  let batch = lock_batch(conn, id)?
  if !Bytes.secure_equals(signed.message, batch.message) do
    return Err("treasury_batch_packet_mismatch")
  end
  if batch.state != 0 do
    if !Bytes.secure_equals(batch.packet, packet)
      || !Bytes.secure_equals(batch.transaction_signature, signature) do
      return Err("treasury_batch_packet_conflict")
    end
    return Ok(batch)
  end
  Pg.execute_values(conn,
    "INSERT INTO issuer_treasury_batch_attempts(transaction_signature,batch_id,nonce_address,nonce_value,message,packet,state) VALUES($1,$2,$3,$4,$5,$6,1)",
    [
      Binary(signature),
      Binary(id),
      Binary(batch.nonce_address),
      Binary(batch.nonce_value),
      Binary(batch.message),
      Binary(packet)
    ])?
  Pg.execute_values(conn,
    "UPDATE issuer_treasury_batches SET state=1,packet=$2,transaction_signature=$3 WHERE batch_id=$1",
    [Binary(id), Binary(packet), Binary(signature)])?
  Pg.execute_values(conn,
    "UPDATE issuer_treasury_movements SET state=1,packet=$2,transaction_signature=$3 WHERE batch_id=$1",
    [Binary(id), Binary(packet), Binary(signature)])?
  load_treasury_batch(conn, id)
end

pub fn block_treasury_batch(conn :: borrow PgConn,
  id :: Bytes,
  signature :: Bytes) -> TreasuryPaymentBatch!String do
  let batch = lock_batch(conn, id)?
  if (batch.state != 1 && batch.state != 4)
    || !Bytes.secure_equals(batch.transaction_signature, signature) do
    return Err("treasury_attempt_mismatch")
  end
  Pg.execute_values(conn,
    "UPDATE issuer_treasury_batches SET state=4 WHERE batch_id=$1",
    [Binary(id)])?
  Pg.execute_values(conn,
    "UPDATE issuer_treasury_movements SET state=4 WHERE batch_id=$1",
    [Binary(id)])?
  load_treasury_batch(conn, id)
end

pub fn finalize_treasury_batch(conn :: borrow PgConn,
  id :: Bytes,
  config :: TreasuryChainConfig,
  outcome :: FinalizedTransactionOutcome) -> TreasuryPaymentBatch!String do
  let batch = lock_batch(conn, id)?
  let costs = treasury_batch_costs(batch, config, outcome)?
  let succeeded = case outcome.execution_error do
    None -> true
    Some(_) -> false
  end
  let state = if succeeded do
    2
  else
    3
  end
  if batch.state == 2 || batch.state == 3 do
    let rows = Pg.query_values(conn,
      "SELECT finalized_slot::text,execution_error FROM issuer_treasury_batches WHERE batch_id=$1",
      [Binary(id)])?
    let row = List.head(rows)
    let same_error = case (Map.get(row, "execution_error"), outcome.execution_error) do
      (Null, None) -> true
      (Text(a), Some(b)) -> a == b
      _ -> false
    end
    if batch.state != state
      || batch.fee != outcome.transaction.fee
      || batch_text(Map.get(row, "finalized_slot"))? != U64.to_string(outcome.transaction.slot)
      || !same_error do
      return Err("treasury_finality_conflict")
    end
    return Ok(batch)
  end
  if batch.state != 1 && batch.state != 4 do
    return Err("treasury_packet_not_committed")
  end
  let error = case outcome.execution_error do
    None -> Null
    Some(value) -> Text(value)
  end
  let rent = treasury_sum(for cost in costs do
    cost.rent
  end)?
  Pg.execute_values(conn,
    "UPDATE issuer_treasury_batch_attempts SET state=$2::smallint,finalized_slot=$3::numeric,execution_error=$4,fee=$5::numeric,rent=$6::numeric WHERE transaction_signature=$1 AND state=1",
    [
      Binary(batch.transaction_signature),
      Text(Int.to_string(state)),
      Text(U64.to_string(outcome.transaction.slot)),
      error,
      Text(U64.to_string(outcome.transaction.fee)),
      Text(U64.to_string(rent))
    ])?
  Pg.execute_values(conn,
    "UPDATE issuer_treasury_batches SET state=$2::smallint,finalized_slot=$3::numeric,execution_error=$4,fee=$5::numeric,rent=$6::numeric WHERE batch_id=$1",
    [
      Binary(id),
      Text(Int.to_string(state)),
      Text(U64.to_string(outcome.transaction.slot)),
      error,
      Text(U64.to_string(outcome.transaction.fee)),
      Text(U64.to_string(rent))
    ])?
  for cost in costs do
    Pg.execute_values(conn,
      "UPDATE issuer_treasury_movements SET state=$2::smallint,finalized_slot=$3::numeric,execution_error=$4,fee=$5::numeric,rent=$6::numeric WHERE movement_id=$1 AND batch_id=$7",
      [
        Binary(cost.movement_id),
        Text(Int.to_string(state)),
        Text(U64.to_string(outcome.transaction.slot)),
        error,
        Text(U64.to_string(cost.fee)),
        Text(U64.to_string(cost.rent)),
        Binary(id)
      ])?
    Pg.execute_values(conn,
      "INSERT INTO issuer_treasury_batch_costs(transaction_signature,movement_id,fee,rent) VALUES($1,$2,$3::numeric,$4::numeric)",
      [
        Binary(batch.transaction_signature),
        Binary(cost.movement_id),
        Text(U64.to_string(cost.fee)),
        Text(U64.to_string(cost.rent))
      ])?
  end
  release_treasury_nonce_lane(conn, config.nonce_address, 1, id)?
  load_treasury_batch(conn, id)
end

pub fn retry_failed_treasury_batch(conn :: borrow PgConn,
  id :: Bytes,
  config :: TreasuryChainConfig,
  nonce :: NonceAccountState) -> TreasuryPaymentBatch!String do
  let batch = lock_batch(conn, id)?
  if batch.state != 3 do
    return Err("treasury_failure_not_proved")
  end
  let old = Pg.query_values(conn,
    "SELECT transaction_signature FROM issuer_treasury_batch_attempts WHERE batch_id=$1 AND nonce_address=$2 AND nonce_value=$3",
    [Binary(id), Binary(config.nonce_address), Binary(nonce.nonce.bytes)])?
  if List.length(old) != 0 do
    return Err("treasury_nonce_already_attempted")
  end
  let encoded = serialize_legacy_message(treasury_batch_message(batch, config, nonce)?)?
  reserve_treasury_nonce_lane(conn, config.nonce_address, 1, id)?
  Pg.execute_values(conn,
    "UPDATE issuer_treasury_batches SET state=0,nonce_address=$2,nonce_value=$3,message=$4,packet=NULL,transaction_signature=NULL,finalized_slot=NULL,execution_error=NULL,fee=NULL,rent=NULL WHERE batch_id=$1",
    [Binary(id), Binary(config.nonce_address), Binary(nonce.nonce.bytes), Binary(encoded)])?
  Pg.execute_values(conn,
    "UPDATE issuer_treasury_movements SET state=0,nonce_address=$2,nonce_value=$3,message=$4,packet=NULL,transaction_signature=NULL,finalized_slot=NULL,execution_error=NULL,fee=NULL,rent=0 WHERE batch_id=$1",
    [Binary(id), Binary(config.nonce_address), Binary(nonce.nonce.bytes), Binary(encoded)])?
  load_treasury_batch(conn, id)
end
