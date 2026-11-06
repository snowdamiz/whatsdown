from Payment.SolConversion import sol_conversion_identity, sol_conversion_floor
from Payment.SolConversionPacket import (
  SolConversionProfile,
  SolConversionPacket,
  sol_conversion_profile_hash,
  sol_conversion_message,
  sol_conversion_packet,
  conversion_destination
)
from Payment.SolConversionBank import SolConversionBank
from Payment.SolConversionOutcome import sol_conversion_outcome
from Solana.Read import Hash
from Solana.Tx import serialize_legacy_message
from Solana.TransactionRead import FinalizedTransactionOutcome

pub struct StoredSolConversion do
  plan :: SolConversionPacket
  ordinal :: Int
  state :: Int
  bank_hash :: Bytes
  prepared_slot :: U64
  prepared_at :: U64
  price :: U64
  price_at :: U64
  last_height :: U64
  packet :: Bytes
  receipt :: Bytes
end

fn text(v :: DbValue) -> String!String do
  case v do
    Text(value) -> Ok(value)
    _ -> Err("invalid_sol_conversion_row")
  end
end

fn bytes(v :: DbValue) -> Bytes!String do
  case v do
    Binary(value) -> Ok(value)
    _ -> Err("invalid_sol_conversion_row")
  end
end

fn optional(v :: DbValue) -> Bytes!String do
  case v do
    Null -> Ok(Bytes.empty())
    Binary(value) -> Ok(value)
    _ -> Err("invalid_sol_conversion_row")
  end
end

fn number(row :: Map<String, DbValue>, name :: String) -> U64!String do
  U64.parse(text(Map.get(row, name))?)
end

fn small(row :: Map<String, DbValue>, name :: String) -> Int!String do
  case String.to_int(text(Map.get(row, name))?) do
    Some(v) -> Ok(v)
    None -> Err("invalid_sol_conversion_row")
  end
end

fn identity(conn :: borrow PgConn,
  profile :: SolConversionProfile,
  batch :: U64,
  bucket :: Int) -> Bytes!String do
  let rows = Pg.query_values(conn,
    "SELECT asset::text,mint,config_hash,witness::text,burn::text,policy_version::text,policy_hash,membership_hash FROM issuer_treasury_weekly WHERE batch_id=$1::bigint FOR UPDATE",
    [Text(U64.to_string(batch))])?
  if List.length(rows) != 1 || (bucket != 0 && bucket != 1) do
    return Err("unknown_sol_conversion_bucket")
  end
  let row = List.head(rows)
  if text(Map.get(row, "asset"))? != "1"
    || Bytes.to_hex(bytes(Map.get(row, "mint"))?) != String.repeat("00", 32)
    || bytes(Map.get(row, "config_hash"))? != profile.treasury_config do
    return Err("sol_conversion_source_conflict")
  end
  sol_conversion_identity(sol_conversion_profile_hash(profile)?,
    batch,
    small(row, "policy_version")?,
    bytes(Map.get(row, "policy_hash"))?,
    bytes(Map.get(row, "membership_hash"))?,
    bucket,
    number(row,
      if bucket == 0 do
        "witness"
      else
        "burn"
      end)?)
end

# Transaction-only. Never changes the source allocation, its asset, or its carry.
pub fn reserve_sol_conversion(conn :: borrow PgConn,
  profile :: SolConversionProfile,
  batch :: U64,
  bucket :: Int) -> Bytes!String do
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365496)", [])?
  # Share the existing burn reservation lock before acquiring its source rows.
  # An already-created conversion remains recoverable after funding; only a new
  # burn conversion needs an extant, unconsumed original lamport liability.
  if bucket == 1 do
    Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365495)", [])?
  end
  let id = identity(conn, profile, batch, bucket)?
  let existing = Pg.query_values(conn,
    "SELECT intent_id FROM issuer_sol_conversions WHERE batch_id=$1::bigint AND bucket=$2::smallint",
    [Text(U64.to_string(batch)), Text(Int.to_string(bucket))])?
  if List.length(existing) == 0 && bucket == 1 do
    let liability = Pg.query_values(conn,
      "SELECT l.batch_id FROM issuer_treasury_burn_liabilities l JOIN issuer_treasury_weekly b USING(batch_id) WHERE l.batch_id=$1::bigint AND l.state=0 AND l.amount=b.burn FOR UPDATE OF l",
      [Text(U64.to_string(batch))])?
    if List.length(liability) != 1 do
      return Err("sol_conversion_burn_liability_unavailable")
    end
  end
  let amount = List.head(Pg.query_values(conn,
    "SELECT witness::text,burn::text FROM issuer_treasury_weekly WHERE batch_id=$1::bigint",
    [Text(U64.to_string(batch))])?)
  Pg.execute_values(conn,
    "INSERT INTO issuer_sol_conversions(intent_id,batch_id,bucket,profile_hash,lamports) VALUES($1,$2::bigint,$3::smallint,$4,$5::numeric) ON CONFLICT(batch_id,bucket) DO NOTHING",
    [
      Binary(id),
      Text(U64.to_string(batch)),
      Text(Int.to_string(bucket)),
      Binary(sol_conversion_profile_hash(profile)?),
      Text(U64.to_string(number(amount,
        if bucket == 0 do
          "witness"
        else
          "burn"
        end)?))
    ])?
  let found = Pg.query_values(conn,
    "SELECT intent_id FROM issuer_sol_conversions WHERE batch_id=$1::bigint AND bucket=$2::smallint",
    [Text(U64.to_string(batch)), Text(Int.to_string(bucket))])?
  if List.length(found) != 1 || bytes(Map.get(List.head(found), "intent_id"))? != id do
    return Err("sol_conversion_profile_conflict")
  end
  Ok(id)
end

fn locked(conn :: borrow PgConn,
  profile :: SolConversionProfile,
  id :: Bytes) -> Map<String, DbValue>!String do
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365496)", [])?
  let rows = Pg.query_values(conn,
    "SELECT intent_id,batch_id::text,bucket::text,profile_hash,lamports::text FROM issuer_sol_conversions WHERE intent_id=$1 FOR UPDATE",
    [Binary(id)])?
  if List.length(rows) != 1 do
    return Err("unknown_sol_conversion")
  end
  let row = List.head(rows)
  if bytes(Map.get(row, "profile_hash"))? != sol_conversion_profile_hash(profile)?
    || identity(conn, profile, number(row, "batch_id")?, small(row, "bucket")?)? != id do
    return Err("sol_conversion_profile_conflict")
  end
  Ok(row)
end

pub fn load_sol_conversion(conn :: borrow PgConn,
  profile :: SolConversionProfile,
  id :: Bytes) -> StoredSolConversion!String do
  let source = locked(conn, profile, id)?
  let rows = Pg.query_values(conn,
    "SELECT ordinal::text,state::text,bank_hash,prepared_slot::text,prepared_at::text,price::text,price_at::text,minimum::text,blockhash,last_height::text,message,packet,receipt FROM issuer_sol_conversion_attempts WHERE intent_id=$1 ORDER BY ordinal DESC LIMIT 1",
    [Binary(id)])?
  if List.length(rows) != 1 do
    return Err("sol_conversion_not_prepared")
  end
  let row = List.head(rows)
  let plan = SolConversionPacket {
    intent_id: id,
    profile_hash: sol_conversion_profile_hash(profile)?,
    lamports: number(source, "lamports")?,
    minimum: number(row, "minimum")?,
    blockhash: Hash { bytes: bytes(Map.get(row, "blockhash"))? },
    message: bytes(Map.get(row, "message"))?
  }
  if plan.message != serialize_legacy_message(sol_conversion_message(profile,
      id,
      plan.lamports,
      plan.minimum,
      plan.blockhash)?)? do
    return Err("sol_conversion_message_conflict")
  end
  let stored = StoredSolConversion {
    plan: plan,
    ordinal: small(row, "ordinal")?,
    state: small(row, "state")?,
    bank_hash: bytes(Map.get(row, "bank_hash"))?,
    prepared_slot: number(row, "prepared_slot")?,
    prepared_at: number(row, "prepared_at")?,
    price: number(row, "price")?,
    price_at: number(row, "price_at")?,
    last_height: number(row, "last_height")?,
    packet: optional(Map.get(row, "packet"))?,
    receipt: optional(Map.get(row, "receipt"))?
  }
  if stored.state != 0 && stored.state != 4 do
    sol_conversion_packet(profile, plan, stored.packet)?
  end
  Ok(stored)
end

pub fn prepare_sol_conversion(conn :: borrow PgConn,
  profile :: SolConversionProfile,
  id :: Bytes,
  bank :: SolConversionBank,
  blockhash :: Bytes,
  last_height :: U64) -> StoredSolConversion!String do
  let source = locked(conn, profile, id)?
  let previous = Pg.query_values(conn,
    "SELECT ordinal::text,state::text,blockhash FROM issuer_sol_conversion_attempts WHERE intent_id=$1 ORDER BY ordinal DESC LIMIT 1",
    [Binary(id)])?
  let ordinal = if List.length(previous) == 0 do
    0
  else
    let row = List.head(previous)
    # Even an expired signed packet remains reconciliation-only. Only an exact
    # authenticated finalized failure permits an explicit new signing attempt.
    if small(row, "state")? != 3 && small(row, "state")? != 4 do
      return load_sol_conversion(conn, profile, id)
    end
    if bytes(Map.get(row, "blockhash"))? == blockhash do
      return Err("sol_conversion_new_hash_required")
    end
    small(row, "ordinal")? + 1
  end
  if ordinal >= 64
    || bank.profile_hash != sol_conversion_profile_hash(profile)?
    || last_height == U64.parse("0")?
    || Bytes.length(bank.bank_hash) != 32 do
    return Err("invalid_sol_conversion_preparation")
  end
  let amount = number(source, "lamports")?
  if U64.compare(bank.owner_lamports, amount) < 0
    || U64.compare(bank.payer_lamports, U64.add(profile.rent, profile.maximum_fee)?) < 0 do
    return Err("sol_conversion_principal_unavailable")
  end
  let minimum = sol_conversion_floor(amount, bank.usd_micros, bank.published, bank.now)?
  let message = serialize_legacy_message(sol_conversion_message(profile,
    id,
    amount,
    minimum,
    Hash { bytes: blockhash })?)?
  Pg.execute_values(conn,
    "INSERT INTO issuer_sol_conversion_attempts(intent_id,ordinal,bank_hash,prepared_slot,prepared_at,price,price_at,minimum,blockhash,last_height,message) VALUES($1,$2::smallint,$3,$4::numeric,$5::numeric,$6::numeric,$7::numeric,$8::numeric,$9,$10::numeric,$11)",
    [
      Binary(id),
      Text(Int.to_string(ordinal)),
      Binary(bank.bank_hash),
      Text(U64.to_string(bank.slot)),
      Text(U64.to_string(bank.now)),
      Text(U64.to_string(bank.usd_micros)),
      Text(U64.to_string(bank.published)),
      Text(U64.to_string(minimum)),
      Binary(blockhash),
      Text(U64.to_string(last_height)),
      Binary(message)
    ])?
  load_sol_conversion(conn, profile, id)
end

fn fresh(profile :: SolConversionProfile,
  saved :: StoredSolConversion,
  bank :: SolConversionBank,
  now :: U64) -> Result<(), String> do
  if saved.plan.profile_hash != sol_conversion_profile_hash(profile)?
    || bank.profile_hash != saved.plan.profile_hash
    || U64.compare(bank.slot, saved.prepared_slot) < 0
    || U64.compare(now, saved.prepared_at) < 0
    || U64.compare(bank.now, now) > 0
    || U64.compare(U64.subtract(now, bank.now)?, U64.parse("30")?) > 0
    || U64.compare(saved.plan.minimum,
      sol_conversion_floor(saved.plan.lamports, bank.usd_micros, bank.published, now)?) < 0 do
    return Err("sol_conversion_reconcile_only")
  end
  Ok(nil)
end

pub fn commit_sol_conversion(conn :: borrow PgConn,
  profile :: SolConversionProfile,
  id :: Bytes,
  ordinal :: Int,
  packet :: Bytes,
  bank :: SolConversionBank,
  now :: U64) -> StoredSolConversion!String do
  let saved = load_sol_conversion(conn, profile, id)?
  if saved.ordinal != ordinal do
    return Err("sol_conversion_attempt_conflict")
  end
  let decoded = sol_conversion_packet(profile, saved.plan, packet)?
  if saved.state != 0 do
    if saved.packet != packet do
      return Err("sol_conversion_packet_conflict")
    end
    return Ok(saved)
  end
  fresh(profile, saved, bank, now)?
  Pg.execute_values(conn,
    "UPDATE issuer_sol_conversion_attempts SET state=1,packet=$3,signature=$4 WHERE intent_id=$1 AND ordinal=$2::smallint AND state=0",
    [Binary(id), Text(Int.to_string(ordinal)), Binary(packet), Binary(decoded.signature)])?
  load_sol_conversion(conn, profile, id)
end

# Internal runtime calls this only after exact finalized hash-validity/height and
# fresh same-bank profile/code/oracle admission. No missing-history replacement.
pub fn sol_conversion_ready_packet(profile :: SolConversionProfile,
  saved :: StoredSolConversion,
  bank :: SolConversionBank,
  now :: U64,
  height :: U64) -> Bytes!String do
  if saved.state != 1 || U64.compare(height, saved.last_height) > 0 do
    return Err("sol_conversion_reconcile_only")
  end
  fresh(profile, saved, bank, now)?
  sol_conversion_packet(profile, saved.plan, saved.packet)?
  Ok(saved.packet)
end

# Internal storage boundary: runtime first obtains the same exact finalized
# transaction/outcome from the two pinned providers and authenticates current code.
pub fn reconcile_sol_conversion(conn :: borrow PgConn,
  profile :: SolConversionProfile,
  id :: Bytes,
  ordinal :: Int,
  outcome :: FinalizedTransactionOutcome) -> StoredSolConversion!String do
  let saved = load_sol_conversion(conn, profile, id)?
  if saved.ordinal != ordinal || saved.state == 0 do
    return Err("sol_conversion_attempt_conflict")
  end
  let result = sol_conversion_outcome(profile,
    saved.plan,
    saved.packet,
    saved.prepared_slot,
    outcome)?
  if saved.state == 2 || saved.state == 3 do
    if saved.receipt != result.receipt do
      return Err("sol_conversion_receipt_conflict")
    end
    return Ok(saved)
  end
  if result.successful do
    Pg.execute_values(conn,
      "INSERT INTO issuer_sol_conversion_outputs(intent_id,ordinal,mint,owner,custody,amount,receipt) VALUES($1,$2::smallint,$3,$4,$5,$6::numeric,$7)",
      [
        Binary(id),
        Text(Int.to_string(ordinal)),
        Binary(profile.usdc.bytes),
        Binary(profile.owner.bytes),
        Binary(conversion_destination(profile)?.bytes),
        Text(U64.to_string(result.received)),
        Binary(result.receipt)
      ])?
  end
  Pg.execute_values(conn,
    "UPDATE issuer_sol_conversion_attempts SET state=$3::smallint,receipt=$4 WHERE intent_id=$1 AND ordinal=$2::smallint AND state=1",
    [
      Binary(id),
      Text(Int.to_string(ordinal)),
      Text(if result.successful do
        "2"
      else
        "3"
      end),
      Binary(result.receipt)
    ])?
  load_sol_conversion(conn, profile, id)
end
