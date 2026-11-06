from Payment.TreasuryBurnSources import (
  CreditBurnSource,
  credit_burn_source_id,
  select_credit_burn_sources
)
from Storage.TreasuryBurnBtc import (
  available_btc_burn_rows,
  load_btc_burn_rows,
  reserve_btc_burn_row,
  active_btc_burn_rows,
  release_btc_burn_rows
)
from Payment.Verify import payment_token_address
from Payment.TreasuryBurnHandoff import (
  CreditBurnAllocation,
  CreditBurnHandoff,
  prepare_credit_burn_handoff,
  match_credit_burn_handoff_frame
)
from Transparency.TokenBurnExpiry import match_token_burn_unfunded
from Solana.Read import Pubkey
from Transparency.TokenBurn import decode_token_burn_profile

pub struct StoredCreditBurnHandoff do
  intent :: CreditBurnHandoff
  state :: Int
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid_credit_burn_row")
  end
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(output) -> Ok(output)
    _ -> Err("invalid_credit_burn_row")
  end
end

fn state(value :: DbValue) -> Int!String do
  case text(value)? do
    "0" -> Ok(0)
    "1" -> Ok(1)
    "2" -> Ok(2)
    _ -> Err("invalid_credit_burn_state")
  end
end

fn allocation(row :: Map<String, DbValue>, source :: Int) -> CreditBurnAllocation!String do
  Ok(CreditBurnAllocation {
    batch_id: credit_burn_source_id(source, U64.parse(text(Map.get(row, "batch_id"))?)?)?,
    policy_hash: binary(Map.get(row, "policy_hash"))?,
    config_hash: binary(Map.get(row, "config_hash"))?,
    mint: Pubkey { bytes: binary(Map.get(row, "mint"))? },
    amount: U64.parse(text(Map.get(row, "amount"))?)?
  })
end

fn rows(conn :: borrow PgConn, id :: Bytes) -> List<Map<String, DbValue>>!String do
  Pg.query_values(conn,
    "SELECT intent_id,config_hash,token_program,payer,profile,epoch::text,cash::text,carry::text,instruction,membership_hash,funding_hash,state::text FROM issuer_treasury_burn_intents WHERE intent_id=$1",
    [Binary(id)])
end

pub fn load_credit_burn_handoff(conn :: borrow PgConn,
  id :: Bytes) -> StoredCreditBurnHandoff!String do
  let found = rows(conn, id)?
  if List.length(found) != 1 do
    return Err("unknown_credit_burn_handoff")
  end
  let row = List.head(found)
  let data = binary(Map.get(row, "instruction"))?
  if Bytes.length(data) != 313 || Bytes.get(data, 0)? != 14 do
    return Err("invalid_credit_burn_instruction")
  end
  let weights = for index in 0..24 do
    U64.parse(Bytes.read_uint_le(data, 25 + 12 * index, 4)?)?
  end
  let entropy = for index in 0..24 do
    U64.parse(Bytes.read_uint_le(data, 29 + 12 * index, 8)?)?
  end
  let profile = decode_token_burn_profile(binary(Map.get(row, "profile"))?)?
  let members = Pg.query_values(conn,
    "SELECT b.batch_id::text,b.policy_hash,b.config_hash,CASE WHEN b.asset=0 THEN b.mint ELSE o.mint END AS mint,CASE WHEN b.asset=0 THEN l.amount ELSE o.amount END::text AS amount FROM issuer_treasury_burn_members m JOIN issuer_treasury_burn_liabilities l USING(batch_id) JOIN issuer_treasury_weekly b USING(batch_id) LEFT JOIN issuer_sol_conversions c ON c.intent_id=m.conversion_id LEFT JOIN issuer_sol_conversion_outputs o ON o.intent_id=c.intent_id LEFT JOIN issuer_sol_conversion_attempts a ON a.intent_id=o.intent_id AND a.ordinal=o.ordinal WHERE m.intent_id=$1 AND l.amount=b.burn AND ((b.asset=0 AND m.conversion_id IS NULL) OR(b.asset=1 AND c.batch_id=b.batch_id AND c.bucket=1 AND c.lamports=l.amount AND a.state=2 AND a.receipt=o.receipt AND o.mint=$2 AND o.owner=$3 AND o.custody=$4)) ORDER BY b.batch_id",
    [
      Binary(id),
      Binary(profile.usdc.bytes),
      Binary(profile.treasury.bytes),
      Binary(payment_token_address(profile.treasury.bytes, profile.usdc.bytes)?)
    ])?
  let btc_members = load_btc_burn_rows(conn,
    id,
    binary(Map.get(row, "config_hash"))?,
    profile.usdc.bytes,
    profile.treasury.bytes,
    payment_token_address(profile.treasury.bytes, profile.usdc.bytes)?)?
  let allocations = (for member in members do
    allocation(member, 0)?
  end)
    ++ (for member in btc_members do
      allocation(member, 1)?
    end)
  let intent = prepare_credit_burn_handoff(binary(Map.get(row, "config_hash"))?,
    Pubkey { bytes: binary(Map.get(row, "token_program"))? },
    Pubkey { bytes: binary(Map.get(row, "payer"))? },
    profile,
    U64.parse(text(Map.get(row, "epoch"))?)?,
    allocations,
    U64.parse(text(Map.get(row, "carry"))?)?,
    weights,
    entropy)?
  if intent.intent_id != id
    || intent.cash != U64.parse(text(Map.get(row, "cash"))?)?
    || intent.membership_hash != binary(Map.get(row, "membership_hash"))?
    || intent.funding_hash != binary(Map.get(row, "funding_hash"))?
    || intent.instruction.data != data do
    return Err("credit_burn_handoff_conflict")
  end
  Ok(StoredCreditBurnHandoff { intent: intent, state: state(Map.get(row, "state"))? })
end

# Transaction-only, privileged operator boundary. New reservations must use an
# authenticated current profile/clock/carry bank; retries preserve old members.
# Only an authenticated permanent tombstone may release these exact members;
# elapsed time or missing RPC data alone never authorizes another packet.
pub fn reserve_credit_burn_handoff(conn :: borrow PgConn,
  config_hash :: Bytes,
  program :: Pubkey,
  payer :: Pubkey,
  raw_profile :: Bytes,
  epoch :: U64,
  carry :: U64,
  weights :: List<U64>,
  entropy :: List<U64>,
  now :: U64) -> Option<StoredCreditBurnHandoff>!String do
  let profile = decode_token_burn_profile(raw_profile)?
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365495)", [])?
  let previous = Pg.query_values(conn,
    "SELECT intent_id,config_hash,payer,profile,carry::text FROM issuer_treasury_burn_intents WHERE token_program=$1 AND epoch=$2::numeric FOR UPDATE",
    [Binary(program.bytes), Text(U64.to_string(epoch))])?
  if List.length(previous) == 1 do
    let row = List.head(previous)
    if binary(Map.get(row, "config_hash"))? != config_hash
      || binary(Map.get(row, "payer"))? != payer.bytes
      || binary(Map.get(row, "profile"))? != raw_profile
      || U64.parse(text(Map.get(row, "carry"))?)? != carry do
      return Err("credit_burn_week_conflict")
    end
    return Ok(Some(load_credit_burn_handoff(conn, binary(Map.get(row, "intent_id"))?)?))
  end
  let current = U64.divide(now, U64.parse("604800")?)?
  let start = U64.multiply(epoch, U64.parse("604800")?)?
  if now == U64.parse("0")?
    || U64.compare(now, U64.parse("9223372036854775807")?) > 0
    || U64.compare(now, profile.ready_at) < 0
    || (epoch != current && epoch != U64.add(current, U64.parse("1")?)?)
    || U64.compare(now, U64.add(start, U64.parse("25200")?)?) >= 0 do
    return Err("credit_burn_funding_window_closed")
  end
  let available = Pg.query_values(conn,
    "SELECT b.batch_id::text,b.week::text,b.policy_hash,b.config_hash,CASE WHEN b.asset=0 THEN b.mint ELSE o.mint END AS mint,CASE WHEN b.asset=0 THEN l.amount ELSE o.amount END::text AS amount,CASE WHEN b.asset=0 THEN NULL ELSE c.intent_id END AS conversion_id FROM issuer_treasury_burn_liabilities l JOIN issuer_treasury_weekly b USING(batch_id) LEFT JOIN issuer_treasury_burn_members m ON m.batch_id=l.batch_id AND NOT m.released LEFT JOIN issuer_sol_conversions c ON c.batch_id=b.batch_id AND c.bucket=1 LEFT JOIN issuer_sol_conversion_outputs o ON o.intent_id=c.intent_id LEFT JOIN issuer_sol_conversion_attempts a ON a.intent_id=o.intent_id AND a.ordinal=o.ordinal WHERE b.policy_version=2 AND b.config_hash=$1 AND l.amount=b.burn AND ((b.asset=0 AND b.mint=$2) OR(b.asset=1 AND c.lamports=l.amount AND a.state=2 AND a.receipt=o.receipt AND o.mint=$2 AND o.owner=$3 AND o.custody=$4)) AND l.state=0 AND m.batch_id IS NULL ORDER BY b.week,b.batch_id LIMIT 64 FOR UPDATE OF l,b",
    [
      Binary(config_hash),
      Binary(profile.usdc.bytes),
      Binary(profile.treasury.bytes),
      Binary(payment_token_address(profile.treasury.bytes, profile.usdc.bytes)?)
    ])?
  let btc_available = available_btc_burn_rows(conn,
    config_hash,
    profile.usdc.bytes,
    profile.treasury.bytes,
    payment_token_address(profile.treasury.bytes, profile.usdc.bytes)?)?
  let source_sets = [available, btc_available]
  let candidates = List.flatten(for source in 0..2 do
    for member in List.get(source_sets, source) do
      CreditBurnSource {
        source: source,
        batch_id: U64.parse(text(Map.get(member, "batch_id"))?)?,
        week: U64.parse(text(Map.get(member, "week"))?)?
      }
    end
  end)
  let selected = select_credit_burn_sources(candidates)?
  if List.length(selected) == 0 do
    return Ok(None)
  end
  let selected_rows = for key in selected do
    let matches = List.filter(List.get(source_sets, key.source),
      fn(row) do
        case Map.get(row, "batch_id") do
          Text(value) -> value == U64.to_string(key.batch_id)
          _ -> false
        end
      end)
    if List.length(matches) != 1 do
      return Err("credit_burn_source_selection_conflict")
    end
    List.head(matches)
  end
  let allocations = for index in 0..List.length(selected) do
    allocation(List.get(selected_rows, index), List.get(selected, index).source)?
  end
  let cash = List.reduce(allocations,
    Ok(U64.parse("0")?),
    fn(total, member) do U64.add(total?, member.amount) end)?
  if U64.compare(U64.add(cash, carry)?, U64.parse("24")?) < 0 do
    return Ok(None)
  end
  let intent = prepare_credit_burn_handoff(config_hash,
    program,
    payer,
    profile,
    epoch,
    allocations,
    carry,
    weights,
    entropy)?
  Pg.execute_values(conn,
    "INSERT INTO issuer_treasury_burn_intents(intent_id,config_hash,token_program,payer,profile,epoch,cash,carry,instruction,membership_hash,funding_hash) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8::numeric,$9,$10,$11)",
    [
      Binary(intent.intent_id),
      Binary(config_hash),
      Binary(program.bytes),
      Binary(payer.bytes),
      Binary(raw_profile),
      Text(U64.to_string(epoch)),
      Text(U64.to_string(intent.cash)),
      Text(U64.to_string(carry)),
      Binary(intent.instruction.data),
      Binary(intent.membership_hash),
      Binary(intent.funding_hash)
    ])?
  for index in 0..List.length(selected) do
    let key = List.get(selected, index)
    let row = List.get(selected_rows, index)
    if key.source == 0 do
      Pg.execute_values(conn,
        "INSERT INTO issuer_treasury_burn_members(batch_id,intent_id,conversion_id) VALUES($1::bigint,$2,$3)",
        [
          Text(U64.to_string(key.batch_id)),
          Binary(intent.intent_id),
          Map.get(row, "conversion_id")
        ])?
      nil
    else
      reserve_btc_burn_row(conn, binary(Map.get(row, "conversion_id"))?, intent.intent_id)?
    end
  end
  Ok(Some(load_credit_burn_handoff(conn, intent.intent_id)?))
end

# Internal storage commit ONLY after Payment's canonical finalized-bank proof.
# A caller boolean, RPC acknowledgment or raw unowned frame is never sufficient.
pub fn confirm_credit_burn_handoff(conn :: borrow PgConn,
  id :: Bytes,
  raw :: Bytes,
  receipt :: Option<Bytes>,
  slot :: U64) -> StoredCreditBurnHandoff!String do
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365495)", [])?
  let locked = Pg.query_values(conn,
    "SELECT intent_id FROM issuer_treasury_burn_intents WHERE intent_id=$1 FOR UPDATE",
    [Binary(id)])?
  if List.length(locked) != 1 do
    return Err("unknown_credit_burn_handoff")
  end
  let stored = load_credit_burn_handoff(conn, id)?
  if slot == U64.parse("0")? do
    return Err("invalid_credit_burn_finalized_slot")
  end
  if stored.state == 2 do
    return Err("credit_burn_handoff_permanently_expired")
  end
  match_credit_burn_handoff_frame(stored.intent, raw, receipt)?
  if stored.state == 1 do
    return Ok(stored)
  end
  let members = Pg.query_values(conn,
    "UPDATE issuer_treasury_burn_liabilities l SET state=1,funding_hash=$2,receipt=$3 FROM issuer_treasury_burn_members m WHERE l.batch_id=m.batch_id AND m.intent_id=$1 AND NOT m.released AND l.state=0 RETURNING l.batch_id::text",
    [Binary(id), Binary(stored.intent.funding_hash), Binary(raw)])?
  let btc_members = active_btc_burn_rows(conn, id)?
  if List.length(members) + List.length(btc_members) != List.length(stored.intent.allocations) do
    return Err("credit_burn_liability_conflict")
  end
  Pg.execute_values(conn,
    "UPDATE issuer_treasury_burn_intents SET state=1,finalized_slot=$2::numeric,week_frame=$3,close_receipt=$4 WHERE intent_id=$1",
    [
      Binary(id),
      Text(U64.to_string(slot)),
      Binary(raw),
      case receipt do
        None -> Null
        Some(value) -> Binary(value)
      end
    ])?
  load_credit_burn_handoff(conn, id)
end

pub fn find_credit_burn_handoff(conn :: borrow PgConn,
  program :: Pubkey,
  epoch :: U64) -> Option<StoredCreditBurnHandoff>!String do
  let rows = Pg.query_values(conn,
    "SELECT intent_id FROM issuer_treasury_burn_intents WHERE token_program=$1 AND epoch=$2::numeric",
    [Binary(program.bytes), Text(U64.to_string(epoch))])?
  if List.length(rows) == 0 do
    return Ok(None)
  end
  Ok(Some(load_credit_burn_handoff(conn, binary(Map.get(List.head(rows), "intent_id"))?)?))
end

# Internal storage commit after an authenticated finalized expiry pair.
pub fn expire_credit_burn_handoff(conn :: borrow PgConn,
  id :: Bytes,
  frame :: Bytes,
  receipt :: Bytes,
  slot :: U64) -> StoredCreditBurnHandoff!String do
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365495)", [])?
  let locked = Pg.query_values(conn,
    "SELECT intent_id,profile,expiry_frame,expiry_receipt FROM issuer_treasury_burn_intents WHERE intent_id=$1 FOR UPDATE",
    [Binary(id)])?
  if List.length(locked) != 1 || slot == U64.parse("0")? do
    return Err("invalid_credit_burn_expiry_intent")
  end
  let row = List.head(locked)
  let stored = load_credit_burn_handoff(conn, id)?
  if stored.state == 1 do
    return Err("credit_burn_funded_intent_cannot_expire")
  end
  # This is a consistency check against the immutable pending intent. It is
  # not chain authentication; Runtime must first obtain both finalized banks.
  match_token_burn_unfunded(stored.intent.program,
    binary(Map.get(row, "profile"))?,
    stored.intent.epoch,
    frame,
    receipt)?
  if stored.state == 2 do
    if binary(Map.get(row, "expiry_frame"))? != frame
      || binary(Map.get(row, "expiry_receipt"))? != receipt do
      return Err("credit_burn_expiry_receipt_conflict")
    end
    return Ok(stored)
  end
  Pg.execute_values(conn,
    "UPDATE issuer_treasury_burn_intents SET state=2,expiry_slot=$2::numeric,expiry_frame=$3,expiry_receipt=$4 WHERE intent_id=$1 AND state=0",
    [Binary(id), Text(U64.to_string(slot)), Binary(frame), Binary(receipt)])?
  let released = Pg.query_values(conn,
    "UPDATE issuer_treasury_burn_members m SET released=true FROM issuer_treasury_burn_liabilities l WHERE m.batch_id=l.batch_id AND m.intent_id=$1 AND NOT m.released AND l.state=0 RETURNING m.batch_id::text",
    [Binary(id)])?
  let btc_released = release_btc_burn_rows(conn, id, receipt)?
  if List.length(released) + btc_released != List.length(stored.intent.allocations) do
    return Err("credit_burn_expiry_reservation_conflict")
  end
  load_credit_burn_handoff(conn, id)
end
