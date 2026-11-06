from Runtime.Treasury import TreasuryWorkerConfig
from Payment.Treasury import treasury_config_hash
from Payment.TreasuryBurnExpiry import read_treasury_burn_expiry_bank
from Payment.TreasuryBurn import (
  read_treasury_burn_ready,
  read_treasury_burn_funding,
  TreasuryBurnReady
)
from Storage.TreasuryBurn import (
  StoredCreditBurnHandoff,
  load_credit_burn_handoff,
  find_credit_burn_handoff,
  reserve_credit_burn_handoff,
  confirm_credit_burn_handoff,
  expire_credit_burn_handoff
)
from Transparency.TokenBurnRead import TokenBurnReadPins
from Transparency.TokenBurnExpiry import token_burn_expire_instruction
from Solana.Tx import instruction_report_json

fn compatible(worker :: TreasuryWorkerConfig,
  pins :: TokenBurnReadPins,
  value :: StoredCreditBurnHandoff) -> Result<(), String> do
  if value.intent.config_hash != treasury_config_hash(worker.chain)?
    || value.intent.program != pins.program
    || value.intent.profile.usdc != pins.usdc
    || value.intent.profile.treasury != pins.treasury do
    return Err("credit_burn_handoff_config_changed")
  end
  Ok(nil)
end

pub fn reconcile_credit_burn_handoff(pool :: PoolHandle,
  worker :: TreasuryWorkerConfig,
  pins :: TokenBurnReadPins,
  id :: Bytes) -> StoredCreditBurnHandoff!String do
  let stored = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_credit_burn_handoff(conn, id) end)?
  compatible(worker, pins, stored)?
  if stored.state != 0 do
    return Ok(stored)
  end
  case read_treasury_burn_funding(worker, pins, stored.intent) do
    Ok(proof) -> Repo.transaction(pool,
      fn(conn :: borrow PgConn) do confirm_credit_burn_handoff(conn,
        id,
        proof.frame,
        proof.receipt,
        proof.context_slot) end)
    Err(funding_error) -> do
      let bank = read_treasury_burn_expiry_bank(worker, pins, stored.intent.epoch)?
      if bank.profile_bytes != stored_profile(pool, id)? do
        return Err("credit_burn_pending_profile_changed")
      end
      case bank.frame do
        # Canonical absence, even after the deadline, is never release proof.
        None -> Err(funding_error)
        Some(_) -> Repo.transaction(pool,
          fn(conn :: borrow PgConn) do expire_credit_burn_handoff(conn,
            id,
            bank.raw_frame,
            bank.raw_receipt,
            bank.context_slot) end)
      end
    end
  end
end

pub fn prepare_credit_burn_expiry(pool :: PoolHandle,
  worker :: TreasuryWorkerConfig,
  pins :: TokenBurnReadPins,
  epoch :: U64) -> String!String do
  let stored = case Repo.transaction(pool,
    fn(conn :: borrow PgConn) do find_credit_burn_handoff(conn, pins.program, epoch) end)? do
    None -> return Err("unknown_credit_burn_handoff")
    Some(value) -> value
  end
  compatible(worker, pins, stored)?
  if stored.state == 1 do
    return Err("credit_burn_funded_intent_cannot_expire")
  end
  if stored.state == 2 do
    return Ok(credit_burn_funding_json(stored))
  end
  let bank = read_treasury_burn_expiry_bank(worker, pins, epoch)?
  if bank.profile_bytes != stored_profile(pool, stored.intent.intent_id)? do
    return Err("credit_burn_pending_profile_changed")
  end
  case bank.frame do
    Some(_) -> do
      let terminal = Repo.transaction(pool,
        fn(conn :: borrow PgConn) do expire_credit_burn_handoff(conn,
          stored.intent.intent_id,
          bank.raw_frame,
          bank.raw_receipt,
          bank.context_slot) end)?
      return Ok(credit_burn_funding_json(terminal))
    end
    None -> nil
  end
  # Preparation never reserves chain state or releases members. Re-read the
  # journal after the provider calls so a concurrent terminal commit wins.
  let current = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_credit_burn_handoff(conn, stored.intent.intent_id) end)?
  if current.state == 1 do
    return Err("credit_burn_funded_intent_cannot_expire")
  end
  if current.state == 2 do
    return Ok(credit_burn_funding_json(current))
  end
  let instruction = token_burn_expire_instruction(current.intent.program,
    current.intent.payer,
    current.intent.profile,
    current.intent.epoch)?
  Ok("{\"state\":\"expiry_pending\",\"action\":\"token-expire-unfunded\",\"intent_id\":"
    <> Json.encode_string(Bytes.to_hex(current.intent.intent_id))
    <> ",\"epoch\":"
    <> Json.encode_string(U64.to_string(epoch))
    <> ",\"instruction\":"
    <> instruction_report_json(instruction)
    <> "}")
end

fn checked_ready(worker :: TreasuryWorkerConfig,
  pins :: TokenBurnReadPins,
  epoch :: U64,
  carry :: U64,
  now :: U64) -> TreasuryBurnReady!String do
  let ready = read_treasury_burn_ready(worker, pins, epoch, U64.parse("0")?, now)?
  if U64.compare(carry, ready.available_carry) > 0 do
    return Err("credit_burn_carry_underfunded")
  end
  Ok(ready)
end

pub fn prepare_credit_burn_funding(pool :: PoolHandle,
  worker :: TreasuryWorkerConfig,
  pins :: TokenBurnReadPins,
  epoch :: U64,
  carry :: U64,
  now :: U64) -> Option<StoredCreditBurnHandoff>!String do
  let previous = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do find_credit_burn_handoff(conn, pins.program, epoch) end)?
  case previous do
    Some(stored) -> do
      compatible(worker, pins, stored)?
      if stored.intent.carry != carry do
        return Err("credit_burn_week_conflict")
      end
      if stored.state != 0 do
        return Ok(Some(stored))
      end
      case reconcile_credit_burn_handoff(pool, worker, pins, stored.intent.intent_id) do
        Ok(value) -> return Ok(Some(value))
        Err(_) -> nil
      end
      # A missing/failed receipt read never frees the reservation. Only another
      # complete ready bank can return the identical idempotent funding request.
      let ready = checked_ready(worker, pins, epoch, carry, now)?
      if ready.profile_bytes != stored_profile(pool, stored.intent.intent_id)?
        || U64.compare(stored.intent.cash, ready.source_balance) > 0 do
        return Err("credit_burn_pending_profile_or_balance_changed")
      end
      return Repo.transaction(pool,
        fn(conn :: borrow PgConn) do Ok(Some(load_credit_burn_handoff(conn,
          stored.intent.intent_id)?)) end)
    end
    None -> nil
  end
  let ready = checked_ready(worker, pins, epoch, carry, now)?
  let random = case Crypto.random_bytes(288) do
    Ok(value) -> value
    Err(_) -> return Err("credit_burn_entropy_unavailable")
  end
  let maximum = U64.parse("4294967295")?
  let weights = for index in 0..24 do
    let raw = U64.parse(Bytes.read_uint_le(random, index * 12, 4)?)?
    U64.add(U64.subtract(raw, U64.multiply(U64.divide(raw, maximum)?, maximum)?)?, U64.parse("1")?)?
  end
  let entropy = for index in 0..24 do
    U64.parse(Bytes.read_uint_le(random, index * 12 + 4, 8)?)?
  end
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let reserved = reserve_credit_burn_handoff(conn,
        treasury_config_hash(worker.chain)?,
        pins.program,
        pins.treasury,
        ready.profile_bytes,
        epoch,
        carry,
        weights,
        entropy,
        ready.timestamp)?
      case reserved do
        Some(value) -> if U64.compare(value.intent.cash, ready.source_balance) > 0 do
          return Err("credit_burn_cash_underfunded")
        end
        None -> nil
      end
      Ok(reserved)
    end)
end

fn stored_profile(pool :: PoolHandle, id :: Bytes) -> Bytes!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let rows = Pg.query_values(conn,
        "SELECT profile FROM issuer_treasury_burn_intents WHERE intent_id=$1",
        [Binary(id)])?
      if List.length(rows) != 1 do
        return Err("unknown_credit_burn_handoff")
      end
      case Map.get(List.head(rows), "profile") do
        Binary(value) -> Ok(value)
        _ -> Err("invalid_credit_burn_row")
      end
    end)
end

fn values(items :: List<U64>) -> String do
  "["
    <> String.join(for value in items do
        Json.encode_string(U64.to_string(value))
      end,
      ",")
    <> "]"
end

pub fn credit_burn_funding_json(stored :: StoredCreditBurnHandoff) -> String do
  let value = stored.intent
  let shared = "\"intent_id\":"
    <> Json.encode_string(Bytes.to_hex(value.intent_id))
    <> ",\"epoch\":"
    <> Json.encode_string(U64.to_string(value.epoch))
    <> ",\"cash\":"
    <> Json.encode_string(U64.to_string(value.cash))
    <> ",\"carry\":"
    <> Json.encode_string(U64.to_string(value.carry))
    <> ",\"funding_hash\":"
    <> Json.encode_string(Bytes.to_hex(value.funding_hash))
    <> ",\"membership_hash\":"
    <> Json.encode_string(Bytes.to_hex(value.membership_hash))
  if stored.state == 1 do
    return "{\"state\":\"funded\"," <> shared <> "}"
  end
  if stored.state == 2 do
    return "{\"state\":\"expired_unfunded\"," <> shared <> "}"
  end
  "{\"state\":\"pending\",\"action\":\"token-fund-v2\","
    <> shared
    <> ",\"weights\":"
    <> values(value.weights)
    <> ",\"entropy\":"
    <> values(value.entropy)
    <> ",\"instruction\":"
    <> instruction_report_json(value.instruction)
    <> "}"
end
