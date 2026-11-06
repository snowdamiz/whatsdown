from Payment.SolConversionPacket import (
  SolConversionProfile,
  sol_conversion_profile_hash,
  conversion_destination
)
from Payment.Treasury import TreasuryChainConfig, treasury_config_hash
from Storage.TreasuryFunding import TreasuryFundingIntent, treasury_funding_instruction
from Payment.TreasuryRewards import TreasuryFundingProof
from Transparency.RewardsChain import reward_pool_address, decode_reward_funding_receipt
from Transparency.RewardsWrite import RewardWriteContext
from Solana.Read import Pubkey
from Solana.Tx import Instruction

fn text(value :: DbValue) -> String!String do
  case value do
    Text(v) -> Ok(v)
    _ -> Err("invalid_sol_funding_row")
  end
end

fn bytes(value :: DbValue) -> Bytes!String do
  case value do
    Binary(v) -> Ok(v)
    _ -> Err("invalid_sol_funding_row")
  end
end

fn cat(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts, Ok(Bytes.empty()), fn(a, b) do Bytes.concat(a?, b) end)
end

pub fn sol_witness_funding_id(conversion :: Bytes,
  receipt :: Bytes,
  epoch :: U64,
  program :: Bytes,
  pool :: Bytes) -> Bytes!String do
  if Bytes.length(conversion) != 32
    || Bytes.length(receipt) != 197
    || Bytes.length(program) != 32
    || Bytes.length(pool) != 32 do
    return Err("invalid_sol_funding_identity")
  end
  Ok(Crypto.sha256(cat([
    Bytes.from_utf8("morse-sol-witness-funding-v1"),
    conversion,
    Crypto.sha256(receipt),
    Bytes.write_uint_le(U64.to_string(epoch), 8)?,
    program,
    pool
  ])?))
end

fn binding(profile :: SolConversionProfile, chain :: TreasuryChainConfig) -> Result<(), String> do
  if profile.treasury_config != treasury_config_hash(chain)?
    || profile.owner.bytes != chain.treasury_owner
    || profile.usdc.bytes != chain.mint
    || profile.payer.bytes != chain.fee_payer
    || reward_pool_address(Pubkey { bytes: chain.rewards_program })?.bytes != chain.rewards_pool do
    return Err("sol_funding_config_binding")
  end
  Ok(nil)
end

fn output(conn :: borrow PgConn,
  profile :: SolConversionProfile,
  id :: Bytes) -> Map<String, DbValue>!String do
  let found = Pg.query_values(conn,
    "SELECT c.batch_id::text,c.bucket::text,c.profile_hash,o.mint,o.owner,o.custody,o.amount::text,o.receipt FROM issuer_sol_conversions c JOIN issuer_sol_conversion_outputs o USING(intent_id) JOIN issuer_sol_conversion_attempts a ON a.intent_id=o.intent_id AND a.ordinal=o.ordinal WHERE c.intent_id=$1 AND a.state=2 AND a.receipt=o.receipt",
    [Binary(id)])?
  if List.length(found) != 1 do
    return Err("sol_conversion_output_not_finalized")
  end
  let row = List.head(found)
  if text(Map.get(row, "bucket"))? != "0"
    || bytes(Map.get(row, "profile_hash"))? != sol_conversion_profile_hash(profile)?
    || bytes(Map.get(row, "mint"))? != profile.usdc.bytes
    || bytes(Map.get(row, "owner"))? != profile.owner.bytes
    || bytes(Map.get(row, "custody"))? != conversion_destination(profile)?.bytes do
    return Err("sol_funding_output_binding")
  end
  Ok(row)
end

pub fn load_sol_witness_funding(conn :: borrow PgConn,
  profile :: SolConversionProfile,
  chain :: TreasuryChainConfig,
  id :: Bytes) -> TreasuryFundingIntent!String do
  binding(profile, chain)?
  let rows = Pg.query_values(conn,
    "SELECT conversion_id,epoch::text,pool,state::text FROM issuer_sol_witness_funding WHERE funding_id=$1",
    [Binary(id)])?
  if List.length(rows) != 1 do
    return Err("unknown_sol_witness_funding")
  end
  let row = List.head(rows)
  let conversion = bytes(Map.get(row, "conversion_id"))?
  let actual = output(conn, profile, conversion)?
  let epoch = U64.parse(text(Map.get(row, "epoch"))?)?
  if bytes(Map.get(row, "pool"))? != chain.rewards_pool
    || id != sol_witness_funding_id(conversion,
        bytes(Map.get(actual, "receipt"))?,
        epoch,
        chain.rewards_program,
        chain.rewards_pool)? do
    return Err("sol_funding_identity_conflict")
  end
  let state = case String.to_int(text(Map.get(row, "state"))?) do
    Some(v) -> v
    None -> return Err("invalid_sol_funding_row")
  end
  Ok(TreasuryFundingIntent {
    intent_id: id,
    batch_id: U64.parse(text(Map.get(actual, "batch_id"))?)?,
    epoch: epoch,
    pool: chain.rewards_pool,
    funder: profile.owner.bytes,
    source: conversion_destination(profile)?.bytes,
    mint: profile.usdc.bytes,
    amount: U64.parse(text(Map.get(actual, "amount"))?)?,
    state: state
  })
end

pub fn reserve_sol_witness_funding(conn :: borrow PgConn,
  profile :: SolConversionProfile,
  chain :: TreasuryChainConfig,
  conversion :: Bytes,
  epoch :: U64) -> TreasuryFundingIntent!String do
  binding(profile, chain)?
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365496)", [])?
  let actual = output(conn, profile, conversion)?
  let prior = Pg.query_values(conn,
    "SELECT funding_id FROM issuer_sol_witness_funding WHERE conversion_id=$1 AND state IN(0,1)",
    [Binary(conversion)])?
  if List.length(prior) == 1 do
    return load_sol_witness_funding(conn,
      profile,
      chain,
      bytes(Map.get(List.head(prior), "funding_id"))?)
  end
  let id = sol_witness_funding_id(conversion,
    bytes(Map.get(actual, "receipt"))?,
    epoch,
    chain.rewards_program,
    chain.rewards_pool)?
  Pg.execute_values(conn,
    "INSERT INTO issuer_sol_witness_funding(funding_id,conversion_id,epoch,pool) VALUES($1,$2,$3::numeric,$4)",
    [Binary(id), Binary(conversion), Text(U64.to_string(epoch)), Binary(chain.rewards_pool)])?
  load_sol_witness_funding(conn, profile, chain, id)
end

# Raw receipt bytes/Boolean are not a public completion authority. Runtime first
# obtains the pinned-program, canonical-PDA, same-finalized-bank two-source proof.
pub fn reconcile_sol_witness_funding(conn :: borrow PgConn,
  profile :: SolConversionProfile,
  chain :: TreasuryChainConfig,
  id :: Bytes,
  proof :: TreasuryFundingProof) -> TreasuryFundingIntent!String do
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365496)", [])?
  let intent = load_sol_witness_funding(conn, profile, chain, id)?
  case proof.receipt do
    None -> do
      if Bytes.length(proof.receipt_bytes) != 0 || intent.state == 1 do
        return Err("sol_funded_receipt_missing")
      end
      if U64.compare(proof.current_epoch, intent.epoch) > 0 do
        Pg.execute_values(conn,
          "UPDATE issuer_sol_witness_funding SET state=2 WHERE funding_id=$1 AND state=0",
          [Binary(id)])?
      end
    end
    Some(_) -> do
      let r = decode_reward_funding_receipt(proof.receipt_bytes)?
      if intent.state == 2
        || r.kind != 0
        || r.pool != intent.pool
        || r.funder != intent.funder
        || r.operation_id != id
        || r.epoch != intent.epoch
        || r.amount != intent.amount
        || r.source != intent.source
        || r.mint != intent.mint
        || U64.compare(r.epoch, proof.current_epoch) > 0 do
        return Err("sol_funding_receipt_conflict")
      end
      if intent.state == 1 do
        let row = List.head(Pg.query_values(conn,
          "SELECT receipt FROM issuer_sol_witness_funding WHERE funding_id=$1",
          [Binary(id)])?)
        if bytes(Map.get(row, "receipt"))? != proof.receipt_bytes do
          return Err("sol_funding_receipt_conflict")
        end
      else
        Pg.execute_values(conn,
          "UPDATE issuer_sol_witness_funding SET state=1,receipt=$2 WHERE funding_id=$1 AND state=0",
          [Binary(id), Binary(proof.receipt_bytes)])?
        nil
      end
    end
  end
  load_sol_witness_funding(conn, profile, chain, id)
end

pub fn sol_witness_funding_instruction(intent :: TreasuryFundingIntent,
  context :: RewardWriteContext,
  profile :: SolConversionProfile) -> Instruction!String do
  if intent.funder != profile.owner.bytes
    || intent.mint != profile.usdc.bytes
    || intent.source != conversion_destination(profile)?.bytes do
    return Err("sol_funding_handoff_binding")
  end
  treasury_funding_instruction(intent, context, profile.payer)
end

pub fn active_sol_witness_funding(conn :: borrow PgConn,
  profile :: SolConversionProfile,
  chain :: TreasuryChainConfig,
  conversion :: Bytes) -> Option<TreasuryFundingIntent>!String do
  binding(profile, chain)?
  output(conn, profile, conversion)?
  let found = Pg.query_values(conn,
    "SELECT funding_id FROM issuer_sol_witness_funding WHERE conversion_id=$1 AND state IN(0,1)",
    [Binary(conversion)])?
  if List.length(found) == 0 do
    Ok(None)
  else
    Ok(Some(load_sol_witness_funding(conn,
      profile,
      chain,
      bytes(Map.get(List.head(found), "funding_id"))?)?))
  end
end
