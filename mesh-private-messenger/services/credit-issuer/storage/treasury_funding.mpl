from Payment.RevenuePolicy import credit_revenue_policy_hash
from Payment.Treasury import TreasuryChainConfig, treasury_config_hash
from Payment.Verify import payment_token_address
from Payment.TreasuryRewards import TreasuryFundingProof
from Solana.Read import Pubkey
from Solana.Tx import Instruction
from Transparency.RewardsChain import reward_pool_address, decode_reward_funding_receipt
from Transparency.RewardsWrite import RewardWriteContext, reward_fund_instruction

pub struct TreasuryFundingIntent do
  intent_id :: Bytes
  batch_id :: U64
  epoch :: U64
  pool :: Bytes
  funder :: Bytes
  source :: Bytes
  mint :: Bytes
  amount :: U64
  state :: Int
end

fn funding_text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid_treasury_row")
  end
end

fn funding_binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(output) -> Ok(output)
    _ -> Err("invalid_treasury_row")
  end
end

fn intent_from_row(row :: Map<String, DbValue>) -> TreasuryFundingIntent!String do
  let state = case String.to_int(funding_text(Map.get(row, "state"))?) do
    Some(value) -> value
    None -> return Err("invalid_treasury_row")
  end
  Ok(TreasuryFundingIntent {
    intent_id: funding_binary(Map.get(row, "intent_id"))?,
    batch_id: U64.parse(funding_text(Map.get(row, "batch_id"))?)?,
    epoch: U64.parse(funding_text(Map.get(row, "epoch"))?)?,
    pool: funding_binary(Map.get(row, "pool"))?,
    funder: funding_binary(Map.get(row, "funder"))?,
    source: funding_binary(Map.get(row, "source"))?,
    mint: funding_binary(Map.get(row, "mint"))?,
    amount: U64.parse(funding_text(Map.get(row, "amount"))?)?,
    state: state
  })
end

pub fn load_treasury_funding(conn :: borrow PgConn, id :: Bytes) -> TreasuryFundingIntent!String do
  let rows = Pg.query_values(conn,
    "SELECT i.intent_id,i.batch_id::text,i.epoch::text,i.pool,i.funder,i.source,i.mint,i.amount::text,i.state::text,b.asset::text,b.mint AS batch_mint,b.witness::text,b.config_hash,b.policy_version::text,b.policy_hash,b.membership_hash FROM issuer_treasury_rewards_intents i JOIN issuer_treasury_weekly b USING(batch_id) WHERE i.intent_id=$1",
    [Binary(id)])?
  if List.length(rows) != 1 do
    return Err("unknown_treasury_funding")
  end
  let row = List.head(rows)
  let intent = intent_from_row(row)?
  # Validate on every read, including direct reconciliation. Historical records
  # keep their original IDs; policy2 binds the complete immutable weekly intent.
  if funding_text(Map.get(row, "policy_version"))? == "2" do
    if funding_text(Map.get(row, "asset"))? != "0"
      || intent.mint != funding_binary(Map.get(row, "batch_mint"))?
      || intent.amount != U64.parse(funding_text(Map.get(row, "witness"))?)?
      || intent.source != payment_token_address(intent.funder, intent.mint)?
      || intent.intent_id != treasury_funding_operation_id(2,
          funding_binary(Map.get(row, "policy_hash"))?,
          funding_binary(Map.get(row, "membership_hash"))?,
          funding_binary(Map.get(row, "config_hash"))?,
          intent.batch_id,
          intent.epoch,
          intent.amount)? do
      return Err("treasury_funding_policy_conflict")
    end
  end
  Ok(intent)
end

pub fn reserve_treasury_funding(conn :: borrow PgConn,
  batch_id :: U64,
  config :: TreasuryChainConfig,
  current_epoch :: U64) -> Option<TreasuryFundingIntent>!String do
  let hash = treasury_config_hash(config)?
  if !Bytes.secure_equals(reward_pool_address(Pubkey { bytes: config.rewards_program })?.bytes,
    config.rewards_pool) do
    return Err("treasury_rewards_pool_mismatch")
  end
  let batches = Pg.query_values(conn,
    "SELECT asset::text,mint,config_hash,witness::text,policy_version::text,policy_hash,membership_hash FROM issuer_treasury_weekly WHERE batch_id=$1::bigint FOR UPDATE",
    [Text(U64.to_string(batch_id))])?
  if List.length(batches) != 1 do
    return Err("unknown_treasury_week")
  end
  let batch = List.head(batches)
  if funding_text(Map.get(batch, "asset"))? != "0" do
    return Err("treasury_sol_conversion_pending")
  end
  if !Bytes.secure_equals(funding_binary(Map.get(batch, "mint"))?, config.mint)
    || !Bytes.secure_equals(funding_binary(Map.get(batch, "config_hash"))?, hash) do
    return Err("treasury_week_config_conflict")
  end
  let version = case String.to_int(funding_text(Map.get(batch, "policy_version"))?) do
    Some(value) -> value
    None -> return Err("invalid_treasury_revenue_policy")
  end
  let policy_hash = funding_binary(Map.get(batch, "policy_hash"))?
  let membership_hash = funding_binary(Map.get(batch, "membership_hash"))?
  let amount = U64.parse(funding_text(Map.get(batch, "witness"))?)?
  if amount == U64.parse("0")? do
    return Ok(None)
  end
  let existing = Pg.query_values(conn,
    "SELECT intent_id FROM issuer_treasury_rewards_intents WHERE batch_id=$1::bigint AND state IN (0,1)",
    [Text(U64.to_string(batch_id))])?
  if List.length(existing) == 1 do
    let intent = load_treasury_funding(conn,
      funding_binary(Map.get(List.head(existing), "intent_id"))?)?
    if intent.amount != amount
      || intent.pool != config.rewards_pool
      || intent.funder != config.treasury_owner
      || intent.mint != config.mint
      || intent.source != payment_token_address(config.treasury_owner, config.mint)?
      || (version == 2
        && intent.intent_id != treasury_funding_operation_id(version,
            policy_hash,
            membership_hash,
            hash,
            batch_id,
            intent.epoch,
            amount)?) do
      return Err("treasury_funding_policy_conflict")
    end
    if intent.state == 0 && intent.epoch != current_epoch do
      return Err("treasury_old_funding_unreconciled")
    end
    return Ok(Some(intent))
  end
  let id = treasury_funding_operation_id(version,
    policy_hash,
    membership_hash,
    hash,
    batch_id,
    current_epoch,
    amount)?
  Pg.execute_values(conn,
    "INSERT INTO issuer_treasury_rewards_intents(intent_id,batch_id,epoch,pool,funder,source,mint,amount) VALUES($1,$2::bigint,$3::numeric,$4,$5,$6,$7,$8::numeric)",
    [
      Binary(id),
      Text(U64.to_string(batch_id)),
      Text(U64.to_string(current_epoch)),
      Binary(config.rewards_pool),
      Binary(config.treasury_owner),
      Binary(payment_token_address(config.treasury_owner, config.mint)?),
      Binary(config.mint),
      Text(U64.to_string(amount))
    ])?
  Ok(Some(load_treasury_funding(conn, id)?))
end

pub fn reconcile_treasury_funding(conn :: borrow PgConn,
  id :: Bytes,
  proof :: TreasuryFundingProof) -> TreasuryFundingIntent!String do
  let rows = Pg.query_values(conn,
    "SELECT intent_id,receipt FROM issuer_treasury_rewards_intents WHERE intent_id=$1 FOR UPDATE",
    [Binary(id)])?
  if List.length(rows) != 1 do
    return Err("unknown_treasury_funding")
  end
  let intent = load_treasury_funding(conn, id)?
  case proof.receipt do
    Some(_) -> do
      let receipt = decode_reward_funding_receipt(proof.receipt_bytes)?
      if U64.compare(receipt.epoch, proof.current_epoch) > 0 do
        return Err("treasury_future_funding_receipt")
      end
      if intent.state == 1 do
        if !Bytes.secure_equals(funding_binary(Map.get(List.head(rows), "receipt"))?,
          proof.receipt_bytes) do
          return Err("treasury_rewards_receipt_conflict")
        end
      end
      if intent.state == 2
        || receipt.kind != 0
        || receipt.epoch != intent.epoch
        || receipt.amount != intent.amount
        || !Bytes.secure_equals(receipt.pool, intent.pool)
        || !Bytes.secure_equals(receipt.funder, intent.funder)
        || !Bytes.secure_equals(receipt.operation_id, id)
        || !Bytes.secure_equals(receipt.source, intent.source)
        || !Bytes.secure_equals(receipt.mint, intent.mint)
        || Bytes.length(proof.receipt_bytes) != 192 do
        return Err("treasury_rewards_receipt_conflict")
      end
      Pg.execute_values(conn,
        "UPDATE issuer_treasury_rewards_intents SET state=1,receipt=$2 WHERE intent_id=$1 AND state=0",
        [Binary(id), Binary(proof.receipt_bytes)])?
      nil
    end
    None -> do
      if Bytes.length(proof.receipt_bytes) != 0 || intent.state == 1 do
        return Err("treasury_funded_receipt_missing")
      end
      if U64.compare(proof.current_epoch, intent.epoch) > 0 do
        Pg.execute_values(conn,
          "UPDATE issuer_treasury_rewards_intents SET state=2 WHERE intent_id=$1 AND state=0",
          [Binary(id)])?
      end
    end
  end
  load_treasury_funding(conn, id)
end

# Hand off only the idempotent tag12 revenue operation to the existing rewards
# operator. A packet acknowledgment never marks this intent funded.
pub fn treasury_funding_instruction(intent :: TreasuryFundingIntent,
  context :: RewardWriteContext,
  payer :: Pubkey) -> Instruction!String do
  if intent.state != 0
    || !Bytes.secure_equals(context.mint.bytes, intent.mint)
    || !Bytes.secure_equals(reward_pool_address(context.program)?.bytes, intent.pool)
    || !Bytes.secure_equals(payment_token_address(intent.funder, intent.mint)?, intent.source) do
    return Err("invalid_treasury_funding_handoff")
  end
  reward_fund_instruction(context,
    Pubkey { bytes: intent.funder },
    payer,
    intent.epoch,
    0,
    intent.amount,
    intent.intent_id)
end

pub fn active_treasury_funding(conn :: borrow PgConn,
  batch_id :: U64) -> Option<TreasuryFundingIntent>!String do
  let rows = Pg.query_values(conn,
    "SELECT intent_id FROM issuer_treasury_rewards_intents WHERE batch_id=$1::bigint AND state IN (0,1)",
    [Text(U64.to_string(batch_id))])?
  if List.length(rows) == 0 do
    return Ok(None)
  end
  Ok(Some(load_treasury_funding(conn, funding_binary(Map.get(List.head(rows), "intent_id"))?)?))
end

pub fn treasury_funding_request(intent :: TreasuryFundingIntent,
  context :: RewardWriteContext,
  payer :: Pubkey) -> String!String do
  treasury_funding_instruction(intent, context, payer)?
  Ok("{\"action\":\"fund\",\"program\":"
    <> Json.encode_string(Bytes.to_base58(context.program.bytes))
    <> ",\"mint\":"
    <> Json.encode_string(Bytes.to_base58(intent.mint))
    <> ",\"log\":"
    <> Json.encode_string(context.log_name)
    <> ",\"payer\":"
    <> Json.encode_string(Bytes.to_base58(payer.bytes))
    <> ",\"epoch\":"
    <> Json.encode_string(U64.to_string(intent.epoch))
    <> ",\"funder\":"
    <> Json.encode_string(Bytes.to_base58(intent.funder))
    <> ",\"kind\":0,\"amount\":"
    <> Json.encode_string(U64.to_string(intent.amount))
    <> ",\"operation_id\":"
    <> Json.encode_string(Bytes.to_hex(intent.intent_id))
    <> "}")
end

# V1 is byte-for-byte historical. V2 commits to the immutable accounting
# policy and ordered membership, so another revenue bucket cannot inherit a
# permanent old receipt after replay, reimport or a policy boundary.
pub fn treasury_funding_operation_id(version :: Int,
  policy_hash :: Bytes,
  membership_hash :: Bytes,
  config_hash :: Bytes,
  batch_id :: U64,
  epoch :: U64,
  amount :: U64) -> Bytes!String do
  if policy_hash != credit_revenue_policy_hash(version)?
    || Bytes.length(membership_hash) != 32
    || Bytes.length(config_hash) != 32
    || amount == U64.parse("0")? do
    return Err("invalid_treasury_funding_identity")
  end
  let domain = if version == 1 do
    "morse-credit-week-funding-v1"
  else
    "morse-credit-week-funding-v2"
  end
  let suffix = if version == 1 do
    Bytes.empty()
  else
    Bytes.from_hex(Bytes.to_hex(policy_hash)
      <> Bytes.to_hex(membership_hash)
      <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(amount), 8)?))?
  end
  Ok(Crypto.sha256(Bytes.from_hex(Bytes.to_hex(Bytes.from_utf8(domain))
    <> Bytes.to_hex(config_hash)
    <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(batch_id), 8)?)
    <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(epoch), 8)?)
    <> Bytes.to_hex(suffix))?))
end
