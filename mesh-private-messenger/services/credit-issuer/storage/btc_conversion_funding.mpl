from Payment.BtcConversionConfig import BtcConversionConfig, btc_conversion_profile
from Payment.Treasury import TreasuryChainConfig, treasury_config_hash
from Payment.Verify import payment_token_address
from Storage.BtcConversion import BtcConversionIntent, load_btc_conversion, reserve_btc_output_use
from Storage.TreasuryFunding import TreasuryFundingIntent, treasury_funding_instruction
from Payment.TreasuryRewards import TreasuryFundingProof
from Transparency.RewardsChain import reward_pool_address, decode_reward_funding_receipt
from Transparency.RewardsWrite import RewardWriteContext
from Solana.Read import Pubkey
from Solana.Tx import Instruction

fn text(value :: DbValue) -> String!String do
  case value do
    Text(v) -> Ok(v)
    _ -> Err("invalid_btc_funding_row")
  end
end

fn bytes(value :: DbValue) -> Bytes!String do
  case value do
    Binary(v) -> Ok(v)
    _ -> Err("invalid_btc_funding_row")
  end
end

fn cat(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts, Ok(Bytes.empty()), fn(a, b) do Bytes.concat(a?, b) end)
end

pub fn btc_witness_funding_binding(config :: BtcConversionConfig,
  chain :: TreasuryChainConfig) -> Result<(), String> do
  if config.treasury_config_hash != treasury_config_hash(chain)?
    || config.cluster != chain.cluster
    || config.owner != chain.treasury_owner
    || config.mint != chain.mint
    || config.custody != payment_token_address(config.owner, config.mint)?
    || reward_pool_address(Pubkey { bytes: chain.rewards_program })?.bytes != chain.rewards_pool do
    return Err("btc_funding_config_binding")
  end
  Ok(nil)
end

# Stable across every epoch attempt. Migration014 makes bucket0 use permanent.
pub fn btc_witness_output_reservation(conversion :: Bytes,
  receipt :: Bytes,
  chain_hash :: Bytes) -> Bytes!String do
  if Bytes.length(conversion) != 32
    || Bytes.length(receipt) != 340
    || Bytes.length(chain_hash) != 32 do
    return Err("invalid_btc_funding_identity")
  end
  Ok(Crypto.sha256(cat([
    Bytes.from_utf8("morse-btc-witness-output-use-v1"),
    conversion,
    Crypto.sha256(receipt),
    chain_hash
  ])?))
end

pub fn btc_witness_funding_id(conversion :: Bytes,
  receipt :: Bytes,
  chain_hash :: Bytes,
  epoch :: U64,
  program :: Bytes,
  pool :: Bytes) -> Bytes!String do
  if Bytes.length(program) != 32 || Bytes.length(pool) != 32 do
    return Err("invalid_btc_funding_identity")
  end
  let reservation = btc_witness_output_reservation(conversion, receipt, chain_hash)?
  Ok(Crypto.sha256(cat([
    Bytes.from_utf8("morse-btc-witness-funding-v1"),
    conversion,
    reservation,
    Crypto.sha256(receipt),
    Bytes.write_uint_le(U64.to_string(epoch), 8)?,
    program,
    pool
  ])?))
end

struct BtcWitnessOutput do
  value :: BtcConversionIntent
  row :: Map<String, DbValue>
end

fn output(conn :: borrow PgConn,
  config :: BtcConversionConfig,
  id :: Bytes) -> BtcWitnessOutput!String do
  let rows = Pg.query_values(conn,
    "SELECT c.batch_id::text,c.bucket::text,c.treasury_config_hash,o.mint,o.owner,o.custody,o.amount::text,o.receipt,o.transaction_signature FROM issuer_btc_conversion_intents c JOIN issuer_btc_conversion_outputs o USING(intent_id) WHERE c.intent_id=$1",
    [Binary(id)])?
  if List.length(rows) != 1 do
    return Err("btc_conversion_output_not_finalized")
  end
  let row = List.head(rows)
  if text(Map.get(row, "bucket"))? != "0" do
    return Err("btc_witness_bucket_required")
  end
  let value = case load_btc_conversion(conn,
    config,
    U64.parse(text(Map.get(row, "batch_id"))?)?,
    0)? do
    None -> return Err("btc_conversion_output_not_finalized")
    Some(v) -> v
  end
  let receipt = bytes(Map.get(row, "receipt"))?
  if value.intent_id != id
    || (value.stage != "arrived" && value.stage != "output-reserved")
    || bytes(Map.get(row, "treasury_config_hash"))? != config.treasury_config_hash
    || bytes(Map.get(row, "mint"))? != config.mint
    || bytes(Map.get(row, "owner"))? != config.owner
    || bytes(Map.get(row, "custody"))? != config.custody
    || Bytes.length(receipt) != 340 do
    return Err("btc_funding_output_binding")
  end
  let amount = U64.parse(text(Map.get(row, "amount"))?)?
  if Bytes.to_hex(Bytes.slice(receipt, 0, 4)?) != "4d434232"
    || Bytes.slice(receipt, 4, 32)? != id
    || Bytes.slice(receipt, 36, 32)? != btc_conversion_profile(config)?
    || Bytes.slice(receipt, 68, 64)? != bytes(Map.get(row, "transaction_signature"))?
    || U64.parse(Bytes.read_uint_le(receipt, 172, 8)?)? != amount
    || amount == U64.parse("0")?
    || U64.compare(amount, value.plan.minimum_output_usdc) < 0
    || Bytes.slice(receipt, 180, 32)? != config.mint
    || Bytes.slice(receipt, 212, 32)? != config.owner
    || Bytes.slice(receipt, 244, 32)? != config.custody
    || Bytes.slice(receipt, 276, 32)? != Crypto.sha256(Bytes.from_utf8(value.withdrawal_id)) do
    return Err("btc_funding_receipt_binding")
  end
  # The immutable014 admission already checks the selected order-draft hash.
  let draft = Pg.query_values(conn,
    "SELECT body_sha256 FROM issuer_btc_conversion_drafts WHERE intent_id=$1 AND kind='order' AND revision=$2::bigint",
    [Binary(id), Text(U64.to_string(value.order_draft_revision))])?
  if List.length(draft) != 1
    || bytes(Map.get(List.head(draft), "body_sha256"))? != Bytes.slice(receipt, 308, 32)? do
    return Err("btc_funding_order_binding")
  end
  Ok(BtcWitnessOutput { value: value, row: row })
end

pub fn load_btc_witness_funding(conn :: borrow PgConn,
  config :: BtcConversionConfig,
  chain :: TreasuryChainConfig,
  id :: Bytes) -> TreasuryFundingIntent!String do
  btc_witness_funding_binding(config, chain)?
  let rows = Pg.query_values(conn,
    "SELECT conversion_id,reservation_id,receipt_hash,epoch::text,program,pool,state::text FROM issuer_btc_witness_funding WHERE funding_id=$1",
    [Binary(id)])?
  if List.length(rows) != 1 do
    return Err("unknown_btc_witness_funding")
  end
  let row = List.head(rows)
  let conversion = bytes(Map.get(row, "conversion_id"))?
  let actual = output(conn, config, conversion)?
  let receipt = bytes(Map.get(actual.row, "receipt"))?
  let epoch = U64.parse(text(Map.get(row, "epoch"))?)?
  let reservation = btc_witness_output_reservation(conversion,
    receipt,
    config.treasury_config_hash)?
  if bytes(Map.get(row, "reservation_id"))? != reservation
    || bytes(Map.get(row, "receipt_hash"))? != Crypto.sha256(receipt)
    || bytes(Map.get(row, "program"))? != chain.rewards_program
    || bytes(Map.get(row, "pool"))? != chain.rewards_pool
    || id != btc_witness_funding_id(conversion,
        receipt,
        config.treasury_config_hash,
        epoch,
        chain.rewards_program,
        chain.rewards_pool)? do
    return Err("btc_funding_identity_conflict")
  end
  let uses = Pg.query_values(conn,
    "SELECT operation_id,receipt_hash FROM issuer_btc_conversion_output_uses WHERE intent_id=$1 AND bucket=0 AND NOT released",
    [Binary(conversion)])?
  if List.length(uses) != 1
    || bytes(Map.get(List.head(uses), "operation_id"))? != reservation
    || bytes(Map.get(List.head(uses), "receipt_hash"))? != Crypto.sha256(receipt) do
    return Err("btc_funding_reservation_conflict")
  end
  let state = case String.to_int(text(Map.get(row, "state"))?) do
    Some(v) -> v
    None -> return Err("invalid_btc_funding_row")
  end
  Ok(TreasuryFundingIntent {
    intent_id: id,
    batch_id: actual.value.batch_id,
    epoch: epoch,
    pool: chain.rewards_pool,
    funder: config.owner,
    source: config.custody,
    mint: config.mint,
    amount: U64.parse(text(Map.get(actual.row, "amount"))?)?,
    state: state
  })
end

pub fn active_btc_witness_funding(conn :: borrow PgConn,
  config :: BtcConversionConfig,
  chain :: TreasuryChainConfig,
  conversion :: Bytes) -> Option<TreasuryFundingIntent>!String do
  btc_witness_funding_binding(config, chain)?
  output(conn, config, conversion)?
  let rows = Pg.query_values(conn,
    "SELECT funding_id FROM issuer_btc_witness_funding WHERE conversion_id=$1 AND state IN(0,1)",
    [Binary(conversion)])?
  if List.length(rows) == 0 do
    Ok(None)
  else
    Ok(Some(load_btc_witness_funding(conn,
      config,
      chain,
      bytes(Map.get(List.head(rows), "funding_id"))?)?))
  end
end

pub fn reserve_btc_witness_funding(conn :: borrow PgConn,
  config :: BtcConversionConfig,
  chain :: TreasuryChainConfig,
  conversion :: Bytes,
  epoch :: U64) -> TreasuryFundingIntent!String do
  btc_witness_funding_binding(config, chain)?
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365502)", [])?
  let actual = output(conn, config, conversion)?
  let reservation = btc_witness_output_reservation(conversion,
    bytes(Map.get(actual.row, "receipt"))?,
    config.treasury_config_hash)?
  reserve_btc_output_use(conn, actual.value, reservation)?
  case active_btc_witness_funding(conn, config, chain, conversion)? do
    Some(v) -> return Ok(v)
    None -> nil
  end
  let expired = Pg.query_values(conn,
    "SELECT COALESCE(MAX(expired_epoch),0)::text AS epoch FROM issuer_btc_witness_funding WHERE conversion_id=$1",
    [Binary(conversion)])?
  if U64.compare(epoch, U64.parse(text(Map.get(List.head(expired), "epoch"))?)?) < 0 do
    return Err("btc_funding_epoch_regressed")
  end
  let id = btc_witness_funding_id(conversion,
    bytes(Map.get(actual.row, "receipt"))?,
    config.treasury_config_hash,
    epoch,
    chain.rewards_program,
    chain.rewards_pool)?
  Pg.execute_values(conn,
    "INSERT INTO issuer_btc_witness_funding(funding_id,conversion_id,reservation_id,receipt_hash,epoch,program,pool) VALUES($1,$2,$3,$4,$5::numeric,$6,$7)",
    [
      Binary(id),
      Binary(conversion),
      Binary(reservation),
      Binary(Crypto.sha256(bytes(Map.get(actual.row, "receipt"))?)),
      Text(U64.to_string(epoch)),
      Binary(chain.rewards_program),
      Binary(chain.rewards_pool)
    ])?
  load_btc_witness_funding(conn, config, chain, id)
end

# The runtime obtains this proof from the existing two pinned finalized sources;
# neither HTTP acknowledgments nor an arbitrary raw receipt complete funding.
pub fn reconcile_btc_witness_funding(conn :: borrow PgConn,
  config :: BtcConversionConfig,
  chain :: TreasuryChainConfig,
  id :: Bytes,
  proof :: TreasuryFundingProof) -> TreasuryFundingIntent!String do
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365502)", [])?
  let intent = load_btc_witness_funding(conn, config, chain, id)?
  if U64.compare(proof.current_epoch, intent.epoch) < 0 do
    return Err("btc_funding_proof_before_attempt")
  end
  case proof.receipt do
    None -> do
      if Bytes.length(proof.receipt_bytes) != 0 || intent.state == 1 do
        return Err("btc_funded_receipt_missing")
      end
      if intent.state == 0 && U64.compare(proof.current_epoch, intent.epoch) > 0 do
        Pg.execute_values(conn,
          "UPDATE issuer_btc_witness_funding SET state=2,expired_epoch=$2::numeric WHERE funding_id=$1 AND state=0",
          [Binary(id), Text(U64.to_string(proof.current_epoch))])?
        nil
      end
    end
    Some(parsed) -> do
      let r = decode_reward_funding_receipt(proof.receipt_bytes)?
      if r != parsed
        || intent.state == 2
        || r.kind != 0
        || r.pool != intent.pool
        || r.funder != intent.funder
        || r.operation_id != id
        || r.epoch != intent.epoch
        || r.amount != intent.amount
        || r.source != intent.source
        || r.mint != intent.mint
        || U64.compare(r.epoch, proof.current_epoch) > 0 do
        return Err("btc_funding_receipt_conflict")
      end
      if intent.state == 1 do
        let rows = Pg.query_values(conn,
          "SELECT receipt FROM issuer_btc_witness_funding WHERE funding_id=$1",
          [Binary(id)])?
        if bytes(Map.get(List.head(rows), "receipt"))? != proof.receipt_bytes do
          return Err("btc_funding_receipt_conflict")
        end
      else
        Pg.execute_values(conn,
          "UPDATE issuer_btc_witness_funding SET state=1,receipt=$2 WHERE funding_id=$1 AND state=0",
          [Binary(id), Binary(proof.receipt_bytes)])?
        nil
      end
    end
  end
  load_btc_witness_funding(conn, config, chain, id)
end

pub fn btc_witness_funding_instruction(intent :: TreasuryFundingIntent,
  context :: RewardWriteContext,
  config :: BtcConversionConfig,
  chain :: TreasuryChainConfig) -> Instruction!String do
  btc_witness_funding_binding(config, chain)?
  if context.program.bytes != chain.rewards_program
    || intent.pool != chain.rewards_pool
    || intent.funder != config.owner
    || intent.source != config.custody
    || intent.mint != config.mint do
    return Err("btc_funding_handoff_binding")
  end
  treasury_funding_instruction(intent, context, Pubkey { bytes: chain.fee_payer })
end
