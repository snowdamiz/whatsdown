from Runtime.TreasuryBurn import (
  prepare_credit_burn_funding,
  prepare_credit_burn_expiry,
  reconcile_credit_burn_handoff,
  credit_burn_funding_json
)
from Transparency.TokenBurnRead import TokenBurnReadPins
from Runtime.Config import IssuerServerConfig, open_storage_key
from Runtime.KeySync import issuer_now
from Runtime.TreasuryCommand import TreasuryCommand, parse_treasury_command
from Runtime.TreasuryKeys import provision_treasury_keys, treasury_operational_keys
from Runtime.TreasuryControl import configured_treasury, run_treasury_cycle, treasury_cycle_json
from Runtime.TreasurySettlement import (
  settle_treasury_week,
  settle_policy_treasury_week,
  treasury_week_json
)
from Runtime.TreasuryFunding import (
  prepare_weekly_treasury_funding,
  reconcile_weekly_treasury_funding
)
from Runtime.Treasury import observe_treasury_deposit, retry_treasury_movement
from Runtime.TreasuryBatch import retry_treasury_batch
from Storage.TreasuryFunding import TreasuryFundingIntent, treasury_funding_request
from Storage.TreasuryQueue import treasury_queue_status
from Payment.Treasury import treasury_config_hash
from Transparency.RewardsWrite import RewardWriteContext
from Transparency.AnchorChain import configured_anchor_pins
from Solana.Read import Pubkey

pub fn treasury_funding_json(value :: TreasuryFundingIntent) -> String do
  "{\"intent_id\":"
    <> Json.encode_string(Bytes.to_hex(value.intent_id))
    <> ",\"batch_id\":"
    <> Json.encode_string(U64.to_string(value.batch_id))
    <> ",\"epoch\":"
    <> Json.encode_string(U64.to_string(value.epoch))
    <> ",\"amount\":"
    <> Json.encode_string(U64.to_string(value.amount))
    <> ",\"state\":"
    <> Int.to_string(value.state)
    <> "}"
end

fn status(pool :: PoolHandle, config :: IssuerServerConfig) -> String!String do
  let keys = case treasury_operational_keys(pool,
    config.policy.service_key,
    config.policy.purpose) do
    Ok(value) -> Some(value)
    Err(error) -> if error == "treasury_keys_not_provisioned" do
      None
    else
      return Err(error)
    end
  end
  let enabled = case config.treasury do
    Some(_) -> "true"
    None -> "false"
  end
  let public = case keys do
    None -> "\"provisioned\":false"
    Some(value) -> "\"provisioned\":true,\"fee_payer\":"
      <> Json.encode_string(Bytes.to_base58(value.fee_payer))
      <> ",\"nonce_authority\":"
      <> Json.encode_string(Bytes.to_base58(value.nonce_authority))
  end
  let counts = case config.treasury do
    None -> "{}"
    Some(worker) -> Repo.transaction(pool,
      fn(conn :: borrow PgConn) do treasury_queue_status(conn,
        treasury_config_hash(worker.chain)?) end)?
  end
  let scope = case config.treasury do
    None -> ""
    Some(worker) -> ",\"config_hash\":"
      <> Json.encode_string(Bytes.to_hex(treasury_config_hash(worker.chain)?))
  end
  Ok("{\"enabled\":"
    <> enabled
    <> ","
    <> public
    <> ",\"movements_by_state\":"
    <> counts
    <> scope
    <> "}")
end

fn burn_pins(config :: IssuerServerConfig) -> TokenBurnReadPins!String do
  case config.burn do
    None -> Err("treasury_burn_not_enabled")
    Some(value) -> Ok(value)
  end
end

pub fn execute_treasury_command(pool :: PoolHandle,
  config :: IssuerServerConfig,
  command :: TreasuryCommand) -> String!String do
  case command do
    TreasuryProvision -> do
      let keys = provision_treasury_keys(pool,
        config.policy.service_key,
        config.policy.purpose,
        fn() do open_storage_key(config.key_directory) end)?
      Ok("{\"fee_payer\":"
        <> Json.encode_string(Bytes.to_base58(keys.fee_payer))
        <> ",\"nonce_authority\":"
        <> Json.encode_string(Bytes.to_base58(keys.nonce_authority))
        <> "}")
    end
    TreasuryStatus -> status(pool, config)
    TreasuryRun -> Ok(treasury_cycle_json(run_treasury_cycle(pool, config, issuer_now()?)?))
    TreasuryRefund(quote_id, signature) -> do
      let worker = configured_treasury(config)?
      case observe_treasury_deposit(pool, worker, quote_id, signature, 1, issuer_now()?)? do
        None -> Ok("{\"status\":\"payment_pending\"}")
        Some(value) -> Ok("{\"movement_id\":"
          <> Json.encode_string(Bytes.to_hex(value.movement_id))
          <> ",\"state\":"
          <> Int.to_string(value.state)
          <> ",\"amount\":"
          <> Json.encode_string(U64.to_string(value.amount))
          <> ",\"destination_owner\":"
          <> Json.encode_string(Bytes.to_base58(value.destination_owner))
          <> "}")
      end
    end
    TreasuryWeekly(week, asset) -> Ok(treasury_week_json(settle_treasury_week(pool,
      configured_treasury(config)?,
      week,
      asset,
      issuer_now()?)?))
    TreasuryWeeklyPolicy(week, asset, version) -> Ok(treasury_week_json(settle_policy_treasury_week(pool,
      configured_treasury(config)?,
      week,
      asset,
      version,
      issuer_now()?)?))
    TreasuryBurnRequest(epoch, carry) -> case prepare_credit_burn_funding(pool,
      configured_treasury(config)?,
      burn_pins(config)?,
      epoch,
      carry,
      issuer_now()?)? do
      None -> Ok("{\"state\":\"pending_budget\"}")
      Some(value) -> Ok(credit_burn_funding_json(value))
    end
    TreasuryBurnExpireRequest(epoch) -> prepare_credit_burn_expiry(pool,
      configured_treasury(config)?,
      burn_pins(config)?,
      epoch)
    TreasuryBurnReconcile(id) -> Ok(credit_burn_funding_json(reconcile_credit_burn_handoff(pool,
      configured_treasury(config)?,
      burn_pins(config)?,
      id)?))
    TreasuryFundingReconcile(id) -> Ok(treasury_funding_json(reconcile_weekly_treasury_funding(pool,
      configured_treasury(config)?,
      id)?))
    TreasuryFundingRequest(batch_id) -> do
      let worker = configured_treasury(config)?
      let anchors = case configured_anchor_pins(config.trust)? do
        Some(value) -> value
        None -> return Err("treasury_funding_requires_anchor_pins")
      end
      let intent = case prepare_weekly_treasury_funding(pool, worker, batch_id)? do
        None -> return Ok("{\"status\":\"no_funding_due\"}")
        Some(value) -> value
      end
      if intent.state != 0 do
        return Ok(treasury_funding_json(intent))
      end
      # This handoff uses the separately held treasury owner's payer. The
      # issuer's opaque fee/nonce keys never leave their storage runtime.
      treasury_funding_request(intent,
        RewardWriteContext {
          program: Pubkey { bytes: worker.chain.rewards_program },
          judge: anchors.program,
          log_name: anchors.log_name,
          mint: Pubkey { bytes: worker.chain.mint }
        },
        Pubkey { bytes: worker.chain.treasury_owner })
    end
    TreasuryRetryBatch(id) -> do
      let batch = retry_treasury_batch(pool, configured_treasury(config)?, id)?
      Ok("{\"batch_id\":"
        <> Json.encode_string(Bytes.to_hex(batch.batch_id))
        <> ",\"state\":"
        <> Int.to_string(batch.state)
        <> "}")
    end
    TreasuryRetryMovement(id) -> do
      let movement = retry_treasury_movement(pool, configured_treasury(config)?, id)?
      Ok("{\"movement_id\":"
        <> Json.encode_string(Bytes.to_hex(movement.movement_id))
        <> ",\"state\":"
        <> Int.to_string(movement.state)
        <> "}")
    end
  end
end

pub fn run_treasury_operator(pool :: PoolHandle,
  config :: IssuerServerConfig,
  args :: List<String>) -> String!String do
  execute_treasury_command(pool, config, parse_treasury_command(args)?)
end
