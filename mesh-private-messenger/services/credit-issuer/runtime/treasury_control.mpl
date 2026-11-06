from Runtime.Config import IssuerServerConfig, open_storage_key
from Runtime.KeySync import issuer_now
from Runtime.TreasuryKeys import open_treasury_signer
from Runtime.Treasury import TreasuryWorkerConfig, observe_treasury_deposit, run_treasury_movement
from Runtime.TreasuryBatch import prepare_treasury_batch, run_treasury_batch
from Payment.Treasury import treasury_config_hash
from Payment.TreasuryBatchTypes import TreasuryPaymentBatch
from Runtime.TreasurySettlement import treasury_settlement_cycle
from Storage.TreasuryQueue import (
  claim_treasury_observations,
  complete_treasury_observation,
  pending_treasury_batches,
  pending_treasury_singles,
  ready_treasury_batch_members
)

pub struct TreasuryCycle do
  observations :: Int
  errors :: Int
  settled :: Int
  unknown :: Int
  failed :: Int
  blocked :: Int
end

pub fn configured_treasury(config :: IssuerServerConfig) -> TreasuryWorkerConfig!String do
  case config.treasury do
    Some(value) -> Ok(value)
    None -> Err("treasury_disabled")
  end
end

pub fn validate_treasury_startup(pool :: PoolHandle,
  config :: IssuerServerConfig) -> Result<(), String> do
  case config.treasury do
    None -> Ok(nil)
    Some(worker) -> do
      let wrapping = open_storage_key(config.key_directory)?
      let payer = open_treasury_signer(pool,
        config.policy.service_key,
        config.policy.purpose,
        0,
        worker.chain.fee_payer,
        wrapping)?
      let authority = open_treasury_signer(pool,
        config.policy.service_key,
        config.policy.purpose,
        1,
        worker.chain.nonce_authority,
        wrapping)?
      Secret.destroy(payer)
      Secret.destroy(authority)
      Ok(nil)
    end
  end
end

fn prepare_ready(pool :: PoolHandle,
  worker :: TreasuryWorkerConfig,
  ids :: List<Bytes>,
  now :: U64) -> TreasuryPaymentBatch!String do
  case prepare_treasury_batch(pool, worker, ids, now) do
    Ok(value)
    Err(error) -> if error == "treasury_batch_packet_too_large" && List.length(ids) > 1 do
      # Size rejection occurs before reservation. Once prepare succeeds every
      # member is immutable, including after a lost acknowledgment or restart.
      prepare_ready(pool, worker, List.take(ids, List.length(ids) - 1), now)
    else
      Err(error)
    end
  end
end

pub fn run_treasury_cycle(pool :: PoolHandle,
  config :: IssuerServerConfig,
  now :: U64) -> TreasuryCycle!String do
  let worker = configured_treasury(config)?
  let hash = treasury_config_hash(worker.chain)?
  let wrapping = open_storage_key(config.key_directory)?
  let payer = open_treasury_signer(pool,
    config.policy.service_key,
    config.policy.purpose,
    0,
    worker.chain.fee_payer,
    wrapping)?
  let authority = open_treasury_signer(pool,
    config.policy.service_key,
    config.policy.purpose,
    1,
    worker.chain.nonce_authority,
    wrapping)?
  let singles = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do pending_treasury_singles(conn, hash) end)?
  let old_states = for id in singles do
    case run_treasury_movement(pool,
      worker,
      id,
      wrapping,
      config.policy.service_key,
      payer,
      authority,
      now) do
      Ok(value) -> value.state
      Err(_) -> -1
    end
  end
  let batches = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do pending_treasury_batches(conn, hash) end)?
  let batch_states = for id in batches do
    case run_treasury_batch(pool,
      worker,
      id,
      wrapping,
      config.policy.service_key,
      payer,
      authority,
      now) do
      Ok(value) -> value.state
      Err(_) -> -1
    end
  end
  let jobs = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do claim_treasury_observations(conn,
      config.policy.purpose,
      hash,
      now) end)?
  let observations = for job in jobs do
    case observe_treasury_deposit(pool, worker, job.quote_id, job.payment_signature, 0, now) do
      Ok(Some(_)) -> case Repo.transaction(pool,
        fn(conn :: borrow PgConn) do complete_treasury_observation(conn, hash, job.quote_id) end) do
        Ok(_) -> 1
        Err(_) -> -1
      end
      Ok(None) -> 0
      Err(_) -> -1
    end
  end
  let ready = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do ready_treasury_batch_members(conn, hash, now) end)?
  let new_states = if List.length(ready) == 0 do
    []
  else
    [
      case prepare_ready(pool, worker, ready, now) do
        Err(_) -> -1
        Ok(batch) -> case run_treasury_batch(pool,
          worker,
          batch.batch_id,
          wrapping,
          config.policy.service_key,
          payer,
          authority,
          now) do
          Ok(value) -> value.state
          Err(_) -> -1
        end
      end
    ]
  end
  let states = List.concat(List.concat(old_states, batch_states), new_states)
  let settlement_errors = case treasury_settlement_cycle(pool, worker, now) do
    Ok(value) -> value
    Err(_) -> 1
  end
  Ok(TreasuryCycle {
    observations: List.length(List.filter(observations, fn(value) do value == 1 end)),
    errors: settlement_errors
      + List.length(List.filter(List.concat(observations, states), fn(value) do value == -1 end)),
    settled: List.length(List.filter(states, fn(value) do value == 2 end)),
    unknown: List.length(List.filter(states, fn(value) do value == 0 || value == 1 end)),
    failed: List.length(List.filter(states, fn(value) do value == 3 end)),
    blocked: List.length(List.filter(states, fn(value) do value == 4 end))
  })
end

pub fn treasury_cycle_json(value :: TreasuryCycle) -> String do
  "{\"observations\":"
    <> Int.to_string(value.observations)
    <> ",\"errors\":"
    <> Int.to_string(value.errors)
    <> ",\"settled\":"
    <> Int.to_string(value.settled)
    <> ",\"unknown\":"
    <> Int.to_string(value.unknown)
    <> ",\"failed\":"
    <> Int.to_string(value.failed)
    <> ",\"blocked_history\":"
    <> Int.to_string(value.blocked)
    <> "}"
end

fn worker_loop(pool :: PoolHandle, config :: IssuerServerConfig) do
  if Process.shutdown_requested() do
    return
  end
  case issuer_now() do
    Err(_) -> io_eprintln("credit treasury clock unavailable")
    Ok(now) -> case run_treasury_cycle(pool, config, now) do
      Err(_) -> io_eprintln("credit treasury cycle failed")
      Ok(value) -> if value.errors > 0 || value.failed > 0 || value.blocked > 0 do
        io_eprintln("credit treasury requires operator attention " <> treasury_cycle_json(value))
      end
    end
  end
  Timer.sleep(30000)
  worker_loop(pool, config)
end

actor treasury_worker(pool :: PoolHandle, config :: IssuerServerConfig) do
  worker_loop(pool, config)
end

pub fn start_treasury_worker(pool :: PoolHandle, config :: IssuerServerConfig) do
  case config.treasury do
    Some(_) -> do
      spawn(treasury_worker, pool, config)
      nil
    end
    None -> nil
  end
end
