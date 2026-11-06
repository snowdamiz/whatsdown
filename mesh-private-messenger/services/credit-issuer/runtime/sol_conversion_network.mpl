from Payment.SolConversion import sol_conversion_floor
from Payment.Treasury import TreasuryChainConfig, treasury_config_hash
from Runtime.Treasury import treasury_provider_hash
from Payment.SolConversionPacket import (
  SolConversionProfile,
  sol_conversion_profile_hash,
  sol_conversion_packet
)
from Payment.SolConversionBank import (
  SolConversionBank,
  admit_sol_conversion_bank,
  sol_conversion_bank_keys,
  sol_conversion_reconciliation_bank
)
from Payment.SolConversionOutcome import sol_conversion_outcome
from Storage.SolConversion import (
  StoredSolConversion,
  load_sol_conversion,
  reserve_sol_conversion,
  prepare_sol_conversion,
  commit_sol_conversion,
  reconcile_sol_conversion,
  sol_conversion_ready_packet
)
from Solana.Read import (
  Pubkey,
  Hash,
  OptionalAccountsAtSlot,
  rpc_request,
  rpc_send,
  get_latest_blockhash_request,
  latest_blockhash_from_response,
  get_multiple_accounts_context_request,
  optional_accounts_from_response
)
from Solana.TransactionRead import get_finalized_transaction_outcome
from Solana.TransactionSend import send_transaction_request, sent_signature_from_response
from Runtime.KeySync import issuer_now

pub struct SolConversionConfig do
  chain :: TreasuryChainConfig
  profile :: SolConversionProfile
  providers :: List<String>
  test_mode :: Bool
end

pub struct SolConversionRead do
  bank :: SolConversionBank
  blockhash :: Bytes
  last_height :: U64
  height :: U64
  hash_valid :: Bool
end

pub fn validate_sol_conversion_config(config :: SolConversionConfig) -> Result<(), String> do
  sol_conversion_profile_hash(config.profile)?
  if config.profile.treasury_config != treasury_config_hash(config.chain)?
    || config.profile.owner.bytes != config.chain.treasury_owner
    || config.profile.payer.bytes != config.chain.fee_payer
    || config.profile.usdc.bytes != config.chain.mint
    || treasury_provider_hash(config.providers)? != config.chain.providers_hash do
    return Err("sol_conversion_config_binding")
  end
  let origins = for url in config.providers do
    let origin = Http.url_origin(url)?
    if Bytes.length(Bytes.from_utf8(url)) > 2048
      || origin != url
      || !(if config.test_mode do
        String.starts_with(origin, "http://127.0.0.1:")
      else
        String.starts_with(origin, "https://")
      end) do
      return Err("sol_conversion_provider_origin")
    end
    origin
  end
  if List.length(origins) != 2 || List.get(origins, 0) == List.get(origins, 1) do
    return Err("sol_conversion_provider_quorum")
  end
  Ok(nil)
end

fn genesis(client :: Int,
  url :: String,
  config :: SolConversionConfig,
  id :: Int) -> Result<(), String> do
  let value = rpc_send(client, url, rpc_request(id, "getGenesisHash", "[]")?, 3000, 4096)?
  if !value.ok
    || Bytes.from_base58(Json.as_string(Json.parse(value.result_json)?)?)? != config.chain.cluster do
    return Err("sol_conversion_cluster_mismatch")
  end
  Ok(nil)
end

fn wide(value :: Json, name :: String) -> U64!String do
  U64.parse(Json.encode(Json.object_get(value, name)?))
end

fn accounts(client :: Int,
  url :: String,
  config :: SolConversionConfig,
  id :: Bytes,
  minimum :: U64,
  request_id :: Int) -> OptionalAccountsAtSlot!String do
  optional_accounts_from_response(rpc_send(client,
    url,
    get_multiple_accounts_context_request(request_id,
      sol_conversion_bank_keys(config.profile, id)?,
      "finalized",
      Some(minimum))?,
    3000,
    6291456)?)
end

fn one(client :: Int,
  url :: String,
  config :: SolConversionConfig,
  id :: Bytes,
  target :: Option<Bytes>,
  request_id :: Int) -> SolConversionRead!String do
  genesis(client, url, config, request_id)?
  let latest = latest_blockhash_from_response(rpc_send(client,
    url,
    get_latest_blockhash_request(request_id + 1, "finalized")?,
    3000,
    8192)?)?
  let raw = accounts(client, url, config, id, latest.context_slot, request_id + 2)?
  if raw.slot != latest.context_slot do
    return Err("sol_conversion_bank_changed")
  end
  let bank = admit_sol_conversion_bank(config.profile, id, raw)?
  let epoch = rpc_send(client,
    url,
    rpc_request(request_id + 3,
      "getEpochInfo",
      "[{\"commitment\":\"finalized\",\"minContextSlot\":" <> U64.to_string(raw.slot) <> "}]")?,
    3000,
    8192)?
  if !epoch.ok do
    return Err("sol_conversion_height_unavailable")
  end
  let data = Json.parse(epoch.result_json)?
  if wide(data, "absoluteSlot")? != bank.slot do
    return Err("sol_conversion_bank_changed")
  end
  let height = wide(data, "blockHeight")?
  if U64.compare(height, bank.slot) > 0 do
    return Err("sol_conversion_height_slot_mismatch")
  end
  let checked_hash = case target do
    None -> latest.blockhash.bytes
    Some(value) -> value
  end
  if Bytes.length(checked_hash) != 32 do
    return Err("sol_conversion_hash_shape")
  end
  let valid = rpc_send(client,
    url,
    rpc_request(request_id + 4,
      "isBlockhashValid",
      "["
        <> Json.encode_string(Bytes.to_base58(checked_hash))
        <> ",{\"commitment\":\"finalized\",\"minContextSlot\":"
        <> U64.to_string(bank.slot)
        <> "}]")?,
    3000,
    8192)?
  if !valid.ok do
    return Err("sol_conversion_hash_unavailable")
  end
  let parsed = Json.parse(valid.result_json)?
  if wide(Json.object_get(parsed, "context")?, "slot")? != bank.slot do
    return Err("sol_conversion_bank_changed")
  end
  let hash_valid = Json.as_bool(Json.object_get(parsed, "value")?)?
  Ok(SolConversionRead {
    bank: bank,
    blockhash: latest.blockhash.bytes,
    last_height: latest.last_valid_block_height,
    height: height,
    hash_valid: hash_valid
  })
end

fn quorum(client :: Int,
  config :: SolConversionConfig,
  id :: Bytes,
  target :: Option<Bytes>) -> SolConversionRead!String do
  validate_sol_conversion_config(config)?
  let first = one(client, List.get(config.providers, 0), config, id, target, 800)?
  let second = one(client, List.get(config.providers, 1), config, id, target, 820)?
  if first.bank.bank_hash != second.bank.bank_hash
    || first.blockhash != second.blockhash
    || first.last_height != second.last_height
    || first.height != second.height
    || first.hash_valid != second.hash_valid do
    return Err("sol_conversion_bank_quorum")
  end
  Ok(first)
end

pub fn read_sol_conversion(config :: SolConversionConfig,
  id :: Bytes,
  target :: Option<Bytes>) -> SolConversionRead!String do
  let client = Http.client()
  let result = quorum(client, config, id, target)
  Http.client_close(client)
  result
end

fn now(config :: SolConversionConfig, observed :: U64) -> U64!String do
  if config.test_mode do
    Ok(observed)
  else
    issuer_now()
  end
end

pub fn prepare_weekly_sol_conversion(pool :: PoolHandle,
  config :: SolConversionConfig,
  batch :: U64,
  bucket :: Int) -> StoredSolConversion!String do
  validate_sol_conversion_config(config)?
  let id = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do reserve_sol_conversion(conn, config.profile, batch, bucket) end)?
  # Recovery never depends on a quote oracle or replaces an unknown packet.
  let saved = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_sol_conversion(conn, config.profile, id) end)
  case saved do
    Ok(value) -> if value.state != 3 do
      return Ok(value)
    end
    Err(error) -> if error != "sol_conversion_not_prepared" do
      return Err(error)
    end
  end
  let proof = read_sol_conversion(config, id, None)?
  if !proof.hash_valid || U64.compare(proof.height, proof.last_height) > 0 do
    return Err("sol_conversion_dead_hash")
  end
  let current = now(config, proof.bank.now)?
  if U64.compare(current, proof.bank.now) < 0
    || U64.compare(U64.subtract(current, proof.bank.now)?, U64.parse("30")?) > 0 do
    return Err("sol_conversion_stale_bank")
  end
  sol_conversion_floor(U64.parse("1")?, proof.bank.usd_micros, proof.bank.published, current)?
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do prepare_sol_conversion(conn,
      config.profile,
      id,
      proof.bank,
      proof.blockhash,
      proof.last_height) end)
end

pub fn commit_weekly_sol_conversion(pool :: PoolHandle,
  config :: SolConversionConfig,
  id :: Bytes,
  ordinal :: Int,
  wire :: Bytes) -> StoredSolConversion!String do
  validate_sol_conversion_config(config)?
  let saved = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_sol_conversion(conn, config.profile, id) end)?
  sol_conversion_packet(config.profile, saved.plan, wire)?
  if saved.state != 0 do
    if saved.ordinal != ordinal || saved.packet != wire do
      return Err("sol_conversion_packet_conflict")
    end
    return Ok(saved)
  end
  let proof = read_sol_conversion(config, id, Some(saved.plan.blockhash.bytes))?
  if !proof.hash_valid || U64.compare(proof.height, saved.last_height) > 0 do
    return Err("sol_conversion_dead_hash")
  end
  let current = now(config, proof.bank.now)?
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do commit_sol_conversion(conn,
      config.profile,
      id,
      ordinal,
      wire,
      proof.bank,
      current) end)
end

fn reconcile(client :: Int,
  pool :: PoolHandle,
  config :: SolConversionConfig,
  id :: Bytes) -> StoredSolConversion!String do
  validate_sol_conversion_config(config)?
  let saved = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_sol_conversion(conn, config.profile, id) end)?
  if saved.state != 1 do
    return Ok(saved)
  end
  let signature = sol_conversion_packet(config.profile, saved.plan, saved.packet)?.signature
  let first = get_finalized_transaction_outcome(client,
    List.get(config.providers, 0),
    signature,
    850,
    3000,
    262144)?
  let second = get_finalized_transaction_outcome(client,
    List.get(config.providers, 1),
    signature,
    851,
    3000,
    262144)?
  case (first, second) do
    (None, None) -> Ok(saved)
    (Some(a), Some(b)) -> do
      let left = sol_conversion_outcome(config.profile,
        saved.plan,
        saved.packet,
        saved.prepared_slot,
        a)?
      let right = sol_conversion_outcome(config.profile,
        saved.plan,
        saved.packet,
        saved.prepared_slot,
        b)?
      if left.receipt != right.receipt do
        return Err("sol_conversion_outcome_quorum")
      end
      for url in config.providers do
        genesis(client, url, config, 860)?
        sol_conversion_reconciliation_bank(config.profile,
          accounts(client, url, config, id, left.slot, 861)?,
          left.slot)?
      end
      Repo.transaction(pool,
        fn(conn :: borrow PgConn) do reconcile_sol_conversion(conn,
          config.profile,
          id,
          saved.ordinal,
          a) end)
    end
    _ -> Err("sol_conversion_outcome_quorum")
  end
end

pub fn reconcile_weekly_sol_conversion(pool :: PoolHandle,
  config :: SolConversionConfig,
  id :: Bytes) -> StoredSolConversion!String do
  let client = Http.client()
  let result = reconcile(client, pool, config, id)
  Http.client_close(client)
  result
end

# No raw signing here. The exact externally signed packet is committed before
# this can submit it. Each bounded provider attempt rereads bank/code/oracle/hash.
pub fn submit_weekly_sol_conversion(pool :: PoolHandle,
  config :: SolConversionConfig,
  id :: Bytes) -> StoredSolConversion!String do
  let prior = reconcile_weekly_sol_conversion(pool, config, id)?
  if prior.state == 0 do
    return Err("sol_conversion_signature_required")
  end
  if prior.state != 1 do
    return Ok(prior)
  end
  for url in config.providers do
    let proof = read_sol_conversion(config, id, Some(prior.plan.blockhash.bytes))?
    if !proof.hash_valid do
      return Err("sol_conversion_reconcile_only")
    end
    let packet = sol_conversion_ready_packet(config.profile,
      prior,
      proof.bank,
      now(config, proof.bank.now)?,
      proof.height)?
    let client = Http.client()
    let result = rpc_send(client,
      url,
      send_transaction_request(870,
        packet,
        sol_conversion_packet(config.profile, prior.plan, packet)?.signature,
        prior.prepared_slot)?,
      3000,
      8192)
    Http.client_close(client)
    # Acknowledgment is not a custody receipt. Unknown outcomes keep exact bytes.
    case result do
      Ok(value) -> case sent_signature_from_response(value,
        sol_conversion_packet(config.profile, prior.plan, packet)?.signature) do
        Ok(_) -> nil
        Err(_) -> nil
      end
      Err(_) -> nil
    end
    let current = reconcile_weekly_sol_conversion(pool, config, id)?
    if current.state != 1 do
      return Ok(current)
    end
  end
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_sol_conversion(conn, config.profile, id) end)
end

# Explicit unsigned-only recovery. Both the retired hash's invalidity and the
# fresh hash's validity must be observed at the same exact finalized bank on
# both providers. Elapsed time or a too-small stored lifetime is insufficient.
pub fn refresh_unsigned_weekly_sol_conversion(pool :: PoolHandle,
  config :: SolConversionConfig,
  id :: Bytes) -> StoredSolConversion!String do
  validate_sol_conversion_config(config)?
  let saved = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_sol_conversion(conn, config.profile, id) end)?
  if saved.state != 0 do
    return Err("sol_conversion_signed_reconcile_only")
  end
  let retired = read_sol_conversion(config, id, Some(saved.plan.blockhash.bytes))?
  if retired.hash_valid || U64.compare(retired.height, saved.last_height) <= 0 do
    return Err("sol_conversion_old_hash_not_expired")
  end
  let fresh = read_sol_conversion(config, id, None)?
  if !fresh.hash_valid
    || fresh.blockhash == saved.plan.blockhash.bytes
    || fresh.bank.bank_hash != retired.bank.bank_hash
    || fresh.height != retired.height
    || U64.compare(fresh.height, fresh.last_height) > 0 do
    return Err("sol_conversion_refresh_bank_mismatch")
  end
  sol_conversion_floor(saved.plan.lamports,
    fresh.bank.usd_micros,
    fresh.bank.published,
    now(config, fresh.bank.now)?)?
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let current = load_sol_conversion(conn, config.profile, id)?
      if current.ordinal != saved.ordinal
        || current.state != 0
        || current.plan.message != saved.plan.message do
        return Err("sol_conversion_attempt_conflict")
      end
      Pg.execute_values(conn,
        "UPDATE issuer_sol_conversion_attempts SET state=4 WHERE intent_id=$1 AND ordinal=$2::smallint AND state=0",
        [Binary(id), Text(Int.to_string(saved.ordinal))])?
      prepare_sol_conversion(conn,
        config.profile,
        id,
        fresh.bank,
        fresh.blockhash,
        fresh.last_height)
    end)
end
