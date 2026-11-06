from Payment.Treasury import TreasuryChainConfig, treasury_config_hash
from Payment.Observation import CreditDepositObservation, observe_credit_deposit
from Credits.Issuance import CreditQuote, decode_credit_quote
from Storage.Treasury import (
  TreasuryMovement,
  load_treasury_movement,
  record_credit_deposit,
  reserve_treasury_movement
)
from Storage.TreasuryPacket import (
  reserve_treasury_message,
  commit_treasury_packet,
  finalize_treasury_packet,
  block_treasury_history,
  retry_failed_treasury_movement
)
from Runtime.TreasurySigning import (
  load_treasury_deposit_sealed,
  unseal_treasury_deposit_key,
  sign_treasury_packet
)
from Solana.Read import (
  Pubkey,
  account_from_response,
  get_account_info_request,
  rpc_request,
  rpc_send
)
from Solana.Nonce import NonceAccountState, nonce_account
from Solana.TransactionRead import (
  FinalizedTransactionOutcome,
  TransactionTokenBalance,
  get_finalized_transaction_outcome,
  signed_transaction
)
from Solana.TransactionSend import send_transaction_request, sent_signature_from_response

pub struct TreasuryWorkerConfig do
  chain :: TreasuryChainConfig
  providers :: List<String>
  test_mode :: Bool
end

pub fn treasury_provider_hash(providers :: List<String>) -> Bytes!String do
  if List.length(providers) != 2 || List.get(providers, 0) == List.get(providers, 1) do
    return Err("treasury_provider_quorum_required")
  end
  let first = Bytes.from_utf8(List.get(providers, 0))
  let second = Bytes.from_utf8(List.get(providers, 1))
  if Bytes.length(first) > 2048 || Bytes.length(second) > 2048 do
    return Err("invalid_treasury_provider")
  end
  Ok(Crypto.sha256(Bytes.from_hex(Bytes.to_hex(Bytes.from_utf8("morse-credit-treasury-providers-v1"))
    <> Bytes.to_hex(Bytes.write_uint_le(Int.to_string(Bytes.length(first)), 2)?)
    <> Bytes.to_hex(first)
    <> Bytes.to_hex(Bytes.write_uint_le(Int.to_string(Bytes.length(second)), 2)?)
    <> Bytes.to_hex(second))?))
end

pub fn validate_worker(config :: TreasuryWorkerConfig) -> Result<(), String> do
  treasury_config_hash(config.chain)?
  if !Bytes.secure_equals(treasury_provider_hash(config.providers)?, config.chain.providers_hash) do
    return Err("treasury_provider_pin_mismatch")
  end
  for url in config.providers do
    let loopback = String.starts_with(url, "http://127.0.0.1:")
      || String.starts_with(url, "http://localhost:")
    if !String.starts_with(url, "https://") && !(config.test_mode && loopback) do
      return Err("treasury_provider_requires_tls")
    end
    if String.contains(url, "@") || String.contains(url, "#") do
      return Err("invalid_treasury_provider")
    end
  end
  Ok(nil)
end

fn read_nonce(client :: Int,
  url :: String,
  config :: TreasuryChainConfig,
  id :: Int) -> NonceAccountState!String do
  let genesis = rpc_send(client, url, rpc_request(id, "getGenesisHash", "[]")?, 3000, 4096)?
  if !genesis.ok
    || !Bytes.secure_equals(Bytes.from_base58(Json.as_string(Json.parse(genesis.result_json)?)?)?,
      config.cluster) do
    return Err("treasury_cluster_mismatch")
  end
  let response = rpc_send(client,
    url,
    get_account_info_request(id + 1, Pubkey { bytes: config.nonce_address }, "finalized")?,
    3000,
    4096)?
  let state = nonce_account(account_from_response(response)?.account)?
  if !Bytes.secure_equals(state.authority.bytes, config.nonce_authority) do
    return Err("treasury_nonce_authority_mismatch")
  end
  Ok(state)
end

pub fn nonce_quorum(client :: Int, config :: TreasuryWorkerConfig) -> NonceAccountState!String do
  let first = read_nonce(client, List.get(config.providers, 0), config.chain, 200)?
  let second = read_nonce(client, List.get(config.providers, 1), config.chain, 210)?
  if !Bytes.secure_equals(first.nonce.bytes, second.nonce.bytes)
    || first.lamports_per_signature != second.lamports_per_signature do
    return Err("treasury_nonce_quorum_mismatch")
  end
  Ok(first)
end

fn same_optional_key(left :: Option<Pubkey>, right :: Option<Pubkey>) -> Bool do
  case (left, right) do
    (None, None) -> true
    (Some(a), Some(b)) -> Bytes.secure_equals(a.bytes, b.bytes)
    _ -> false
  end
end

fn same_tokens(left :: List<TransactionTokenBalance>,
  right :: List<TransactionTokenBalance>) -> Bool do
  if List.length(left) != List.length(right) do
    return false
  end
  for index in 0..List.length(left) do
    let a = List.get(left, index)
    let b = List.get(right, index)
    if a.account_index != b.account_index
      || a.amount != b.amount
      || a.decimals != b.decimals
      || !Bytes.secure_equals(a.mint.bytes, b.mint.bytes)
      || !same_optional_key(a.owner, b.owner)
      || !same_optional_key(a.program_id, b.program_id) do
      return false
    end
  end
  true
end

fn same_outcome(left :: FinalizedTransactionOutcome,
  right :: FinalizedTransactionOutcome) -> Bool do
  let errors_equal = case (left.execution_error, right.execution_error) do
    (None, None) -> true
    (Some(a), Some(b)) -> a == b
    _ -> false
  end
  let a = left.transaction
  let b = right.transaction
  if !errors_equal
    || a.slot != b.slot
    || a.block_time != b.block_time
    || a.fee != b.fee
    || !Bytes.secure_equals(a.signed.wire, b.signed.wire)
    || a.inner_instruction_count != b.inner_instruction_count
    || !same_tokens(a.pre_token_balances, b.pre_token_balances)
    || !same_tokens(a.post_token_balances, b.post_token_balances)
    || List.length(a.pre_balances) != List.length(b.pre_balances)
    || List.length(a.post_balances) != List.length(b.post_balances)
    || List.length(a.inner_instructions) != List.length(b.inner_instructions) do
    return false
  end
  for index in 0..List.length(a.pre_balances) do
    if List.get(a.pre_balances, index) != List.get(b.pre_balances, index)
      || List.get(a.post_balances, index) != List.get(b.post_balances, index) do
      return false
    end
  end
  for index in 0..List.length(a.inner_instructions) do
    let x = List.get(a.inner_instructions, index)
    let y = List.get(b.inner_instructions, index)
    if x.instruction_index != y.instruction_index
      || List.length(x.instructions) != List.length(y.instructions) do
      return false
    end
    for item in 0..List.length(x.instructions) do
      let first = List.get(x.instructions, item)
      let second = List.get(y.instructions, item)
      if !Bytes.secure_equals(first.program_id.bytes, second.program_id.bytes)
        || !Bytes.secure_equals(first.data, second.data)
        || List.length(first.accounts) != List.length(second.accounts) do
        return false
      end
      for key in 0..List.length(first.accounts) do
        let first_key = List.get(first.accounts, key)
        let second_key = List.get(second.accounts, key)
        if !Bytes.secure_equals(first_key.pubkey.bytes, second_key.pubkey.bytes)
          || first_key.signer != second_key.signer
          || first_key.writable != second_key.writable do
          return false
        end
      end
    end
  end
  true
end

pub fn outcome_quorum(client :: Int,
  config :: TreasuryWorkerConfig,
  signature :: Bytes) -> Option<FinalizedTransactionOutcome>!String do
  let first = get_finalized_transaction_outcome(client,
    List.get(config.providers, 0),
    signature,
    220,
    3000,
    262144)?
  let second = get_finalized_transaction_outcome(client,
    List.get(config.providers, 1),
    signature,
    221,
    3000,
    262144)?
  case (first, second) do
    (None, None) -> Ok(None)
    (Some(a), Some(b)) -> if same_outcome(a, b) do
      Ok(Some(a))
    else
      Err("treasury_outcome_quorum_mismatch")
    end
    _ -> Err("treasury_outcome_quorum_mismatch")
  end
end

fn load_worker_movement(pool :: PoolHandle, id :: Bytes) -> TreasuryMovement!String do
  Repo.transaction(pool, fn(conn :: borrow PgConn) do load_treasury_movement(conn, id) end)
end

fn settle_known_outcome(client :: Int,
  pool :: PoolHandle,
  config :: TreasuryWorkerConfig,
  movement :: TreasuryMovement) -> TreasuryMovement!String do
  case outcome_quorum(client, config, movement.transaction_signature)? do
    None -> Ok(movement)
    Some(value) -> Repo.transaction(pool,
      fn(conn :: borrow PgConn) do finalize_treasury_packet(conn,
        movement.movement_id,
        config.chain,
        value) end)
  end
end

fn submit_committed(client :: Int,
  pool :: PoolHandle,
  config :: TreasuryWorkerConfig,
  original :: TreasuryMovement) -> TreasuryMovement!String do
  let movement = settle_known_outcome(client, pool, config, original)?
  if movement.state == 2 || movement.state == 3 || movement.state == 4 do
    return Ok(movement)
  end
  if movement.state != 1 do
    return Err("treasury_packet_not_committed")
  end
  let current = nonce_quorum(client, config)?
  let signed = signed_transaction(movement.packet, movement.transaction_signature)?
  if !Bytes.secure_equals(current.nonce.bytes, signed.recent_blockhash) do
    Repo.transaction(pool,
      fn(conn :: borrow PgConn) do block_treasury_history(conn,
        movement.movement_id,
        movement.transaction_signature) end)?
    return load_worker_movement(pool, movement.movement_id)
  end
  # One bounded submission per invocation. Lost acknowledgments and transport
  # errors preserve the exact packet; the next invocation reconciles first.
  let response = rpc_send(client,
    List.get(config.providers, 0),
    send_transaction_request(230,
      movement.packet,
      movement.transaction_signature,
      U64.parse("0")?)?,
    3000,
    4096)
  case response do
    Ok(value) -> if value.ok do
      sent_signature_from_response(value, movement.transaction_signature)?
    end
    Err(_) -> nil
  end
  settle_known_outcome(client, pool, config, movement)
end

fn run_worker(client :: Int,
  pool :: PoolHandle,
  config :: TreasuryWorkerConfig,
  id :: Bytes,
  wrapping :: borrow StorageKey,
  service_key :: Bytes,
  fee_payer :: borrow SigningPrivateKey,
  nonce_authority :: borrow SigningPrivateKey,
  now :: U64) -> TreasuryMovement!String do
  validate_worker(config)?
  let original = load_worker_movement(pool, id)?
  if Bytes.length(original.batch_id) != 0 do
    return Err("treasury_movement_batched")
  end
  if !Bytes.secure_equals(treasury_config_hash(config.chain)?, original.config_hash) do
    return Err("treasury_config_changed")
  end
  if original.state == 2 || original.state == 3 do
    return Ok(original)
  end
  if original.state != 0 do
    return submit_committed(client, pool, config, original)
  end
  let nonce = nonce_quorum(client, config)?
  let movement = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do reserve_treasury_message(conn, id, config.chain, nonce, now) end)?
  if movement.state != 0 do
    return submit_committed(client, pool, config, movement)
  end
  let sealed = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_treasury_deposit_sealed(conn, movement) end)?
  let deposit = unseal_treasury_deposit_key(sealed, movement, wrapping, service_key)?
  let packet = sign_treasury_packet(movement,
    config.chain,
    nonce,
    deposit,
    fee_payer,
    nonce_authority)?
  let signature = Bytes.slice(packet, 1, 64)?
  let committed = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do commit_treasury_packet(conn, id, packet, signature) end)?
  submit_committed(client, pool, config, committed)
end

# No background worker or network route enables this implicitly. The privileged
# operator owns these opaque keys and pins; no buyer supplies a chain proof Bool.
pub fn run_treasury_movement(pool :: PoolHandle,
  config :: TreasuryWorkerConfig,
  id :: Bytes,
  wrapping :: borrow StorageKey,
  service_key :: Bytes,
  fee_payer :: borrow SigningPrivateKey,
  nonce_authority :: borrow SigningPrivateKey,
  now :: U64) -> TreasuryMovement!String do
  let client = Http.client()
  let result = run_worker(client,
    pool,
    config,
    id,
    wrapping,
    service_key,
    fee_payer,
    nonce_authority,
    now)
  Http.client_close(client)
  result
end

pub struct TreasuryDepositQuote do
  quote :: CreditQuote
  price_observed_at :: U64
end

fn treasury_db_binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(output) -> Ok(output)
    _ -> Err("invalid_treasury_row")
  end
end

fn treasury_db_text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid_treasury_row")
  end
end

fn observe_and_reserve(client :: Int,
  pool :: PoolHandle,
  config :: TreasuryWorkerConfig,
  quote_id :: Bytes,
  signature :: Bytes,
  kind :: Int,
  now :: U64) -> Option<TreasuryMovement>!String do
  validate_worker(config)?
  if kind != 0 && kind != 1 do
    return Err("invalid_treasury_intent")
  end
  let prepared = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let rows = Pg.query_values(conn,
        "SELECT quote,price_observed_at::text FROM issuer_quotes WHERE quote_id=$1",
        [Binary(quote_id)])?
      if List.length(rows) != 1 do
        return Err("unknown_credit_quote")
      end
      let row = List.head(rows)
      Ok(TreasuryDepositQuote {
        quote: decode_credit_quote(treasury_db_binary(Map.get(row, "quote"))?)?,
        price_observed_at: U64.parse(treasury_db_text(Map.get(row, "price_observed_at"))?)?
      })
    end)?
  if prepared.quote.purpose != (if config.test_mode do
      1
    else
      0
    end) do
    return Err("treasury_quote_purpose_mismatch")
  end
  nonce_quorum(client, config)?
  let first = observe_credit_deposit(client,
    List.get(config.providers, 0),
    signature,
    240,
    prepared.quote,
    config.chain.mint,
    prepared.price_observed_at,
    now)?
  let second = observe_credit_deposit(client,
    List.get(config.providers, 1),
    signature,
    241,
    prepared.quote,
    config.chain.mint,
    prepared.price_observed_at,
    now)?
  let observation = case (first, second) do
    (None, None) -> return Ok(None)
    (Some(a), Some(b)) -> do
      if !Bytes.secure_equals(a.wire_sha256, b.wire_sha256)
        || a.payment.slot != b.payment.slot
        || a.payment.block_time != b.payment.block_time
        || a.payment.received_amount != b.payment.received_amount
        || !Bytes.secure_equals(a.payment.payer, b.payment.payer)
        || a.disposition != b.disposition do
        return Err("treasury_deposit_quorum_mismatch")
      end
      a
    end
    _ -> return Err("treasury_deposit_quorum_mismatch")
  end
  let delay = if kind == 1 do
    U64.parse("0")?
  else
    let random = case Crypto.random_bytes(4) do
      Ok(value) -> value
      Err(_) -> return Err("treasury_entropy_unavailable")
    end
    let number = U64.parse(Bytes.read_uint_le(random, 0, 4)?)?
    let divisor = U64.parse("3301")?
    U64.add(U64.parse("300")?,
      U64.subtract(number, U64.multiply(U64.divide(number, divisor)?, divisor)?)?)?
  end
  let hash = treasury_config_hash(config.chain)?
  let movement = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      record_credit_deposit(conn, observation)?
      reserve_treasury_movement(conn,
        quote_id,
        signature,
        kind,
        config.chain.treasury_owner,
        hash,
        now,
        delay)
    end)?
  Ok(Some(movement))
end

# An underpayment request supplies only quote and signature. This fetches both
# configured finalized chain proofs and derives its recipient from their payer.
pub fn observe_treasury_deposit(pool :: PoolHandle,
  config :: TreasuryWorkerConfig,
  quote_id :: Bytes,
  signature :: Bytes,
  kind :: Int,
  now :: U64) -> Option<TreasuryMovement>!String do
  let client = Http.client()
  let result = observe_and_reserve(client, pool, config, quote_id, signature, kind, now)
  Http.client_close(client)
  result
end

# Explicit operator action only; the normal worker never resets a proved failure.
# Reauthenticate the configured cluster/nonce before touching the durable state.
pub fn retry_treasury_movement(pool :: PoolHandle,
  config :: TreasuryWorkerConfig,
  id :: Bytes) -> TreasuryMovement!String do
  validate_worker(config)?
  let original = load_worker_movement(pool, id)?
  if Bytes.length(original.batch_id) != 0
    || !Bytes.secure_equals(original.config_hash, treasury_config_hash(config.chain)?) do
    return Err("treasury_intent_mismatch")
  end
  let client = Http.client()
  let checked = nonce_quorum(client, config)
  Http.client_close(client)
  checked?
  Repo.transaction(pool, fn(conn :: borrow PgConn) do retry_failed_treasury_movement(conn, id) end)
end
