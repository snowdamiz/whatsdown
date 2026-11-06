from Runtime.Treasury import TreasuryWorkerConfig, validate_worker, nonce_quorum, outcome_quorum
from Runtime.TreasurySigning import (
  load_treasury_deposit_sealed,
  unseal_treasury_deposit_key,
  check_treasury_key,
  sign_treasury_bytes
)
from Payment.Treasury import treasury_config_hash
from Payment.TreasuryBatch import treasury_batch_id, treasury_batch_message
from Payment.TreasuryBatchTypes import TreasuryPaymentBatch
from Storage.TreasuryBatch import (
  load_treasury_batch,
  reserve_treasury_batch,
  commit_treasury_batch,
  block_treasury_batch,
  finalize_treasury_batch,
  retry_failed_treasury_batch
)
from Solana.Read import Pubkey, Hash, rpc_send
from Solana.Nonce import NonceAccountState
from Solana.Tx import serialize_legacy_message
from Solana.TransactionWrite import serialize_signed_legacy_transaction
from Solana.TransactionSend import send_transaction_request, sent_signature_from_response

fn worker_batch(pool :: PoolHandle, id :: Bytes) -> TreasuryPaymentBatch!String do
  Repo.transaction(pool, fn(conn :: borrow PgConn) do load_treasury_batch(conn, id) end)
end

pub fn prepare_treasury_batch(pool :: PoolHandle,
  config :: TreasuryWorkerConfig,
  ids :: List<Bytes>,
  now :: U64) -> TreasuryPaymentBatch!String do
  validate_worker(config)?
  let id = treasury_batch_id(config.chain, ids)?
  let existing = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let rows = Pg.query_values(conn,
        "SELECT batch_id FROM issuer_treasury_batches WHERE batch_id=$1",
        [Binary(id)])?
      if List.length(rows) == 0 do
        Ok(None)
      else
        Ok(Some(load_treasury_batch(conn, id)?))
      end
    end)?
  case existing do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let client = Http.client()
  let nonce = nonce_quorum(client, config)
  Http.client_close(client)
  let snapshot = nonce?
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do reserve_treasury_batch(conn, config.chain, ids, snapshot, now) end)
end

fn settle_batch(client :: Int,
  pool :: PoolHandle,
  config :: TreasuryWorkerConfig,
  batch :: TreasuryPaymentBatch) -> TreasuryPaymentBatch!String do
  if batch.state == 0 || batch.state == 2 || batch.state == 3 do
    return Ok(batch)
  end
  case outcome_quorum(client, config, batch.transaction_signature)? do
    None -> Ok(batch)
    Some(value) -> Repo.transaction(pool,
      fn(conn :: borrow PgConn) do finalize_treasury_batch(conn,
        batch.batch_id,
        config.chain,
        value) end)
  end
end

pub fn reconcile_treasury_batch(pool :: PoolHandle,
  config :: TreasuryWorkerConfig,
  id :: Bytes) -> TreasuryPaymentBatch!String do
  validate_worker(config)?
  let batch = worker_batch(pool, id)?
  if !Bytes.secure_equals(batch.config_hash, treasury_config_hash(config.chain)?) do
    return Err("treasury_config_changed")
  end
  let client = Http.client()
  let result = settle_batch(client, pool, config, batch)
  Http.client_close(client)
  result
end

fn sign_batch(pool :: PoolHandle,
  config :: TreasuryWorkerConfig,
  batch :: TreasuryPaymentBatch,
  wrapping :: borrow StorageKey,
  service_key :: Bytes,
  fee_payer :: borrow SigningPrivateKey,
  nonce_authority :: borrow SigningPrivateKey) -> Bytes!String do
  if batch.state != 0 do
    return Err("treasury_packet_not_reserved")
  end
  let nonce = NonceAccountState {
    authority: Pubkey { bytes: config.chain.nonce_authority },
    nonce: Hash { bytes: batch.nonce_value },
    lamports_per_signature: U64.parse("0")?
  }
  let message = treasury_batch_message(batch, config.chain, nonce)?
  let encoded = serialize_legacy_message(message)?
  if !Bytes.secure_equals(encoded, batch.message) do
    return Err("treasury_batch_message_not_reserved")
  end
  check_treasury_key(fee_payer, config.chain.fee_payer)?
  check_treasury_key(nonce_authority, config.chain.nonce_authority)?
  # Only sealed byte blobs cross the database callback. Opaque key resources are
  # unsealed and dropped one at a time outside every transaction and RPC call.
  let sealed = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do Ok(for member in batch.members do
      load_treasury_deposit_sealed(conn, member)?
    end) end)?
  let signatures = for index in 0..message.header.num_required_signatures do
    let public = List.get(message.account_keys, index).bytes
    if Bytes.secure_equals(public, config.chain.fee_payer) do
      sign_treasury_bytes(fee_payer, encoded)?
    else if Bytes.secure_equals(public, config.chain.nonce_authority) do
      sign_treasury_bytes(nonce_authority, encoded)?
    else
      let indices = List.filter(for ordinal in 0..List.length(batch.members) do
          ordinal
        end,
        fn(ordinal) do Bytes.secure_equals(List.get(batch.members, ordinal).quote.deposit_owner,
          public) end)
      if List.length(indices) == 0 do
        return Err("unexpected_treasury_signer")
      end
      let ordinal = List.head(indices)
      let deposit = unseal_treasury_deposit_key(List.get(sealed, ordinal),
        List.get(batch.members, ordinal),
        wrapping,
        service_key)?
      sign_treasury_bytes(deposit, encoded)?
    end
  end
  serialize_signed_legacy_transaction(message, signatures)
end

fn submit_batch(client :: Int,
  pool :: PoolHandle,
  config :: TreasuryWorkerConfig,
  original :: TreasuryPaymentBatch) -> TreasuryPaymentBatch!String do
  let batch = settle_batch(client, pool, config, original)?
  if batch.state == 2 || batch.state == 3 || batch.state == 4 do
    return Ok(batch)
  end
  if batch.state != 1 do
    return Err("treasury_packet_not_committed")
  end
  let current = nonce_quorum(client, config)?
  if !Bytes.secure_equals(current.nonce.bytes, batch.nonce_value) do
    return Repo.transaction(pool,
      fn(conn :: borrow PgConn) do block_treasury_batch(conn,
        batch.batch_id,
        batch.transaction_signature) end)
  end
  let response = rpc_send(client,
    List.get(config.providers, 0),
    send_transaction_request(230, batch.packet, batch.transaction_signature, U64.parse("0")?)?,
    3000,
    4096)
  case response do
    Ok(value) -> if value.ok do
      sent_signature_from_response(value, batch.transaction_signature)?
    end
    Err(_) -> nil
  end
  settle_batch(client, pool, config, batch)
end

fn run_batch_worker(client :: Int,
  pool :: PoolHandle,
  config :: TreasuryWorkerConfig,
  id :: Bytes,
  wrapping :: borrow StorageKey,
  service_key :: Bytes,
  fee_payer :: borrow SigningPrivateKey,
  nonce_authority :: borrow SigningPrivateKey) -> TreasuryPaymentBatch!String do
  validate_worker(config)?
  let original = worker_batch(pool, id)?
  if !Bytes.secure_equals(original.config_hash, treasury_config_hash(config.chain)?) do
    return Err("treasury_config_changed")
  end
  if original.state == 2 || original.state == 3 do
    return Ok(original)
  end
  let committed = if original.state == 0 do
    let packet = sign_batch(pool,
      config,
      original,
      wrapping,
      service_key,
      fee_payer,
      nonce_authority)?
    let signature = Bytes.slice(packet, 1, 64)?
    Repo.transaction(pool,
      fn(conn :: borrow PgConn) do commit_treasury_batch(conn, id, packet, signature) end)?
  else
    original
  end
  submit_batch(client, pool, config, committed)
end

pub fn run_treasury_batch(pool :: PoolHandle,
  config :: TreasuryWorkerConfig,
  id :: Bytes,
  wrapping :: borrow StorageKey,
  service_key :: Bytes,
  fee_payer :: borrow SigningPrivateKey,
  nonce_authority :: borrow SigningPrivateKey,
  now :: U64) -> TreasuryPaymentBatch!String do
  let client = Http.client()
  let result = run_batch_worker(client,
    pool,
    config,
    id,
    wrapping,
    service_key,
    fee_payer,
    nonce_authority)
  Http.client_close(client)
  result
end

# Explicit operator retry only after proved finalized failure. Membership and all
# previous packet/cost evidence remain immutable; current nonce is read afresh.
pub fn retry_treasury_batch(pool :: PoolHandle,
  config :: TreasuryWorkerConfig,
  id :: Bytes) -> TreasuryPaymentBatch!String do
  validate_worker(config)?
  let client = Http.client()
  let nonce = nonce_quorum(client, config)
  Http.client_close(client)
  let snapshot = nonce?
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do retry_failed_treasury_batch(conn, id, config.chain, snapshot) end)
end
