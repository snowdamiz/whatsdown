from Payment.BtcConversionConfig import BtcConversionConfig, validate_btc_conversion_config
from Payment.BitcoinOracle import BtcPrice, btc_price_from_account
from Payment.TreasuryOutcome import movement_index, movement_token
from Solana.Read import (
  Pubkey,
  rpc_request,
  rpc_send,
  get_account_info_request,
  account_from_response,
  spl_token_program
)
from Solana.TransactionRead import FinalizedTransaction, get_finalized_transaction
from Solana.Tx import Instruction

pub struct BtcArrival do
  amount :: U64
  slot :: U64
  signature :: Bytes
  receipt :: Bytes
end

struct OracleVote do
  digest :: Bytes
  price :: BtcPrice
end

fn genesis(client :: Int,
  url :: String,
  config :: BtcConversionConfig,
  id :: Int) -> Result<(), String> do
  let response = rpc_send(client, url, rpc_request(id, "getGenesisHash", "[]")?, 5000, 4096)?
  if !response.ok
    || Bytes.from_base58(Json.as_string(Json.parse(response.result_json)?)?)? != config.cluster do
    return Err("btc_conversion_cluster_mismatch")
  end
  Ok(nil)
end

fn oracle_vote(client :: Int,
  url :: String,
  config :: BtcConversionConfig,
  now :: U64) -> OracleVote!String do
  genesis(client, url, config, 7100)?
  let value = account_from_response(rpc_send(client,
    url,
    get_account_info_request(7101, Pubkey { bytes: config.oracle_account }, "finalized")?,
    5000,
    8192)?)?
  let price = btc_price_from_account(value, now)?
  Ok(OracleVote { digest: Crypto.sha256(value.account.data), price: price })
end

pub fn btc_oracle_quorum(config :: BtcConversionConfig, now :: U64) -> BtcPrice!String do
  validate_btc_conversion_config(config)?
  let client = Http.client()
  let votes = for url in config.providers do
    case oracle_vote(client, url, config, now) do
      Ok(value) -> Some(value)
      Err(_) -> None
    end
  end
  Http.client_close(client)
  for i in 0..3 do
    case List.get(votes, i) do
      None -> nil
      Some(first) -> do
        case oracle_peer(votes, first, i + 1) do
          Some(price) -> return Ok(price)
          None -> nil
        end
      end
    end
  end
  Err("btc_independent_fresh_oracle_quorum_unavailable")
end

fn transfer_amount(instruction :: Instruction, config :: BtcConversionConfig) -> U64!String do
  if instruction.program_id.bytes != spl_token_program()?.bytes do
    return U64.parse("0")
  end
  let data = instruction.data
  if Bytes.length(data) < 1 do
    return Err("btc_arrival_invalid_token_instruction")
  end
  let tag = Bytes.get(data, 0)?
  if tag != 3 && tag != 12 do
    # ATA initialization/synchronization are not credited as transfers.
    return U64.parse("0")
  end
  let destination = if tag == 3 do
    1
  else
    2
  end
  if List.length(instruction.accounts) < destination + 1 do
    return Err("btc_arrival_token_accounts")
  end
  if List.head(instruction.accounts).pubkey.bytes == config.custody do
    return Err("btc_arrival_outgoing_custody_transfer")
  end
  if List.get(instruction.accounts, destination).pubkey.bytes != config.custody do
    return U64.parse("0")
  end
  if (tag == 3 && Bytes.length(data) != 9)
    || (tag == 12
      && (Bytes.length(data) != 10
        || Bytes.get(data, 9)? != 6
        || List.get(instruction.accounts, 1).pubkey.bytes != config.mint)) do
    return Err("btc_arrival_invalid_transfer")
  end
  U64.parse(Bytes.read_uint_le(data, 1, 8)?)
end

fn sum_transfers(rows :: List<Instruction>,
  config :: BtcConversionConfig,
  at :: Int,
  total :: U64) -> U64!String do
  if at == List.length(rows) do
    return Ok(total)
  end
  sum_transfers(rows, config, at + 1, U64.add(total, transfer_amount(List.get(rows, at), config)?)?)
end

pub fn btc_arrival_from_transaction(config :: BtcConversionConfig,
  intent :: Bytes,
  profile :: Bytes,
  withdrawal_id :: String,
  expected :: U64,
  minimum :: U64,
  reserved_at :: U64,
  transaction :: FinalizedTransaction,
  order_draft_hash :: Bytes,
  now :: U64) -> BtcArrival!String do
  validate_btc_conversion_config(config)?
  if Bytes.length(intent) != 32
    || Bytes.length(profile) != 32
    || transaction.slot == U64.parse("0")?
    || transaction.inner_instruction_count < 0 do
    return Err("btc_arrival_missing_execution_metadata")
  end
  let time = case transaction.block_time do
    Some(value) -> value
    None -> return Err("btc_arrival_missing_time")
  end
  if Bytes.length(order_draft_hash) != 32
    || time < 0
    || U64.compare(U64.parse(Int.to_string(time))?, U64.add(now, U64.parse("30")?)?) > 0
    || U64.compare(U64.parse(Int.to_string(time))?, reserved_at) < 0 do
    return Err("btc_arrival_predates_conversion")
  end
  let index = movement_index(transaction, config.custody)?
  let before = movement_token(transaction.pre_token_balances,
    index,
    config.owner,
    config.mint,
    true)?
  let current = movement_token(transaction.post_token_balances,
    index,
    config.owner,
    config.mint,
    false)?
  let delta = U64.subtract(current, before)?
  let all = List.concat(transaction.signed.instructions,
    List.flat_map(transaction.inner_instructions, fn(group) do group.instructions end))
  let transferred = sum_transfers(all, config, 0, U64.parse("0")?)?
  if delta != expected
    || delta != transferred
    || delta == U64.parse("0")?
    || U64.compare(delta, minimum) < 0 do
    return Err("btc_arrival_actual_delta_mismatch")
  end
  let receipt = Bytes.from_hex("4d434232"
    <> Bytes.to_hex(intent)
    <> Bytes.to_hex(profile)
    <> Bytes.to_hex(transaction.signed.signature)
    <> Bytes.to_hex(Crypto.sha256(transaction.signed.wire))
    <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(transaction.slot), 8)?)
    <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(delta), 8)?)
    <> Bytes.to_hex(config.mint)
    <> Bytes.to_hex(config.owner)
    <> Bytes.to_hex(config.custody)
    <> Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(withdrawal_id)))
    <> Bytes.to_hex(order_draft_hash))?
  Ok(BtcArrival {
    amount: delta,
    slot: transaction.slot,
    signature: transaction.signed.signature,
    receipt: receipt
  })
end

fn arrival_vote(client :: Int,
  url :: String,
  config :: BtcConversionConfig,
  intent :: Bytes,
  profile :: Bytes,
  withdrawal :: String,
  signature :: Bytes,
  expected :: U64,
  minimum :: U64,
  reserved_at :: U64,
  order_draft_hash :: Bytes,
  now :: U64) -> BtcArrival!String do
  genesis(client, url, config, 7200)?
  let transaction = case get_finalized_transaction(client, url, signature, 7201, 10000, 262144)? do
    Some(value) -> value
    None -> return Err("btc_arrival_not_finalized")
  end
  btc_arrival_from_transaction(config,
    intent,
    profile,
    withdrawal,
    expected,
    minimum,
    reserved_at,
    transaction,
    order_draft_hash,
    now)
end

pub fn btc_arrival_quorum(config :: BtcConversionConfig,
  intent :: Bytes,
  profile :: Bytes,
  withdrawal :: String,
  signature :: Bytes,
  expected :: U64,
  minimum :: U64,
  reserved_at :: U64,
  order_draft_hash :: Bytes,
  now :: U64) -> BtcArrival!String do
  validate_btc_conversion_config(config)?
  let client = Http.client()
  let votes = for url in config.providers do
    case arrival_vote(client,
      url,
      config,
      intent,
      profile,
      withdrawal,
      signature,
      expected,
      minimum,
      reserved_at,
      order_draft_hash,
      now) do
      Ok(value) -> Some(value)
      Err(_) -> None
    end
  end
  Http.client_close(client)
  for i in 0..3 do
    case List.get(votes, i) do
      Some(first) -> do
        if arrival_peer(votes, first, i + 1) do
          return Ok(first)
        end
      end
      None -> nil
    end
  end
  Err("btc_finalized_actual_output_quorum_unavailable")
end

fn oracle_peer(votes :: List<Option<OracleVote>>,
  first :: OracleVote,
  start :: Int) -> Option<BtcPrice> do
  for j in start..3 do
    case List.get(votes, j) do
      Some(second) -> if first.digest == second.digest
        && first.price.usd_micros == second.price.usd_micros
        && first.price.observed_at == second.price.observed_at do
        return Some(first.price)
      end
      None -> nil
    end
  end
  None
end

fn arrival_peer(votes :: List<Option<BtcArrival>>, first :: BtcArrival, start :: Int) -> Bool do
  for j in start..3 do
    case List.get(votes, j) do
      Some(second) -> if first.receipt == second.receipt do
        return true
      end
      None -> nil
    end
  end
  false
end
