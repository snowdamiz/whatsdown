##! Solana JSON-RPC for the issuer: reading payments at `finalized`, and
##! building, signing and sending the sweep and refund transactions.
##!
##! A payment is read from the transaction's balances (jsonParsed), as Solana
##! Pay's validateTransfer does: SOL from the deposit's pre/post lamports, USDC
##! from the token balances owned by the deposit address in the USDC mint.

from Issuer.Derivation import DepositKey, issuer_sign
from Solana.Read import Hash, Pubkey, hash_value, pubkey
from Solana.Tx import AccountMeta, Instruction, compile_legacy_message, serialize_legacy_message

pub struct ChainPayment do
  signature :: String
  received :: Int
  payer :: String
  payer_account :: String
  deposit_account :: String
  paid_at_s :: Int
end

pub type ChainLookup do
  ChainPaid(payment :: ChainPayment)
  ChainPending
  ChainNotPayment
end

fn field(value :: Json, name :: String) -> Json!String do
  Json.object_get(value, name)
end

fn text(value :: Json, name :: String) -> String!String do
  Json.as_string(field(value, name)?)
end

fn number(value :: Json, name :: String) -> Int!String do
  Json.as_int(field(value, name)?)
end

## One JSON-RPC call; the result, or Err on a transport, HTTP or RPC error.

pub fn issuer_rpc(url :: String, method :: String, params :: String) -> Json!String do
  let body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":"
    <> Json.encode_string(method)
    <> ",\"params\":"
    <> params
    <> "}"
  let answer = Http.build(:post, url)
    |> Http.header("Content-Type", "application/json")
    |> Http.body(body)
    |> Http.timeout(15000)
    |> Http.max_response_bytes(4194304)
    |> Http.send()
  case answer do
    Err(error) -> Err("solana rpc unreachable: #{error}")
    Ok(response) -> if response.status != 200 do
      Err("solana rpc answered #{response.status}")
    else
      let parsed = Json.parse(response.body)?
      case Json.object_get(parsed, "error") do
        Ok(error) -> if Json.is_null(error) do
          field(parsed, "result")
        else
          Err("solana rpc error: #{Json.encode(error)}")
        end
        Err(_) -> field(parsed, "result")
      end
    end
  end
end

fn list(value :: Json) -> List<Json>!String do
  let count = Json.array_length(value)?
  let values = for index in 0..count do
    Json.array_get(value, index)?
  end
  Ok(values)
end

fn account_keys(transaction :: Json) -> List<String>!String do
  let keys = list(field(field(field(transaction, "transaction")?, "message")?, "accountKeys")?)?
  let values = for key in keys do
    text(key, "pubkey")?
  end
  Ok(values)
end

fn index_of(values :: List<String>, wanted :: String, index :: Int) -> Int do
  if index >= List.length(values) do
    -1
  else if List.get(values, index) == wanted do
    index
  else
    index_of(values, wanted, index + 1)
  end
end

fn sol_received(meta :: Json, keys :: List<String>, deposit :: String) -> Int!String do
  let index = index_of(keys, deposit, 0)
  if index < 0 do
    Ok(0)
  else
    let before = Json.as_int(Json.array_get(field(meta, "preBalances")?, index)?)?
    let later = Json.as_int(Json.array_get(field(meta, "postBalances")?, index)?)?
    Ok(later - before)
  end
end

struct TokenBalance do
  account_index :: Int
  mint :: String
  owner :: String
  amount :: Int
end

fn token_balances(meta :: Json, name :: String) -> List<TokenBalance>!String do
  let entries = case Json.object_get(meta, name) do
    Err(_) -> Ok(List.new())
    Ok(value) -> if Json.is_null(value) do
      Ok(List.new())
    else
      list(value)
    end
  end?
  collect_balances(entries, 0, List.new())
end

fn token_balance(entry :: Json) -> TokenBalance!String do
  let amount = case String.to_int(text(field(entry, "uiTokenAmount")?, "amount")?) do
    Some(parsed) -> Ok(parsed)
    None -> Err("invalid token amount")
  end?
  Ok(TokenBalance {
    account_index: number(entry, "accountIndex")?,
    mint: text(entry, "mint")?,
    owner: text(entry, "owner")?,
    amount: amount
  })
end

fn collect_balances(entries :: List<Json>,
  index :: Int,
  output :: List<TokenBalance>) -> List<TokenBalance>!String do
  if index >= List.length(entries) do
    Ok(output)
  else
    collect_balances(entries,
      index + 1,
      List.append(output, token_balance(List.get(entries, index))?))
  end
end

fn balance_of(values :: List<TokenBalance>, account_index :: Int) -> Int do
  case List.find(values, fn value -> value.account_index == account_index end) do
    Some(found) -> found.amount
    None -> 0
  end
end

fn sol_payment(signature :: String,
  meta :: Json,
  keys :: List<String>,
  deposit :: String,
  paid_at_s :: Int) -> ChainLookup!String do
  let received = sol_received(meta, keys, deposit)?
  if received <= 0 do
    Ok(ChainNotPayment)
  else
    Ok(ChainPaid(ChainPayment {
      signature: signature,
      received: received,
      payer: List.get(keys, 0),
      payer_account: List.get(keys, 0),
      deposit_account: deposit,
      paid_at_s: paid_at_s
    }))
  end
end

fn usdc_payment(signature :: String,
  meta :: Json,
  keys :: List<String>,
  deposit :: String,
  mint :: String,
  paid_at_s :: Int) -> ChainLookup!String do
  let before = List.filter(token_balances(meta, "preTokenBalances")?,
    fn value -> value.mint == mint end)
  let later = List.filter(token_balances(meta, "postTokenBalances")?,
    fn value -> value.mint == mint end)
  let credited = List.filter(later, fn value -> value.owner == deposit end)
  let received = List.reduce(credited,
    0,
    fn total, value -> total + value.amount - balance_of(before, value.account_index) end)
  let payer = List.find(before,
    fn value -> value.owner != deposit && balance_of(later, value.account_index) < value.amount end)
  case (credited, payer) do
    ([deposit_balance], Some(source)) -> if received <= 0 do
      Ok(ChainNotPayment)
    else
      Ok(ChainPaid(ChainPayment {
        signature: signature,
        received: received,
        payer: source.owner,
        payer_account: List.get(keys, source.account_index),
        deposit_account: List.get(keys, deposit_balance.account_index),
        paid_at_s: paid_at_s
      }))
    end
    _ -> Ok(ChainNotPayment)
  end
end

## What finalized transaction `signature` paid to `deposit` in `asset` (sol or
## usdc): pending while it is not finalized, not a payment when it failed or
## moved nothing to the deposit.

pub fn issuer_solana_payment(rpc_url :: String,
  usdc_mint :: String,
  deposit :: String,
  asset :: String,
  signature :: String) -> ChainLookup!String do
  let result = issuer_rpc(rpc_url,
    "getTransaction",
    "["
      <> Json.encode_string(signature)
      <> ",{\"encoding\":\"jsonParsed\",\"commitment\":\"finalized\",\"maxSupportedTransactionVersion\":0}]")?
  if Json.is_null(result) do
    return Ok(ChainPending)
  end
  let meta = field(result, "meta")?
  if !Json.is_null(field(meta, "err")?) do
    return Ok(ChainNotPayment)
  end
  let keys = account_keys(result)?
  let paid_at_s = number(result, "blockTime")?
  if asset == "sol" do
    sol_payment(signature, meta, keys, deposit, paid_at_s)
  else
    usdc_payment(signature, meta, keys, deposit, usdc_mint, paid_at_s)
  end
end

## Recent finalized transactions touching `deposit`, newest first, without
## the failed ones: how a quote paid by an external wallet is found.

pub fn issuer_deposit_signatures(rpc_url :: String, deposit :: String) -> List<String>!String do
  let result = issuer_rpc(rpc_url,
    "getSignaturesForAddress",
    "[" <> Json.encode_string(deposit) <> ",{\"limit\":20,\"commitment\":\"finalized\"}]")?
  let entries = list(result)?
  let succeeded = List.filter(entries,
    fn entry -> case Json.object_get(entry, "err") do
      Ok(error) -> Json.is_null(error)
      Err(_) -> true
    end end)
  let signatures = for entry in succeeded do
    text(entry, "signature")?
  end
  Ok(signatures)
end

pub fn issuer_balance(rpc_url :: String, address :: String) -> Int!String do
  let result = issuer_rpc(rpc_url,
    "getBalance",
    "[" <> Json.encode_string(address) <> ",{\"commitment\":\"finalized\"}]")?
  number(result, "value")
end

pub fn issuer_token_balance(rpc_url :: String, account :: String) -> Int!String do
  let result = issuer_rpc(rpc_url,
    "getTokenAccountBalance",
    "[" <> Json.encode_string(account) <> ",{\"commitment\":\"finalized\"}]")?
  case String.to_int(text(field(result, "value")?, "amount")?) do
    Some(amount) -> Ok(amount)
    None -> Err("invalid token balance")
  end
end

fn latest_blockhash(rpc_url :: String) -> Hash!String do
  let result = issuer_rpc(rpc_url, "getLatestBlockhash", "[{\"commitment\":\"finalized\"}]")?
  hash_value(text(field(result, "value")?, "blockhash")?)
end

fn u64_le(value :: Int, width :: Int) -> Bytes!String do
  Bytes.write_uint_le(Int.to_string(value), width)
end

fn meta(key :: String, signer :: Bool, writable :: Bool) -> AccountMeta!String do
  Ok(AccountMeta { pubkey: pubkey(key)?, signer: signer, writable: writable })
end

## System Program transfer of `lamports` from `from` (signer) to `to`.

pub fn issuer_sol_transfer(from :: String, to :: String, lamports :: Int) -> Instruction!String do
  Ok(Instruction {
    program_id: pubkey("11111111111111111111111111111111")?,
    accounts: [meta(from, true, true)?, meta(to, false, true)?],
    data: Bytes.concat(u64_le(2, 4)?, u64_le(lamports, 8)?)?
  })
end

## SPL Token TransferChecked of `amount` (6 decimals, USDC).

pub fn issuer_usdc_transfer(source :: String,
  mint :: String,
  destination :: String,
  owner :: String,
  amount :: Int) -> Instruction!String do
  let data = Bytes.concat(Bytes.concat(Bytes.from_hex("0c")?, u64_le(amount, 8)?)?,
    Bytes.from_hex("06")?)?
  Ok(Instruction {
    program_id: pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?,
    accounts: [
      meta(source, false, true)?,
      meta(mint, false, false)?,
      meta(destination, false, true)?,
      meta(owner, true, false)?
    ],
    data: data
  })
end

## SPL Token CloseAccount: the emptied deposit token account's rent goes to
## `destination` (the fee payer).

pub fn issuer_close_token_account(account :: String,
  destination :: String,
  owner :: String) -> Instruction!String do
  Ok(Instruction {
    program_id: pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?,
    accounts: [
      meta(account, false, true)?,
      meta(destination, false, true)?,
      meta(owner, true, false)?
    ],
    data: Bytes.from_hex("09")?
  })
end

fn short_length(value :: Int) -> Bytes!String do
  let encoded = if value < 128 do
    Bytes.from_list([value])
  else
    Bytes.from_list([value % 128 + 128, value / 128])
  end
  case encoded do
    Err(_) -> Err("invalid signature count")
    Ok(output)
  end
end

fn signatures_for(keys :: List<Pubkey>,
  count :: Int,
  signers :: List<DepositKey>,
  message :: Bytes,
  index :: Int,
  output :: Bytes) -> Bytes!String do
  if index >= count do
    Ok(output)
  else
    let wanted = List.get(keys, index)
    let signer = case List.find(signers,
      fn key -> Bytes.secure_equals(key.public_key, wanted.bytes) end) do
      None -> Err("a required signer is missing")
      Some(found) -> Ok(found)
    end?
    signatures_for(keys,
      count,
      signers,
      message,
      index + 1,
      Bytes.concat(output, issuer_sign(signer, message)?)?)
  end
end

## A signed legacy transaction: `payer` pays the fee, every signer the
## instructions need is among `signers`.

pub fn issuer_signed_transaction(payer :: DepositKey,
  signers :: List<DepositKey>,
  blockhash :: Hash,
  instructions :: List<Instruction>) -> Bytes!String do
  let message = compile_legacy_message(Pubkey { bytes: payer.public_key }, blockhash, instructions)?
  let bytes = serialize_legacy_message(message)?
  let count = message.header.num_required_signatures
  let signatures = signatures_for(message.account_keys,
    count,
    [payer] ++ signers,
    bytes,
    0,
    Bytes.empty())?
  let transaction = Bytes.concat(Bytes.concat(short_length(count)?, signatures)?, bytes)?
  if Bytes.length(transaction) > 1232 do
    Err("transaction exceeds 1232 bytes")
  else
    Ok(transaction)
  end
end

## Signs and sends a transaction at the latest finalized blockhash; returns
## its signature (base58), which is also its ID.

pub fn issuer_send(rpc_url :: String,
  payer :: DepositKey,
  signers :: List<DepositKey>,
  instructions :: List<Instruction>) -> String!String do
  let transaction = issuer_signed_transaction(payer,
    signers,
    latest_blockhash(rpc_url)?,
    instructions)?
  let result = issuer_rpc(rpc_url,
    "sendTransaction",
    "["
      <> Json.encode_string(Bytes.to_base64(transaction))
      <> ",{\"encoding\":\"base64\",\"preflightCommitment\":\"finalized\"}]")?
  Json.as_string(result)
end

## finalized, failed, or pending (unknown yet, or not final).

pub fn issuer_signature_status(rpc_url :: String, signature :: String) -> String!String do
  let result = issuer_rpc(rpc_url,
    "getSignatureStatuses",
    "[[" <> Json.encode_string(signature) <> "],{\"searchTransactionHistory\":true}]")?
  let status = Json.array_get(field(result, "value")?, 0)?
  if Json.is_null(status) do
    Ok("pending")
  else if !Json.is_null(field(status, "err")?) do
    Ok("failed")
  else
    case Json.object_get(status, "confirmationStatus") do
      Ok(value) -> if Json.as_string(value) == Ok("finalized") do
        Ok("finalized")
      else
        Ok("pending")
      end
      Err(_) -> Ok("pending")
    end
  end
end
