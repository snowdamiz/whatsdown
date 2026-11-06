from Transparency.TokenBurnRead import (
  TokenBurnReadPins,
  TokenBurnState,
  token_burn_read_keys,
  decode_token_burn_snapshot,
  token_burn_rpc_sources
)
from Transparency.TokenBurnCarryRead import (
  TokenBurnCarryState,
  token_burn_carry_read_keys,
  decode_token_burn_carry_snapshot
)
from Solana.Read import (
  Pubkey,
  Hash,
  LatestBlockhash,
  OptionalAccountSlicesAtSlot,
  RpcResponse,
  rpc_request,
  rpc_send,
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response
)

pub struct TokenBurnBank do
  program :: Pubkey
  custody :: TokenBurnCarryState
  market :: Option<TokenBurnState>
  height :: U64
  blockhash :: Hash
  tip :: LatestBlockhash
  expired_hash :: Option<Hash>
  digest :: Bytes
end

pub fn token_burn_worker_keys(pins :: TokenBurnReadPins, epoch :: U64) -> List<Pubkey>!String do
  Ok(token_burn_read_keys(pins, epoch)? ++ token_burn_carry_read_keys(pins, epoch)?)
end

fn bank_cat(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts, Ok(Bytes.empty()), fn(result, value) do Bytes.concat(result?, value) end)
end

# JSON integer metadata must be numeric, not quoted/coerced, fractional or exponential.
pub fn token_burn_rpc_integer(value :: Json) -> U64!String do
  let encoded = Json.encode(value)
  let bytes = Bytes.from_utf8(encoded)
  if Bytes.length(bytes) < 1 || Bytes.length(bytes) > 20 do
    return Err("invalid_burn_bank_integer")
  end
  for index in 0..Bytes.length(bytes) do
    let digit = Bytes.get(bytes, index)?
    if digit < 48 || digit > 57 do
      return Err("invalid_burn_bank_integer")
    end
  end
  U64.parse(encoded)
end

fn bank_integer(root :: Json, name :: String) -> U64!String do
  token_burn_rpc_integer(Json.object_get(root, name)?)
end

fn bank_hash(root :: Json, name :: String) -> Hash!String do
  let text = Json.as_string(Json.object_get(root, name)?)?
  let bytes = Bytes.from_base58(text)?
  if Bytes.length(bytes) != 32 || Bytes.to_base58(bytes) != text do
    Err("invalid_burn_bank_hash")
  else
    Ok(Hash { bytes: bytes })
  end
end

fn bank_result(response :: RpcResponse) -> Json!String do
  if !response.ok do
    Err("burn_bank_rpc_error")
  else
    Json.parse(response.result_json)
  end
end

pub fn token_burn_worker_tip(response :: RpcResponse, minimum :: U64) -> LatestBlockhash!String do
  let root = bank_result(response)?
  let slot = bank_integer(Json.object_get(root, "context")?, "slot")?
  let value = Json.object_get(root, "value")?
  let height = bank_integer(value, "lastValidBlockHeight")?
  if slot == U64.parse("0")? || U64.compare(slot, minimum) < 0 || height == U64.parse("0")? do
    return Err("invalid_burn_bank_tip")
  end
  Ok(LatestBlockhash {
    context_slot: slot,
    blockhash: bank_hash(value, "blockhash")?,
    last_valid_block_height: height
  })
end

# The getBlock request is for exactly the authenticated account context slot.
# A standalone getBlockHeight result has no bank context and cannot authorize replacement.
pub fn token_burn_worker_bank(pins :: TokenBurnReadPins,
  epoch :: U64,
  minimum :: U64,
  tip :: LatestBlockhash,
  snapshot :: OptionalAccountSlicesAtSlot,
  block :: RpcResponse) -> TokenBurnBank!String do
  if List.length(snapshot.accounts) != 31
    || U64.compare(snapshot.slot, minimum) < 0
    || U64.compare(snapshot.slot, tip.context_slot) < 0 do
    return Err("invalid_burn_bank_context")
  end
  let keys = token_burn_worker_keys(pins, epoch)?
  # Repeated canonical roles in one RPC bank must have identical original metadata
  # and prefixes, even if a difference would be discarded by a typed projection.
  for first in 0..31 do
    for second in 0..first do
      if List.get(keys, first) == List.get(keys, second)
        && List.get(snapshot.accounts, first) != List.get(snapshot.accounts, second) do
        return Err("burn_bank_contradictory_account")
      end
    end
  end
  let custody_accounts = for value in List.drop(snapshot.accounts, 19) do
    case value do
      None
      Some(value) -> Some(%{value |
        info: %{value.info |
          data: Bytes.slice(value.info.data,
            0,
            (if Bytes.length(value.info.data) > 2240 do
              2240
            else
              Bytes.length(value.info.data)
            end))?
        }
      })
    end
  end
  let custody = decode_token_burn_carry_snapshot(pins,
    epoch,
    minimum,
    OptionalAccountSlicesAtSlot { slot: snapshot.slot, accounts: custody_accounts })?
  let frame = case custody.frame do
    None -> return Err("burn_bank_week_missing")
    Some(value) -> value
  end
  # Closing custody never depends on an available oracle/DEX. Active execution does.
  let end_time = U64.multiply(U64.add(epoch, U64.parse("1")?)?, U64.parse("604800")?)?
  let market = if frame.closed
    || U64.compare(U64.parse(Int.to_string(custody.timestamp))?, end_time) >= 0 do
    None
  else
    let value = decode_token_burn_snapshot(pins,
      epoch,
      minimum,
      OptionalAccountSlicesAtSlot {
        slot: snapshot.slot,
        accounts: List.take(snapshot.accounts, 19)
      })?
    if value.profile != custody.profile
      || value.week != Some(frame.week)
      || value.timestamp != custody.timestamp do
      return Err("burn_bank_cross_read_mismatch")
    end
    Some(value)
  end
  let raw = bank_result(block)?
  let height = bank_integer(raw, "blockHeight")?
  let parent = bank_integer(raw, "parentSlot")?
  let time = bank_integer(raw, "blockTime")?
  let hash = bank_hash(raw, "blockhash")?
  bank_hash(raw, "previousBlockhash")?
  if height == U64.parse("0")?
    || U64.compare(parent, snapshot.slot) >= 0
    || time != U64.parse(Int.to_string(custody.timestamp))?
    || U64.compare(height, tip.last_valid_block_height) > 0 do
    return Err("invalid_burn_bank_block")
  end
  let pieces = for index in 0..31 do
    let account = case List.get(snapshot.accounts, index) do
      None -> Bytes.from_hex("00")?
      Some(value) -> bank_cat([
        Bytes.from_hex(if value.info.executable do
          "0101"
        else
          "0100"
        end)?,
        value.info.owner.bytes,
        Bytes.write_uint_le(U64.to_string(value.space), 8)?,
        Bytes.write_uint_le(U64.to_string(value.info.lamports), 8)?,
        Crypto.sha256(value.info.data)
      ])?
    end
    bank_cat([List.get(keys, index).bytes, account])?
  end
  let digest = Crypto.sha256(bank_cat([
    Bytes.from_utf8("morse-token-burn-worker-bank-v1"),
    Bytes.write_uint_le(U64.to_string(snapshot.slot), 8)?,
    Bytes.from_utf8(Json.encode(raw)),
    Bytes.write_uint_le(U64.to_string(tip.context_slot), 8)?,
    tip.blockhash.bytes,
    Bytes.write_uint_le(U64.to_string(tip.last_valid_block_height), 8)?,
    bank_cat(pieces)?
  ])?)
  Ok(TokenBurnBank {
    program: pins.program,
    custody: custody,
    market: market,
    height: height,
    blockhash: hash,
    tip: tip,
    expired_hash: None,
    digest: digest
  })
end

fn bank_expired_hash(bank :: TokenBurnBank,
  hash :: Hash,
  response :: RpcResponse) -> TokenBurnBank!String do
  let root = bank_result(response)?
  let slot = bank_integer(Json.object_get(root, "context")?, "slot")?
  let valid = Json.as_bool(Json.object_get(root, "value")?)?
  if valid || slot != bank.custody.context_slot do
    return Err("token_burn_hash_not_proven_expired")
  end
  Ok(%{bank |
    expired_hash: Some(hash),
    digest: Crypto.sha256(bank_cat([
      Bytes.from_utf8("morse-token-burn-expired-hash-v1"),
      bank.digest,
      hash.bytes,
      Bytes.write_uint_le(U64.to_string(slot), 8)?,
      Bytes.from_hex("00")?
    ])?)
  })
end

fn bank_from(client :: Int,
  url :: String,
  pins :: TokenBurnReadPins,
  epoch :: U64,
  minimum :: U64,
  expired :: Option<Hash>) -> TokenBurnBank!String do
  let tip_request = rpc_request(30,
    "getLatestBlockhash",
    "[{\"commitment\":\"finalized\",\"minContextSlot\":" <> U64.to_string(minimum) <> "}]")?
  let tip = token_burn_worker_tip(rpc_send(client, url, tip_request, 3000, 4096)?, minimum)?
  let context = if U64.compare(tip.context_slot, minimum) > 0 do
    tip.context_slot
  else
    minimum
  end
  let request = get_multiple_accounts_slice_request(31,
    token_burn_worker_keys(pins, epoch)?,
    "finalized",
    0,
    5728,
    Some(context))?
  let snapshot = optional_accounts_slice_from_response(rpc_send(client,
    url,
    request,
    3000,
    262144)?)?
  if snapshot.slot == U64.parse("0")? || U64.compare(snapshot.slot, context) < 0 do
    return Err("invalid_burn_bank_context")
  end
  let block_request = rpc_request(32,
    "getBlock",
    "["
      <> U64.to_string(snapshot.slot)
      <> ",{\"commitment\":\"finalized\",\"transactionDetails\":\"none\",\"rewards\":false,\"maxSupportedTransactionVersion\":0}]")?
  let bank = token_burn_worker_bank(pins,
    epoch,
    minimum,
    tip,
    snapshot,
    rpc_send(client, url, block_request, 3000, 4096)?)?
  case expired do
    None -> Ok(bank)
    Some(hash) -> do
      let request = rpc_request(33,
        "isBlockhashValid",
        "["
          <> Json.encode_string(Bytes.to_base58(hash.bytes))
          <> ",{\"commitment\":\"finalized\",\"minContextSlot\":"
          <> U64.to_string(snapshot.slot)
          <> "}]")?
      bank_expired_hash(bank, hash, rpc_send(client, url, request, 3000, 4096)?)
    end
  end
end

pub fn read_token_burn_worker_from(client :: Int,
  url :: String,
  pins :: TokenBurnReadPins,
  epoch :: U64,
  minimum :: U64) -> TokenBurnBank!String do
  bank_from(client, url, pins, epoch, minimum, None)
end

fn bank_agree(first :: TokenBurnBank!String,
  second :: TokenBurnBank!String) -> Option<TokenBurnBank> do
  case first do
    Err(_) -> None
    Ok(a) -> case second do
      Err(_) -> None
      Ok(b) -> if a.digest == b.digest do
        Some(a)
      else
        None
      end
    end
  end
end

# A disagreement or unavailable bank never produces a signing/replacement authorization.
fn bank_quorum(client :: Int,
  urls :: List<String>,
  test_mode :: Bool,
  pins :: TokenBurnReadPins,
  epoch :: U64,
  minimum :: U64,
  expired :: Option<Hash>) -> TokenBurnBank!String do
  token_burn_rpc_sources(urls, test_mode)?
  let first = bank_from(client, List.get(urls, 0), pins, epoch, minimum, expired)
  let second = bank_from(client, List.get(urls, 1), pins, epoch, minimum, expired)
  case bank_agree(first, second) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let third = bank_from(client, List.get(urls, 2), pins, epoch, minimum, expired)
  case bank_agree(first, third) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  case bank_agree(second, third) do
    Some(value) -> Ok(value)
    None -> Err("token_burn_worker_no_agreement")
  end
end

pub fn read_token_burn_worker_quorum(client :: Int,
  urls :: List<String>,
  test_mode :: Bool,
  pins :: TokenBurnReadPins,
  epoch :: U64,
  minimum :: U64) -> TokenBurnBank!String do
  bank_quorum(client, urls, test_mode, pins, epoch, minimum, None)
end

pub fn read_token_burn_expiry_quorum(client :: Int,
  urls :: List<String>,
  test_mode :: Bool,
  pins :: TokenBurnReadPins,
  epoch :: U64,
  minimum :: U64,
  old_hash :: Hash) -> TokenBurnBank!String do
  if Bytes.length(old_hash.bytes) != 32 do
    return Err("invalid_burn_expiry_hash")
  end
  bank_quorum(client, urls, test_mode, pins, epoch, minimum, Some(old_hash))
end
