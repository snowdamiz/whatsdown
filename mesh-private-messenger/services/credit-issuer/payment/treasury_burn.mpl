from Runtime.Treasury import validate_worker
from Payment.TreasuryBurnHandoff import match_credit_burn_handoff_frame
from Transparency.TokenBurnCarryRead import (
  token_burn_carry_read_keys,
  decode_token_burn_carry_snapshot
)
from Solana.Read import (
  rpc_send,
  rpc_request,
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response
)
from Runtime.Treasury import TreasuryWorkerConfig
from Payment.TreasuryBurnHandoff import CreditBurnHandoff
from Transparency.TokenBurn import TokenBurnProfile
from Transparency.TokenBurnRead import (
  TokenBurnReadPins,
  token_burn_read_keys,
  decode_token_burn_snapshot
)
from Transparency.TokenBurnCarry import decode_token_burn_carry_account
from Transparency.TokenBurnCarryWrite import token_burn_carry_addresses
from Transparency.TokenBurnWrite import token_burn_addresses
from Transparency.TokenChain import token_payout_address
from Solana.Read import Pubkey, AccountSlice, OptionalAccountSlicesAtSlot, pubkey, token_account

pub struct TreasuryBurnReady do
  context_slot :: U64
  timestamp :: U64
  profile :: TokenBurnProfile
  profile_bytes :: Bytes
  available_carry :: U64
  source_balance :: U64
  footprint :: Bytes
end

fn absent(value :: Option<AccountSlice>) -> Bool do
  case value do
    None -> true
    Some(a) -> !a.info.executable
      && U64.to_string(a.space) == "0"
      && Bytes.length(a.info.data) == 0
      && Bytes.to_hex(a.info.owner.bytes) == String.repeat("00", 32)
  end
end

fn required(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  owner :: Pubkey,
  length :: Int) -> AccountSlice!String do
  let account = case List.get(snapshot.accounts, index) do
    None -> return Err("treasury_burn_account_missing")
    Some(value) -> value
  end
  if account.info.owner != owner
    || account.info.executable
    || account.info.lamports == U64.parse("0")?
    || account.space != U64.parse(Int.to_string(length))?
    || Bytes.length(account.info.data) != length do
    return Err("treasury_burn_account_mismatch")
  end
  Ok(account)
end

fn balance(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  mint :: Pubkey,
  authority :: Pubkey) -> U64!String do
  let spl = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let account = token_account(required(snapshot, index, spl, 165)?.info)?
  if account.mint != mint
    || account.owner != authority
    || account.state != 1
    || account.delegate != None
    || account.native_reserve != None
    || account.close_authority != None
    || account.delegated_amount != U64.parse("0")? do
    return Err("treasury_burn_vault_mismatch")
  end
  Ok(account.amount)
end

pub fn treasury_burn_ready_keys(pins :: TokenBurnReadPins, epoch :: U64) -> List<Pubkey>!String do
  let old = token_burn_read_keys(pins, epoch)?
  let a = token_burn_carry_addresses(pins.program, pins.usdc, epoch)?
  let source = from_solana_source(pins)?
  Ok(old ++ [a.carry, a.carry_vault, source])
end

fn from_solana_source(pins :: TokenBurnReadPins) -> Pubkey!String do
  token_payout_address(pins.treasury, pins.usdc)
end

# Complete single-bank source/profile/oracle/DEX/carry authentication before any
# reservation. Host freshness limits stale-provider clock and funding-window risk.
pub fn decode_treasury_burn_ready(pins :: TokenBurnReadPins,
  epoch :: U64,
  minimum :: U64,
  native_now :: U64,
  snapshot :: OptionalAccountSlicesAtSlot) -> TreasuryBurnReady!String do
  if List.length(snapshot.accounts) != 22 do
    return Err("treasury_burn_ready_account_count")
  end
  let prefix = OptionalAccountSlicesAtSlot {
    slot: snapshot.slot,
    accounts: List.take(snapshot.accounts, 19)
  }
  let old = decode_token_burn_snapshot(pins, epoch, minimum, prefix)?
  if !old.code_current || old.spot == None || Option.is_some(old.week) || old.timestamp <= 0 do
    return Err("treasury_burn_not_ready")
  end
  let timestamp = U64.parse(Int.to_string(old.timestamp))?
  let elapsed = if U64.compare(timestamp, native_now) >= 0 do
    U64.subtract(timestamp, native_now)?
  else
    U64.subtract(native_now, timestamp)?
  end
  let current = U64.divide(timestamp, U64.parse("604800")?)?
  let start = U64.multiply(epoch, U64.parse("604800")?)?
  if U64.compare(elapsed, U64.parse("60")?) > 0
    || U64.compare(timestamp, old.profile.ready_at) < 0
    || (epoch != current && epoch != U64.add(current, U64.parse("1")?)?)
    || U64.compare(timestamp, U64.add(start, U64.parse("25200")?)?) >= 0 do
    return Err("treasury_burn_clock_or_window_mismatch")
  end
  let a = token_burn_carry_addresses(pins.program, pins.usdc, epoch)?
  let addresses = token_burn_addresses(pins.program, old.profile, epoch, 0)?
  if addresses.treasury_source == a.carry_vault
    || addresses.treasury_source == addresses.week_vault
    || a.carry_vault == addresses.week_vault do
    return Err("treasury_burn_custody_alias")
  end
  let accounted = if absent(List.get(snapshot.accounts, 19)) do
    U64.parse("0")?
  else
    let value = decode_token_burn_carry_account(required(snapshot,
      19,
      pins.program,
      192)?.info.data)?
    if value.profile != addresses.profile
      || value.usdc != pins.usdc
      || value.vault != a.carry_vault do
      return Err("treasury_burn_carry_mismatch")
    end
    value.accounted
  end
  let carry_balance = if absent(List.get(snapshot.accounts, 20)) do
    if !absent(List.get(snapshot.accounts, 19)) do
      return Err("treasury_burn_carry_vault_missing")
    end
    U64.parse("0")?
  else
    balance(snapshot, 20, pins.usdc, a.carry)?
  end
  if U64.compare(carry_balance, accounted) < 0 do
    return Err("treasury_burn_carry_underfunded")
  end
  let source = balance(snapshot, 21, pins.usdc, pins.treasury)?
  let profile = required(snapshot, 2, pins.program, 320)?.info.data
  let footprint = Crypto.sha256(Bytes.from_hex(Bytes.to_hex(Bytes.from_utf8("morse-credit-burn-ready-v1"))
    <> Bytes.to_hex(profile)
    <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(epoch), 8)?)
    <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(accounted), 8)?)
    <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(source), 8)?))?)
  Ok(TreasuryBurnReady {
    context_slot: snapshot.slot,
    timestamp: timestamp,
    profile: old.profile,
    profile_bytes: profile,
    available_carry: accounted,
    source_balance: source,
    footprint: footprint
  })
end

pub struct TreasuryBurnFundingProof do
  context_slot :: U64
  frame :: Bytes
  receipt :: Option<Bytes>
end

pub fn treasury_burn_check_sources(worker :: TreasuryWorkerConfig,
  pins :: TokenBurnReadPins) -> Result<(), String> do
  validate_worker(worker)?
  if Http.url_origin(List.get(worker.providers, 0))? == Http.url_origin(List.get(worker.providers,
      1))?
    || worker.chain.mint != pins.usdc.bytes
    || worker.chain.treasury_owner != pins.treasury.bytes do
    return Err("treasury_burn_provider_or_custody_pin_mismatch")
  end
  Ok(nil)
end

pub fn treasury_burn_check_genesis(client :: Int,
  url :: String,
  worker :: TreasuryWorkerConfig,
  id :: Int) -> Result<(), String> do
  let result = rpc_send(client, url, rpc_request(id, "getGenesisHash", "[]")?, 3000, 4096)?
  if !result.ok
    || Bytes.from_base58(Json.as_string(Json.parse(result.result_json)?)?)? != worker.chain.cluster do
    return Err("treasury_burn_cluster_mismatch")
  end
  Ok(nil)
end

fn one_ready(client :: Int,
  url :: String,
  worker :: TreasuryWorkerConfig,
  pins :: TokenBurnReadPins,
  epoch :: U64,
  minimum :: U64,
  native_now :: U64,
  id :: Int) -> TreasuryBurnReady!String do
  treasury_burn_check_genesis(client, url, worker, id)?
  let request = get_multiple_accounts_slice_request(id + 1,
    treasury_burn_ready_keys(pins, epoch)?,
    "finalized",
    0,
    5728,
    Some(minimum))?
  let response = rpc_send(client, url, request, 5000, 262144)?
  decode_treasury_burn_ready(pins,
    epoch,
    minimum,
    native_now,
    optional_accounts_slice_from_response(response)?)
end

fn ready_quorum(client :: Int,
  worker :: TreasuryWorkerConfig,
  pins :: TokenBurnReadPins,
  epoch :: U64,
  minimum :: U64,
  native_now :: U64) -> TreasuryBurnReady!String do
  treasury_burn_check_sources(worker, pins)?
  let first = one_ready(client,
    List.get(worker.providers, 0),
    worker,
    pins,
    epoch,
    minimum,
    native_now,
    310)?
  let second = one_ready(client,
    List.get(worker.providers, 1),
    worker,
    pins,
    epoch,
    minimum,
    native_now,
    320)?
  # Clocks/slots may advance independently. Both banks must independently pass
  # freshness/window checks and agree on exact immutable profile + spendable
  # balances. Donated carry surplus never enlarges the accounted input amount.
  if first.footprint != second.footprint do
    return Err("treasury_burn_ready_quorum_mismatch")
  end
  Ok(first)
end

pub fn read_treasury_burn_ready(worker :: TreasuryWorkerConfig,
  pins :: TokenBurnReadPins,
  epoch :: U64,
  minimum :: U64,
  native_now :: U64) -> TreasuryBurnReady!String do
  let client = Http.client()
  let result = ready_quorum(client, worker, pins, epoch, minimum, native_now)
  Http.client_close(client)
  result
end

fn one_funding(client :: Int,
  url :: String,
  worker :: TreasuryWorkerConfig,
  pins :: TokenBurnReadPins,
  intent :: CreditBurnHandoff,
  id :: Int) -> TreasuryBurnFundingProof!String do
  treasury_burn_check_genesis(client, url, worker, id)?
  let request = get_multiple_accounts_slice_request(id + 1,
    token_burn_carry_read_keys(pins, intent.epoch)?,
    "finalized",
    0,
    2240,
    None)?
  let response = rpc_send(client, url, request, 5000, 131072)?
  let snapshot = optional_accounts_slice_from_response(response)?
  let state = decode_token_burn_carry_snapshot(pins, intent.epoch, U64.parse("0")?, snapshot)?
  if !state.code_current do
    return Err("treasury_burn_program_release_changed")
  end
  let raw = case List.get(snapshot.accounts, 5) do
    None -> return Err("treasury_burn_funding_missing")
    Some(a) -> a.info.data
  end
  let receipt = case state.receipt do
    None
    Some(_) -> case List.get(snapshot.accounts, 9) do
      None -> return Err("treasury_burn_receipt_missing")
      Some(a) -> Some(a.info.data)
    end
  end
  match_credit_burn_handoff_frame(intent, raw, receipt)?
  Ok(TreasuryBurnFundingProof { context_slot: snapshot.slot, frame: raw, receipt: receipt })
end

fn funding_quorum(client :: Int,
  worker :: TreasuryWorkerConfig,
  pins :: TokenBurnReadPins,
  intent :: CreditBurnHandoff) -> TreasuryBurnFundingProof!String do
  treasury_burn_check_sources(worker, pins)?
  if intent.program != pins.program
    || intent.profile.usdc != pins.usdc
    || intent.profile.treasury != pins.treasury do
    return Err("treasury_burn_funding_config_changed")
  end
  let first = one_funding(client, List.get(worker.providers, 0), worker, pins, intent, 330)?
  one_funding(client, List.get(worker.providers, 1), worker, pins, intent, 340)?
  # Completion can progress between independent finalized banks. Both strict
  # frames must match the same permanent funding hash and every original row;
  # active-vs-closed progression never reclassifies the cash/carry split.
  Ok(first)
end

pub fn read_treasury_burn_funding(worker :: TreasuryWorkerConfig,
  pins :: TokenBurnReadPins,
  intent :: CreditBurnHandoff) -> TreasuryBurnFundingProof!String do
  let client = Http.client()
  let result = funding_quorum(client, worker, pins, intent)
  Http.client_close(client)
  result
end
