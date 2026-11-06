from Bounty.Transfer import BountyTransfer, decode_bounty_transfer, bounty_token_account
from Bounty.Settlement import (
  BountyTransferSettlement,
  bounty_transfer_settlement,
  bounty_settlements_agree
)
from Mobile.Bounty import bounty_state
from Mobile.BountyTransferState import (
  BountyTransferJournal,
  load_bounty_transfer,
  prepare_bounty_transfer,
  commit_bounty_transfer,
  acknowledge_bounty_transfer,
  settle_bounty_transfer
)
from Mobile.Codec import current_time
from Mobile.ForkFiling import FilingPlan, filing_receipt_observation
from Solana.Read import (
  Pubkey,
  AccountInfo,
  pubkey_equal,
  mint,
  token_account,
  get_latest_blockhash_request,
  latest_blockhash_from_response,
  get_block_height_request,
  block_height_from_response
)
from Solana.TransactionRead import (
  get_finalized_transaction_request,
  finalized_transaction_outcome_from_response
)
from Solana.TransactionSend import send_transaction_request, sent_signature_from_response
from Transparency.AnchorRpc import validate_anchor_sources, read_anchor_rpc_response
from Transparency.AnchorBatch import read_anchor_accounts
from Transparency.SlashReceiptRead import read_slash_receipt_state

pub struct BountyWalletPins do
  purpose :: Int
  usdc :: Bytes
end

fn time(floor :: U64) -> U64!String do
  let value = U64.divide(current_time()?, U64.parse("1000")?)?
  Ok(if U64.compare(value, floor) > 0 do
    value
  else
    floor
  end)
end

fn fence(current :: Fun() -> Bool) -> Result<(), String> do
  if current() do
    Ok(nil)
  else
    Err("bounty_transfer_context_changed")
  end
end

fn current_transfer(path :: String,
  key :: borrow StorageKey,
  plan :: FilingPlan,
  pins :: BountyWalletPins,
  identity :: Bytes) -> BountyTransferJournal!String do
  let value = case load_bounty_transfer(path, key)? do
    None -> return Err("bounty_transfer_not_started")
    Some(value) -> value
  end
  let selected = bounty_state(path, key)?
  let intent = decode_bounty_transfer(value.intent)?
  if !Bytes.secure_equals(value.identity, identity)
    || !Bytes.secure_equals(value.identity, plan.identity)
    || selected.status != 3
    || selected.index != intent.index
    || !Bytes.secure_equals(selected.proof_identity, value.proof_identity)
    || !Bytes.secure_equals(intent.finder, selected.finder)
    || !Bytes.secure_equals(intent.finder, plan.proof.finder)
    || !Bytes.secure_equals(intent.mint, plan.mint.bytes)
    || !Bytes.secure_equals(value.usdc, pins.usdc)
    || intent.purpose != pins.purpose do
    return Err("bounty_transfer_context_changed")
  end
  Ok(value)
end

fn height(endpoints :: List<String>) -> U64!String do
  validate_anchor_sources(endpoints)?
  for index in 0..3 do
    let response = read_anchor_rpc_response(List.get(endpoints, index),
      get_block_height_request(61, "confirmed")?,
      1024)
    case response do
      Err(_) -> nil
      Ok(raw) -> case block_height_from_response(raw) do
        Err(_) -> nil
        Ok(value) -> return Ok(value.value)
      end
    end
  end
  Err("wallet_rpc_unavailable")
end

fn account(value :: Option<AccountInfo>) -> AccountInfo!String do
  let found = case value do
    None -> return Err("bounty_transfer_asset_missing")
    Some(value) -> value
  end
  if found.executable || found.lamports == U64.parse("0")? do
    return Err("invalid_bounty_transfer_asset")
  end
  Ok(found)
end

pub fn prepare_bounty_movement(path :: String,
  key :: borrow StorageKey,
  plan :: FilingPlan,
  pins :: BountyWalletPins,
  destination :: Bytes,
  payer :: Bytes,
  now :: U64,
  current :: Fun() -> Bool) -> BountyTransferJournal!String do
  fence(current)?
  validate_anchor_sources(plan.pins.endpoints)?
  let previous = case load_bounty_transfer(path, key)? do
    None
    Some(value) -> Some(current_transfer(path, key, plan, pins, value.identity)?)
  end
  case previous do
    Some(value) -> do
      if !Bytes.secure_equals(value.payer, payer) do
        return Err("bounty_transfer_payer_changed")
      end
      if value.status >= 2 && value.status <= 4 do
        return Ok(value)
      end
    end
    None -> nil
  end
  let observed_height = height(plan.pins.endpoints)?
  fence(current)?
  case previous do
    Some(value) when value.status == 1 -> do
      let intent = decode_bounty_transfer(value.intent)?
      if !Bytes.secure_equals(intent.destination, destination) do
        return Err("bounty_transfer_destination_changed")
      end
      if U64.compare(time(now)?, intent.expires_at) < 0
        && U64.compare(observed_height, value.last_valid_block_height) <= 0 do
        return Ok(value)
      end
    end
    _ -> nil
  end
  let selection = bounty_state(path, key)?
  if selection.status != 3 || !Bytes.secure_equals(selection.finder, plan.proof.finder) do
    return Err("bounty_transfer_selection_changed")
  end
  let floor = case previous do
    None -> U64.parse("0")?
    Some(value) -> if U64.compare(value.finalized_slot, value.context_slot) > 0 do
      value.finalized_slot
    else
      value.context_slot
    end
  end
  let receipt = read_slash_receipt_state(plan.pins,
    plan.config.service_public_key,
    plan.config.log_version,
    plan.mint,
    plan.proof_hash,
    floor)?
  let paid = filing_receipt_observation(plan, receipt, floor)?
  if paid.status != "settled" || paid.units == U64.parse("0")? do
    return Err("bounty_not_paid")
  end
  if !Bytes.secure_equals(paid.finder, selection.finder) do
    return Err("bounty_paid_elsewhere")
  end
  fence(current)?
  let source = bounty_token_account(selection.finder, plan.mint.bytes)?
  let assets = read_anchor_accounts(plan.pins.endpoints, [plan.mint, source], paid.context_slot)?
  let denomination = mint(account(List.get(assets.accounts, 0))?)?
  let holding = token_account(account(List.get(assets.accounts, 1))?)?
  if !denomination.initialized
    || denomination.decimals > 18
    || (Bytes.secure_equals(plan.mint.bytes, pins.usdc) && denomination.decimals != 6)
    || holding.state != 1
    || holding.delegate != None
    || holding.close_authority != None
    || holding.native_reserve != None
    || !pubkey_equal(holding.mint, plan.mint)
    || !Bytes.secure_equals(holding.owner.bytes, selection.finder)
    || U64.compare(holding.amount, paid.units) < 0 do
    return Err("bounty_transfer_asset_unavailable")
  end
  for index in 0..3 do
    fence(current)?
    let response = read_anchor_rpc_response(List.get(plan.pins.endpoints, index),
      get_latest_blockhash_request(62, "confirmed")?,
      2048)
    case response do
      Err(_) -> nil
      Ok(raw) -> case latest_blockhash_from_response(raw) do
        Err(_) -> nil
        Ok(hash) -> do
          if U64.compare(hash.context_slot, assets.slot) < 0
            || U64.compare(hash.last_valid_block_height, observed_height) <= 0 do
            continue
          end
          fence(current)?
          let issued = time(now)?
          return prepare_bounty_transfer(path,
            key,
            plan.identity,
            BountyTransfer {
              index: selection.index,
              finder: selection.finder,
              destination: destination,
              mint: plan.mint.bytes,
              amount: paid.units,
              blockhash: hash.blockhash.bytes,
              issued_at: issued,
              expires_at: U64.add(issued, U64.parse("300")?)?,
              purpose: pins.purpose,
              decimals: denomination.decimals
            },
            payer,
            pins.usdc,
            hash.context_slot,
            hash.last_valid_block_height,
            observed_height,
            issued)
        end
      end
    end
  end
  Err("wallet_rpc_unavailable")
end

pub fn commit_bounty_movement(path :: String,
  key :: borrow StorageKey,
  plan :: FilingPlan,
  pins :: BountyWalletPins,
  identity :: Bytes,
  wire :: Bytes,
  now :: U64,
  current :: Fun() -> Bool) -> BountyTransferJournal!String do
  fence(current)?
  let value = current_transfer(path, key, plan, pins, identity)?
  let observed = if value.status < 2 do
    height(plan.pins.endpoints)?
  else
    U64.parse("0")?
  end
  fence(current)?
  commit_bounty_transfer(path, key, identity, wire, observed, time(now)?)
end

fn from_provider(endpoint :: String,
  value :: BountyTransferJournal) -> Option<BountyTransferSettlement>!String do
  let raw = read_anchor_rpc_response(endpoint,
    get_finalized_transaction_request(63, value.signature)?,
    131072)?
  let outcome = case finalized_transaction_outcome_from_response(raw, value.signature, 63)? do
    None -> return Ok(None)
    Some(value) -> value
  end
  let intent = decode_bounty_transfer(value.intent)?
  Ok(Some(bounty_transfer_settlement(outcome,
    value.wire,
    intent,
    Pubkey { bytes: value.payer },
    value.usdc,
    intent.purpose,
    value.context_slot)?))
end

fn agreement(left :: Option<BountyTransferSettlement>!String,
  right :: Option<BountyTransferSettlement>!String) -> Option<Option<BountyTransferSettlement>> do
  case (left, right) do
    (Ok(None), Ok(None)) -> Some(None)
    (Ok(Some(a)), Ok(Some(b))) -> if bounty_settlements_agree(a, b) do
      Some(Some(a))
    else
      None
    end
    _ -> None
  end
end

pub fn read_bounty_settlement(endpoints :: List<String>,
  value :: BountyTransferJournal) -> Option<BountyTransferSettlement>!String do
  validate_anchor_sources(endpoints)?
  let a = from_provider(List.get(endpoints, 0), value)
  let b = from_provider(List.get(endpoints, 1), value)
  case agreement(a, b) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let c = from_provider(List.get(endpoints, 2), value)
  case agreement(a, c) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  case agreement(b, c) do
    Some(value) -> Ok(value)
    None -> Err("bounty_transfer_rpc_disagree")
  end
end

pub fn recover_bounty_movement(path :: String,
  key :: borrow StorageKey,
  plan :: FilingPlan,
  pins :: BountyWalletPins,
  identity :: Bytes,
  current :: Fun() -> Bool) -> BountyTransferJournal!String do
  fence(current)?
  let value = current_transfer(path, key, plan, pins, identity)?
  if value.status < 2 || value.status >= 4 do
    return Ok(value)
  end
  let outcome = read_bounty_settlement(plan.pins.endpoints, value)?
  fence(current)?
  case outcome do
    # A missing transaction is never proof of failure/nonexecution. Preserve
    # the signature indefinitely if the providers cannot supply its history.
    None -> Ok(value)
    Some(found) -> settle_bounty_transfer(path, key, identity, found)
  end
end

pub fn submit_bounty_movement(path :: String,
  key :: borrow StorageKey,
  plan :: FilingPlan,
  pins :: BountyWalletPins,
  identity :: Bytes,
  now :: U64,
  current :: Fun() -> Bool) -> BountyTransferJournal!String do
  fence(current)?
  let value = current_transfer(path, key, plan, pins, identity)?
  if value.status < 2 do
    return Err("bounty_transfer_signature_required")
  end
  if value.status >= 4 do
    return Ok(value)
  end
  let intent = decode_bounty_transfer(value.intent)?
  for index in 0..3 do
    fence(current)?
    let fresh = current_transfer(path, key, plan, pins, identity)?
    if fresh.status >= 4 do
      return Ok(fresh)
    end
    if !Bytes.secure_equals(fresh.wire, value.wire) do
      return Err("bounty_transfer_packet_changed")
    end
    if U64.compare(time(now)?, intent.expires_at) >= 0 do
      return Ok(fresh)
    end
    let response = read_anchor_rpc_response(List.get(plan.pins.endpoints, index),
      send_transaction_request(64, value.wire, value.signature, value.context_slot)?,
      2048)
    case response do
      Err(_) -> nil
      Ok(raw) -> case sent_signature_from_response(raw, value.signature) do
        Err(_) -> nil
        Ok(_) -> do
          fence(current)?
          return acknowledge_bounty_transfer(path, key, identity, value.signature)
        end
      end
    end
  end
  Ok(value)
end
