from Bounty.Transfer import BountyTransfer, decode_bounty_transfer, bounty_token_account
from Bounty.Settlement import (
  BountyTransferSettlement,
  bounty_transfer_settlement,
  bounty_settlements_agree
)
from Mobile.Bounty import bounty_state
from Mobile.BountyTransferState import (
  BountyTransferAuthority,
  BountyTransferRoute,
  BountyTransferJournal,
  load_bounty_transfer,
  load_bounty_transfer_identity,
  read_bounty_transfer_movement,
  read_bounty_transfer_route,
  bounty_transfer_claim_id,
  bounty_transfer_attempt_handle,
  admit_bounty_transfer_root,
  prepare_bounty_transfer_route,
  prepare_bounty_transfer,
  commit_bounty_transfer,
  commit_bounty_transfer_route,
  acknowledge_bounty_transfer,
  settle_bounty_transfer
)
from Mobile.Codec import current_time, mobile_byte, mobile_join, mobile_write_u64
from Mobile.CreditState import pack_credit_parts
from Mobile.ForkFiling import FilingPlan, read_filing_receipt
from Mobile.ForkFilingPins import filing_receipt_binding
from Transparency.Config import SecurityConfig
from Transparency.AnchorChain import configured_anchor_pins
from Transparency.SlashReceipt import slash_receipt_address
from Transparency.TokenChain import token_addresses
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
from Transparency.RpcTransport import (
  RpcTransport,
  RpcEndpoint,
  rpc_transport,
  rpc_urls,
  rpc_fatal_error,
  require_rpc_current
)
from Transparency.AnchorBatch import read_anchor_accounts

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

fn height(rpc :: RpcTransport) -> U64!String do
  validate_anchor_sources(rpc_urls(rpc))?
  for index in 0..3 do
    let response = read_anchor_rpc_response(rpc,
      List.get(rpc.sources, index),
      get_block_height_request(61, "confirmed")?,
      1024)
    case response do
      Err(error) when rpc_fatal_error(error) -> return Err(error)
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

fn reuses_failed_hash(previous :: Option<BountyTransferJournal>,
  blockhash :: Bytes) -> Bool!String do
  case previous do
    Some(value) when value.status == 5 -> Ok(decode_bounty_transfer(value.intent)?.blockhash == blockhash)
    _ -> Ok(false)
  end
end

fn guarded_plan(plan :: FilingPlan, current :: Fun() -> Bool) -> FilingPlan!String do
  let rpc = rpc_transport(plan.pins.rpc.sources,
    fn() do
      plan.pins.rpc.require_current()?
      fence(current)
    end)?
  Ok(%{plan | pins: %{plan.pins | rpc: rpc}})
end

pub fn prepare_bounty_movement(path :: String,
  key :: borrow StorageKey,
  plan :: FilingPlan,
  pins :: BountyWalletPins,
  destination :: Bytes,
  payer :: Bytes,
  now :: U64,
  current :: Fun() -> Bool) -> BountyTransferJournal!String do
  let plan = guarded_plan(plan, current)?
  require_rpc_current(plan.pins.rpc.require_current)?
  validate_anchor_sources(rpc_urls(plan.pins.rpc))?
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
  let observed_height = height(plan.pins.rpc)?
  require_rpc_current(plan.pins.rpc.require_current)?
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
  let paid = read_filing_receipt(plan, floor)?
  if paid.receipt_format == 2 do
    return Err("bounty_transfer_asset_required")
  end
  if paid.status != "settled" || paid.units == U64.parse("0")? do
    return Err("bounty_not_paid")
  end
  if !Bytes.secure_equals(paid.finder, selection.finder) do
    return Err("bounty_paid_elsewhere")
  end
  require_rpc_current(plan.pins.rpc.require_current)?
  let source = bounty_token_account(selection.finder, plan.mint.bytes)?
  let assets = read_anchor_accounts(plan.pins.rpc, [plan.mint, source], paid.context_slot)?
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
    require_rpc_current(plan.pins.rpc.require_current)?
    let response = read_anchor_rpc_response(plan.pins.rpc,
      List.get(plan.pins.rpc.sources, index),
      get_latest_blockhash_request(62, "confirmed")?,
      2048)
    case response do
      Err(error) when rpc_fatal_error(error) -> return Err(error)
      Err(_) -> nil
      Ok(raw) -> case latest_blockhash_from_response(raw) do
        Err(_) -> nil
        Ok(hash) -> do
          if U64.compare(hash.context_slot, assets.slot) < 0
            || U64.compare(hash.last_valid_block_height, observed_height) <= 0
            || reuses_failed_hash(previous, hash.blockhash.bytes)? do
            continue
          end
          let issued = time(now)?
          require_rpc_current(plan.pins.rpc.require_current)?
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
  let plan = guarded_plan(plan, current)?
  require_rpc_current(plan.pins.rpc.require_current)?
  let value = current_transfer(path, key, plan, pins, identity)?
  let observed = if value.status < 2 do
    height(plan.pins.rpc)?
  else
    U64.parse("0")?
  end
  require_rpc_current(plan.pins.rpc.require_current)?
  commit_bounty_transfer(path, key, identity, wire, observed, time(now)?)
end

fn from_provider(rpc :: RpcTransport,
  endpoint :: RpcEndpoint,
  value :: BountyTransferJournal) -> Option<BountyTransferSettlement>!String do
  let raw = read_anchor_rpc_response(rpc,
    endpoint,
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

pub fn read_bounty_settlement(rpc :: RpcTransport,
  value :: BountyTransferJournal) -> Option<BountyTransferSettlement>!String do
  validate_anchor_sources(rpc_urls(rpc))?
  let a = case from_provider(rpc, List.get(rpc.sources, 0), value) do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    result
  end
  let b = case from_provider(rpc, List.get(rpc.sources, 1), value) do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    result
  end
  case agreement(a, b) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let c = case from_provider(rpc, List.get(rpc.sources, 2), value) do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    result
  end
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
  let plan = guarded_plan(plan, current)?
  let value = leg_journal(path, key, identity)?
  let intent = decode_bounty_transfer(value.intent)?
  if intent.purpose != pins.purpose
    || value.identity != bounty_legacy_recovery_identity(plan.config,
        plan.pins.rpc,
        intent.mint,
        plan.wire)? do
    return Err("bounty_transfer_context_changed")
  end
  recover_bounty_journal(path, key, plan.pins.rpc, value, current)
end

pub fn submit_bounty_movement(path :: String,
  key :: borrow StorageKey,
  plan :: FilingPlan,
  pins :: BountyWalletPins,
  identity :: Bytes,
  now :: U64,
  current :: Fun() -> Bool) -> BountyTransferJournal!String do
  let plan = guarded_plan(plan, current)?
  let value = leg_journal(path, key, identity)?
  let intent = decode_bounty_transfer(value.intent)?
  if intent.purpose != pins.purpose
    || value.identity != bounty_legacy_recovery_identity(plan.config,
        plan.pins.rpc,
        intent.mint,
        plan.wire)? do
    return Err("bounty_transfer_context_changed")
  end
  submit_bounty_journal(path, key, plan.pins.rpc, value, now, current)
end

# Network scope deliberately excludes endpoints, economic sources, governance,
# oracle and program deployment revisions. Those fence a call, not a claim.
fn namespace(program :: Bytes,
  log_id :: Bytes,
  service_key :: Bytes,
  version :: Int,
  purpose :: Int) -> Bytes!String do
  if purpose < 0 || purpose > 1 do
    return Err("invalid_bounty_transfer_scope")
  end
  Ok(Crypto.sha256(pack_credit_parts([
    Bytes.from_utf8("bounty-namespace/v2"),
    program,
    log_id,
    service_key,
    mobile_byte(version)?,
    mobile_byte(purpose)?
  ])?))
end

pub fn bounty_transfer_namespace(plan :: FilingPlan, purpose :: Int) -> Bytes!String do
  namespace(plan.pins.program.bytes,
    plan.pins.log_id,
    plan.config.service_public_key,
    plan.config.log_version,
    purpose)
end

pub fn bounty_recovery_namespace(config :: SecurityConfig,
  rpc :: RpcTransport,
  purpose :: Int) -> Bytes!String do
  let pins = case configured_anchor_pins(config, rpc)? do
    None -> return Err("bounty_transfer_configuration_required")
    Some(value) -> value
  end
  namespace(pins.program.bytes, pins.log_id, config.service_public_key, config.log_version, purpose)
end

# The old BWJ1 identity includes its historical mint. Reconstruct that exact
# namespace without asking today's receipt pins or today's slash_mint for it.
pub fn bounty_legacy_recovery_identity(config :: SecurityConfig,
  rpc :: RpcTransport,
  mint :: Bytes,
  wire :: Bytes) -> Bytes!String do
  let pins = case configured_anchor_pins(config, rpc)? do
    None -> return Err("bounty_transfer_configuration_required")
    Some(value) -> value
  end
  Ok(Crypto.sha256(mobile_join([
      Bytes.from_utf8("morse-phone-filing-v1"),
      pins.program.bytes,
      pins.log_id,
      config.service_public_key,
      mint,
      mobile_byte(config.log_version)?,
      Crypto.sha256(wire)
    ],
    0,
    Bytes.empty())?))
end

# A private prompt handle names the exact prepared attempt, including the
# current receipt policy. A stable leg ID alone cannot fence a stale prompt.
pub fn bounty_transfer_prepare_handle(route :: BountyTransferRoute) -> Bytes!String do
  bounty_transfer_attempt_handle(route)
end

fn larger(a :: U64, b :: U64) -> U64 do
  if U64.compare(a, b) > 0 do
    a
  else
    b
  end
end

fn leg_journal(path :: String,
  key :: borrow StorageKey,
  identity :: Bytes) -> BountyTransferJournal!String do
  let value = load_bounty_transfer_identity(path, key, identity)?
  let selected = bounty_state(path, key)?
  let intent = decode_bounty_transfer(value.intent)?
  if selected.status != 3
    || selected.index != intent.index
    || selected.proof_identity != value.proof_identity
    || selected.finder != intent.finder do
    return Err("bounty_transfer_selection_changed")
  end
  Ok(value)
end

fn same_packet(path :: String,
  key :: borrow StorageKey,
  before :: BountyTransferJournal) -> BountyTransferJournal!String do
  let value = leg_journal(path, key, before.identity)?
  if value.intent != before.intent
    || value.payer != before.payer
    || value.usdc != before.usdc
    || value.wire != before.wire
    || value.context_slot != before.context_slot
    || value.last_valid_block_height != before.last_valid_block_height do
    return Err("bounty_transfer_packet_changed")
  end
  Ok(value)
end

# One explicit action prepares only the requested asset. Receipt arrival and
# observation-only recovery never enter this function.
pub fn prepare_bounty_leg(path :: String,
  key :: borrow StorageKey,
  plan :: FilingPlan,
  pins :: BountyWalletPins,
  asset :: Int,
  destination :: Bytes,
  payer :: Bytes,
  now :: U64,
  current :: Fun() -> Bool) -> BountyTransferJournal!String do
  if asset == 0 do
    return prepare_bounty_movement(path, key, plan, pins, destination, payer, now, current)
  end
  if asset != 1 && asset != 2 do
    return Err("invalid_bounty_transfer_asset")
  end
  let plan = guarded_plan(plan, current)?
  require_rpc_current(plan.pins.rpc.require_current)?
  let selected = bounty_state(path, key)?
  if selected.status != 3 || selected.finder != plan.proof.finder do
    return Err("bounty_transfer_selection_changed")
  end
  let before = read_bounty_transfer_movement(path, key)?
  let scope = bounty_transfer_namespace(plan, pins.purpose)?
  let previous = case before.root do
    None -> None
    Some(root) -> do
      if Bytes.length(root.legacy_identity) != 0 do
        return Err("bounty_transfer_legacy_conflict")
      end
      if root.namespace != scope
        || root.purpose != pins.purpose
        || root.proof_identity != selected.proof_identity
        || root.finder != selected.finder
        || root.index != selected.index do
        return Err("bounty_transfer_context_changed")
      end
      read_bounty_transfer_route(path, key, asset)?.journal
    end
  end
  case previous do
    Some(value) -> do
      # Never consult current receipt/source authority to replace signed history.
      if value.status >= 2 && value.status <= 4 do
        return Ok(value)
      end
      let old = decode_bounty_transfer(value.intent)?
      if value.status == 1 && old.destination != destination do
        return Err("bounty_transfer_destination_changed")
      end
    end
    None -> nil
  end
  let floor = larger(case before.root do
      None -> U64.parse("0")?
      Some(root) -> root.admission_slot
    end,
    case previous do
      None -> U64.parse("0")?
      Some(value) -> larger(value.context_slot, value.finalized_slot)
    end)
  let permanent = case plan.permanent do
    None -> return Err("bounty_transfer_permanent_pins_required")
    Some(value) -> value
  end
  let morse = token_addresses(permanent.token)?.mint
  if permanent.usdc.bytes != pins.usdc || permanent.usdc != plan.mint || morse == permanent.usdc do
    return Err("bounty_transfer_mint_binding")
  end
  # This is a fresh authenticated common reader, never the FFS display cache.
  let paid = read_filing_receipt(plan, floor)?
  if paid.status != "settled" do
    return Err("bounty_not_paid")
  end
  if paid.receipt_format != 2
    || Bytes.length(paid.receipt_binding) != 32
    || paid.receipt_binding != filing_receipt_binding(permanent)? do
    return Err("invalid_bounty_transfer_receipt")
  end
  if paid.finder != selected.finder do
    return Err("bounty_paid_elsewhere")
  end
  let receipt = slash_receipt_address(plan.pins.program, plan.pins.log_id, plan.proof_hash)?.bytes
  let terms = Crypto.sha256(pack_credit_parts([
    Bytes.from_utf8("bounty-terms/v2"),
    scope,
    receipt,
    plan.proof_hash,
    paid.finder,
    mobile_write_u64(selected.index)?,
    pins.usdc,
    mobile_write_u64(paid.units)?,
    morse.bytes,
    mobile_write_u64(paid.morse_units)?
  ])?)
  require_rpc_current(plan.pins.rpc.require_current)?
  let root = admit_bounty_transfer_root(path,
    key,
    BountyTransferAuthority {
      claim_id: bounty_transfer_claim_id(selected.proof_identity, selected.finder, selected.index)?,
      proof_identity: selected.proof_identity,
      proof_hash: plan.proof_hash,
      finder: selected.finder,
      index: selected.index,
      namespace: scope,
      purpose: pins.purpose,
      receipt: receipt,
      terms_hash: terms,
      admission_binding: paid.receipt_binding,
      admission_slot: paid.context_slot,
      usdc_mint: pins.usdc,
      usdc_units: paid.units,
      morse_mint: morse.bytes,
      morse_units: paid.morse_units,
      legacy_identity: Bytes.empty()
    })?
  let mint_key = Pubkey {
    bytes: if asset == 1 do
      root.usdc_mint
    else
      root.morse_mint
    end
  }
  let units = if asset == 1 do
    root.usdc_units
  else
    root.morse_units
  end
  if units == U64.parse("0")? do
    return Err("bounty_transfer_zero")
  end
  let source = bounty_token_account(selected.finder, mint_key.bytes)?
  let assets = read_anchor_accounts(plan.pins.rpc,
    [mint_key, source],
    larger(paid.context_slot, floor))?
  let denomination = mint(account(List.get(assets.accounts, 0))?)?
  let holding = token_account(account(List.get(assets.accounts, 1))?)?
  if !denomination.initialized
    || denomination.decimals > 18
    || (asset == 1 && denomination.decimals != 6)
    || holding.state != 1
    || holding.delegate != None
    || holding.close_authority != None
    || holding.native_reserve != None
    || holding.mint != mint_key
    || holding.owner.bytes != selected.finder
    || U64.compare(holding.amount, units) < 0 do
    return Err("bounty_transfer_asset_unavailable")
  end
  let observed_height = height(plan.pins.rpc)?
  for index in 0..3 do
    require_rpc_current(plan.pins.rpc.require_current)?
    let response = read_anchor_rpc_response(plan.pins.rpc,
      List.get(plan.pins.rpc.sources, index),
      get_latest_blockhash_request(62, "confirmed")?,
      2048)
    case response do
      Err(error) when rpc_fatal_error(error) -> return Err(error)
      Err(_) -> nil
      Ok(raw) -> case latest_blockhash_from_response(raw) do
        Err(_) -> nil
        Ok(hash) -> do
          if U64.compare(hash.context_slot, assets.slot) < 0
            || U64.compare(hash.last_valid_block_height, observed_height) <= 0
            || reuses_failed_hash(previous, hash.blockhash.bytes)? do
            continue
          end
          let issued = time(now)?
          require_rpc_current(plan.pins.rpc.require_current)?
          return prepare_bounty_transfer_route(path,
            key,
            asset,
            paid.receipt_binding,
            BountyTransfer {
              index: selected.index,
              finder: selected.finder,
              destination: destination,
              mint: mint_key.bytes,
              amount: units,
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

pub fn commit_bounty_leg(path :: String,
  key :: borrow StorageKey,
  plan :: FilingPlan,
  pins :: BountyWalletPins,
  asset :: Int,
  handle :: Bytes,
  wire :: Bytes,
  now :: U64,
  current :: Fun() -> Bool) -> BountyTransferJournal!String do
  let plan = guarded_plan(plan, current)?
  require_rpc_current(plan.pins.rpc.require_current)?
  let route = read_bounty_transfer_route(path, key, asset)?
  if bounty_transfer_prepare_handle(route)? != handle
    || route.root.namespace != bounty_transfer_namespace(plan, pins.purpose)? do
    return Err("bounty_transfer_context_changed")
  end
  let value = leg_journal(path, key, route.identity)?
  let intent = decode_bounty_transfer(value.intent)?
  if intent.purpose != pins.purpose || value.usdc != pins.usdc do
    return Err("bounty_transfer_context_changed")
  end
  if asset != 0 do
    let permanent = case plan.permanent do
      None -> return Err("bounty_transfer_permanent_pins_required")
      Some(value) -> value
    end
    if route.attempt_binding != filing_receipt_binding(permanent)? do
      return Err("bounty_transfer_context_changed")
    end
  end
  let observed = if value.status < 2 do
    height(plan.pins.rpc)?
  else
    U64.parse("0")?
  end
  require_rpc_current(plan.pins.rpc.require_current)?
  # State authenticates the SDK packet and persists it before a send can load it.
  commit_bounty_transfer_route(path, key, asset, handle, wire, observed, time(now)?)
end

pub fn recover_bounty_journal(path :: String,
  key :: borrow StorageKey,
  rpc :: RpcTransport,
  value :: BountyTransferJournal,
  current :: Fun() -> Bool) -> BountyTransferJournal!String do
  let rpc = rpc_transport(rpc.sources,
    fn() do
      rpc.require_current()?
      fence(current)
    end)?
  require_rpc_current(rpc.require_current)?
  let value = same_packet(path, key, value)?
  if value.status < 2 || value.status >= 4 do
    return Ok(value)
  end
  let outcome = read_bounty_settlement(rpc, value)?
  require_rpc_current(rpc.require_current)?
  # Neither null history, expiry, nor a closed source proves nonexecution.
  case outcome do
    None -> same_packet(path, key, value)
    Some(found) -> settle_bounty_transfer(path, key, value.identity, found)
  end
end

pub fn submit_bounty_journal(path :: String,
  key :: borrow StorageKey,
  rpc :: RpcTransport,
  value :: BountyTransferJournal,
  now :: U64,
  current :: Fun() -> Bool) -> BountyTransferJournal!String do
  let rpc = rpc_transport(rpc.sources,
    fn() do
      rpc.require_current()?
      fence(current)
    end)?
  require_rpc_current(rpc.require_current)?
  let value = same_packet(path, key, value)?
  if value.status < 2 do
    return Err("bounty_transfer_signature_required")
  end
  if value.status >= 4 do
    return Ok(value)
  end
  let intent = decode_bounty_transfer(value.intent)?
  for index in 0..3 do
    require_rpc_current(rpc.require_current)?
    let fresh = same_packet(path, key, value)?
    if fresh.status >= 4 do
      return Ok(fresh)
    end
    if U64.compare(time(now)?, intent.expires_at) >= 0 do
      return Ok(fresh)
    end
    let response = read_anchor_rpc_response(rpc,
      List.get(rpc.sources, index),
      send_transaction_request(64, value.wire, value.signature, value.context_slot)?,
      2048)
    case response do
      Err(error) when rpc_fatal_error(error) -> return Err(error)
      Err(_) -> nil
      Ok(raw) -> case sent_signature_from_response(raw, value.signature) do
        Err(_) -> nil
        Ok(_) -> do
          require_rpc_current(rpc.require_current)?
          return acknowledge_bounty_transfer(path, key, value.identity, value.signature)
        end
      end
    end
  end
  same_packet(path, key, value)
end
