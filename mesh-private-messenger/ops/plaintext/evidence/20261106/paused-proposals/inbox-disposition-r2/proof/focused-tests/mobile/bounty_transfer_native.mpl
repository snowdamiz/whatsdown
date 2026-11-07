from Bounty.Transfer import decode_bounty_transfer
from Mobile.Bounty import disclosable_fork
from Mobile.BountyTransferState import (
  BountyTransferJournal,
  BountyTransferRoute,
  BountyTransferMovement,
  read_bounty_transfer_movement,
  read_bounty_transfer_route,
  load_bounty_transfer_identity,
  migrate_bounty_transfer_legacy,
  load_bounty_transfer,
  cancel_bounty_transfer
)
from Mobile.BountyTransferNetwork import (
  BountyWalletPins,
  prepare_bounty_leg,
  commit_bounty_leg,
  recover_bounty_journal,
  submit_bounty_journal,
  bounty_transfer_namespace,
  bounty_recovery_namespace,
  bounty_legacy_recovery_identity,
  bounty_transfer_prepare_handle,
  prepare_bounty_movement,
  commit_bounty_movement
)
from Mobile.Codec import current_time, mobile_byte, mobile_write_u64, mobile_utf8
from Mobile.CreditState import pack_credit_parts, unpack_credit_parts
from Mobile.ForkFiling import FilingPlan, prepare_native_filing, native_filing_current
from Transparency.Config import encode_security_config
from Storage.Blobs import ensure_schema, load_blob
from Mobile.Platform import decode_native_security_config
from Mobile.OhttpContext import capture_native_ohttp_context, rpc_transport_from_context
from Transparency.RpcTransport import RpcTransport
from Storage.Keys import platform_key

struct MovementContext do
  path :: String
  frame :: Bytes
  wire :: Bytes
  filing :: FilingPlan
  wallet :: BountyWalletPins
end

fn database(input :: Bytes) -> String!String do
  if Bytes.length(input) == 0 || Bytes.length(input) > 4096 do
    return Err("invalid_database_path")
  end
  mobile_utf8(input, "invalid_database_path")
end

struct MovementRequest do
  path :: String
  asset :: Int
  versioned :: Bool
  fields :: List<Bytes>
end

fn legacy_database(input :: Bytes) -> String!String do
  # Version 2 and the BMR discriminator namespace cannot name a legacy database.
  let reserved = Bytes.length(input) > 0 && Bytes.get(input, 0)? == 2
    || Bytes.length(input) >= 4 && Bytes.slice(input, 1, 3)? == Bytes.from_utf8("BMR")
  if reserved do
    return Err("invalid_bounty_transfer_request")
  end
  database(input)
end

fn request(input :: Bytes, count :: Int) -> MovementRequest!String do
  if Bytes.length(input) > 5500 do
    return Err("invalid_bounty_transfer_request")
  end
  let parts = unpack_credit_parts(input, count + 2, 4096)?
  let versioned = List.length(parts) > 0 && List.head(parts) == Bytes.from_hex("02424d52")?
  if versioned do
    if List.length(parts) != count + 2 || Bytes.length(List.get(parts, 2)) != 1 do
      return Err("invalid_bounty_transfer_request")
    end
    let asset = Bytes.get(List.get(parts, 2), 0)?
    if asset > 2 do
      return Err("invalid_bounty_transfer_request")
    end
    let path = database(List.get(parts, 1))?
    Ok(MovementRequest {
      path: path,
      asset: asset,
      versioned: true,
      fields: [List.get(parts, 1)] ++ List.drop(parts, 3)
    })
  else
    if List.length(parts) != count do
      return Err("invalid_bounty_transfer_request")
    end
    let path = legacy_database(List.head(parts))?
    Ok(MovementRequest { path: path, asset: 0, versioned: false, fields: parts })
  end
end

fn wallet_pins() -> BountyWalletPins!String do
  # These native pins exist independently of the optional credits issuer.
  let pins = case Host.push_get_token(Bytes.from_utf8("messenger/wallet/v1")) do
    Err(_) -> return Err("wallet_configuration_required")
    Ok(value) -> value
  end
  if Bytes.length(pins) != 34
    || Bytes.get(pins, 0)? != 1
    || Bytes.get(pins, 1)? > 1
    || Bytes.to_hex(Bytes.slice(pins, 2, 32)?) == String.repeat("00", 32) do
    return Err("wallet_configuration_required")
  end
  Ok(BountyWalletPins { purpose: Bytes.get(pins, 1)?, usdc: Bytes.slice(pins, 2, 32)? })
end

fn context(path :: String) -> MovementContext!String do
  ensure_schema(path)?
  let key = platform_key()?
  let wire = disclosable_fork(path, key)?
  if Bytes.length(wire) == 0 do
    return Err("bounty_not_selected")
  end
  let filing = case prepare_native_filing(path, wire)? do
    None -> return Err("bounty_transfer_configuration_required")
    Some(value) -> value
  end
  Ok(MovementContext {
    path: path,
    frame: encode_security_config(filing.config)?,
    wire: wire,
    filing: filing,
    wallet: wallet_pins()?
  })
end

fn current(value :: MovementContext) -> Bool do
  if !native_filing_current(value.path, value.frame, value.wire) do
    return false
  end
  case wallet_pins() do
    Err(_) -> false
    Ok(pins) -> pins.purpose == value.wallet.purpose
      && Bytes.secure_equals(pins.usdc, value.wallet.usdc)
  end
end

fn now() -> U64!String do
  U64.divide(current_time()?, U64.parse("1000")?)
end

fn view(value :: Option<BountyTransferJournal>) -> Bytes!String do
  case value do
    None -> pack_credit_parts([
      Bytes.from_hex("01424d57")?,
      Bytes.empty(),
      mobile_byte(0)?,
      Bytes.empty(),
      Bytes.empty(),
      Bytes.empty(),
      Bytes.empty(),
      mobile_write_u64(U64.parse("0")?)?,
      mobile_byte(0)?,
      mobile_write_u64(U64.parse("0")?)?,
      mobile_write_u64(U64.parse("0")?)?,
      Bytes.empty()
    ])
    Some(value) -> do
      let intent = decode_bounty_transfer(value.intent)?
      pack_credit_parts([
        Bytes.from_hex("01424d57")?,
        value.identity,
        mobile_byte(value.status)?,
        value.signature,
        intent.finder,
        intent.destination,
        intent.mint,
        mobile_write_u64(intent.amount)?,
        mobile_byte(intent.decimals)?,
        mobile_write_u64(value.fee)?,
        mobile_write_u64(value.finalized_slot)?,
        Bytes.from_utf8(value.execution_error)
      ])
    end
  end
end

fn absent_view(reason :: String) -> Bytes!String do
  pack_credit_parts([
    Bytes.from_hex("02424d57")?,
    mobile_byte(0)?,
    Bytes.from_utf8(reason),
    Bytes.empty(),
    Bytes.empty(),
    Bytes.empty()
  ])
end

fn leg_view(route :: BountyTransferRoute) -> Bytes!String do
  let mint = if route.asset == 1 do
    route.root.usdc_mint
  else
    route.root.morse_mint
  end
  let amount = if route.asset == 1 do
    route.root.usdc_units
  else
    route.root.morse_units
  end
  let state = case route.journal do
    Some(_) -> 3
    None -> if amount == U64.parse("0")? do
      1
    else
      2
    end
  end
  let decimals = case route.journal do
    None -> 255
    Some(value) -> decode_bounty_transfer(value.intent)?.decimals
  end
  pack_credit_parts([
    Bytes.from_hex("02424d4c")?,
    mobile_byte(route.asset)?,
    mobile_byte(state)?,
    mint,
    mobile_write_u64(amount)?,
    mobile_byte(decimals)?,
    case route.journal do
      None -> Bytes.empty()
      Some(value) -> view(Some(value))?
    end
  ])
end

fn aggregate_view(movement :: BountyTransferMovement,
  legacy :: Option<BountyTransferJournal>) -> Bytes!String do
  case movement.root do
    None -> case legacy do
      None -> absent_view("not_observed")
      Some(value) -> pack_credit_parts([
        Bytes.from_hex("02424d57")?,
        mobile_byte(1)?,
        Bytes.empty(),
        view(Some(value))?,
        Bytes.empty(),
        Bytes.empty()
      ])
    end
    Some(root) -> if Bytes.length(root.legacy_identity) != 0 do
      let route = case movement.legacy do
        None -> return Err("invalid_bounty_transfer_route")
        Some(value) -> value
      end
      let value = case route.journal do
        None -> return Err("invalid_bounty_transfer_route")
        Some(value) -> value
      end
      pack_credit_parts([
        Bytes.from_hex("02424d57")?,
        mobile_byte(1)?,
        Bytes.empty(),
        view(Some(value))?,
        Bytes.empty(),
        Bytes.empty()
      ])
    else
      let usdc = case movement.usdc do
        None -> return Err("invalid_bounty_transfer_route")
        Some(value) -> value
      end
      let morse = case movement.morse do
        None -> return Err("invalid_bounty_transfer_route")
        Some(value) -> value
      end
      pack_credit_parts([
        Bytes.from_hex("02424d57")?,
        mobile_byte(2)?,
        Bytes.empty(),
        Bytes.empty(),
        leg_view(usdc)?,
        leg_view(morse)?
      ])
    end
  end
end

fn aggregate(path :: String, key :: borrow StorageKey) -> Bytes!String do
  let movement = read_bounty_transfer_movement(path, key)?
  let legacy = case movement.root do
    None -> load_bounty_transfer(path, key)?
    Some(_) -> None
  end
  aggregate_view(movement, legacy)
end

pub fn native_bounty_transfer_status(input :: Bytes) -> Bytes!String do
  # A framed request is never retried as a raw legacy path after a parse error.
  if Bytes.length(input) >= 4 && Bytes.get(input, 0)? == 0 do
    let parts = unpack_credit_parts(input, 2, 4096)?
    if List.length(parts) != 2 || List.head(parts) != Bytes.from_hex("02424d52")? do
      return Err("invalid_bounty_transfer_request")
    end
    let path = database(List.get(parts, 1))?
    ensure_schema(path)?
    let key = platform_key()?
    return aggregate(path, key)
  end
  let path = legacy_database(input)?
  ensure_schema(path)?
  let key = platform_key()?
  view(load_bounty_transfer(path, key)?)
end

fn existing_leg(path :: String,
  key :: borrow StorageKey,
  asset :: Int) -> Option<BountyTransferJournal>!String do
  let movement = read_bounty_transfer_movement(path, key)?
  case movement.root do
    None -> if asset == 0 do
      load_bounty_transfer(path, key)
    else
      Ok(None)
    end
    Some(_) -> do
      let route = case asset do
        0 -> movement.legacy
        1 -> movement.usdc
        2 -> movement.morse
        _ -> None
      end
      case route do
        None -> Err("bounty_transfer_asset_unavailable")
        Some(value) -> Ok(value.journal)
      end
    end
  end
end

fn prepared_view(path :: String,
  key :: borrow StorageKey,
  asset :: Int,
  value :: Option<BountyTransferJournal>,
  destination :: Bytes) -> Bytes!String do
  let movement = read_bounty_transfer_movement(path, key)?
  let route = case asset do
    0 -> movement.legacy
    1 -> movement.usdc
    2 -> movement.morse
    _ -> None
  end
  let route = case route do
    None -> return Err("bounty_transfer_asset_unavailable")
    Some(value) -> value
  end
  # One snapshot correlates prompt handle, selected row and both visible legs.
  # The commit CAS still rechecks it after the native prompt and height read.
  if route.journal != value do
    return Err("bounty_transfer_context_changed")
  end
  let status = case value do
    None -> 0
    Some(value) -> value.status
  end
  let intent = case value do
    None -> Bytes.empty()
    Some(value) -> value.intent
  end
  let needs = case value do
    None -> false
    Some(value) -> value.status == 1
      && decode_bounty_transfer(value.intent)?.destination == destination
  end
  let handle = case value do
    None -> Bytes.empty()
    Some(_) -> bounty_transfer_prepare_handle(route)?
  end
  pack_credit_parts([
    Bytes.from_hex("02424d50")?,
    mobile_byte(asset)?,
    handle,
    mobile_byte(if needs do
      1
    else
      0
    end)?,
    intent,
    case value do
      None -> Bytes.empty()
      Some(value) -> value.signature
    end,
    mobile_byte(status)?,
    aggregate_view(movement, None)?
  ])
end

# Private host orchestration only: no payer/index/mint/amount is accepted from JS.
pub fn native_bounty_transfer_prepare(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 3)?
  let fields = parsed.fields
  let destination = List.get(fields, 1)
  let payer = List.get(fields, 2)
  if Bytes.length(destination) != 32 || Bytes.length(payer) != 32 do
    return Err("invalid_bounty_transfer_request")
  end
  ensure_schema(parsed.path)?
  let key = platform_key()?
  # Signed/terminal history and a different saved destination are observed
  # before any current receipt, asset-account or permanent-pin preparation.
  if parsed.versioned do
    case existing_leg(parsed.path, key, parsed.asset)? do
      Some(saved) -> if (saved.status >= 2 && saved.status <= 4)
        || (saved.status == 1
          && decode_bounty_transfer(saved.intent)?.destination != destination) do
        # A raw BWJ1 needs historical namespace admission before a v2 handle.
        let movement = read_bounty_transfer_movement(parsed.path, key)?
        if movement.root == None do
          historical_context(parsed.path, key, 0, saved.identity)?
        end
        return prepared_view(parsed.path, key, parsed.asset, Some(saved), destination)
      end
      None -> nil
    end
  end
  let config = context(parsed.path)?
  let result = if parsed.versioned do
    prepare_bounty_leg(config.path,
      key,
      config.filing,
      config.wallet,
      parsed.asset,
      destination,
      payer,
      now()?,
      fn() do current(config) end)
  else
    prepare_bounty_movement(config.path,
      key,
      config.filing,
      config.wallet,
      destination,
      payer,
      now()?,
      fn() do current(config) end)
  end
  let value = case result do
    Err(error) when parsed.versioned && error == "bounty_transfer_zero" ->
      return prepared_view(parsed.path, key, parsed.asset, None, destination)
    Err(error) -> return Err(error)
    Ok(value) -> value
  end
  if parsed.versioned do
    if parsed.asset == 0 do
      migrate_bounty_transfer_legacy(parsed.path,
        key,
        bounty_transfer_namespace(config.filing, config.wallet.purpose)?)?
    end
    return prepared_view(parsed.path, key, parsed.asset, Some(value), destination)
  end
  pack_credit_parts([
    Bytes.from_hex("01424d50")?,
    value.identity,
    mobile_byte(if value.status == 1 do
      1
    else
      0
    end)?,
    value.intent,
    value.signature,
    mobile_byte(value.status)?
  ])
end

pub fn native_bounty_transfer_commit(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 3)?
  let fields = parsed.fields
  if Bytes.length(List.get(fields, 1)) != 32 || Bytes.length(List.get(fields, 2)) > 1232 do
    return Err("invalid_bounty_transfer_request")
  end
  let config = context(parsed.path)?
  let key = platform_key()?
  let value = if parsed.versioned do
    commit_bounty_leg(config.path,
      key,
      config.filing,
      config.wallet,
      parsed.asset,
      List.get(fields, 1),
      List.get(fields, 2),
      now()?,
      fn() do current(config) end)?
  else
    commit_bounty_movement(config.path,
      key,
      config.filing,
      config.wallet,
      List.get(fields, 1),
      List.get(fields, 2),
      now()?,
      fn() do current(config) end)?
  end
  if parsed.versioned do
    aggregate(parsed.path, key)
  else
    view(Some(value))
  end
end

struct HistoricalContext do
  rpc :: RpcTransport
  value :: BountyTransferJournal
  path :: String
  frame :: Bytes
  wire :: Bytes
  wallet :: BountyWalletPins
end

fn historical_current(value :: HistoricalContext) -> Bool do
  if !native_filing_current(value.path, value.frame, value.wire) do
    return false
  end
  case wallet_pins() do
    Err(_) -> false
    Ok(pins) -> pins.purpose == value.wallet.purpose && pins.usdc == value.wallet.usdc
  end
end

fn historical_context(path :: String,
  key :: borrow StorageKey,
  asset :: Int,
  identity :: Bytes) -> HistoricalContext!String do
  # Authenticate stored packet/route FIRST. Today's release pins and slash mint
  # never gate recovery of this already signed immutable packet.
  let movement = read_bounty_transfer_movement(path, key)?
  let value = case movement.root do
    None -> do
      if asset != 0 do
        return Err("bounty_transfer_asset_unavailable")
      end
      load_bounty_transfer_identity(path, key, identity)?
    end
    Some(_) -> do
      let route = read_bounty_transfer_route(path, key, asset)?
      if route.identity != identity do
        return Err("bounty_transfer_identity_mismatch")
      end
      case route.journal do
        None -> return Err("bounty_transfer_not_started")
        Some(value) -> value
      end
    end
  end
  let intent = decode_bounty_transfer(value.intent)?
  let wire = disclosable_fork(path, key)?
  let native = capture_native_ohttp_context(path, load_blob(path, "profile/v1")?)?
  let config = decode_native_security_config(native.security_frame)?
  let rpc = rpc_transport_from_context(path, native)?
  let wallet = wallet_pins()?
  if wallet.purpose != intent.purpose do
    return Err("bounty_transfer_context_changed")
  end
  let namespace = bounty_recovery_namespace(config, rpc, intent.purpose)?
  if asset == 0 do
    if bounty_legacy_recovery_identity(config, rpc, intent.mint, wire)? != value.identity do
      return Err("bounty_transfer_context_changed")
    end
  end
  case movement.root do
    None -> do
      migrate_bounty_transfer_legacy(path, key, namespace)?
      nil
    end
    Some(root) -> if root.namespace != namespace || root.purpose != intent.purpose do
      return Err("bounty_transfer_context_changed")
    end
  end
  let result = HistoricalContext {
    rpc: rpc,
    value: value,
    path: path,
    frame: encode_security_config(config)?,
    wire: wire,
    wallet: wallet
  }
  if !historical_current(result) do
    return Err("bounty_transfer_context_changed")
  end
  Ok(result)
end

pub fn native_bounty_transfer_submit(input :: Bytes) -> Bytes!String do
  # A leg ID survives a proved failure and retry. The original host action must
  # name its exact signed attempt before any submission.
  let parsed = request(input, 3)?
  if Bytes.length(List.get(parsed.fields, 1)) != 32
    || Bytes.length(List.get(parsed.fields, 2)) != 64 do
    return Err("invalid_bounty_transfer_request")
  end
  ensure_schema(parsed.path)?
  let key = platform_key()?
  let saved = historical_context(parsed.path, key, parsed.asset, List.get(parsed.fields, 1))?
  if !Bytes.secure_equals(saved.value.signature, List.get(parsed.fields, 2)) do
    return Err("bounty_transfer_attempt_changed")
  end
  let value = submit_bounty_journal(parsed.path,
    key,
    saved.rpc,
    saved.value,
    now()?,
    fn() do historical_current(saved) end)?
  if parsed.versioned do
    aggregate(parsed.path, key)
  else
    view(Some(value))
  end
end

pub fn native_bounty_transfer_recover(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 2)?
  if Bytes.length(List.get(parsed.fields, 1)) != 32 do
    return Err("invalid_bounty_transfer_request")
  end
  ensure_schema(parsed.path)?
  let key = platform_key()?
  let saved = historical_context(parsed.path, key, parsed.asset, List.get(parsed.fields, 1))?
  let value = recover_bounty_journal(parsed.path,
    key,
    saved.rpc,
    saved.value,
    fn() do historical_current(saved) end)?
  if parsed.versioned do
    aggregate(parsed.path, key)
  else
    view(Some(value))
  end
end

pub fn native_bounty_transfer_cancel(input :: Bytes) -> Bytes!String do
  let parsed = request(input, 2)?
  let identity = List.get(parsed.fields, 1)
  if Bytes.length(identity) != 32 do
    return Err("invalid_bounty_transfer_request")
  end
  ensure_schema(parsed.path)?
  let key = platform_key()?
  let existing = existing_leg(parsed.path, key, parsed.asset)?
  case existing do
    None -> return Err("bounty_transfer_not_started")
    Some(value) -> if value.identity != identity do
      return Err("bounty_transfer_identity_mismatch")
    end
  end
  let value = cancel_bounty_transfer(parsed.path, key, identity)?
  if parsed.versioned do
    aggregate(parsed.path, key)
  else
    view(Some(value))
  end
end
