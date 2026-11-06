from Bounty.Transfer import decode_bounty_transfer
from Mobile.Bounty import disclosable_fork
from Mobile.BountyTransferState import (
  BountyTransferJournal,
  load_bounty_transfer,
  cancel_bounty_transfer
)
from Mobile.BountyTransferNetwork import (
  BountyWalletPins,
  prepare_bounty_movement,
  commit_bounty_movement,
  submit_bounty_movement,
  recover_bounty_movement
)
from Mobile.Codec import current_time, mobile_byte, mobile_write_u64, mobile_utf8
from Mobile.CreditState import pack_credit_parts, unpack_credit_parts
from Mobile.ForkFiling import FilingPlan, prepare_native_filing, native_filing_current
from Transparency.Config import encode_security_config
from Storage.Blobs import ensure_schema
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

fn request(input :: Bytes, count :: Int) -> List<Bytes>!String do
  if Bytes.length(input) > 5500 do
    return Err("invalid_bounty_transfer_request")
  end
  let parts = unpack_credit_parts(input, count, 4096)?
  if List.length(parts) != count do
    return Err("invalid_bounty_transfer_request")
  end
  database(List.head(parts))?
  Ok(parts)
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

pub fn native_bounty_transfer_status(input :: Bytes) -> Bytes!String do
  let path = database(input)?
  ensure_schema(path)?
  let key = platform_key()?
  view(load_bounty_transfer(path, key)?)
end

# Private host orchestration only: JS cannot pass payer/index/mint/amount to the
# SDK. Its destination choice is shown again by the SDK's own native prompt.
pub fn native_bounty_transfer_prepare(input :: Bytes) -> Bytes!String do
  let fields = request(input, 3)?
  let destination = List.get(fields, 1)
  let payer = List.get(fields, 2)
  if Bytes.length(destination) != 32 || Bytes.length(payer) != 32 do
    return Err("invalid_bounty_transfer_request")
  end
  let config = context(database(List.head(fields))?)?
  let key = platform_key()?
  let value = prepare_bounty_movement(config.path,
    key,
    config.filing,
    config.wallet,
    destination,
    payer,
    now()?,
    fn() do current(config) end)?
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
  let fields = request(input, 3)?
  if Bytes.length(List.get(fields, 1)) != 32 || Bytes.length(List.get(fields, 2)) > 1232 do
    return Err("invalid_bounty_transfer_request")
  end
  let config = context(database(List.head(fields))?)?
  let key = platform_key()?
  view(Some(commit_bounty_movement(config.path,
    key,
    config.filing,
    config.wallet,
    List.get(fields, 1),
    List.get(fields, 2),
    now()?,
    fn() do current(config) end)?))
end

pub fn native_bounty_transfer_submit(input :: Bytes) -> Bytes!String do
  let fields = request(input, 2)?
  if Bytes.length(List.get(fields, 1)) != 32 do
    return Err("invalid_bounty_transfer_request")
  end
  let config = context(database(List.head(fields))?)?
  let key = platform_key()?
  view(Some(submit_bounty_movement(config.path,
    key,
    config.filing,
    config.wallet,
    List.get(fields, 1),
    now()?,
    fn() do current(config) end)?))
end

pub fn native_bounty_transfer_recover(input :: Bytes) -> Bytes!String do
  let fields = request(input, 2)?
  if Bytes.length(List.get(fields, 1)) != 32 do
    return Err("invalid_bounty_transfer_request")
  end
  let config = context(database(List.head(fields))?)?
  let key = platform_key()?
  view(Some(recover_bounty_movement(config.path,
    key,
    config.filing,
    config.wallet,
    List.get(fields, 1),
    fn() do current(config) end)?))
end

pub fn native_bounty_transfer_cancel(input :: Bytes) -> Bytes!String do
  let fields = request(input, 2)?
  if Bytes.length(List.get(fields, 1)) != 32 do
    return Err("invalid_bounty_transfer_request")
  end
  let path = database(List.head(fields))?
  ensure_schema(path)?
  let key = platform_key()?
  view(Some(cancel_bounty_transfer(path, key, List.get(fields, 1))?))
end
