##! Optional release resource, captured verbatim and retired on any replacement.
from Mobile.NetworkCounterPins import NetworkCounterPins, decode_filing_counter_pins
from Transparency.Config import SecurityConfig
from Solana.Read import pubkey
from Transparency.PermanentReceipt import PermanentReceiptPins
from Transparency.AnchorChain import anchor_addresses
from Transparency.TokenChain import token_addresses
from Mobile.Codec import mobile_write_u64, mobile_byte

# Economic/source rotations and RPC/relay URLs do not change an earned receipt.
# The exact program release and both mint identities remain part of its meaning.
pub fn filing_receipt_binding(pins :: PermanentReceiptPins) -> Bytes!String do
  let bytes = case Bytes.concat_many([
      Bytes.from_utf8("morse-permanent-filing-pins-v1"),
      pins.judge.bytes,
      pins.token.bytes,
      anchor_addresses(pins.judge, pins.log_name)?.log_id,
      pins.usdc.bytes,
      token_addresses(pins.token)?.mint.bytes,
      mobile_write_u64(pins.judge_slot)?,
      pins.service_key,
      mobile_byte(pins.log_version)?
    ],
    256) do
    Err(_) -> return Err("invalid_filing_pins")
    Ok(value) -> value
  end
  Ok(Crypto.sha256(bytes))
end

pub fn native_filing_pin_frame() -> Bytes!String do
  let frame = case Host.push_get_token(Bytes.from_utf8("messenger/network-counter/v1")) do
    Err(error) -> if error == "host_callback_failed:4:2" do
      return Ok(Bytes.empty())
    else
      return Err("filing_pins_unavailable")
    end
    Ok(value) -> value
  end
  # Empty success is a present invalid resource, not the absence sentinel.
  if Bytes.length(frame) < 1 || Bytes.length(frame) > 24576 do
    Err("invalid_filing_pins")
  else
    Ok(frame)
  end
end

pub fn require_filing_pin_frame(captured :: Bytes) -> Result<(), String> do
  let current = case native_filing_pin_frame() do
    Err(_) -> return Err("filing_pins_changed")
    Ok(value) -> value
  end
  if Bytes.secure_equals(current, captured) do
    Ok(nil)
  else
    Err("filing_pins_changed")
  end
end

pub fn filing_pin_selection(frame :: Bytes,
  security :: SecurityConfig) -> Option<NetworkCounterPins>!String do
  if Bytes.length(frame) == 0 do
    return Ok(None)
  end
  let selected = decode_filing_counter_pins(frame, security)?
  if security.slash_mint != "-" do
    let mint = pubkey(security.slash_mint)?
    let expected = case selected.collateral do
      Some(value) -> value.pins.usdc
      None -> case selected.legacy_mint do
        None -> return Err("invalid_filing_pins")
        Some(value) -> value
      end
    end
    if mint != expected do
      return Err("filing_mint_binding")
    end
  end
  Ok(Some(selected))
end
