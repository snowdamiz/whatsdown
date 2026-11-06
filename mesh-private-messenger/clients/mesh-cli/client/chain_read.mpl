from Transparency.Config import SecurityConfig, decode_security_config
from Transparency.AnchorChain import AnchorPins, configured_anchor_pins, sample_anchor_sources
from Transparency.RpcTransport import webpki_rpc_transport
from Solana.Read import Pubkey, pubkey

pub struct ChainReadOptions do
  config :: SecurityConfig
  pins :: AnchorPins
  mint :: Pubkey
  version :: Int
  minimum_slot :: U64
end

pub fn load_chain_read_options(name :: String, command :: String) -> ChainReadOptions!String do
  let frame = Env.get("MESSENGER_SECURITY_CONFIG", "")
  if frame == "" do
    return Err("MESSENGER_SECURITY_CONFIG is required for #{command}")
  end
  let config = decode_security_config(Bytes.from_utf8(frame))?
  let pins = case configured_anchor_pins(config, webpki_rpc_transport(config.rpc_urls)?)? do
    None -> return Err("#{command}_requires_anchor_pins")
    Some(value) -> value
  end
  if pins.log_name != name do
    return Err("#{command}_log_mismatch")
  end
  let mint = Env.get("MORSE_BOND_MINT", "")
  if mint == "" do
    return Err("MORSE_BOND_MINT is required for #{command}")
  end
  let mint = pubkey(mint)?
  let version = case Env.get("MORSE_BOND_LOG_VERSION", Int.to_string(config.log_version)) do
    "1" -> 1
    "2" -> 2
    _ -> return Err("MORSE_BOND_LOG_VERSION must be 1 or 2")
  end
  let minimum = Env.get("MORSE_BOND_MIN_CONTEXT_SLOT", "0")
  let slot = U64.parse(minimum)?
  if U64.to_string(slot) != minimum do
    return Err("invalid_#{command}_minimum_slot")
  end
  Ok(ChainReadOptions {
    config: config,
    pins: sample_anchor_sources(pins)?,
    mint: mint,
    version: version,
    minimum_slot: slot
  })
end
