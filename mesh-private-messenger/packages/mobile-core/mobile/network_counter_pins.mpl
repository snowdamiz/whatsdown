##! Optional release-owned pins. No endpoint, witness or service identity is
##! accepted from a native invocation. v1-v5 SecurityConfig semantics stay intact.
from Transparency.Config import SecurityConfig, encode_security_config, pinned_witness_keys
from Transparency.AnchorChain import configured_anchor_pins
from Transparency.RpcTransport import webpki_rpc_transport
from Transparency.NetworkCollateralPins import CollateralPins, CollateralSelection
from Transparency.TokenChain import token_addresses
from Solana.Read import Pubkey, pubkey

pub struct NetworkOraclePins do
  receiver :: Pubkey
  source :: Pubkey
  feed :: Bytes
  revision :: U64
end

pub struct NetworkCounterPins do
  identity :: Bytes
  security :: SecurityConfig
  minimum_slot :: U64
  judge_slot :: U64
  log_version :: Int
  legacy_governance :: Option<Pubkey>
  legacy_authority :: Option<Pubkey>
  legacy_mint :: Option<Pubkey>
  collateral :: Option<CollateralSelection>
  oracle :: Option<NetworkOraclePins>
  tls_root :: Option<Bytes>
end

pub fn counter_integer(text :: String) -> U64!String do
  let n = U64.parse(text)?
  if U64.to_string(n) != text do
    Err("invalid_network_counter_configuration")
  else
    Ok(n)
  end
end

fn key(text :: String) -> Pubkey!String do
  let result = pubkey(text)?
  if Bytes.to_base58(result.bytes) != text
    || Bytes.to_hex(result.bytes) == String.repeat("00", 32) do
    Err("invalid_network_counter_configuration")
  else
    Ok(result)
  end
end

pub fn decode_network_counter_pins(frame :: Bytes,
  security :: SecurityConfig) -> NetworkCounterPins!String do
  decode_counter_pins(frame, security, true)
end

# Filing authenticates the release's own log, including its permanent receipts.
# The Settings counter retains its existing morse-main-only product boundary.
pub fn decode_filing_counter_pins(frame :: Bytes,
  security :: SecurityConfig) -> NetworkCounterPins!String do
  decode_counter_pins(frame, security, false)
end

fn decode_counter_pins(frame :: Bytes,
  security :: SecurityConfig,
  main_only :: Bool) -> NetworkCounterPins!String do
  if Bytes.length(frame) < 1 || Bytes.length(frame) > 24576 do
    return Err("invalid_network_counter_configuration")
  end
  let text = Bytes.to_utf8(frame)?
  let fields = String.split(text, "\n")
  if List.length(fields) != 17 || List.get(fields, 0) != "1" || String.contains(text, "\r") do
    return Err("invalid_network_counter_configuration")
  end
  let security_frame = encode_security_config(security)?
  if List.get(fields, 1) != Bytes.to_hex(Crypto.sha256(security_frame)) do
    return Err("network_counter_security_binding")
  end
  let anchor = case configured_anchor_pins(security, webpki_rpc_transport(security.rpc_urls)?)? do
    None -> return Err("network_counter_anchor_required")
    Some(value) -> value
  end
  if (main_only && anchor.log_name != "morse-main") || List.length(security.rpc_urls) < 3 do
    return Err("network_counter_main_only")
  end
  let mode = List.get(fields, 2)
  let judge_slot = counter_integer(List.get(fields, 4))?
  let zero = U64.parse("0")?
  let selected = if mode == "v2" do
    let pins = CollateralPins {
      token: key(List.get(fields, 5))?,
      token_governance: key(List.get(fields, 7))?,
      token_slot: counter_integer(List.get(fields, 6))?,
      usdc: key(List.get(fields, 8))?,
      morse: key(List.get(fields, 9))?,
      judge: anchor.program,
      judge_slot: judge_slot,
      rewards: key(List.get(fields, 10))?,
      rewards_slot: counter_integer(List.get(fields, 11))?,
      rewards_governance: key(List.get(fields, 12))?,
      log_name: anchor.log_name,
      log_version: case List.get(fields, 16) do
        "1" -> 1
        "2" -> 2
        _ -> return Err("invalid_network_counter_configuration")
      end,
      service_key: security.service_public_key,
      network_started: counter_integer(List.get(fields, 13))?
    }
    if pins.token == pins.judge
      || pins.token == pins.rewards
      || pins.judge == pins.rewards
      || pins.usdc == pins.morse
      || token_addresses(pins.token)?.mint != pins.morse
      || pins.network_started == zero do
      return Err("invalid_network_counter_configuration")
    end
    Some(CollateralSelection { pins: pins, witnesses: pinned_witness_keys(security), proofs: [] })
  else if mode == "legacy-v1" do
    for index in [6, 9, 10, 11, 12, 13, 14] do
      if List.get(fields, index) != "-" do
        return Err("invalid_network_counter_configuration")
      end
    end
    None
  else
    return Err("invalid_network_counter_configuration")
  end
  let oracle = if List.get(fields, 14) == "-" do
    None
  else
    if mode != "v2" do
      return Err("invalid_network_counter_configuration")
    end
    let parts = String.split(List.get(fields, 14), " ")
    if List.length(parts) != 4 do
      return Err("invalid_network_counter_configuration")
    end
    let feed = Bytes.from_hex(List.get(parts, 2))?
    let revision = counter_integer(List.get(parts, 3))?
    if Bytes.length(feed) != 32
      || Bytes.to_hex(feed) != List.get(parts, 2)
      || Bytes.to_hex(feed) == String.repeat("00", 32)
      || revision == zero do
      return Err("invalid_network_counter_configuration")
    end
    Some(NetworkOraclePins {
      receiver: key(List.get(parts, 0))?,
      source: key(List.get(parts, 1))?,
      feed: feed,
      revision: revision
    })
  end
  let root = if List.get(fields, 15) == "-" do
    None
  else
    let pem = Bytes.from_base64(List.get(fields, 15))?
    if Bytes.length(pem) < 1
      || Bytes.length(pem) > 8192
      || Bytes.to_base64(pem) != List.get(fields, 15) do
      return Err("invalid_network_counter_configuration")
    end
    Some(pem)
  end
  # Explicit chain log layout, independent of the preferred checkpoint format.
  if List.get(fields, 16) != "1" && List.get(fields, 16) != "2" do
    return Err("invalid_network_counter_configuration")
  end
  Ok(NetworkCounterPins {
    identity: Crypto.sha256(Bytes.concat(Bytes.from_utf8("morse-native-network-counter-v1\n"),
      frame)?),
    security: security,
    minimum_slot: counter_integer(List.get(fields, 3))?,
    judge_slot: judge_slot,
    log_version: if List.get(fields, 16) == "1" do
      1
    else
      2
    end,
    collateral: selected,
    oracle: oracle,
    tls_root: root,
    legacy_authority: if mode == "legacy-v1" do
      Some(key(List.get(fields, 5))?)
    else
      None
    end,
    legacy_governance: if mode == "legacy-v1" do
      Some(key(List.get(fields, 7))?)
    else
      None
    end,
    legacy_mint: if mode == "legacy-v1" do
      Some(key(List.get(fields, 8))?)
    else
      None
    end
  })
end
