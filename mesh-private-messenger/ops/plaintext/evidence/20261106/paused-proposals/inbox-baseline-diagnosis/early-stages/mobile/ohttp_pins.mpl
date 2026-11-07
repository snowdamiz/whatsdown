##! Release-owned OHTTP companion. Parsing binds existing native configuration;
##! it never fetches keys, changes destinations or enables a direct fallback.
from Mobile.NetworkPins import MobileNetworkPins, decode_network_pins
from Transparency.Config import SecurityConfig, encode_security_config
from Ohttp.Keys import OhttpKeyConfig, decode_key_config

pub struct MobileOhttpKey do
  config :: OhttpKeyConfig
  not_before_ms :: U64
  not_after_ms :: U64
end

pub struct MobileOhttpPins do
  identity :: Bytes
  revision :: U64
  network :: MobileNetworkPins
  required :: Bool
  keys :: List<MobileOhttpKey>
end

fn invalid() -> String do
  "invalid_ohttp_configuration"
end

fn integer(text :: String) -> U64!String do
  let value = U64.parse(text)?
  if U64.to_string(value) != text do
    Err(invalid())
  else
    Ok(value)
  end
end

fn decode_pin(line :: String) -> MobileOhttpKey!String do
  let fields = String.split(line, " ")
  if List.length(fields) != 3 do
    return Err(invalid())
  end
  let start = integer(List.get(fields, 0))?
  let finish = integer(List.get(fields, 1))?
  if U64.compare(start, finish) >= 0 do
    return Err(invalid())
  end
  let encoded = List.get(fields, 2)
  if String.length(encoded) < 56 || String.length(encoded) > 136 do
    return Err(invalid())
  end
  let wire = Bytes.from_base64(encoded)?
  if Bytes.to_base64(wire) != encoded do
    return Err(invalid())
  end
  let config = decode_key_config(wire)?
  if Bytes.to_hex(config.public_key.bytes) == String.repeat("00", 32) do
    return Err(invalid())
  end
  Ok(MobileOhttpKey { config: config, not_before_ms: start, not_after_ms: finish })
end

pub fn decode_ohttp_pins(frame :: Bytes,
  network_frame :: Bytes,
  security :: SecurityConfig) -> MobileOhttpPins!String do
  if Bytes.length(frame) < 1 || Bytes.length(frame) > 600 do
    return Err(invalid())
  end
  let text = Bytes.to_utf8(frame)?
  if String.contains(text, "\r") do
    return Err(invalid())
  end
  let fields = String.split(text, "\n")
  if List.length(fields) < 6 || List.length(fields) > 8 || List.get(fields, 0) != "1" do
    return Err(invalid())
  end
  let network = decode_network_pins(network_frame)?
  if List.get(fields, 1) != Bytes.to_hex(Crypto.sha256(network_frame)) do
    return Err("ohttp_network_binding")
  end
  if List.get(fields, 2) != Bytes.to_hex(Crypto.sha256(encode_security_config(security)?)) do
    return Err("ohttp_security_binding")
  end
  let revision = integer(List.get(fields, 3))?
  if U64.to_string(revision) == "0" do
    return Err(invalid())
  end
  let required = case List.get(fields, 4) do
    "off" -> false
    "required" -> true
    _ -> return Err(invalid())
  end
  let count = case List.get(fields, 5) do
    "0" -> 0
    "1" -> 1
    "2" -> 2
    _ -> return Err(invalid())
  end
  if List.length(fields) != 6 + count || (required && count == 0) || (!required && count != 0) do
    return Err(invalid())
  end
  let keys = for index in 0..count do
    decode_pin(List.get(fields, 6 + index))?
  end
  if count == 2 do
    let first = List.get(keys, 0).config
    let second = List.get(keys, 1).config
    if first.key_id == second.key_id
      || Bytes.secure_equals(first.public_key.bytes, second.public_key.bytes) do
      return Err("ohttp_duplicate_key_configuration")
    end
  end
  Ok(MobileOhttpPins {
    identity: Crypto.sha256(Bytes.concat(Bytes.from_utf8("morse-native-ohttp-v1\n"), frame)?),
    revision: revision,
    network: network,
    required: required,
    keys: keys
  })
end

# The whole companion is validated before this selection. No currently valid
# key is an error in required mode; absence is returned only for explicit off.
pub fn select_ohttp_key(pins :: MobileOhttpPins, now :: U64) -> Option<OhttpKeyConfig>!String do
  if !pins.required do
    if List.length(pins.keys) != 0 do
      return Err(invalid())
    end
    return Ok(None)
  end
  if List.length(pins.keys) < 1 || List.length(pins.keys) > 2 do
    return Err(invalid())
  end
  for key in pins.keys do
    if U64.compare(now, key.not_before_ms) >= 0 && U64.compare(now, key.not_after_ms) < 0 do
      return Ok(Some(key.config))
    end
  end
  Err("ohttp_no_active_key")
end
