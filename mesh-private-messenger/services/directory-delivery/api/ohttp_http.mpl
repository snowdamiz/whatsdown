##! Fixed OHTTP HTTP ingress. Configuration and private keys belong only to the core.
from Api.Ohttp import execute_read_ohttp
from Ohttp.Keys import OhttpKeyConfig, decode_key_configs, encode_key_configs
from Ohttp.Policy import prekey_claim_request
from Privacy.Edge import internal_delivery_authorized, internal_delivery_token
from Runtime.Registry import get_pool

struct GatewayConfig do
  origin :: String
  development :: Bool
  keys :: List<OhttpKeyConfig>
end

fn invalid() -> String do
  "invalid_ohttp_gateway_configuration"
end

fn mode(name :: String) -> Bool!String do
  case Env.get(name, "off") do
    "off" -> Ok(false)
    "on" -> Ok(true)
    _ -> Err(invalid())
  end
end

fn configuration() -> GatewayConfig!String do
  let origin = Env.get("MESSENGER_OHTTP_CORE_ORIGIN", "")
  let development = mode("MESSENGER_OHTTP_DEVELOPMENT")?
  prekey_claim_request(origin, development, Bytes.empty())?
  let encoded = Env.get("MESSENGER_OHTTP_KEY_CONFIG_HEX", "")
  if String.length(encoded) > 412 do
    return Err(invalid())
  end
  let bytes = case Bytes.from_hex(encoded) do
    Err(_) -> return Err(invalid())
    Ok(value) -> value
  end
  let keys = decode_key_configs(bytes)?
  if !Bytes.secure_equals(encode_key_configs(keys)?, bytes) do
    return Err(invalid())
  end
  Ok(GatewayConfig { origin: origin, development: development, keys: keys })
end

fn private_key(config :: GatewayConfig, index :: Int) -> X25519PrivateKey!String do
  if index < 0 || index >= List.length(config.keys) || index > 1 do
    return Err(invalid())
  end
  let name = if index == 0 do
    "MESSENGER_OHTTP_PRIVATE_KEY_0_HEX"
  else
    "MESSENGER_OHTTP_PRIVATE_KEY_1_HEX"
  end
  let secret = case Env.get_secret_hex(name) do
    Err(_) -> return Err(invalid())
    Ok(value) -> value
  end
  let pair = case Crypto.x25519_from_secret(secret) do
    Err(_) -> return Err(invalid())
    Ok(value) -> value
  end
  if !Bytes.secure_equals(pair.public_key.bytes, List.get(config.keys, index).public_key.bytes) do
    return Err(invalid())
  end
  Ok(pair.private_key)
end

pub fn validate_ohttp_gateway_config() -> Result<(), String> do
  if !mode("MORSE_OHTTP")? do
    return Ok(nil)
  end
  let config = configuration()?
  for index in 0..List.length(config.keys) do
    let key = private_key(config, index)?
    Secret.destroy(key)
  end
  Ok(nil)
end

fn header(request :: Request, name :: String) -> String do
  case Request.header(request, name) do
    None -> ""
    Some(value) -> value
  end
end

fn respond(status :: Int, body :: Bytes) -> Response do
  let headers = Map.put(Map.new(), "Cache-Control", "no-store")
  if status == 200 do
    HTTP.response_bytes_with_headers(status,
      body,
      Map.put(headers, "Content-Type", "message/ohttp-res"))
  else
    HTTP.response_bytes_with_headers(status, Bytes.empty(), headers)
  end
end

pub fn handle_ohttp(request :: Request) -> Response do
  case mode("MORSE_OHTTP") do
    Err(_) -> return respond(503, Bytes.empty())
    Ok(false) -> return respond(404, Bytes.empty())
    Ok(true) -> nil
  end
  let token = case internal_delivery_token(Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", "")) do
    Err(_) -> return respond(503, Bytes.empty())
    Ok(value) -> value
  end
  if !internal_delivery_authorized(Request.header(request, "authorization"), token) do
    return respond(401, Bytes.empty())
  end
  if header(request, "content-type") != "message/ohttp-req"
    || (header(request, "content-encoding") != ""
      && header(request, "content-encoding") != "identity") do
    return respond(415, Bytes.empty())
  end
  let wire = Request.body_bytes(request)
  if Bytes.length(wire) > 1048576 do
    return respond(413, Bytes.empty())
  end
  if Bytes.length(wire) < 55 do
    return respond(400, Bytes.empty())
  end
  let config = case configuration() do
    Err(_) -> return respond(503, Bytes.empty())
    Ok(value) -> value
  end
  let key_id = case Bytes.get(wire, 0) do
    Err(_) -> return respond(400, Bytes.empty())
    Ok(value) -> value
  end
  let now = case U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now()))) do
    Err(_) -> return respond(503, Bytes.empty())
    Ok(value) -> value
  end
  for index in 0..List.length(config.keys) do
    if List.get(config.keys, index).key_id == key_id do
      let key = case private_key(config, index) do
        Err(_) -> return respond(503, Bytes.empty())
        Ok(value) -> value
      end
      let result = execute_read_ohttp(get_pool(),
        key,
        key_id,
        wire,
        config.origin,
        config.development,
        now,
        Env.get_int("MESSENGER_ABUSE_DIFFICULTY", 16))
      return respond(result.status, result.body)
    end
  end
  respond(400, Bytes.empty())
end
