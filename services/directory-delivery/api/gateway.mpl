##! The Oblivious HTTP gateway (RFC 9458; protocol/ohttp-v1.md). The privacy
##! edge relays a phone's encapsulated request to POST /internal/v1/ohttp
##! with its bearer; the gateway opens it with its key, answers it from the
##! same code as the direct route, and encapsulates the answer to that phone.
##! So the core learns the request but not the phone's address, and the edge
##! the address but neither request nor answer.
##!
##! Keys: MESSENGER_OHTTP_GATEWAY_KEY_ID (0-255) and
##! MESSENGER_OHTTP_GATEWAY_SEED_HEX, the X25519 private key; while rotating,
##! the retiring key as MESSENGER_OHTTP_GATEWAY_PREVIOUS_KEY_ID and
##! MESSENGER_OHTTP_GATEWAY_PREVIOUS_SEED_HEX. Without a key id the gateway
##! is off and answers 503.

from Api.Binary import BinaryResult, acknowledge_request, consistency_request, fetch_request
from Api.CreditRoutes import credits_issuer_keys_request
from Api.Http import directory_prekey_claim_result, directory_resolve_result
from Api.WitnessNetwork import leaf_request
from Privacy.Bhttp import bhttp_decode_request
from Privacy.Edge import internal_delivery_authorized, internal_delivery_token
from Privacy.Ohttp import OhttpContext, ohttp_decapsulate_request, ohttp_encapsulate_response
from Privacy.OhttpWire import (
  OhttpKeyConfig,
  ohttp_keys_encode,
  ohttp_request_key_id,
  ohttp_response_message
)
from Runtime.OhttpStrikes import ohttp_strike_claim
from Runtime.Registry import get_pool

fn now_ms() -> Int do
  DateTime.to_unix_ms(DateTime.utc_now())
end

fn plain(status :: Int) -> BinaryResult do
  BinaryResult { status: status, body: Bytes.empty() }
end

fn key_id_from(name :: String) -> Int do
  let value = Env.get_int(name, -1)
  if value >= 0 && value <= 255 do
    value
  else
    -1
  end
end

# (key id, seed variable) of each configured key: the current one, then the
# one being retired.

fn slots() -> List<(Int, String)> do
  let current = key_id_from("MESSENGER_OHTTP_GATEWAY_KEY_ID")
  let previous = key_id_from("MESSENGER_OHTTP_GATEWAY_PREVIOUS_KEY_ID")
  let first = if current >= 0 do
    [(current, "MESSENGER_OHTTP_GATEWAY_SEED_HEX")]
  else
    List.new()
  end
  if previous >= 0 && previous != current do
    first ++ [(previous, "MESSENGER_OHTTP_GATEWAY_PREVIOUS_SEED_HEX")]
  else
    first
  end
end

fn key_pair(seed_variable :: String) -> X25519KeyPair!String do
  let material = case Env.get_secret_hex(seed_variable) do
    Err(_) -> Err("invalid OHTTP gateway key")
    Ok(value)
  end?
  case Crypto.x25519_from_secret(material) do
    Err(_) -> Err("invalid OHTTP gateway key")
    Ok(pair)
  end
end

fn configs(values :: List<(Int, String)>,
  index :: Int,
  output :: List<OhttpKeyConfig>) -> List<OhttpKeyConfig>!String do
  if index >= List.length(values) do
    Ok(output)
  else
    let (key_id, variable) = List.get(values, index)
    let pair = key_pair(variable)?
    configs(values,
      index + 1,
      List.append(output, OhttpKeyConfig { key_id: key_id, public_key: pair.public_key.bytes }))
  end
end

## Startup check: every configured key loads.

pub fn ohttp_gateway_validate_config() -> Result<(), String> do
  configs(slots(), 0, List.new())?
  Ok(nil)
end

## GET /v1/ohttp/keys: `application/ohttp-keys` for the configured keys, the
## current one first, so an operator can compare it with what builds pin.

pub fn ohttp_gateway_keys() -> BinaryResult do
  case configs(slots(), 0, List.new()) do
    Err(_) -> plain(503)
    Ok([]) -> plain(404)
    Ok(values) -> case ohttp_keys_encode(values) do
      Err(_) -> plain(500)
      Ok(body) -> BinaryResult { status: 200, body: body }
    end
  end
end

fn query_value(query :: String, name :: String) -> Option<String> do
  let prefix = name <> "="
  case List.find(String.split(query, "&"), fn part -> String.starts_with(part, prefix) end) do
    None
    Some(part) -> Some(String.slice(part, String.length(prefix), String.length(part)))
  end
end

# The routes the gateway serves: the stateless reads and the signed mailbox
# fetch and acknowledgement. Everything else is 404, so the gateway can't be
# used to reach any other resource.

fn dispatch(method :: String, target :: String, body :: Bytes) -> BinaryResult do
  let parts = String.split(target, "?")
  let path = List.get(parts, 0)
  let query = if List.length(parts) == 2 do
    List.get(parts, 1)
  else
    ""
  end
  let route = method <> " " <> path
  if List.length(parts) > 2 || (query != "" && route != "GET /v1/credits/issuer-keys") do
    plain(404)
  else if route == "POST /v1/devices/resolve" do
    directory_resolve_result(body)
  else if route == "POST /v1/prekeys/bundle" do
    directory_prekey_claim_result(body)
  else if route == "POST /v1/transparency/consistency" do
    consistency_request(get_pool(), body)
  else if route == "POST /v1/transparency/leaf" do
    leaf_request(get_pool(), body)
  else if route == "GET /v1/credits/issuer-keys" do
    credits_issuer_keys_request(get_pool(), query_value(query, "previous_tree_size"), now_ms())
  else if route == "POST /v1/mailbox/fetch" do
    fetch_request(get_pool(), body)
  else if route == "POST /v1/mailbox/ack" do
    acknowledge_request(get_pool(), body)
  else
    plain(404)
  end
end

fn answered(context :: borrow OhttpContext, result :: BinaryResult) -> BinaryResult do
  let sealed = case ohttp_response_message(result.status, result.body) do
    Err(_) -> Err("encoding failed")
    Ok(message) -> ohttp_encapsulate_response(context, message)
  end
  case sealed do
    Err(_) -> plain(500)
    Ok(body) -> BinaryResult { status: 200, body: body }
  end
end

# After the request is open every answer is encapsulated (RFC 9458 section
# 5.2): a replay (409), a malformed inner message (400), and the route's own
# answer. Before that the status goes back bare: 400 for a frame too short,
# 422 for a key, suite or ciphertext the gateway can't open.

fn inner_answer(context :: borrow OhttpContext, request :: Bytes, now :: Int) -> BinaryResult do
  if !ohttp_strike_claim(context.enc, now) do
    answered(context, plain(409))
  else
    case bhttp_decode_request(request) do
      Err(_) -> answered(context, plain(400))
      Ok(inner) -> if inner.scheme != "https" do
        answered(context, plain(400))
      else
        answered(context, dispatch(inner.method, inner.path, inner.content))
      end
    end
  end
end

## One encapsulated request, opened with this key.

pub fn ohttp_gateway_answer_with_key(key_id :: Int,
  private_key :: borrow X25519PrivateKey,
  encapsulated :: Bytes,
  now :: Int) -> BinaryResult do
  case ohttp_decapsulate_request(key_id, private_key, encapsulated) do
    Err(error) -> if error == "ohttp_malformed" do
      plain(400)
    else
      plain(422)
    end
    Ok((request, context)) -> inner_answer(context, request, now)
  end
end

fn seed_variable(values :: List<(Int, String)>, key_id :: Int, index :: Int) -> Option<String> do
  if index >= List.length(values) do
    None
  else
    let (id, variable) = List.get(values, index)
    if id == key_id do
      Some(variable)
    else
      seed_variable(values, key_id, index + 1)
    end
  end
end

## One encapsulated request, with the configured key it names.

pub fn ohttp_gateway_answer(encapsulated :: Bytes) -> BinaryResult do
  case ohttp_request_key_id(encapsulated) do
    Err(_) -> plain(400)
    Ok(key_id) -> case seed_variable(slots(), key_id, 0) do
      None -> if List.length(slots()) == 0 do
        plain(503)
      else
        plain(422)
      end
      Some(variable) -> case key_pair(variable) do
        Err(_) -> plain(503)
        Ok(pair) -> ohttp_gateway_answer_with_key(key_id, pair.private_key, encapsulated, now_ms())
      end
    end
  end
end

fn authorization_header(request :: Request) -> Option<String> do
  case Request.header(request, "Authorization") do
    None -> Request.header(request, "authorization")
    Some(value)
  end
end

fn respond(result :: BinaryResult, content_type :: String) -> Response do
  if result.status == 200 do
    HTTP.response_bytes_with_headers(200,
      result.body,
      Map.put(Map.put(Map.new(), "Content-Type", content_type), "Cache-Control", "no-store"))
  else
    HTTP.response_bytes_with_headers(result.status,
      result.body,
      Map.put(Map.new(), "Cache-Control", "no-store"))
  end
end

## POST /internal/v1/ohttp, from the privacy edge only (its bearer).

pub fn handle_ohttp(request :: Request) -> Response do
  case internal_delivery_token(Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", "")) do
    Err(_) -> HTTP.response(503, "")
    Ok(secret) -> if !internal_delivery_authorized(authorization_header(request), secret) do
      HTTP.response(401, "")
    else
      respond(ohttp_gateway_answer(Request.body_bytes(request)), "message/ohttp-res")
    end
  end
end

pub fn handle_ohttp_keys(_request :: Request) -> Response do
  respond(ohttp_gateway_keys(), "application/ohttp-keys")
end
