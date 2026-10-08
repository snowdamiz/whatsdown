##! Oblivious HTTP for this device's stateless requests (protocol/ohttp-v1.md):
##! lookups, prekey claims, transparency proofs, the credit issuer's keys, and
##! the signed mailbox fetch and acknowledgement. They go to the privacy edge
##! the build pins, sealed to the gateway key it pins, so the backend sees the
##! edge's connection instead of this device's, and the edge sees neither the
##! request nor the answer.
##!
##! The app performs the HTTP for its own requests: it asks for the
##! encapsulated request, posts it, and hands the answer back. The response
##! key never reaches it: it gets the key sealed under the platform storage
##! key, bound to its request. Requests the core makes itself go through
##! `oblivious_exchange`. A build that pins no gateway (development) has none
##! of this and sends directly.

from Binary.Reader import BinaryReader
from Mobile.Codec import (
  mobile_finish,
  mobile_join,
  mobile_reader,
  mobile_utf8,
  mobile_vector,
  mobile_write_u16,
  take_vector_error
)
from Mobile.Platform import native_security_config
from Mobile.Types import MobileSecurityConfig
from Privacy.Bhttp import bhttp_decode_response
from Privacy.Ohttp import (
  OhttpContext,
  ohttp_decapsulate_response,
  ohttp_encapsulate_request,
  ohttp_exchange
)
from Privacy.OhttpWire import OhttpKeyConfig, ohttp_key_config_decode, ohttp_request_message
from Security.Config import SecurityConfig
from Storage.Keys import pending_context, platform_key

pub struct ObliviousPin do
  config :: OhttpKeyConfig
  relay :: String
end

## The gateway key and relay the security config pins, if any.

fn pinned_config(native :: MobileSecurityConfig) -> SecurityConfig do
  native.config
end

pub fn oblivious_pin() -> Option<ObliviousPin>!String do
  let pinned = pinned_config(native_security_config()?)
  if Bytes.length(pinned.ohttp_key_config) == 0 do
    Ok(None)
  else
    Ok(Some(ObliviousPin {
      config: ohttp_key_config_decode(pinned.ohttp_key_config)?,
      relay: pinned.ohttp_relay
    }))
  end
end

# Storage purpose 5 holds a 32-byte SecretBytes with no session, as the
# backup keys do; the label binds the blob to its request's `enc`
# (protocol/secret-purpose-inventory.md).

fn sealed_label(enc :: Bytes) -> Bytes!String do
  pending_context("ohttp-response-key/v1/" <> Bytes.to_hex(enc), 5)
end

# `enc ‖ the response secret sealed under the platform key`: what the app
# holds between a request and its answer.

fn seal_context(context :: borrow OhttpContext) -> Bytes!String do
  let wrapping_key = platform_key()?
  let sealed = case Secret.seal_for_storage(context.secret,
    wrapping_key,
    sealed_label(context.enc)?) do
    Err(_) -> Err("oblivious_context_seal_failed")
    Ok(value)
  end?
  mobile_join([context.enc, sealed], 0, Bytes.empty())
end

fn open_context(sealed :: Bytes) -> OhttpContext!String do
  if Bytes.length(sealed) <= 32 do
    Err("invalid_oblivious_context")
  else
    let enc = case Bytes.slice(sealed, 0, 32) do
      Err(_) -> Err("invalid_oblivious_context")
      Ok(value)
    end?
    let blob = case Bytes.slice(sealed, 32, Bytes.length(sealed) - 32) do
      Err(_) -> Err("invalid_oblivious_context")
      Ok(value)
    end?
    let wrapping_key = platform_key()?
    let secret = case Secret.unseal_from_storage(blob, wrapping_key, sealed_label(enc)?) do
      Err(_) -> Err("invalid_oblivious_context")
      Ok(value)
    end?
    Ok(OhttpContext { enc: enc, secret: secret })
  end
end

fn fields(input :: Bytes, count :: Int, maximum :: Int, error :: String) -> List<Bytes>!String do
  let state = mobile_reader(input, maximum, error)?
  read_fields(state, count, maximum, error, List.new())
end

fn read_fields(state :: BinaryReader,
  count :: Int,
  maximum :: Int,
  error :: String,
  output :: List<Bytes>) -> List<Bytes>!String do
  if count == 0 do
    mobile_finish(state, error)?
    Ok(output)
  else
    let next = take_vector_error(state, maximum, error)?
    read_fields(next.state, count - 1, maximum, error, List.append(output, next.value))
  end
end

fn valid_target(method :: String, path :: String) -> Bool do
  (method == "GET" || method == "POST")
    && String.starts_with(path, "/v1/")
    && !String.contains(path, "#")
    && String.length(path) <= 1024
end

## Export: vector32(method) ‖ vector32(path) ‖ vector32(body). Answer: empty
## when the build pins no gateway, else vector32(relay origin) ‖
## vector32(encapsulated request) ‖ vector32(sealed response key).

pub fn oblivious_encapsulate(request :: Bytes) -> Bytes!String do
  let parts = fields(request, 3, 65536, "invalid_oblivious_request")?
  let method = mobile_utf8(List.get(parts, 0), "invalid_oblivious_request")?
  let path = mobile_utf8(List.get(parts, 1), "invalid_oblivious_request")?
  if !valid_target(method, path) || Bytes.length(List.get(parts, 2)) > 32768 do
    Err("invalid_oblivious_request")
  else
    case oblivious_pin()? do
      None -> Ok(Bytes.empty())
      Some(pin) -> do
        let message = ohttp_request_message(method, path, List.get(parts, 2))?
        let (encapsulated, context) = ohttp_encapsulate_request(pin.config, message)?
        mobile_join([
            mobile_vector(Bytes.from_utf8(pin.relay))?,
            mobile_vector(encapsulated)?,
            mobile_vector(seal_context(context)?)?
          ],
          0,
          Bytes.empty())
      end
    end
  end
end

fn opened(context :: borrow OhttpContext, answer :: Bytes) -> (Int, Bytes)!String do
  let response = case ohttp_decapsulate_response(context, answer) do
    Err(_) -> Err("oblivious_response_invalid")
    Ok(value)
  end?
  case bhttp_decode_response(response) do
    Err(_) -> Err("oblivious_response_invalid")
    Ok(value) -> Ok((value.status, value.content))
  end
end

## Export: vector32(sealed response key) ‖ vector32(encapsulated response).
## Answer: u16 status ‖ body, the gateway's answer from the backend. Anything
## altered on the way is refused (oblivious_response_invalid).

pub fn oblivious_decapsulate(request :: Bytes) -> Bytes!String do
  let parts = fields(request, 2, 1048576 + 8192, "invalid_oblivious_response")?
  let context = open_context(List.get(parts, 0))?
  let (status, body) = opened(context, List.get(parts, 1))?
  mobile_join([mobile_write_u16(status)?, body], 0, Bytes.empty())
end

## A request the core sends itself, through the pinned relay: (status, body)
## of the backend's answer. Err("oblivious_relay_unavailable") when the relay
## or the gateway didn't answer with an encapsulated response.

pub fn oblivious_exchange(pin :: ObliviousPin,
  method :: String,
  path :: String,
  body :: Bytes,
  timeout_ms :: Int) -> (Int, Bytes)!String do
  case ohttp_exchange(pin.config, pin.relay, method, path, body, timeout_ms) do
    Err(error) -> if error == "ohttp_relay_unavailable" do
      Err("oblivious_relay_unavailable")
    else
      Err("oblivious_response_invalid")
    end
    Ok(answer)
  end
end
