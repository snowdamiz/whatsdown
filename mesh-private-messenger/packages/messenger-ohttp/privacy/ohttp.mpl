##! Oblivious HTTP (RFC 9458) encapsulation, sections 4.3 and 4.4, over
##! Mesh's HPKE with a secret export (Crypto.hpke_seal_export and
##! hpke_open_export) and the derived-key AEAD for responses
##! (Crypto.hkdf_aead_seal and hkdf_aead_open). The formats are
##! Privacy.OhttpWire; protocol/ohttp-v1.md describes both.

from Privacy.Bhttp import bhttp_decode_response
from Privacy.OhttpWire import (
  OhttpKeyConfig,
  ohttp_aead_id,
  ohttp_header,
  ohttp_kdf_id,
  ohttp_kem_id,
  ohttp_request_info,
  ohttp_request_key_id,
  ohttp_request_message,
  ohttp_response_context,
  ohttp_response_nonce_length,
  ohttp_valid_config
)

## A request's HPKE context, from either end: what is needed to encapsulate
## (gateway) or decapsulate (client) its response.

pub resource struct OhttpContext do
  enc :: Bytes
  secret :: SecretBytes
end

fn concat(left :: Bytes, right :: Bytes) -> Bytes!String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("ohttp_allocation_failed")
    Ok(value)
  end
end

fn slice(input :: Bytes, offset :: Int, length :: Int, error :: String) -> Bytes!String do
  case Bytes.slice(input, offset, length) do
    Err(_) -> Err(error)
    Ok(value)
  end
end

fn u16_at(input :: Bytes, offset :: Int, error :: String) -> Int!String do
  case Bytes.read_u16_be(input, offset) do
    Err(_) -> Err(error)
    Ok(value)
  end
end

## Section 4.3, client side: `hdr ‖ enc ‖ ct`, and the context the response
## is read with. A fresh HPKE context every time.

pub fn ohttp_encapsulate_request(config :: OhttpKeyConfig,
  request :: Bytes) -> (Bytes, OhttpContext)!String do
  if !ohttp_valid_config(config) do
    Err("ohttp_invalid_key_config")
  else
    let info = ohttp_request_info(config.key_id)?
    let (sealed, secret) = case Crypto.hpke_seal_export(X25519PublicKey {
        bytes: config.public_key
      },
      info,
      Bytes.empty(),
      request,
      ohttp_response_context()) do
      Err(_) -> Err("ohttp_encapsulation_failed")
      Ok(pair)
    end?
    let enc = slice(sealed, 0, 32, "ohttp_encapsulation_failed")?
    let encapsulated = concat(ohttp_header(config.key_id)?, sealed)?
    Ok((encapsulated, OhttpContext { enc: enc, secret: secret }))
  end
end

## Section 4.3, gateway side, with the private key of `key_id`. Refused:
## too short to hold hdr, enc and a tag (ohttp_malformed); another key id
## (ohttp_unknown_key); another KEM, KDF or AEAD (ohttp_unsupported_suite);
## a ciphertext that doesn't open (ohttp_decryption_failed).

pub fn ohttp_decapsulate_request(key_id :: Int,
  private_key :: borrow X25519PrivateKey,
  encapsulated :: Bytes) -> (Bytes, OhttpContext)!String do
  if Bytes.length(encapsulated) < 7 + 32 + 16 do
    Err("ohttp_malformed")
  else if ohttp_request_key_id(encapsulated)? != key_id do
    Err("ohttp_unknown_key")
  else if u16_at(encapsulated, 1, "ohttp_malformed")? != ohttp_kem_id()
    || u16_at(encapsulated, 3, "ohttp_malformed")? != ohttp_kdf_id()
    || u16_at(encapsulated, 5, "ohttp_malformed")? != ohttp_aead_id() do
    Err("ohttp_unsupported_suite")
  else
    let sealed = slice(encapsulated, 7, Bytes.length(encapsulated) - 7, "ohttp_malformed")?
    let (request, secret) = case Crypto.hpke_open_export(private_key,
      ohttp_request_info(key_id)?,
      Bytes.empty(),
      sealed,
      ohttp_response_context()) do
      Err(_) -> Err("ohttp_decryption_failed")
      Ok(pair)
    end?
    Ok((request, OhttpContext { enc: slice(sealed, 0, 32, "ohttp_malformed")?, secret: secret }))
  end
end

## Section 4.4, gateway side: `response_nonce ‖ ct`.

pub fn ohttp_encapsulate_response(context :: borrow OhttpContext,
  response :: Bytes) -> Bytes!String do
  let nonce = case Crypto.random_bytes(ohttp_response_nonce_length()) do
    Err(_) -> Err("ohttp_encapsulation_failed")
    Ok(value)
  end?
  let sealed = case Crypto.hkdf_aead_seal(context.secret,
    concat(context.enc, nonce)?,
    Bytes.empty(),
    response) do
    Err(_) -> Err("ohttp_encapsulation_failed")
    Ok(value)
  end?
  concat(nonce, sealed)
end

## Section 4.4, client side.

pub fn ohttp_decapsulate_response(context :: borrow OhttpContext,
  encapsulated :: Bytes) -> Bytes!String do
  if Bytes.length(encapsulated) < ohttp_response_nonce_length() + 16 do
    Err("ohttp_response_invalid")
  else
    let nonce = slice(encapsulated, 0, ohttp_response_nonce_length(), "ohttp_response_invalid")?
    let sealed = slice(encapsulated,
      ohttp_response_nonce_length(),
      Bytes.length(encapsulated) - ohttp_response_nonce_length(),
      "ohttp_response_invalid")?
    case Crypto.hkdf_aead_open(context.secret,
      concat(context.enc, nonce)?,
      Bytes.empty(),
      sealed) do
      Err(_) -> Err("ohttp_response_invalid")
      Ok(value)
    end
  end
end

## One request through a relay, for a client that makes its own HTTP calls:
## the method, the path (with its query) and the body in, the backend's status
## and body out. Err("ohttp_relay_unavailable") when the relay or the gateway
## didn't answer with an encapsulated response, Err("ohttp_response_invalid")
## when the answer doesn't open.

pub fn ohttp_exchange(config :: OhttpKeyConfig,
  relay :: String,
  method :: String,
  path :: String,
  body :: Bytes,
  timeout_ms :: Int) -> (Int, Bytes)!String do
  let (encapsulated, context) = ohttp_encapsulate_request(config,
    ohttp_request_message(method, path, body)?)?
  let answer = case Http.build(:post, relay <> "/v1/ohttp")
    |> Http.header("Content-Type", "message/ohttp-req")
    |> Http.header("Cache-Control", "no-store")
    |> Http.body_bytes(encapsulated)
    |> Http.timeout(timeout_ms)
    |> Http.max_response_bytes(1048576 + 64)
    |> Http.max_redirects(0)
    |> Http.send() do
    Err(_) -> Err("ohttp_relay_unavailable")
    Ok(value)
  end?
  if answer.status != 200 do
    Err("ohttp_relay_unavailable")
  else
    let response = case bhttp_decode_response(ohttp_decapsulate_response(context,
      answer.body_bytes)?) do
      Err(_) -> Err("ohttp_response_invalid")
      Ok(value)
    end?
    Ok((response.status, response.content))
  end
end
