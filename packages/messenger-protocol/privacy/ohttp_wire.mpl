##! Oblivious HTTP (RFC 9458) wire formats for the requests a phone makes
##! without a connection of its own to the backend (protocol/ohttp-v1.md):
##! key configurations, the encapsulated request's header, and the padded
##! Binary HTTP (Privacy.Bhttp) messages inside. One suite: DHKEM(X25519,
##! HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305 (KEM 0x0020, KDF 0x0001,
##! AEAD 0x0003), which is Mesh's HPKE. The encapsulation itself is
##! Privacy.Ohttp in packages/messenger-ohttp: it needs a Mesh release with
##! the HPKE export, and this package must build without one.

from Privacy.Bhttp import (
  BhttpRequest,
  BhttpResponse,
  bhttp_encode_request,
  bhttp_encode_response
)

pub struct OhttpKeyConfig do
  key_id :: Int
  public_key :: Bytes
end

pub fn ohttp_kem_id() -> Int do
  32
end

pub fn ohttp_kdf_id() -> Int do
  1
end

pub fn ohttp_aead_id() -> Int do
  3
end

# max(Nn, Nk) for ChaCha20-Poly1305: the response nonce and exported secret.
pub fn ohttp_response_nonce_length() -> Int do
  32
end

fn concat(left :: Bytes, right :: Bytes) -> Bytes!String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("ohttp_allocation_failed")
    Ok(value)
  end
end

fn join(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, concat(output, List.get(parts, index))?)
  end
end

fn slice(input :: Bytes, offset :: Int, length :: Int, error :: String) -> Bytes!String do
  case Bytes.slice(input, offset, length) do
    Err(_) -> Err(error)
    Ok(value)
  end
end

fn u8(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("ohttp_invalid_key_id")
    Ok(bytes)
  end
end

fn u16(value :: Int) -> Bytes!String do
  case Bytes.write_u16_be(value) do
    Err(_) -> Err("ohttp_allocation_failed")
    Ok(bytes)
  end
end

fn u16_at(input :: Bytes, offset :: Int, error :: String) -> Int!String do
  case Bytes.read_u16_be(input, offset) do
    Err(_) -> Err(error)
    Ok(value)
  end
end

pub fn ohttp_valid_config(config :: OhttpKeyConfig) -> Bool do
  config.key_id >= 0 && config.key_id <= 255 && Bytes.length(config.public_key) == 32
end

## RFC 9458 section 3.1: key id, KEM, public key, and the one KDF/AEAD pair
## Morse offers (41 bytes).

pub fn ohttp_key_config_encode(config :: OhttpKeyConfig) -> Bytes!String do
  if !ohttp_valid_config(config) do
    Err("ohttp_invalid_key_config")
  else
    join([
        u8(config.key_id)?,
        u16(ohttp_kem_id())?,
        config.public_key,
        u16(4)?,
        u16(ohttp_kdf_id())?,
        u16(ohttp_aead_id())?
      ],
      0,
      Bytes.empty())
  end
end

fn offers_suite(input :: Bytes, offset :: Int, end_at :: Int) -> Bool!String do
  if offset >= end_at do
    Ok(false)
  else if u16_at(input, offset, "ohttp_invalid_key_config")? == ohttp_kdf_id()
    && u16_at(input, offset + 2, "ohttp_invalid_key_config")? == ohttp_aead_id() do
    Ok(true)
  else
    offers_suite(input, offset + 4, end_at)
  end
end

## One key configuration, which must be for X25519 and offer HKDF-SHA256 with
## ChaCha20-Poly1305 among its pairs.

pub fn ohttp_key_config_decode(input :: Bytes) -> OhttpKeyConfig!String do
  let length = Bytes.length(input)
  if length < 41 || u16_at(input, 1, "ohttp_invalid_key_config")? != ohttp_kem_id() do
    Err("ohttp_invalid_key_config")
  else
    let pairs = u16_at(input, 35, "ohttp_invalid_key_config")?
    if pairs < 4 || pairs % 4 != 0 || 37 + pairs != length do
      Err("ohttp_invalid_key_config")
    else if !offers_suite(input, 37, length)? do
      Err("ohttp_key_config_unsupported")
    else
      let key_id = case Bytes.get(input, 0) do
        Err(_) -> Err("ohttp_invalid_key_config")
        Ok(value)
      end?
      Ok(OhttpKeyConfig {
        key_id: key_id,
        public_key: slice(input, 3, 32, "ohttp_invalid_key_config")?
      })
    end
  end
end

## `application/ohttp-keys` (section 3.2): each configuration with a u16
## length.

pub fn ohttp_keys_encode(configs :: List<OhttpKeyConfig>) -> Bytes!String do
  keys_from(configs, 0, Bytes.empty())
end

fn keys_from(configs :: List<OhttpKeyConfig>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(configs) do
    Ok(output)
  else
    let encoded = ohttp_key_config_encode(List.get(configs, index))?
    keys_from(configs,
      index + 1,
      join([output, u16(Bytes.length(encoded))?, encoded], 0, Bytes.empty())?)
  end
end

pub fn ohttp_header(key_id :: Int) -> Bytes!String do
  join([u8(key_id)?, u16(ohttp_kem_id())?, u16(ohttp_kdf_id())?, u16(ohttp_aead_id())?],
    0,
    Bytes.empty())
end

pub fn ohttp_request_info(key_id :: Int) -> Bytes!String do
  join([Bytes.from_utf8("message/bhttp request"), u8(0)?, ohttp_header(key_id)?], 0, Bytes.empty())
end

pub fn ohttp_response_context() -> Bytes do
  Bytes.from_utf8("message/bhttp response")
end

## The key id a request names, so the gateway can load that key.

pub fn ohttp_request_key_id(encapsulated :: Bytes) -> Int!String do
  case Bytes.get(encapsulated, 0) do
    Err(_) -> Err("ohttp_malformed")
    Ok(value)
  end
end

## The size a message is padded to: at least `minimum`, a power of two up to
## 64 KiB, then the next multiple of 64 KiB.

pub fn ohttp_padded_length(length :: Int, minimum :: Int) -> Int do
  if length <= minimum do
    minimum
  else if length > 65536 do
    (length + 65535) / 65536 * 65536
  else
    ohttp_padded_length(length, minimum * 2)
  end
end

## A Morse request as Binary HTTP: the method, the path (with its query) and
## the body, no header fields, padded to at least 256 bytes.

pub fn ohttp_request_message(method :: String, path :: String, body :: Bytes) -> Bytes!String do
  let request = BhttpRequest {
    method: method,
    scheme: "https",
    authority: "",
    path: path,
    fields: List.new(),
    content: body
  }
  let natural = bhttp_encode_request(request, 0)?
  bhttp_encode_request(request, ohttp_padded_length(Bytes.length(natural) + 1, 256))
end

## A response as Binary HTTP: the status and the body, padded to at least 1 KiB.

pub fn ohttp_response_message(status :: Int, body :: Bytes) -> Bytes!String do
  let response = BhttpResponse { status: status, fields: List.new(), content: body }
  let natural = bhttp_encode_response(response, 0)?
  bhttp_encode_response(response, ohttp_padded_length(Bytes.length(natural) + 1, 1024))
end
