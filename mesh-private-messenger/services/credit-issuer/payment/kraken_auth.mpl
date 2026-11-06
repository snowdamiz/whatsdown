# Kraken Spot REST and Funding v1 authentication. The caller owns durable nonce
# allocation and effect reservation. These builders only authenticate the exact
# returned path/body; the secret key never becomes ordinary Mesh bytes.
pub struct KrakenField do
  name :: String
  value :: String
end

pub struct KrakenSignedRequest do
  path :: String
  nonce :: String
  content_type :: String
  body :: String
  signature :: String
end

fn form_escape(value :: String) -> String!String do
  let bytes = Bytes.from_utf8(value)
  if Bytes.length(bytes) > 16384 do
    return Err("kraken_request_too_large")
  end
  let pieces = for index in 0..Bytes.length(bytes) do
    let byte = Bytes.get(bytes, index)?
    if (byte >= 65 && byte <= 90)
      || (byte >= 97 && byte <= 122)
      || (byte >= 48 && byte <= 57)
      || List.contains([45, 46, 95, 126], byte) do
      Bytes.to_utf8(Bytes.slice(bytes, index, 1)?)?
    else if byte == 32 do
      "+"
    else
      "%" <> String.to_upper(Bytes.to_hex(Bytes.slice(bytes, index, 1)?))
    end
  end
  Ok(String.join(pieces, ""))
end

fn valid_field_name(name :: String) -> Bool!String do
  let bytes = Bytes.from_utf8(name)
  if Bytes.length(bytes) < 1 || Bytes.length(bytes) > 128 || name == "nonce" do
    return Ok(false)
  end
  for index in 0..Bytes.length(bytes) do
    let byte = Bytes.get(bytes, index)?
    if !((byte >= 65 && byte <= 90)
      || (byte >= 97 && byte <= 122)
      || (byte >= 48 && byte <= 57)
      || List.contains([95, 91, 93], byte)) do
      return Ok(false)
    end
  end
  Ok(true)
end

fn encoded_fields(fields :: List<KrakenField>) -> String!String do
  if List.length(fields) > 64 do
    return Err("kraken_request_too_large")
  end
  let pairs = for index in 0..List.length(fields) do
    let field = List.get(fields, index)
    if !valid_field_name(field.name)? do
      return Err("invalid_kraken_field")
    end
    for previous in 0..index do
      if List.get(fields, previous).name == field.name do
        return Err("duplicate_kraken_field")
      end
    end
    form_escape(field.name)? <> "=" <> form_escape(field.value)?
  end
  let result = String.join(pairs, "&")
  if String.length(result) > 16384 do
    return Err("kraken_request_too_large")
  end
  Ok(result)
end

fn signature(key :: borrow SecretBytes,
  path :: String,
  nonce :: U64,
  body :: String) -> String!String do
  if nonce == U64.parse("0")?
    || Bytes.length(Bytes.from_utf8(body)) > 16384
    || Bytes.length(Bytes.from_utf8(path)) > 4096 do
    return Err("invalid_kraken_request")
  end
  let digest = Crypto.sha256(Bytes.from_utf8(U64.to_string(nonce) <> body))
  let message = Bytes.concat(Bytes.from_utf8(path), digest)?
  case Crypto.hmac_sha512_tag(key, message) do
    Ok(tag) -> Ok(Bytes.to_base64(tag))
    Err(_) -> Err("kraken_authentication_failed")
  end
end

pub fn kraken_form_request(key :: borrow SecretBytes,
  path :: String,
  nonce :: U64,
  fields :: List<KrakenField>) -> KrakenSignedRequest!String do
  if !List.contains([
      "/0/private/AddOrder",
      "/0/private/QueryOrders",
      "/0/private/OpenOrders",
      "/0/private/ClosedOrders",
      "/0/private/TradesHistory",
      "/0/private/QueryTrades",
      "/0/private/DepositAddresses",
      "/0/private/DepositStatus",
      "/0/private/Ledgers",
      "/0/private/QueryLedgers",
      "/0/private/TradeVolume"
    ],
    path) do
    return Err("unsupported_kraken_path")
  end
  let fields_body = encoded_fields(fields)?
  let body = "nonce="
    <> U64.to_string(nonce)
    <> if fields_body == "" do
      ""
    else
      "&" <> fields_body
    end
  Ok(KrakenSignedRequest {
    path: path,
    nonce: U64.to_string(nonce),
    content_type: "application/x-www-form-urlencoded",
    body: body,
    signature: signature(key, path, nonce, body)?
  })
end

fn funding_path(path :: String) -> Bool!String do
  if List.contains([
      "/funding/v1/methods/deposit",
      "/funding/v1/methods/withdraw",
      "/funding/v1/addresses",
      "/funding/v1/withdrawals",
      "/funding/v1/deposits"
    ],
    path) do
    return Ok(true)
  end
  let prefix = "/funding/v1/fees/"
  let bytes = Bytes.from_utf8(path)
  if !String.starts_with(path, prefix) || Bytes.length(bytes) != String.length(prefix) + 36 do
    return Ok(false)
  end
  let id = Bytes.slice(bytes, String.length(prefix), 36)?
  for index in 0..36 do
    let byte = Bytes.get(id, index)?
    if List.contains([8, 13, 18, 23], index) do
      if byte != 45 do
        return Ok(false)
      end
    else if !((byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)) do
      return Ok(false)
    end
  end
  Ok(true)
end

pub fn kraken_funding_request(key :: borrow SecretBytes,
  path :: String,
  nonce :: U64,
  query :: List<KrakenField>,
  body :: String) -> KrakenSignedRequest!String do
  if !funding_path(path)? || Bytes.length(Bytes.from_utf8(body)) > 16384 do
    return Err("invalid_kraken_funding_request")
  end
  if body != "" do
    if !String.starts_with(String.trim(body), "{") do
      return Err("invalid_kraken_json_body")
    end
    Json.parse(body)?
  end
  let encoded_query = encoded_fields(query)?
  let signed_path = path
    <> if encoded_query == "" do
      ""
    else
      "?" <> encoded_query
    end
  Ok(KrakenSignedRequest {
    path: signed_path,
    nonce: U64.to_string(nonce),
    content_type: "application/json",
    body: body,
    signature: signature(key, signed_path, nonce, body)?
  })
end
