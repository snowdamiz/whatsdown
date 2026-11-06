from Lightning.Invoice import (
  LightningInvoice,
  parse_invoice,
  fixed_invoice_amount,
  invoice_expires_at
)
from Payment.LightningBackend import LndConfig, check_lnd_identity, validate_lnd_config

pub struct OutboundPayment do
  status :: String
  payment_hash :: Bytes
  amount_msat :: U64
  fee_msat :: U64
end

pub fn conversion_invoice(raw :: String,
  amount :: U64,
  network :: Int,
  payee :: Bytes,
  now :: U64,
  maximum_lifetime :: U64) -> LightningInvoice!String do
  if String.length(raw) > 16384 || Bytes.length(payee) != 33 do
    return Err("invalid_conversion_invoice")
  end
  let value = parse_invoice(raw)?
  if value.has_fallback
    || value.network != network
    || value.payee != payee
    || value.payment_hash == Bytes.from_hex(String.repeat("00", 32))?
    || fixed_invoice_amount(value)? != amount
    || U64.compare(value.created_at, now) > 0
    || U64.compare(U64.subtract(now, value.created_at)?, U64.parse("60")?) > 0
    || U64.compare(value.expiry_seconds, maximum_lifetime) > 0
    || U64.compare(invoice_expires_at(value)?, U64.add(now, U64.parse("30")?)?) < 0 do
    return Err("conversion_invoice_binding_mismatch")
  end
  Ok(value)
end

fn field(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn number(root :: Json, name :: String) -> U64!String do
  let raw = field(root, name)?
  let value = U64.parse(raw)?
  if U64.to_string(value) != raw do
    return Err("noncanonical_outbound_payment_number")
  end
  Ok(value)
end

fn hex32(raw :: String) -> Bytes!String do
  let bytes = Bytes.from_hex(raw)?
  if Bytes.length(bytes) != 32 || Bytes.to_hex(bytes) != raw do
    return Err("noncanonical_outbound_payment_hash")
  end
  Ok(bytes)
end

# Stream requests suppress in-flight updates. A single bounded terminal result is
# accepted; a lost response is reconciled by the same hash, never paid again.
pub fn outbound_payment(raw :: String,
  invoice_text :: String,
  fee_limit :: U64) -> OutboundPayment!String do
  if String.length(raw) > 65536 do
    return Err("outbound_payment_response_too_large")
  end
  let invoice = parse_invoice(invoice_text)?
  let parsed = Json.parse(raw)?
  let root = case Json.object_get(parsed, "result") do
    Ok(value) -> value
    Err(_) -> parsed
  end
  let hash = hex32(field(root, "payment_hash")?)?
  let status = field(root, "status")?
  if hash != invoice.payment_hash
    || !List.contains(["INITIATED", "IN_FLIGHT", "FAILED", "SUCCEEDED"], status) do
    return Err("outbound_payment_mismatch")
  end
  if status != "SUCCEEDED" do
    return Ok(OutboundPayment {
      status: status,
      payment_hash: hash,
      amount_msat: U64.parse("0")?,
      fee_msat: U64.parse("0")?
    })
  end
  let amount = number(root, "value_msat")?
  let fee = number(root, "fee_msat")?
  let preimage = hex32(field(root, "payment_preimage")?)?
  if Crypto.sha256(preimage) != hash
    || amount != fixed_invoice_amount(invoice)?
    || U64.compare(fee, fee_limit) > 0
    || field(root, "payment_request")? != invoice_text do
    return Err("outbound_payment_unproven")
  end
  Ok(OutboundPayment { status: status, payment_hash: hash, amount_msat: amount, fee_msat: fee })
end

pub fn outbound_payment_body(invoice :: String, fee_limit :: U64) -> String!String do
  fixed_invoice_amount(parse_invoice(invoice)?)?
  Ok("{\"payment_request\":"
    <> Json.encode_string(invoice)
    <> ",\"fee_limit_msat\":"
    <> Json.encode_string(U64.to_string(fee_limit))
    <> ",\"timeout_seconds\":30,\"no_inflight_updates\":true}")
end

pub fn outbound_track_path(hash :: Bytes) -> String!String do
  if Bytes.length(hash) != 32 do
    return Err("invalid_outbound_payment_hash")
  end
  let encoded = String.replace(String.replace(Bytes.to_base64(hash), "+", "-"), "/", "_")
  Ok("/v2/router/track/" <> encoded <> "?no_inflight_updates=true")
end

pub fn send_outbound_payment(config :: LndConfig,
  invoice :: String,
  fee_limit :: U64) -> String!String do
  validate_lnd_config(config)?
  check_lnd_identity(config)?
  let body = outbound_payment_body(invoice, fee_limit)?
  let response = case Http.build(:post, config.origin <> "/v2/router/send")
    |> Http.header("Grpc-Metadata-macaroon", config.macaroon)
    |> Http.header("Content-Type", "application/json")
    |> Http.body(body)
    |> Http.timeout(45000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(65536)
    |> Http.send() do
    Ok(value) -> value
    Err(_) -> return Err("outbound_payment_unknown")
  end
  if response.status != 200 do
    return Err("outbound_payment_unknown")
  end
  Bytes.to_utf8(response.body_bytes)
end

pub fn track_outbound_payment(config :: LndConfig, hash :: Bytes) -> String!String do
  check_lnd_identity(config)?
  let response = case Http.build(:get, config.origin <> outbound_track_path(hash)?)
    |> Http.header("Grpc-Metadata-macaroon", config.macaroon)
    |> Http.timeout(10000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(65536)
    |> Http.send() do
    Ok(value) -> value
    Err(_) -> return Err("outbound_payment_unknown")
  end
  if response.status != 200 do
    return Err("outbound_payment_unknown")
  end
  Bytes.to_utf8(response.body_bytes)
end
