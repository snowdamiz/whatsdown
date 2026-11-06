from Lightning.Invoice import parse_invoice, fixed_invoice_amount, invoice_expires_at

pub struct LndConfig do
  origin :: String
  macaroon :: String
  network :: Int
  purpose :: Int
  payee :: Bytes
end

pub struct LndInvoice do
  state :: String
  payment_hash :: Bytes
  invoice :: String
  amount_msat :: U64
  paid_msat :: U64
  created_at :: U64
  expires_at :: U64
  settled_at :: U64
  add_index :: U64
  settle_index :: U64
end

pub fn validate_lnd_config(value :: LndConfig) -> Result<(), String> do
  let origin = Http.url_origin(value.origin)?
  if value.origin != origin
    || String.contains(origin, "@")
    || String.contains(origin, "\\")
    || String.length(origin) > 2048
    || String.contains(origin, "?")
    || String.contains(origin, "#")
    || (value.purpose != 0 && value.purpose != 1)
    || value.network < 0
    || value.network > 4
    || (value.purpose == 0 && value.network != 0)
    || (value.purpose == 1 && value.network == 0)
    || (!String.starts_with(origin, "https://")
      && !(value.purpose == 1 && String.starts_with(origin, "http://127.0.0.1:")))
    || Bytes.length(value.payee) != 33
    || (Bytes.get(value.payee, 0)? != 2 && Bytes.get(value.payee, 0)? != 3)
    || String.length(value.macaroon) < 2
    || String.length(value.macaroon) > 4096 do
    return Err("invalid_lightning_backend_config")
  end
  let credential = case Bytes.from_hex(value.macaroon) do
    Ok(bytes) -> bytes
    Err(_) -> return Err("invalid_lightning_backend_config")
  end
  if Bytes.to_hex(credential) != value.macaroon do
    return Err("invalid_lightning_backend_config")
  end
  Ok(nil)
end

fn number(root :: Json, field :: String) -> U64!String do
  let value = Json.as_string(Json.object_get(root, field)?)?
  let parsed = U64.parse(value)?
  if U64.to_string(parsed) != value do
    return Err("invalid_lightning_number")
  end
  Ok(parsed)
end

fn string(root :: Json, field :: String) -> String!String do
  Json.as_string(Json.object_get(root, field)?)
end

pub fn verify_lnd_identity(raw :: String, config :: LndConfig) -> Result<(), String> do
  validate_lnd_config(config)?
  let root = Json.parse(raw)?
  let chains = Json.object_get(root, "chains")?
  if Json.array_length(chains)? != 1 || !Json.as_bool(Json.object_get(root, "synced_to_chain")?)? do
    return Err("lightning_backend_not_ready")
  end
  let chain = Json.array_get(chains, 0)?
  let network = case config.network do
    0 -> "mainnet"
    1 -> "testnet"
    2 -> "regtest"
    3 -> "signet"
    _ -> "simnet"
  end
  if string(chain, "chain")? != "bitcoin"
    || string(chain, "network")? != network
    || !Bytes.secure_equals(Bytes.from_hex(string(root, "identity_pubkey")?)?, config.payee) do
    return Err("lightning_backend_identity_mismatch")
  end
  Ok(nil)
end

# LND protobuf JSON represents int64/uint64 as canonical decimal strings.
# No float conversions, caller-supplied amounts, or Solana receipt fields.
pub fn lnd_invoice_from_json(raw :: String,
  hash :: Bytes,
  config :: LndConfig) -> LndInvoice!String do
  validate_lnd_config(config)?
  if String.length(raw) > 65536 || Bytes.length(hash) != 32 do
    return Err("invalid_lightning_backend_response")
  end
  let root = Json.parse(raw)?
  let invoice_text = string(root, "payment_request")?
  let invoice = parse_invoice(invoice_text)?
  let state = string(root, "state")?
  let amount = number(root, "value_msat")?
  let paid = number(root, "amt_paid_msat")?
  let created = number(root, "creation_date")?
  let settled = number(root, "settle_date")?
  let add_index = number(root, "add_index")?
  let settle_index = number(root, "settle_index")?
  if !List.contains(["OPEN", "ACCEPTED", "SETTLED", "CANCELED"], state)
    || !Bytes.secure_equals(Bytes.from_base64(string(root, "r_hash")?)?, hash)
    || !Bytes.secure_equals(invoice.payment_hash, hash)
    || !Bytes.secure_equals(invoice.payee, config.payee)
    || invoice.network != config.network
    || invoice.has_fallback
    || !Bytes.secure_equals(invoice.description_hash,
      Crypto.sha256(Bytes.from_utf8("Morse credits")))
    || fixed_invoice_amount(invoice)? != amount
    || invoice.created_at != created
    || invoice.expiry_seconds != U64.parse("900")?
    || number(root, "expiry")? != invoice.expiry_seconds
    || U64.compare(paid, U64.parse("2100000000000000000")?) > 0
    || add_index == U64.parse("0")?
    || (state == "SETTLED"
      && (settle_index == U64.parse("0")? || U64.compare(settled, created) < 0))
    || (state != "SETTLED" && (settle_index != U64.parse("0")? || settled != U64.parse("0")?)) do
    return Err("lightning_backend_invoice_mismatch")
  end
  Ok(LndInvoice {
    state: state,
    payment_hash: hash,
    invoice: invoice_text,
    amount_msat: amount,
    paid_msat: paid,
    created_at: created,
    expires_at: invoice_expires_at(invoice)?,
    settled_at: settled,
    add_index: add_index,
    settle_index: settle_index
  })
end

fn get(config :: LndConfig, path :: String) -> HttpResponse!String do
  validate_lnd_config(config)?
  case Http.build(:get, config.origin <> path)
    |> Http.header("Grpc-Metadata-macaroon", config.macaroon)
    |> Http.timeout(10000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(65536)
    |> Http.send() do
    Ok(value)
    Err(_) -> Err("lightning_backend_unavailable")
  end
end

fn post(config :: LndConfig, path :: String, body :: String) -> HttpResponse!String do
  validate_lnd_config(config)?
  case Http.build(:post, config.origin <> path)
    |> Http.header("Grpc-Metadata-macaroon", config.macaroon)
    |> Http.header("Content-Type", "application/json")
    |> Http.body(body)
    |> Http.timeout(10000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(65536)
    |> Http.send() do
    Ok(value)
    Err(_) -> Err("lightning_backend_unavailable")
  end
end

pub fn check_lnd_identity(config :: LndConfig) -> Result<(), String> do
  let response = get(config, "/v1/getinfo")?
  if response.status != 200 do
    return Err("lightning_backend_unavailable")
  end
  verify_lnd_identity(Bytes.to_utf8(response.body_bytes)?, config)
end

pub fn lookup_lnd_invoice(config :: LndConfig, hash :: Bytes) -> Option<LndInvoice>!String do
  if Bytes.length(hash) != 32 do
    return Err("invalid_lightning_hash")
  end
  check_lnd_identity(config)?
  let response = get(config, "/v1/invoice/" <> Bytes.to_hex(hash))?
  let raw = Bytes.to_utf8(response.body_bytes)?
  if response.status == 404 do
    let root = Json.parse(raw)?
    if Json.encode(Json.object_get(root, "code")?) == "5" do
      return Ok(None)
    end
  end
  if response.status != 200 do
    return Err("lightning_backend_unavailable")
  end
  Ok(Some(lnd_invoice_from_json(raw, hash, config)?))
end

# A lost creation acknowledgment is resolved by lookup of the same durable hash.
# This function never generates a hash or replaces an invoice.
pub fn create_lnd_hold(config :: LndConfig, hash :: Bytes, amount :: U64) -> Result<(), String> do
  if Bytes.length(hash) != 32
    || amount == U64.parse("0")?
    || U64.compare(amount, U64.parse("2100000000000000000")?) > 0 do
    return Err("invalid_lightning_hold")
  end
  check_lnd_identity(config)?
  let response = post(config,
    "/v2/invoices/hodl",
    "{\"hash\":"
      <> Json.encode_string(Bytes.to_base64(hash))
      <> ",\"value_msat\":"
      <> Json.encode_string(U64.to_string(amount))
      <> ",\"memo\":\"Morse credits\",\"expiry\":\"900\",\"private\":true}")?
  if response.status != 200 do
    return Err("lightning_hold_creation_unknown")
  end
  Ok(nil)
end

pub fn cancel_lnd_hold(config :: LndConfig, hash :: Bytes) -> Result<(), String> do
  if Bytes.length(hash) != 32 do
    return Err("invalid_lightning_hash")
  end
  check_lnd_identity(config)?
  let response = post(config,
    "/v2/invoices/cancel",
    "{\"payment_hash\":" <> Json.encode_string(Bytes.to_base64(hash)) <> "}")?
  if response.status != 200 do
    return Err("lightning_hold_cancellation_unknown")
  end
  Ok(nil)
end

# Caller must commit the exact prepared blind response before restoring this
# preimage. A successful POST is not a receipt: lookup must report SETTLED.
pub fn settle_lnd_hold(config :: LndConfig, preimage :: HashPreimage) -> Result<(), String> do
  check_lnd_identity(config)?
  let disclosed = case HashPreimage.reveal(preimage) do
    Ok(value) -> value
    Err(_) -> return Err("lightning_preimage_unavailable")
  end
  let response = post(config,
    "/v2/invoices/settle",
    "{\"preimage\":" <> Json.encode_string(Bytes.to_base64(disclosed)) <> "}")?
  if response.status != 200 do
    return Err("lightning_hold_settlement_unknown")
  end
  Ok(nil)
end
