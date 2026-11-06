from Credits.Policy import credit_pack, issuer_epoch, issuer_epoch_accepted
from Credits.Issuer import CreditIssuerKey, issuer_key_id
from Credits.Issuance import credit_batch_hash
from Credits.Wire import CreditTokenRequest, encode_token_request, decode_token_request
from Lightning.Invoice import parse_invoice, fixed_invoice_amount, invoice_expires_at

pub struct LightningQuoteRequest do
  credits :: Int
  network :: Int
  purpose :: Int
  issuer_key_id :: Bytes
  batch_hash :: Bytes
end

pub struct LightningQuote do
  quote_id :: Bytes
  network :: Int
  purpose :: Int
  credits :: Int
  amount_msat :: U64
  issued_at :: U64
  expires_at :: U64
  issuer_key_id :: Bytes
  batch_hash :: Bytes
  payment_hash :: Bytes
  payee :: Bytes
  invoice :: String
end

pub struct SignedLightningQuote do
  quote :: LightningQuote
  signature :: Bytes
end

pub struct LightningIssueRequest do
  quote_id :: Bytes
  payment_hash :: Bytes
  requests :: List<CreditTokenRequest>
end

fn nonzero(value :: Bytes, size :: Int) -> Bool do
  Bytes.length(value) == size && Bytes.to_hex(value) != String.repeat("00", size)
end

fn bytes(values :: List<Int>) -> Bytes!String do
  case Bytes.from_list(values) do
    Ok(value)
    Err(_) -> Err("invalid_lightning_wire")
  end
end

fn narrow(value :: Int) -> Bytes!String do
  case Bytes.write_u16_be(value) do
    Ok(bytes)
    Err(_) -> Err("invalid_lightning_wire")
  end
end

fn wide(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Ok(bytes)
    Err(_) -> Err("invalid_lightning_wire")
  end
end

fn read_narrow(value :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u16_be(value, offset) do
    Ok(number)
    Err(_) -> Err("invalid_lightning_wire")
  end
end

fn read_wide(value :: Bytes, offset :: Int) -> U64!String do
  case Bytes.read_u64_be(value, offset) do
    Ok(number)
    Err(_) -> Err("invalid_lightning_wire")
  end
end

fn concatenate(parts :: List<Bytes>, maximum :: Int) -> Bytes!String do
  let builder = case BytesBuilder.new(maximum) do
    Ok(value) -> value
    Err(_) -> return Err("invalid_lightning_wire")
  end
  for part in parts do
    case BytesBuilder.write_bytes(builder, part) do
      Ok(_) -> nil
      Err(_) -> return Err("invalid_lightning_wire")
    end
  end
  case BytesBuilder.finish(builder) do
    Ok(value)
    Err(_) -> Err("invalid_lightning_wire")
  end
end

fn request_valid(value :: LightningQuoteRequest) -> Result<(), String> do
  credit_pack(value.credits)?
  if (value.purpose != 0 && value.purpose != 1)
    || value.network < 0
    || value.network > 4
    || (value.purpose == 0 && value.network != 0)
    || (value.purpose == 1 && value.network == 0)
    || !nonzero(value.issuer_key_id, 32)
    || !nonzero(value.batch_hash, 32) do
    Err("invalid_lightning_quote_request")
  else
    Ok(nil)
  end
end

pub fn encode_lightning_quote_request(value :: LightningQuoteRequest) -> Bytes!String do
  request_valid(value)?
  concatenate([
      Bytes.from_hex("014c5152")?,
      narrow(value.credits)?,
      bytes([value.network, value.purpose])?,
      value.issuer_key_id,
      value.batch_hash
    ],
    72)
end

pub fn decode_lightning_quote_request(input :: Bytes) -> LightningQuoteRequest!String do
  if Bytes.length(input) != 72 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "014c5152" do
    return Err("invalid_lightning_quote_request")
  end
  let value = LightningQuoteRequest {
    credits: read_narrow(input, 4)?,
    network: Bytes.get(input, 6)?,
    purpose: Bytes.get(input, 7)?,
    issuer_key_id: Bytes.slice(input, 8, 32)?,
    batch_hash: Bytes.slice(input, 40, 32)?
  }
  request_valid(value)?
  Ok(value)
end

# Invoice metadata is independently verified by the public Mesh BOLT11 primitive.
# An on-chain fallback address would introduce a second untracked payment rail.
fn quote_valid(value :: LightningQuote) -> Result<(), String> do
  request_valid(LightningQuoteRequest {
    credits: value.credits,
    network: value.network,
    purpose: value.purpose,
    issuer_key_id: value.issuer_key_id,
    batch_hash: value.batch_hash
  })?
  if !nonzero(value.quote_id, 32)
    || !nonzero(value.payment_hash, 32)
    || !nonzero(value.payee, 33)
    || value.amount_msat == U64.parse("0")?
    || U64.compare(value.amount_msat, U64.parse("2100000000000000000")?) > 0
    || value.expires_at != U64.add(value.issued_at, U64.parse("900")?)? do
    return Err("invalid_lightning_quote")
  end
  let invoice = parse_invoice(value.invoice)?
  if invoice.network != value.network
    || invoice.has_fallback
    || fixed_invoice_amount(invoice)? != value.amount_msat
    || invoice.created_at != value.issued_at
    || invoice_expires_at(invoice)? != value.expires_at
    || !Bytes.secure_equals(invoice.payment_hash, value.payment_hash)
    || !Bytes.secure_equals(invoice.payee, value.payee)
    || !Bytes.secure_equals(invoice.description_hash,
      Crypto.sha256(Bytes.from_utf8("Morse credits"))) do
    return Err("lightning_invoice_quote_mismatch")
  end
  Ok(nil)
end

pub fn encode_lightning_quote(value :: LightningQuote) -> Bytes!String do
  quote_valid(value)?
  let invoice = Bytes.from_utf8(value.invoice)
  concatenate([
      Bytes.from_hex("014c5154")?,
      value.quote_id,
      bytes([value.network, value.purpose])?,
      narrow(value.credits)?,
      wide(value.amount_msat)?,
      wide(value.issued_at)?,
      wide(value.expires_at)?,
      value.issuer_key_id,
      value.batch_hash,
      value.payment_hash,
      value.payee,
      narrow(Bytes.length(invoice))?,
      invoice
    ],
    7284)
end

pub fn decode_lightning_quote(input :: Bytes) -> LightningQuote!String do
  let length = Bytes.length(input)
  if length < 196 || length > 7284 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "014c5154" do
    return Err("invalid_lightning_quote")
  end
  let invoice_length = read_narrow(input, 193)?
  if length != 195 + invoice_length do
    return Err("invalid_lightning_quote")
  end
  let value = LightningQuote {
    quote_id: Bytes.slice(input, 4, 32)?,
    network: Bytes.get(input, 36)?,
    purpose: Bytes.get(input, 37)?,
    credits: read_narrow(input, 38)?,
    amount_msat: read_wide(input, 40)?,
    issued_at: read_wide(input, 48)?,
    expires_at: read_wide(input, 56)?,
    issuer_key_id: Bytes.slice(input, 64, 32)?,
    batch_hash: Bytes.slice(input, 96, 32)?,
    payment_hash: Bytes.slice(input, 128, 32)?,
    payee: Bytes.slice(input, 160, 33)?,
    invoice: Bytes.to_utf8(Bytes.slice(input, 195, invoice_length)?)?
  }
  quote_valid(value)?
  Ok(value)
end

pub fn validate_lightning_quote_response(request :: LightningQuoteRequest,
  value :: LightningQuote,
  key :: CreditIssuerKey,
  now :: U64) -> Result<(), String> do
  quote_valid(value)?
  request_valid(request)?
  if key.purpose != value.purpose
    || key.epoch != issuer_epoch(value.issued_at)?
    || !issuer_epoch_accepted(key.epoch, now)?
    || U64.compare(now, value.issued_at) < 0
    || U64.compare(now, value.expires_at) >= 0
    || !Bytes.secure_equals(value.issuer_key_id, issuer_key_id(key)?)
    || request.credits != value.credits
    || request.network != value.network
    || request.purpose != value.purpose
    || !Bytes.secure_equals(request.issuer_key_id, value.issuer_key_id)
    || !Bytes.secure_equals(request.batch_hash, value.batch_hash) do
    Err("lightning_quote_request_mismatch")
  else
    Ok(nil)
  end
end

fn signing_bytes(value :: LightningQuote) -> Bytes!String do
  Bytes.concat(Bytes.from_utf8("morse-lightning-credit-quote-v1"), encode_lightning_quote(value)?)
end

pub fn sign_lightning_quote(private :: borrow SigningPrivateKey,
  quote :: LightningQuote) -> SignedLightningQuote!String do
  let signature = case Crypto.sign(private, signing_bytes(quote)?) do
    Ok(value) -> value.bytes
    Err(_) -> return Err("lightning_quote_signing_failed")
  end
  Ok(SignedLightningQuote { quote: quote, signature: signature })
end

pub fn encode_signed_lightning_quote(value :: SignedLightningQuote) -> Bytes!String do
  if Bytes.length(value.signature) != 64 do
    return Err("invalid_signed_lightning_quote")
  end
  concatenate([Bytes.from_hex("014c5153")?, encode_lightning_quote(value.quote)?, value.signature],
    7352)
end

pub fn decode_signed_lightning_quote(input :: Bytes) -> SignedLightningQuote!String do
  let length = Bytes.length(input)
  if length < 264 || length > 7352 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "014c5153" do
    return Err("invalid_signed_lightning_quote")
  end
  Ok(SignedLightningQuote {
    quote: decode_lightning_quote(Bytes.slice(input, 4, length - 68)?)?,
    signature: Bytes.slice(input, length - 64, 64)?
  })
end

pub fn verify_lightning_quote(value :: SignedLightningQuote,
  issuer :: CreditIssuerKey) -> Bool!String do
  encode_signed_lightning_quote(value)?
  if !Bytes.secure_equals(value.quote.issuer_key_id, issuer_key_id(issuer)?)
    || value.quote.purpose != issuer.purpose
    || issuer_epoch(value.quote.issued_at)? != issuer.epoch do
    return Ok(false)
  end
  case Crypto.verify(SigningPublicKey { bytes: issuer.quote_public_key },
    signing_bytes(value.quote)?,
    Signature { bytes: value.signature }) do
    Ok(valid)
    Err(_) -> Ok(false)
  end
end

pub fn encode_lightning_issue_request(value :: LightningIssueRequest) -> Bytes!String do
  if !nonzero(value.quote_id, 32) || !nonzero(value.payment_hash, 32) do
    return Err("invalid_lightning_issue_request")
  end
  credit_batch_hash(value.requests)?
  let requests = for item in value.requests do
    encode_token_request(item)?
  end
  concatenate([
      Bytes.from_hex("014c4952")?,
      value.quote_id,
      value.payment_hash,
      narrow(List.length(requests))?
    ]
      ++ requests,
    518070)
end

pub fn decode_lightning_issue_request(input :: Bytes) -> LightningIssueRequest!String do
  let length = Bytes.length(input)
  if length < 25970 || length > 518070 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "014c4952" do
    return Err("invalid_lightning_issue_request")
  end
  let count = read_narrow(input, 68)?
  credit_pack(count)?
  if length != 70 + 259 * count do
    return Err("invalid_lightning_issue_request")
  end
  let requests = for index in 0..count do
    decode_token_request(Bytes.slice(input, 70 + 259 * index, 259)?)?
  end
  let value = LightningIssueRequest {
    quote_id: Bytes.slice(input, 4, 32)?,
    payment_hash: Bytes.slice(input, 36, 32)?,
    requests: requests
  }
  encode_lightning_issue_request(value)?
  Ok(value)
end

pub fn validate_lightning_issue(quote :: LightningQuote,
  request :: LightningIssueRequest) -> Result<(), String> do
  quote_valid(quote)?
  encode_lightning_issue_request(request)?
  if !Bytes.secure_equals(quote.quote_id, request.quote_id)
    || !Bytes.secure_equals(quote.payment_hash, request.payment_hash)
    || quote.credits != List.length(request.requests)
    || !Bytes.secure_equals(quote.batch_hash, credit_batch_hash(request.requests)?)
    || Bytes.get(quote.issuer_key_id, 31)? != List.head(request.requests).truncated_key_id do
    Err("lightning_quote_batch_mismatch")
  else
    Ok(nil)
  end
end
