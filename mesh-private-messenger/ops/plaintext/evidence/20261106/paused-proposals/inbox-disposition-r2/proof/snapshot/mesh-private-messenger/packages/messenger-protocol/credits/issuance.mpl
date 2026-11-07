from Credits.Policy import credit_pack, issuer_epoch, issuer_epoch_accepted
from Credits.Issuer import CreditIssuerKey, issuer_key_id
from Credits.Wire import CreditTokenRequest, encode_token_request, decode_token_request

pub struct CreditQuoteRequest do
  credits :: Int
  asset :: Int
  purpose :: Int
  issuer_key_id :: Bytes
  batch_hash :: Bytes
end

pub struct CreditQuote do
  quote_id :: Bytes
  deposit_owner :: Bytes
  destination :: Bytes
  mint :: Bytes
  asset :: Int
  amount :: U64
  purpose :: Int
  credits :: Int
  issued_at :: U64
  expires_at :: U64
  issuer_key_id :: Bytes
  batch_hash :: Bytes
end

pub struct CreditIssueRequest do
  quote_id :: Bytes
  transaction_signature :: Bytes
  requests :: List<CreditTokenRequest>
end

pub struct CreditIssueResponse do
  quote_id :: Bytes
  batch_hash :: Bytes
  signatures :: List<Bytes>
end

fn nonzero(value :: Bytes, size :: Int) -> Bool do
  Bytes.length(value) == size && Bytes.to_hex(value) != String.repeat("00", size)
end

fn bytes(values :: List<Int>) -> Bytes!String do
  case Bytes.from_list(values) do
    Ok(value)
    Err(_) -> Err("invalid_credit_issuance")
  end
end

fn narrow(value :: Int) -> Bytes!String do
  case Bytes.write_u16_be(value) do
    Ok(bytes)
    Err(_) -> Err("invalid_credit_issuance")
  end
end

fn wide(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Ok(bytes)
    Err(_) -> Err("invalid_credit_issuance")
  end
end

fn read_narrow(value :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u16_be(value, offset) do
    Ok(number)
    Err(_) -> Err("invalid_credit_issuance")
  end
end

fn read_wide(value :: Bytes, offset :: Int) -> U64!String do
  case Bytes.read_u64_be(value, offset) do
    Ok(number)
    Err(_) -> Err("invalid_credit_issuance")
  end
end

fn concatenate(parts :: List<Bytes>, maximum :: Int) -> Bytes!String do
  let builder = case BytesBuilder.new(maximum) do
    Ok(value) -> value
    Err(_) -> return Err("invalid_credit_issuance")
  end
  for part in parts do
    case BytesBuilder.write_bytes(builder, part) do
      Ok(_) -> nil
      Err(_) -> return Err("invalid_credit_issuance")
    end
  end
  case BytesBuilder.finish(builder) do
    Ok(value)
    Err(_) -> Err("invalid_credit_issuance")
  end
end

fn request_valid(value :: CreditQuoteRequest) -> Result<(), String> do
  credit_pack(value.credits)?
  if (value.asset != 0 && value.asset != 1)
    || (value.purpose != 0 && value.purpose != 1)
    || !nonzero(value.issuer_key_id, 32)
    || !nonzero(value.batch_hash, 32) do
    Err("invalid_credit_quote_request")
  else
    Ok(nil)
  end
end

pub fn encode_credit_quote_request(value :: CreditQuoteRequest) -> Bytes!String do
  request_valid(value)?
  concatenate([
      Bytes.from_hex("01435152")?,
      narrow(value.credits)?,
      bytes([value.asset, value.purpose])?,
      value.issuer_key_id,
      value.batch_hash
    ],
    72)
end

pub fn decode_credit_quote_request(input :: Bytes) -> CreditQuoteRequest!String do
  if Bytes.length(input) != 72 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "01435152" do
    return Err("invalid_credit_quote_request")
  end
  let value = CreditQuoteRequest {
    credits: read_narrow(input, 4)?,
    asset: Bytes.get(input, 6)?,
    purpose: Bytes.get(input, 7)?,
    issuer_key_id: Bytes.slice(input, 8, 32)?,
    batch_hash: Bytes.slice(input, 40, 32)?
  }
  request_valid(value)?
  Ok(value)
end

fn quote_valid(value :: CreditQuote) -> Result<(), String> do
  request_valid(CreditQuoteRequest {
    credits: value.credits,
    asset: value.asset,
    purpose: value.purpose,
    issuer_key_id: value.issuer_key_id,
    batch_hash: value.batch_hash
  })?
  if !nonzero(value.quote_id, 32)
    || !nonzero(value.deposit_owner, 32)
    || !nonzero(value.destination, 32)
    || !nonzero(value.issuer_key_id, 32)
    || Bytes.length(value.mint) != 32
    || value.amount == U64.parse("0")?
    || value.expires_at != U64.add(value.issued_at, U64.parse("900")?)? do
    return Err("invalid_credit_quote")
  end
  if value.asset == 0 do
    if !nonzero(value.mint, 32) || value.amount != credit_pack(value.credits)?.usd_micros do
      return Err("invalid_credit_quote")
    end
  else if Bytes.to_hex(value.mint) != String.repeat("00", 32)
    || !Bytes.secure_equals(value.destination, value.deposit_owner) do
    return Err("invalid_credit_quote")
  end
  Ok(nil)
end

pub fn encode_credit_quote(value :: CreditQuote) -> Bytes!String do
  quote_valid(value)?
  concatenate([
      Bytes.from_hex("01435154")?,
      value.quote_id,
      value.deposit_owner,
      value.destination,
      value.mint,
      bytes([value.asset])?,
      wide(value.amount)?,
      bytes([value.purpose])?,
      narrow(value.credits)?,
      wide(value.issued_at)?,
      wide(value.expires_at)?,
      value.issuer_key_id,
      value.batch_hash
    ],
    224)
end

pub fn decode_credit_quote(input :: Bytes) -> CreditQuote!String do
  if Bytes.length(input) != 224 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "01435154" do
    return Err("invalid_credit_quote")
  end
  let value = CreditQuote {
    quote_id: Bytes.slice(input, 4, 32)?,
    deposit_owner: Bytes.slice(input, 36, 32)?,
    destination: Bytes.slice(input, 68, 32)?,
    mint: Bytes.slice(input, 100, 32)?,
    asset: Bytes.get(input, 132)?,
    amount: read_wide(input, 133)?,
    purpose: Bytes.get(input, 141)?,
    credits: read_narrow(input, 142)?,
    issued_at: read_wide(input, 144)?,
    expires_at: read_wide(input, 152)?,
    issuer_key_id: Bytes.slice(input, 160, 32)?,
    batch_hash: Bytes.slice(input, 192, 32)?
  }
  quote_valid(value)?
  Ok(value)
end

# The caller has already admitted this key through witnessed transparency.
# Only the current issuer can issue a new quote; old completed quotes remain
# replayable by the issuer ledger, without creating another batch.
pub fn validate_quote_for_key(value :: CreditQuote,
  key :: CreditIssuerKey,
  now :: U64) -> Result<(), String> do
  quote_valid(value)?
  if key.purpose != value.purpose
    || key.epoch != issuer_epoch(value.issued_at)?
    || !issuer_epoch_accepted(key.epoch, now)?
    || U64.compare(now, value.issued_at) < 0
    || U64.compare(now, value.expires_at) >= 0
    || !Bytes.secure_equals(value.issuer_key_id, issuer_key_id(key)?) do
    Err("inactive_credit_quote")
  else
    Ok(nil)
  end
end

fn batch_bytes(requests :: List<CreditTokenRequest>) -> Bytes!String do
  let count = List.length(requests)
  credit_pack(count)?
  let truncated = List.head(requests).truncated_key_id
  let encoded = for request in requests do
    if request.truncated_key_id != truncated do
      return Err("mixed_credit_issuers")
    end
    encode_token_request(request)?
  end
  let identities = for value in encoded do
    Bytes.to_hex(Crypto.sha256(value))
  end
  if Set.size(Set.from_list(identities)) != count do
    return Err("duplicate_credit_blinded_request")
  end
  concatenate([Bytes.from_hex("01434942")?, narrow(count)?] ++ encoded, 518006)
end

pub fn credit_batch_hash(requests :: List<CreditTokenRequest>) -> Bytes!String do
  Ok(Crypto.sha256(batch_bytes(requests)?))
end

# The commitment is recorded before any public payment. A public quote
# reference and transaction signature cannot authorize replacing this batch.
pub fn validate_issue_for_quote(quote :: CreditQuote,
  request :: CreditIssueRequest) -> Result<(), String> do
  quote_valid(quote)?
  encode_credit_issue_request(request)?
  if !Bytes.secure_equals(quote.quote_id, request.quote_id)
    || quote.credits != List.length(request.requests)
    || !Bytes.secure_equals(quote.batch_hash, credit_batch_hash(request.requests)?)
    || Bytes.get(quote.issuer_key_id, 31)? != List.head(request.requests).truncated_key_id do
    Err("credit_quote_batch_mismatch")
  else
    Ok(nil)
  end
end

pub fn validate_quote_response(request :: CreditQuoteRequest,
  quote :: CreditQuote,
  key :: CreditIssuerKey,
  now :: U64) -> Result<(), String> do
  request_valid(request)?
  validate_quote_for_key(quote, key, now)?
  if quote.credits != request.credits
    || quote.asset != request.asset
    || quote.purpose != request.purpose
    || !Bytes.secure_equals(quote.issuer_key_id, request.issuer_key_id)
    || !Bytes.secure_equals(quote.batch_hash, request.batch_hash) do
    Err("credit_quote_request_mismatch")
  else
    Ok(nil)
  end
end

pub fn encode_credit_issue_request(value :: CreditIssueRequest) -> Bytes!String do
  if !nonzero(value.quote_id, 32) || !nonzero(value.transaction_signature, 64) do
    return Err("invalid_credit_issue_request")
  end
  let batch = batch_bytes(value.requests)?
  concatenate([
      Bytes.from_hex("01434951")?,
      value.quote_id,
      value.transaction_signature,
      Bytes.slice(batch, 4, Bytes.length(batch) - 4)?
    ],
    518102)
end

pub fn decode_credit_issue_request(input :: Bytes) -> CreditIssueRequest!String do
  let length = Bytes.length(input)
  if length < 26002 || length > 518102 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "01434951" do
    return Err("invalid_credit_issue_request")
  end
  let count = read_narrow(input, 100)?
  credit_pack(count)?
  if length != 102 + 259 * count do
    return Err("invalid_credit_issue_request")
  end
  let requests = for index in 0..count do
    decode_token_request(Bytes.slice(input, 102 + 259 * index, 259)?)?
  end
  let value = CreditIssueRequest {
    quote_id: Bytes.slice(input, 4, 32)?,
    transaction_signature: Bytes.slice(input, 36, 64)?,
    requests: requests
  }
  encode_credit_issue_request(value)?
  Ok(value)
end

pub fn encode_credit_issue_response(value :: CreditIssueResponse) -> Bytes!String do
  let count = List.length(value.signatures)
  credit_pack(count)?
  if !nonzero(value.quote_id, 32) || !nonzero(value.batch_hash, 32) do
    return Err("invalid_credit_issue_response")
  end
  for signature in value.signatures do
    if Bytes.length(signature) != 256 do
      return Err("invalid_credit_issue_response")
    end
  end
  concatenate([Bytes.from_hex("01434953")?, value.quote_id, value.batch_hash, narrow(count)?]
      ++ value.signatures,
    512070)
end

pub fn decode_credit_issue_response(input :: Bytes) -> CreditIssueResponse!String do
  let length = Bytes.length(input)
  if length < 25670 || length > 512070 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "01434953" do
    return Err("invalid_credit_issue_response")
  end
  let count = read_narrow(input, 68)?
  credit_pack(count)?
  if length != 70 + 256 * count do
    return Err("invalid_credit_issue_response")
  end
  let signatures = for index in 0..count do
    Bytes.slice(input, 70 + 256 * index, 256)?
  end
  let value = CreditIssueResponse {
    quote_id: Bytes.slice(input, 4, 32)?,
    batch_hash: Bytes.slice(input, 36, 32)?,
    signatures: signatures
  }
  encode_credit_issue_response(value)?
  Ok(value)
end
