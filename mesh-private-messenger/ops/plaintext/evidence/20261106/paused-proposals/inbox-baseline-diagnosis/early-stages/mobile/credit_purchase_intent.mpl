from Credits.Issuer import CreditIssuerKey
from Credits.Issuance import (
  CreditQuoteRequest,
  CreditIssueRequest,
  encode_credit_quote_request,
  decode_credit_quote_request,
  encode_credit_quote,
  decode_credit_quote,
  encode_credit_issue_request,
  decode_credit_issue_request,
  validate_quote_response,
  validate_issue_for_quote
)
from Credits.QuoteAuth import decode_signed_credit_quote, verify_credit_quote
from Credits.Lightning import (
  LightningQuoteRequest,
  LightningIssueRequest,
  encode_lightning_quote_request,
  decode_lightning_quote_request,
  decode_signed_lightning_quote,
  verify_lightning_quote,
  validate_lightning_quote_response,
  encode_lightning_quote,
  decode_lightning_quote,
  encode_lightning_issue_request,
  decode_lightning_issue_request,
  validate_lightning_issue
)
from Credits.Wire import CreditTokenRequest

# This local journal adapter preserves both wire protocols exactly. Asset 2 is
# only a local Lightning selector; it never enters the Solana CQR/CQT formats.
pub struct PurchaseIntent do
  credits :: Int
  asset :: Int
  network :: Int
  purpose :: Int
  issuer_key_id :: Bytes
  batch_hash :: Bytes
end

pub struct PurchaseQuote do
  asset :: Int
  quote_id :: Bytes
  batch_hash :: Bytes
  credits :: Int
  issued_at :: U64
  expires_at :: U64
  wire :: Bytes
end

pub fn decode_purchase_intent(input :: Bytes) -> PurchaseIntent!String do
  if Bytes.length(input) >= 4 && Bytes.to_hex(Bytes.slice(input, 0, 4)?) == "014c5152" do
    let value = decode_lightning_quote_request(input)?
    Ok(PurchaseIntent {
      credits: value.credits,
      asset: 2,
      network: value.network,
      purpose: value.purpose,
      issuer_key_id: value.issuer_key_id,
      batch_hash: value.batch_hash
    })
  else
    let value = decode_credit_quote_request(input)?
    Ok(PurchaseIntent {
      credits: value.credits,
      asset: value.asset,
      network: -1,
      purpose: value.purpose,
      issuer_key_id: value.issuer_key_id,
      batch_hash: value.batch_hash
    })
  end
end

pub fn encode_purchase_intent(value :: PurchaseIntent) -> Bytes!String do
  if value.asset == 2 do
    encode_lightning_quote_request(LightningQuoteRequest {
      credits: value.credits,
      network: value.network,
      purpose: value.purpose,
      issuer_key_id: value.issuer_key_id,
      batch_hash: value.batch_hash
    })
  else
    if value.network != -1 do
      return Err("invalid_credit_purchase_asset")
    end
    encode_credit_quote_request(CreditQuoteRequest {
      credits: value.credits,
      asset: value.asset,
      purpose: value.purpose,
      issuer_key_id: value.issuer_key_id,
      batch_hash: value.batch_hash
    })
  end
end

pub fn verified_purchase_quote(request :: Bytes,
  response :: Bytes,
  issuer :: CreditIssuerKey,
  checked_at :: Option<U64>) -> PurchaseQuote!String do
  let intent = decode_purchase_intent(request)?
  if intent.asset == 2 do
    let signed = decode_signed_lightning_quote(response)?
    if !verify_lightning_quote(signed, issuer)? do
      return Err("unverified_credit_quote")
    end
    let quote = signed.quote
    let now = case checked_at do
      Some(value) -> value
      None -> quote.issued_at
    end
    validate_lightning_quote_response(decode_lightning_quote_request(request)?, quote, issuer, now)?
    Ok(PurchaseQuote {
      asset: 2,
      quote_id: quote.quote_id,
      batch_hash: quote.batch_hash,
      credits: quote.credits,
      issued_at: quote.issued_at,
      expires_at: quote.expires_at,
      wire: encode_lightning_quote(quote)?
    })
  else
    let signed = decode_signed_credit_quote(response)?
    if !verify_credit_quote(signed, issuer)? do
      return Err("unverified_credit_quote")
    end
    let quote = signed.quote
    let now = case checked_at do
      Some(value) -> value
      None -> quote.issued_at
    end
    validate_quote_response(decode_credit_quote_request(request)?, quote, issuer, now)?
    Ok(PurchaseQuote {
      asset: quote.asset,
      quote_id: quote.quote_id,
      batch_hash: quote.batch_hash,
      credits: quote.credits,
      issued_at: quote.issued_at,
      expires_at: quote.expires_at,
      wire: encode_credit_quote(quote)?
    })
  end
end

pub fn purchase_issue_requests(quote :: PurchaseQuote,
  input :: Bytes) -> List<CreditTokenRequest>!String do
  if quote.asset == 2 do
    let request = decode_lightning_issue_request(input)?
    validate_lightning_issue(decode_lightning_quote(quote.wire)?, request)?
    Ok(request.requests)
  else
    let request = decode_credit_issue_request(input)?
    validate_issue_for_quote(decode_credit_quote(quote.wire)?, request)?
    Ok(request.requests)
  end
end

pub fn encode_purchase_issue(quote :: PurchaseQuote,
  payment :: Bytes,
  requests :: List<CreditTokenRequest>) -> Bytes!String do
  let output = if quote.asset == 2 do
    if Bytes.length(payment) != 0 do
      return Err("invalid_lightning_payment_reference")
    end
    let invoice = decode_lightning_quote(quote.wire)?
    encode_lightning_issue_request(LightningIssueRequest {
      quote_id: invoice.quote_id,
      payment_hash: invoice.payment_hash,
      requests: requests
    })?
  else
    encode_credit_issue_request(CreditIssueRequest {
      quote_id: quote.quote_id,
      transaction_signature: payment,
      requests: requests
    })?
  end
  purchase_issue_requests(quote, output)?
  Ok(output)
end

pub fn matches_purchase_payment(quote :: PurchaseQuote,
  request :: Bytes,
  payment :: Bytes) -> Bool!String do
  purchase_issue_requests(quote, request)?
  if quote.asset == 2 do
    Ok(Bytes.length(payment) == 0)
  else
    Ok(Bytes.secure_equals(decode_credit_issue_request(request)?.transaction_signature, payment))
  end
end
