from Credits.Issuance import CreditQuote, encode_credit_quote, decode_credit_quote
from Credits.Issuer import CreditIssuerKey, issuer_key_id
from Credits.Policy import issuer_epoch

pub struct SignedCreditQuote do
  quote :: CreditQuote
  signature :: Bytes
end

fn signing_bytes(value :: CreditQuote) -> Bytes!String do
  Bytes.concat(Bytes.from_utf8("morse-credit-quote-v1"), encode_credit_quote(value)?)
end

pub fn sign_credit_quote(private :: borrow SigningPrivateKey,
  quote :: CreditQuote) -> SignedCreditQuote!String do
  let signature = case Crypto.sign(private, signing_bytes(quote)?) do
    Ok(value) -> value.bytes
    Err(_) -> return Err("credit_quote_signing_failed")
  end
  Ok(SignedCreditQuote { quote: quote, signature: signature })
end

pub fn encode_signed_credit_quote(value :: SignedCreditQuote) -> Bytes!String do
  if Bytes.length(value.signature) != 64 do
    return Err("invalid_signed_credit_quote")
  end
  Bytes.concat(Bytes.concat(Bytes.from_hex("01435351")?, encode_credit_quote(value.quote)?)?,
    value.signature)
end

pub fn decode_signed_credit_quote(input :: Bytes) -> SignedCreditQuote!String do
  if Bytes.length(input) != 292 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "01435351" do
    return Err("invalid_signed_credit_quote")
  end
  Ok(SignedCreditQuote {
    quote: decode_credit_quote(Bytes.slice(input, 4, 224)?)?,
    signature: Bytes.slice(input, 228, 64)?
  })
end

# The Ed25519 quote key is authenticated in the same witnessed leaf as SPKI.
# BR1's blind-signing key cannot authenticate quotes: its signing oracle accepts
# blinded representatives whose original message the issuer does not know.
# Expiry is checked separately on acceptance; saved signed quotes may be needed
# after expiry to recover a payment that was made within the original window.
pub fn verify_credit_quote(value :: SignedCreditQuote, issuer :: CreditIssuerKey) -> Bool!String do
  encode_signed_credit_quote(value)?
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
