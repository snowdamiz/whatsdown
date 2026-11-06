from Credits.Lightning import LightningQuote, encode_lightning_quote
from Credits.Issuer import CreditIssuerKey, issuer_key_id

# A canceled invoice cannot later settle. Only the issuer's witnessed quote
# key may attest that terminal result; an HTTP refusal or expiry is no proof.
pub struct LightningCancellation do
  quote_id :: Bytes
  payment_hash :: Bytes
  batch_hash :: Bytes
  issuer_key_id :: Bytes
  purpose :: Int
  canceled_at :: U64
  signature :: Bytes
end

fn content(value :: LightningCancellation) -> Bytes!String do
  for field in [value.quote_id, value.payment_hash, value.batch_hash, value.issuer_key_id] do
    if Bytes.length(field) != 32 || Bytes.to_hex(field) == String.repeat("00", 32) do
      return Err("invalid_lightning_cancellation")
    end
  end
  if (value.purpose != 0 && value.purpose != 1) || value.canceled_at == U64.parse("0")? do
    return Err("invalid_lightning_cancellation")
  end
  let timestamp = case Bytes.write_u64_be(value.canceled_at) do
    Ok(bytes) -> bytes
    Err(_) -> return Err("invalid_lightning_cancellation")
  end
  Bytes.from_hex("014c434e"
    <> Bytes.to_hex(value.quote_id)
    <> Bytes.to_hex(value.payment_hash)
    <> Bytes.to_hex(value.batch_hash)
    <> Bytes.to_hex(value.issuer_key_id)
    <> (if value.purpose == 0 do
      "00"
    else
      "01"
    end)
    <> Bytes.to_hex(timestamp))
end

fn signing_bytes(value :: LightningCancellation) -> Bytes!String do
  Bytes.concat(Bytes.from_utf8("morse-lightning-credit-cancellation-v1"), content(value)?)
end

pub fn encode_lightning_cancellation(value :: LightningCancellation) -> Bytes!String do
  if Bytes.length(value.signature) != 64 do
    return Err("invalid_lightning_cancellation")
  end
  Bytes.concat(content(value)?, value.signature)
end

pub fn decode_lightning_cancellation(input :: Bytes) -> LightningCancellation!String do
  if Bytes.length(input) != 205 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "014c434e" do
    return Err("invalid_lightning_cancellation")
  end
  let timestamp = case Bytes.read_u64_be(input, 133) do
    Ok(value) -> value
    Err(_) -> return Err("invalid_lightning_cancellation")
  end
  let value = LightningCancellation {
    quote_id: Bytes.slice(input, 4, 32)?,
    payment_hash: Bytes.slice(input, 36, 32)?,
    batch_hash: Bytes.slice(input, 68, 32)?,
    issuer_key_id: Bytes.slice(input, 100, 32)?,
    purpose: Bytes.get(input, 132)?,
    canceled_at: timestamp,
    signature: Bytes.slice(input, 141, 64)?
  }
  encode_lightning_cancellation(value)?
  Ok(value)
end

pub fn sign_lightning_cancellation(private :: borrow SigningPrivateKey,
  quote :: LightningQuote,
  canceled_at :: U64) -> LightningCancellation!String do
  encode_lightning_quote(quote)?
  if U64.compare(canceled_at, quote.issued_at) < 0 do
    return Err("invalid_lightning_cancellation")
  end
  let value = LightningCancellation {
    quote_id: quote.quote_id,
    payment_hash: quote.payment_hash,
    batch_hash: quote.batch_hash,
    issuer_key_id: quote.issuer_key_id,
    purpose: quote.purpose,
    canceled_at: canceled_at,
    signature: Bytes.empty()
  }
  let signature = case Crypto.sign(private, signing_bytes(value)?) do
    Ok(signed) -> signed.bytes
    Err(_) -> return Err("lightning_cancellation_signing_failed")
  end
  Ok(%{value | signature: signature})
end

pub fn verify_lightning_cancellation(value :: LightningCancellation,
  quote :: LightningQuote,
  issuer :: CreditIssuerKey) -> Bool!String do
  encode_lightning_cancellation(value)?
  encode_lightning_quote(quote)?
  if !Bytes.secure_equals(value.quote_id, quote.quote_id)
    || !Bytes.secure_equals(value.payment_hash, quote.payment_hash)
    || !Bytes.secure_equals(value.batch_hash, quote.batch_hash)
    || !Bytes.secure_equals(value.issuer_key_id, quote.issuer_key_id)
    || !Bytes.secure_equals(value.issuer_key_id, issuer_key_id(issuer)?)
    || value.purpose != quote.purpose
    || value.purpose != issuer.purpose
    || U64.compare(value.canceled_at, quote.issued_at) < 0 do
    return Ok(false)
  end
  case Crypto.verify(SigningPublicKey { bytes: issuer.quote_public_key },
    signing_bytes(value)?,
    Signature { bytes: value.signature }) do
    Ok(valid)
    Err(_) -> Ok(false)
  end
end
