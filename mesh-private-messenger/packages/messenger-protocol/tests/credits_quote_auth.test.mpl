from Credits.Issuer import CreditIssuerKey, issuer_key_id
from Credits.Issuance import CreditQuote
from Credits.QuoteAuth import (
  sign_credit_quote,
  verify_credit_quote,
  encode_signed_credit_quote,
  decode_signed_credit_quote
)

fn bytes(value :: String, count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, count))
end

fn pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Ok(value)
    Err(_) -> Err("test signing key failed")
  end
end

fn proof() -> Bool!String do
  let signer = pair()?
  let attacker = pair()?
  let private = case Crypto.blind_rsa_generate() do
    Ok(value) -> value
    Err(_) -> return Err("test RSA generation failed")
  end
  let public = case Crypto.blind_rsa_public(private) do
    Ok(value) -> value
    Err(_) -> return Err("test RSA key failed")
  end
  let issuer = CreditIssuerKey {
    epoch: U64.parse("655")?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: signer.public_key.bytes
  }
  let quote = CreditQuote {
    quote_id: bytes("11", 32)?,
    deposit_owner: bytes("22", 32)?,
    destination: bytes("22", 32)?,
    mint: bytes("00", 32)?,
    asset: 1,
    amount: U64.parse("25000000")?,
    purpose: 1,
    credits: 100,
    issued_at: U64.parse("1700000000")?,
    expires_at: U64.parse("1700000900")?,
    issuer_key_id: issuer_key_id(issuer)?,
    batch_hash: bytes("55", 32)?
  }
  let signed = sign_credit_quote(signer.private_key, quote)?
  let encoded = encode_signed_credit_quote(signed)?
  assert(Bytes.length(encoded) == 292)
  assert(verify_credit_quote(decode_signed_credit_quote(encoded)?, issuer)?)
  assert(Result.is_err(decode_signed_credit_quote(Bytes.slice(encoded, 4, 224)?)))
  assert(Result.is_err(decode_signed_credit_quote(Bytes.concat(encoded, bytes("00", 1)?)?)))
  let replaced = %{quote | deposit_owner: bytes("66", 32)?, destination: bytes("66", 32)?}
  assert(!verify_credit_quote(%{signed | quote: replaced}, issuer)?)
  assert(!verify_credit_quote(sign_credit_quote(attacker.private_key, replaced)?, issuer)?)
  assert(!verify_credit_quote(signed, %{issuer | quote_public_key: attacker.public_key.bytes})?)
  assert(!verify_credit_quote(%{signed | quote: %{quote | batch_hash: bytes("77", 32)?}}, issuer)?)
  assert(!verify_credit_quote(%{signed | quote: %{quote | amount: U64.parse("25000001")?}},
    issuer)?)
  assert(!verify_credit_quote(signed, %{issuer | epoch: U64.parse("654")?})?)
  Ok(true)
end

test("only the separately witnessed quote key authenticates payment destinations and complete intent") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
