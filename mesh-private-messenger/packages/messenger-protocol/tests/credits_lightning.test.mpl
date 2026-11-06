from Credits.Lightning import (
  LightningQuoteRequest,
  LightningQuote,
  LightningIssueRequest,
  encode_lightning_quote_request,
  decode_lightning_quote_request,
  encode_lightning_quote,
  decode_lightning_quote,
  encode_lightning_issue_request,
  decode_lightning_issue_request,
  validate_lightning_issue,
  validate_lightning_quote_response,
  sign_lightning_quote,
  verify_lightning_quote,
  encode_signed_lightning_quote,
  decode_signed_lightning_quote
)
from Credits.Issuance import credit_batch_hash
from Credits.Issuer import CreditIssuerKey, issuer_key_id
from Credits.Policy import issuer_epoch
from Credits.Wire import CreditTokenRequest
from Credits.LightningCancellation import (
  sign_lightning_cancellation,
  encode_lightning_cancellation,
  decode_lightning_cancellation,
  verify_lightning_cancellation
)

fn bytes(value :: String, count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, count))
end

fn fixture() -> LightningQuote!String do
  Ok(LightningQuote {
    quote_id: bytes("11", 32)?,
    network: 2,
    purpose: 1,
    credits: 100,
    amount_msat: U64.parse("5000000")?,
    issued_at: U64.parse("1792605690")?,
    expires_at: U64.parse("1792606590")?,
    issuer_key_id: bytes("55", 32)?,
    batch_hash: bytes("66", 32)?,
    payment_hash: Bytes.from_hex("4a1f7d9811fbfea271b1329eec67b1c852ff1e0e52c4783ae871069a919a7e69")?,
    payee: Bytes.from_hex("03659ee9278803e3667d20d2d081dffc7d6bd6145e4e1bca9fb4a941bfd932dbc2")?,
    invoice: "lnbcrt50u1p4d3l06pp5fg0hmxq3l0l2yud3x20wcea3epf078sw2tz8swhgwyrf4yv60e5sdq4f4hhyum9yp3hyetyd968xcqzzsxqzuysp5xe8fr3fkk2pzgw5nkuy7y8k834jyq0e3e6kpa2vzykfhvaly5sts9qxpqysgqmhy4l6nwn2padyzpmek4hhme5ke5an3g0wasatmllw78wqnhwcjkrsa7zfrff4sttax2gw87lhjvux9wdn7ya0x2caumx57grdkyd9spgyzdct"
  })
end

fn wire_cases() -> Bool!String do
  let value = fixture()?
  let request = LightningQuoteRequest {
    credits: 100,
    network: 2,
    purpose: 1,
    issuer_key_id: value.issuer_key_id,
    batch_hash: value.batch_hash
  }
  let rq = encode_lightning_quote_request(request)?
  assert(Bytes.to_hex(rq) == "014c515200640201"
      <> String.repeat("55", 32)
      <> String.repeat("66", 32))
  assert(decode_lightning_quote_request(rq)?.network == 2)
  let encoded = encode_lightning_quote(value)?
  assert(Bytes.length(encoded) == 195 + String.length(value.invoice))
  assert(Bytes.secure_equals(encode_lightning_quote(decode_lightning_quote(encoded)?)?, encoded))
  for bad in [
    %{value | amount_msat: U64.parse("5000001")?},
    %{value | network: 0},
    %{value | purpose: 0},
    %{value | payment_hash: bytes("77", 32)?},
    %{value | payee: Bytes.concat(Bytes.from_hex("02")?, bytes("77", 32)?)?},
    %{value | issued_at: U64.add(value.issued_at, U64.parse("1")?)?},
    %{value | expires_at: U64.add(value.expires_at, U64.parse("1")?)?},
    %{value | invoice: "lightning:" <> value.invoice},
    %{value | credits: 1}
  ] do
    assert(Result.is_err(encode_lightning_quote(bad)))
  end
  for length in [0, 4, 194, Bytes.length(encoded) - 1] do
    assert(Result.is_err(decode_lightning_quote(Bytes.slice(encoded, 0, length)?)))
  end
  assert(Result.is_err(decode_lightning_quote(Bytes.concat(encoded, bytes("00", 1)?)?)))
  assert(Result.is_err(encode_lightning_quote_request(%{request | network: 0})))
  assert(Result.is_err(encode_lightning_quote_request(%{request | purpose: 0})))
  for count in [100, 500, 2000] do
    let requests = for index in 0..count do
      CreditTokenRequest {
        truncated_key_id: 85,
        blinded_message: Bytes.concat(bytes("00", 254)?,
          Bytes.write_uint_le(Int.to_string(index + 1), 2)?)?
      }
    end
    let quote = %{value | credits: count, batch_hash: credit_batch_hash(requests)?}
    let issue = LightningIssueRequest {
      quote_id: value.quote_id,
      payment_hash: value.payment_hash,
      requests: requests
    }
    let wire = encode_lightning_issue_request(issue)?
    assert(Bytes.length(wire) == 70 + 259 * count)
    validate_lightning_issue(quote, decode_lightning_issue_request(wire)?)?
    assert(Result.is_err(validate_lightning_issue(quote,
      %{issue | requests: List.reverse(requests)})))
    assert(Result.is_err(validate_lightning_issue(quote,
      %{issue | payment_hash: bytes("aa", 32)?})))
    assert(Result.is_err(decode_lightning_issue_request(Bytes.concat(wire, bytes("00", 1)?)?)))
    assert(Result.is_err(encode_lightning_issue_request(%{issue |
      requests: [List.head(requests)] ++ List.take(requests, count - 1)
    })))
  end
  Ok(true)
end

fn auth_cases() -> Bool!String do
  let signer = case Crypto.signing_generate() do
    Ok(value) -> value
    Err(_) -> return Err("fixture_signer_failed")
  end
  let private = case Crypto.blind_rsa_generate() do
    Ok(value) -> value
    Err(_) -> return Err("fixture_rsa_failed")
  end
  let public = case Crypto.blind_rsa_public(private) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_rsa_failed")
  end
  let initial = fixture()?
  let issuer = CreditIssuerKey {
    epoch: issuer_epoch(initial.issued_at)?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: signer.public_key.bytes
  }
  let quote = %{initial | issuer_key_id: issuer_key_id(issuer)?}
  let request = LightningQuoteRequest {
    credits: 100,
    network: 2,
    purpose: 1,
    issuer_key_id: quote.issuer_key_id,
    batch_hash: quote.batch_hash
  }
  let signed = sign_lightning_quote(signer.private_key, quote)?
  let encoded = encode_signed_lightning_quote(signed)?
  assert(verify_lightning_quote(decode_signed_lightning_quote(encoded)?, issuer)?)
  validate_lightning_quote_response(request, quote, issuer, quote.issued_at)?
  assert(Result.is_err(validate_lightning_quote_response(request, quote, issuer, quote.expires_at)))
  assert(Result.is_err(validate_lightning_quote_response(request,
    quote,
    issuer,
    U64.subtract(quote.issued_at, U64.parse("1")?)?)))
  assert(Result.is_err(validate_lightning_quote_response(%{request | batch_hash: bytes("aa", 32)?},
    quote,
    issuer,
    quote.issued_at)))
  assert(!verify_lightning_quote(%{signed | quote: %{quote | batch_hash: bytes("aa", 32)?}},
    issuer)?)
  assert(!verify_lightning_quote(%{signed | quote: %{quote | quote_id: bytes("aa", 32)?}}, issuer)?)
  assert(!verify_lightning_quote(%{signed | signature: bytes("aa", 64)?}, issuer)?)
  assert(Result.is_err(decode_signed_lightning_quote(Bytes.concat(encoded, bytes("00", 1)?)?)))
  Ok(true)
end

test("Lightning wires bind verified BOLT11 fields and the immutable ordered blind batch") do
  case wire_cases() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

test("Lightning quote authorization uses the witnessed quote key and checks acceptance expiry") do
  case auth_cases() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn cancellation_cases() -> Bool!String do
  let signer = case Crypto.signing_generate() do
    Ok(value) -> value
    Err(_) -> return Err("fixture_signer_failed")
  end
  let private = case Crypto.blind_rsa_generate() do
    Ok(value) -> value
    Err(_) -> return Err("fixture_rsa_failed")
  end
  let public = case Crypto.blind_rsa_public(private) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_rsa_failed")
  end
  let initial = fixture()?
  let issuer = CreditIssuerKey {
    epoch: issuer_epoch(initial.issued_at)?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: signer.public_key.bytes
  }
  let quote = %{initial | issuer_key_id: issuer_key_id(issuer)?}
  let canceled_at = U64.add(quote.expires_at, U64.parse("100")?)?
  let cancellation = sign_lightning_cancellation(signer.private_key, quote, canceled_at)?
  let wire = encode_lightning_cancellation(cancellation)?
  assert(Bytes.length(wire) == 205 && Bytes.to_hex(Bytes.slice(wire, 0, 4)?) == "014c434e")
  assert(verify_lightning_cancellation(decode_lightning_cancellation(wire)?, quote, issuer)?)
  # The saved key remains authoritative after quote expiry or key rotation.
  assert(Bytes.secure_equals(encode_lightning_cancellation(decode_lightning_cancellation(wire)?)?,
    wire))
  for modified in [
    %{cancellation | quote_id: bytes("aa", 32)?},
    %{cancellation | payment_hash: bytes("aa", 32)?},
    %{cancellation | batch_hash: bytes("aa", 32)?},
    %{cancellation | issuer_key_id: bytes("aa", 32)?},
    %{cancellation | purpose: 0},
    %{cancellation | canceled_at: U64.add(canceled_at, U64.parse("1")?)?},
    %{cancellation | signature: bytes("aa", 64)?}
  ] do
    assert(!verify_lightning_cancellation(modified, quote, issuer)?)
  end
  assert(!verify_lightning_cancellation(cancellation,
    %{quote | quote_id: bytes("aa", 32)?},
    issuer)?)
  assert(Result.is_err(sign_lightning_cancellation(signer.private_key,
    quote,
    U64.subtract(quote.issued_at, U64.parse("1")?)?)))
  for length in [0, 4, 140, 204] do
    assert(Result.is_err(decode_lightning_cancellation(Bytes.slice(wire, 0, length)?)))
  end
  assert(Result.is_err(decode_lightning_cancellation(Bytes.concat(wire, bytes("00", 1)?)?)))
  Ok(true)
end

test("Lightning cancellation authenticates one invoice and blind batch without authorizing issuance") do
  case cancellation_cases() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
