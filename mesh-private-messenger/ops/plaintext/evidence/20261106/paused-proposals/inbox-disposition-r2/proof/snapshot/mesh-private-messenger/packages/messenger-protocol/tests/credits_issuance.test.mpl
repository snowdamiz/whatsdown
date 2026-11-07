from Credits.Issuance import (
  CreditQuoteRequest,
  CreditQuote,
  CreditIssueRequest,
  CreditIssueResponse,
  encode_credit_quote_request,
  decode_credit_quote_request,
  encode_credit_quote,
  decode_credit_quote,
  encode_credit_issue_request,
  decode_credit_issue_request,
  encode_credit_issue_response,
  decode_credit_issue_response,
  credit_batch_hash,
  validate_quote_for_key,
  validate_issue_for_quote
)
from Credits.Wire import CreditTokenRequest
from Credits.Issuer import CreditIssuerKey, issuer_key_id
from Credits.Policy import issuer_epoch, credit_pack

fn bytes(value :: String, count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, count))
end

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn quote() -> CreditQuote!String do
  Ok(CreditQuote {
    quote_id: bytes("11", 32)?,
    deposit_owner: bytes("22", 32)?,
    destination: bytes("33", 32)?,
    mint: bytes("44", 32)?,
    asset: 0,
    amount: wide(5000000)?,
    purpose: 1,
    credits: 100,
    issued_at: wide(1700000000)?,
    expires_at: wide(1700000900)?,
    issuer_key_id: bytes("55", 32)?,
    batch_hash: bytes("88", 32)?
  })
end

fn quotes() -> Bool!String do
  let request = CreditQuoteRequest {
    credits: 100,
    asset: 0,
    purpose: 1,
    issuer_key_id: bytes("55", 32)?,
    batch_hash: bytes("88", 32)?
  }
  assert(Bytes.to_hex(encode_credit_quote_request(request)?) == "0143515200640001"
      <> String.repeat("55", 32)
      <> String.repeat("88", 32))
  assert(decode_credit_quote_request(encode_credit_quote_request(request)?)?.credits == 100)
  let value = quote()?
  let encoded = encode_credit_quote(value)?
  let expected = "01435154"
    <> String.repeat("11", 32)
    <> String.repeat("22", 32)
    <> String.repeat("33", 32)
    <> String.repeat("44", 32)
    <> "0000000000004c4b40010064000000006553f100000000006553f484"
    <> String.repeat("55", 32)
    <> String.repeat("88", 32)
  assert(Bytes.length(encoded) == 224)
  assert(Bytes.to_hex(encoded) == expected)
  assert(Bytes.secure_equals(encode_credit_quote(decode_credit_quote(encoded)?)?, encoded))
  for invalid in [
    %{value | credits: 101},
    %{value | asset: 2},
    %{value | purpose: 2},
    %{value | amount: wide(0)?},
    %{value | expires_at: wide(1700000901)?},
    %{value | quote_id: bytes("00", 32)?},
    %{value | deposit_owner: bytes("00", 32)?},
    %{value | issuer_key_id: bytes("00", 32)?},
    %{value | mint: bytes("00", 32)?},
    %{value | asset: 1}
  ] do
    assert(Result.is_err(encode_credit_quote(invalid)))
  end
  let sol = %{value | asset: 1, mint: bytes("00", 32)?, destination: value.deposit_owner}
  assert(decode_credit_quote(encode_credit_quote(sol)?)?.asset == 1)
  for length in [0, 4, 223] do
    assert(Result.is_err(decode_credit_quote(Bytes.slice(encoded, 0, length)?)))
  end
  assert(Result.is_err(decode_credit_quote(Bytes.concat(encoded, bytes("00", 1)?)?)))
  assert(Result.is_err(decode_credit_quote_request(Bytes.from_hex("0143515200010001")?)))
  assert(Result.is_err(decode_credit_quote_request(Bytes.from_hex("014351520064000100")?)))
  Ok(true)
end

test("credit quotes encode exact fixed packs and reject ambiguous payment or expiry fields") do
  case quotes() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn batches() -> Bool!String do
  let quote = quote()?
  for count in [100, 500, 2000] do
    let requests = for index in 0..count do
      CreditTokenRequest {
        truncated_key_id: 85,
        blinded_message: Bytes.concat(bytes("00", 254)?,
          case Bytes.write_u16_be(index + 1) do
            Ok(value) -> value
            Err(_) -> return Err("fixture failed")
          end)?
      }
    end
    let request = CreditIssueRequest {
      quote_id: quote.quote_id,
      transaction_signature: bytes("66", 64)?,
      requests: requests
    }
    let encoded = encode_credit_issue_request(request)?
    assert(Bytes.length(encoded) == 102 + 259 * count)
    assert(Bytes.secure_equals(encode_credit_issue_request(decode_credit_issue_request(encoded)?)?,
      encoded))
    let hash = credit_batch_hash(requests)?
    let committed_quote = %{quote |
      credits: count,
      amount: credit_pack(count)?.usd_micros,
      batch_hash: hash
    }
    validate_issue_for_quote(committed_quote, request)?
    assert(Result.is_err(validate_issue_for_quote(%{committed_quote | batch_hash: quote.batch_hash},
      request)))
    assert(Result.is_err(validate_issue_for_quote(committed_quote,
      %{request | requests: List.reverse(requests)})))
    if count == 100 do
      assert(Bytes.to_hex(hash) == "4d2a3309a785ac4c6dbfff3d1e2e28aef77d25f31c0382e7747661702a89c458")
    end
    let signatures = for _index in 0..count do
      bytes("77", 256)?
    end
    let response = CreditIssueResponse {
      quote_id: quote.quote_id,
      batch_hash: hash,
      signatures: signatures
    }
    let response_bytes = encode_credit_issue_response(response)?
    assert(Bytes.length(response_bytes) == 70 + 256 * count)
    assert(Bytes.secure_equals(encode_credit_issue_response(decode_credit_issue_response(response_bytes)?)?,
      response_bytes))
    for altered in [
      Bytes.slice(encoded, 0, Bytes.length(encoded) - 1)?,
      Bytes.concat(encoded, bytes("00", 1)?)?
    ] do
      assert(Result.is_err(decode_credit_issue_request(altered)))
    end
    assert(Result.is_err(encode_credit_issue_request(%{request | requests: [List.head(requests)]})))
    assert(Result.is_err(encode_credit_issue_response(%{response |
      signatures: [bytes("77", 255)?]
    })))
    assert(Result.is_err(encode_credit_issue_request(%{request |
      transaction_signature: bytes("00", 64)?
    })))
    let duplicates = for _index in 0..count do
      List.head(requests)
    end
    assert(Result.is_err(credit_batch_hash(duplicates)))
    let mixed = [%{List.head(requests) | truncated_key_id: 84}] ++ List.tail(requests)
    assert(Result.is_err(credit_batch_hash(mixed)))
  end
  Ok(true)
end

test("issuance batches bind ordered unique requests and preserve the 2000-credit maximum") do
  case batches() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn key_binding() -> Bool!String do
  let secret = case Crypto.blind_rsa_generate() do
    Ok(value) -> value
    Err(_) -> return Err("fixture key failed")
  end
  let public = case Crypto.blind_rsa_public(secret) do
    Ok(value) -> value
    Err(_) -> return Err("fixture key failed")
  end
  let value = quote()?
  let key = CreditIssuerKey {
    quote_public_key: Bytes.from_hex(String.repeat("11", 32))?,
    epoch: issuer_epoch(value.issued_at)?,
    purpose: 1,
    spki: public.bytes
  }
  let bound = %{value | issuer_key_id: issuer_key_id(key)?}
  validate_quote_for_key(bound, key, value.issued_at)?
  validate_quote_for_key(bound, key, U64.subtract(value.expires_at, wide(1)?)?)?
  assert(Result.is_err(validate_quote_for_key(bound, key, value.expires_at)))
  assert(Result.is_err(validate_quote_for_key(bound,
    key,
    U64.subtract(value.issued_at, wide(1)?)?)))
  assert(Result.is_err(validate_quote_for_key(bound, %{key | purpose: 0}, value.issued_at)))
  assert(Result.is_err(validate_quote_for_key(bound,
    %{key | epoch: U64.subtract(key.epoch, wide(1)?)?},
    value.issued_at)))
  assert(Result.is_err(validate_quote_for_key(value, key, value.issued_at)))
  Ok(true)
end

test("purchase quotes bind the admitted issuer epoch purpose and exact expiry boundary") do
  case key_binding() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
