from Credits.Retention import (
  CreditRetentionResult,
  sign_credit_retention_request,
  encode_credit_retention_request,
  decode_credit_retention_request,
  verify_credit_retention_request,
  credit_retention_action,
  encode_credit_retention_result,
  decode_credit_retention_result
)
from Credits.Action import credit_action_price

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

fn bytes(value :: String, count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, count))
end

fn signer() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Ok(value)
    Err(_) -> Err("test signing failed")
  end
end

fn proof() -> Bool!String do
  let owner = signer()?
  let other = signer()?
  let request = sign_credit_retention_request(owner.private_key,
    bytes("11", 32)?,
    bytes("22", 32)?,
    180,
    wide("1600")?,
    wide("1000000")?)?
  let wire = encode_credit_retention_request(request)?
  assert(Bytes.length(wire) == 150)
  assert(Bytes.to_hex(Bytes.slice(wire, 0, 4)?) == "01524554")
  let decoded = decode_credit_retention_request(wire)?
  assert(Bytes.secure_equals(encode_credit_retention_request(decoded)?, wire))
  assert(verify_credit_retention_request(decoded, owner.public_key, wide("1000000")?)?)
  assert(!verify_credit_retention_request(decoded, other.public_key, wide("1000000")?)?)
  assert(!verify_credit_retention_request(%{decoded | days: 179},
    owner.public_key,
    wide("1000000")?)?)
  assert(!verify_credit_retention_request(decoded, owner.public_key, wide("1300001")?)?)
  assert(!verify_credit_retention_request(decoded, owner.public_key, wide("939999")?)?)
  let action = credit_retention_action(decoded)?
  assert(action.kind == 2 && action.quantity == wide("180")?)
  assert(Bytes.secure_equals(action.request_sha256, Crypto.sha256(wire)))
  assert(credit_action_price(action, 0, 16, 16)? == 50)
  for days in [0, 31, 181] do
    assert(Result.is_err(encode_credit_retention_request(%{request | days: days})))
  end
  assert(Result.is_err(encode_credit_retention_request(%{request |
    operation_nonce: bytes("00", 32)?
  })))
  assert(Result.is_err(decode_credit_retention_request(Bytes.concat(wire, bytes("00", 1)?)?)))
  let result = CreditRetentionResult {
    mailbox_hash: request.mailbox_hash,
    days: 180,
    effective_until_ms: wide("15553000000")?
  }
  let result_wire = encode_credit_retention_result(result)?
  assert(Bytes.length(result_wire) == 46)
  assert(Bytes.secure_equals(encode_credit_retention_result(decode_credit_retention_result(result_wire)?)?,
    result_wire))
  assert(Result.is_err(decode_credit_retention_result(Bytes.slice(result_wire, 0, 45)?)))
  Ok(true)
end

test("paid retention requires the mailbox owner and binds bounded days, nonce and exact action body") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
