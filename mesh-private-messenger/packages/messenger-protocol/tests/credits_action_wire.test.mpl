from Credits.Action import CreditAction
from Credits.ActionWire import (
  CreditActionSubmission,
  encode_credit_action_submission,
  decode_credit_action_submission,
  sign_credit_action_receipt,
  encode_credit_action_receipt,
  decode_credit_action_receipt,
  verify_credit_action_receipt
)
from Credits.Wire import CreditFrame, CreditToken, CreditTokenInput

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
  let body = Bytes.from_utf8("exact signed paid action")
  let token = CreditToken {
    input: CreditTokenInput {
      nonce: bytes("11", 32)?,
      challenge_digest: bytes("22", 32)?,
      token_key_id: bytes("33", 32)?
    },
    authenticator: bytes("44", 256)?
  }
  let submission = CreditActionSubmission {
    action: CreditAction {
      kind: 2,
      operation_nonce: bytes("55", 32)?,
      target: bytes("66", 32)?,
      expires_at: U64.parse("1600")?,
      quantity: U64.parse("180")?,
      request_sha256: Crypto.sha256(body)
    },
    request_body: body,
    frame: CreditFrame { binding: Crypto.sha256(body), tokens: [token] }
  }
  let wire = encode_credit_action_submission(submission)?
  let restored = decode_credit_action_submission(wire)?
  assert(Bytes.secure_equals(encode_credit_action_submission(restored)?, wire))
  assert(Result.is_err(encode_credit_action_submission(%{submission |
    request_body: Bytes.from_utf8("different action")
  })))
  assert(Result.is_err(decode_credit_action_submission(Bytes.concat(wire, bytes("00", 1)?)?)))
  let issuer = signer()?
  let other = signer()?
  let receipt = sign_credit_action_receipt(issuer.private_key,
    restored,
    bytes("77", 32)?,
    U64.parse("1000")?,
    Bytes.from_utf8("durable effect result"))?
  let encoded = encode_credit_action_receipt(receipt)?
  let decoded = decode_credit_action_receipt(encoded)?
  assert(verify_credit_action_receipt(decoded, issuer.public_key, restored)?)
  assert(!verify_credit_action_receipt(decoded, other.public_key, restored)?)
  assert(!verify_credit_action_receipt(%{decoded | result: Bytes.from_utf8("forged benefit")},
    issuer.public_key,
    restored)?)
  assert(!verify_credit_action_receipt(decoded,
    issuer.public_key,
    %{restored | action: %{restored.action | operation_nonce: bytes("88", 32)?}})?)
  let different_frame = %{restored.frame | tokens: [%{token | authenticator: bytes("99", 256)?}]}
  assert(!verify_credit_action_receipt(decoded,
    issuer.public_key,
    %{restored | frame: different_frame})?)
  assert(Result.is_err(encode_credit_action_receipt(%{decoded | signature: Bytes.empty()})))
  assert(Result.is_err(decode_credit_action_receipt(Bytes.concat(encoded, bytes("00", 1)?)?)))
  assert(Result.is_err(decode_credit_action_receipt(Bytes.slice(encoded,
    0,
    Bytes.length(encoded) - 1)?)))
  Ok(true)
end

test("only a pinned core receipt bound to the exact operation and CRD can complete a paid action") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
