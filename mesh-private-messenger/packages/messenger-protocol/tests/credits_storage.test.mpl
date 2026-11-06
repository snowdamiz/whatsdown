from Credits.Issuer import CreditIssuerKey
from Credits.Token import (
  PendingCredit,
  blind_credit,
  sign_credit_request,
  finalize_credit,
  verify_credit_token
)
from Credits.Wire import encode_credit_token
from Credits.Storage import (
  seal_pending_credit,
  open_pending_credit,
  seal_credit_token,
  open_credit_token
)

fn pending_rejected(result :: consume Result<PendingCredit, String>) -> Bool do
  case result do
    Err(_) -> true
    Ok(_) -> false
  end
end

fn restore() -> Bool!String do
  let signer = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("test RSA generation failed")
    Ok(value) -> value
  end
  let public = case Crypto.blind_rsa_public(signer) do
    Err(_) -> return Err("test RSA public key failed")
    Ok(value) -> value
  end
  let wrapping = case StorageKey.ephemeral() do
    Err(_) -> return Err("test storage key failed")
    Ok(value) -> value
  end
  let key = CreditIssuerKey {
    quote_public_key: Bytes.from_hex(String.repeat("11", 32))?,
    epoch: U64.parse("10")?,
    purpose: 0,
    spki: public.bytes
  }
  let service_key = Bytes.from_hex(String.repeat("ab", 32))?
  let now = U64.parse("25921000")?
  let context = Bytes.from_hex("01"
    <> String.repeat("00", 48)
    <> String.repeat("22", 32)
    <> String.repeat("11", 32)
    <> "000e0000000000000001")?
  let other_context = Bytes.from_hex("01"
    <> String.repeat("00", 48)
    <> String.repeat("22", 32)
    <> String.repeat("33", 32)
    <> "000e0000000000000001")?
  let pending = blind_credit(key, service_key, now)?
  let request = pending.request
  let snapshot = seal_pending_credit(pending, wrapping, context)?
  # The consumed pending resource no longer needs to survive the process.
  let response = sign_credit_request(signer, key, request)?
  let restored = open_pending_credit(snapshot, wrapping, context)?
  let token = finalize_credit(key, restored, response)?
  assert(verify_credit_token(key, token, service_key, now, 0)?)
  assert(pending_rejected(open_pending_credit(snapshot, wrapping, other_context)))
  assert(pending_rejected(open_pending_credit(Bytes.concat(Bytes.from_hex("00")?, snapshot)?,
    wrapping,
    context)))
  let token_blob = seal_credit_token(token, wrapping, context)?
  let reopened = open_credit_token(token_blob, wrapping, context)?
  assert(Bytes.secure_equals(encode_credit_token(reopened)?, encode_credit_token(token)?))
  assert(!String.contains(Bytes.to_hex(token_blob), Bytes.to_hex(encode_credit_token(token)?)))
  assert(Result.is_err(open_credit_token(token_blob, wrapping, other_context)))
  assert(Result.is_err(open_credit_token(snapshot, wrapping, context)))
  assert(pending_rejected(open_pending_credit(token_blob, wrapping, context)))
  # Replaying a recovered issuance recovers the same token, not new value.
  let again = finalize_credit(key, open_pending_credit(snapshot, wrapping, context)?, response)?
  assert(Bytes.secure_equals(encode_credit_token(again)?, encode_credit_token(token)?))
  Ok(true)
end

test("sealed pending credits survive issuance restart and bind all metadata to local storage") do
  case restore() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
