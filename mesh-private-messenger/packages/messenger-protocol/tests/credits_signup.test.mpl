from Credits.Signup import (
  CreditSignupRequest,
  CreditSignupResult,
  encode_credit_signup_request,
  decode_credit_signup_request,
  credit_signup_action,
  encode_credit_signup_result,
  decode_credit_signup_result
)
from Credits.Action import credit_action_price, validate_credit_action
from Identity.Device import generate_account
from Protocol.DirectoryWire import encode_directory_entry
from Protocol.IdentityWire import encode_account_identity
from Protocol.V1 import DirectoryEntry

fn bytes(value :: String, count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, count))
end

fn proof() -> Bool!String do
  let (_keys, account) = case generate_account(U64.parse("1000")?, U64.parse("1")?) do
    Err(_) -> return Err("test account generation failed")
    Ok(value) -> value
  end
  let identity = case encode_account_identity(account) do
    Err(_) -> return Err("test identity failed")
    Ok(value) -> value
  end
  # Bundle cryptographic verification belongs to the registration transaction.
  let entry = case encode_directory_entry(DirectoryEntry {
    version: 1,
    username: "priority-signup",
    account_identity: identity,
    prekey_bundle: bytes("22", 32)?,
    mailbox_token: bytes("33", 32)?
  }) do
    Err(_) -> return Err("test entry failed")
    Ok(value) -> value
  end
  let request = CreditSignupRequest {
    operation_nonce: bytes("44", 32)?,
    action_expires_at: U64.parse("1600")?,
    entry: entry
  }
  let wire = encode_credit_signup_request(request)?
  assert(Bytes.length(wire) == Bytes.length(entry) + 48)
  let decoded = decode_credit_signup_request(wire)?
  assert(Bytes.secure_equals(encode_credit_signup_request(decoded)?, wire))
  let action = credit_signup_action(decoded)?
  assert(action.kind == 4 && action.quantity == U64.parse("0")?)
  assert(Bytes.secure_equals(action.target, account.account_id))
  assert(Bytes.secure_equals(action.request_sha256, Crypto.sha256(wire)))
  validate_credit_action(action, wire, U64.parse("1000")?)?
  assert(credit_action_price(action, 0, 16, 16)? == 0)
  assert(credit_action_price(action, 0, 16, 17)? == 20)
  assert(Result.is_err(credit_action_price(action, 0, 16, 15)))
  assert(Result.is_err(validate_credit_action(action, wire, U64.parse("1600")?)))
  assert(Result.is_err(validate_credit_action(action,
    encode_credit_signup_request(%{request | operation_nonce: bytes("55", 32)?})?,
    U64.parse("1000")?)))
  assert(Result.is_err(decode_credit_signup_request(Bytes.concat(wire, bytes("00", 1)?)?)))
  assert(Result.is_err(decode_credit_signup_request(Bytes.slice(wire, 0, Bytes.length(wire) - 1)?)))
  assert(Result.is_err(encode_credit_signup_request(%{request | entry: Bytes.empty()})))
  assert(Result.is_err(encode_credit_signup_request(%{request |
    operation_nonce: bytes("00", 32)?
  })))
  let result = CreditSignupResult {
    account_id: account.account_id,
    entry_sha256: Crypto.sha256(entry)
  }
  let result_wire = encode_credit_signup_result(result)?
  assert(Bytes.length(result_wire) == 68)
  assert(Bytes.secure_equals(encode_credit_signup_result(decode_credit_signup_result(result_wire)?)?,
    result_wire))
  assert(Result.is_err(decode_credit_signup_result(Bytes.concat(result_wire, bytes("00", 1)?)?)))
  Ok(true)
end

test("priority signup binds exact registration, operation and expiry; charge only during raised difficulty") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
