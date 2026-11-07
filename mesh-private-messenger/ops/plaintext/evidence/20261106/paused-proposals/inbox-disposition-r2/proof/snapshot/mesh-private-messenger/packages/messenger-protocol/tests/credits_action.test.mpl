from Credits.Action import (
  CreditAction,
  encode_credit_action,
  decode_credit_action,
  credit_action_id,
  validate_credit_action,
  credit_action_price
)

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

fn action() -> CreditAction!String do
  Ok(CreditAction {
    kind: 1,
    operation_nonce: Bytes.from_hex(String.repeat("11", 32))?,
    target: Bytes.from_hex(String.repeat("22", 32))?,
    expires_at: wide("1500")?,
    quantity: wide("16777217")?,
    request_sha256: Crypto.sha256(Bytes.from_utf8("actual action request"))
  })
end

fn proof() -> Bool!String do
  let value = action()?
  let encoded = encode_credit_action(value)?
  assert(Bytes.length(encoded) == 117)
  assert(Bytes.to_hex(Bytes.slice(encoded, 0, 5)?) == "0143414301")
  let decoded = decode_credit_action(encoded)?
  assert(decoded.kind == value.kind && decoded.quantity == value.quantity)
  assert(Bytes.secure_equals(encode_credit_action(decoded)?, encoded))
  assert(credit_action_price(decoded, 0, 16, 16)? == 1)
  assert(Result.is_ok(validate_credit_action(decoded,
    Bytes.from_utf8("actual action request"),
    wide("1000")?)))
  assert(Result.is_err(validate_credit_action(decoded,
    Bytes.from_utf8("other request"),
    wide("1000")?)))
  assert(Result.is_err(validate_credit_action(decoded,
    Bytes.from_utf8("actual action request"),
    wide("1500")?)))
  assert(Result.is_err(validate_credit_action(%{decoded | expires_at: wide("1901")?},
    Bytes.from_utf8("actual action request"),
    wide("1000")?)))
  assert(Result.is_err(encode_credit_action(%{value |
    operation_nonce: Bytes.from_hex(String.repeat("00", 32))?
  })))
  assert(Result.is_err(encode_credit_action(%{value | kind: 5})))
  assert(Result.is_err(encode_credit_action(%{value | quantity: wide("536870913")?})))
  assert(Result.is_err(decode_credit_action(Bytes.concat(encoded, Bytes.from_hex("00")?)?)))
  assert(!Bytes.secure_equals(credit_action_id(value)?,
    credit_action_id(%{value | operation_nonce: value.target})?))
  let retention = %{value | kind: 2, quantity: wide("180")?}
  assert(credit_action_price(retention, 0, 16, 16)? == 50)
  let postage = %{value | kind: 3, quantity: wide("0")?}
  assert(credit_action_price(postage, 25, 16, 16)? == 25)
  assert(Result.is_err(encode_credit_action(%{postage | quantity: wide("1")?})))
  let signup = %{postage | kind: 4}
  assert(credit_action_price(signup, 0, 16, 17)? == 20)
  assert(credit_action_price(signup, 0, 16, 16)? == 0)
  assert(Result.is_err(credit_action_price(signup, 0, 16, 15)))
  Ok(true)
end

test("paid action binding has a unique operation scope, bounded expiry and server-derived price") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
