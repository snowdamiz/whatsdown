from Credits.Discovery import (
  CreditIssuerQuery,
  encode_credit_issuer_query,
  decode_credit_issuer_query
)

fn proof() -> Bool!String do
  let query = CreditIssuerQuery { purpose: 0, previous_size: U64.parse("0")? }
  assert(Bytes.to_hex(encode_credit_issuer_query(query)?) == "0143494b000000000000000000")
  let maximum = %{query | purpose: 1, previous_size: U64.parse("18446744073709551615")?}
  let wire = encode_credit_issuer_query(maximum)?
  assert(Bytes.to_hex(wire) == "0143494b01ffffffffffffffff")
  let decoded = decode_credit_issuer_query(wire)?
  assert(decoded.purpose == 1 && decoded.previous_size == maximum.previous_size)
  assert(Result.is_err(encode_credit_issuer_query(%{query | purpose: 2})))
  for malformed in [
    Bytes.empty(),
    Bytes.slice(wire, 0, 12)?,
    Bytes.concat(wire, Bytes.from_hex("00")?)?,
    Bytes.from_hex("0243494b010000000000000000")?,
    Bytes.from_hex("0143494b020000000000000000")?
  ] do
    assert(Result.is_err(decode_credit_issuer_query(malformed)))
  end
  Ok(true)
end

test("issuer discovery query preserves full tree precision and rejects alternate encodings") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
