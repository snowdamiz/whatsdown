from Payment.RevenuePolicy import (
  CreditRevenueSplit,
  split_credit_revenue,
  credit_revenue_policy_hash
)

fn field(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn reference_vectors() -> Bool!String do
  let model = Json.parse(File.read("ops/credit-treasury-policy/fixtures/model.json")?)?
  let cases = Json.object_get(model, "cases")?
  for index in 0..Json.array_length(cases)? do
    let value = Json.array_get(cases, index)?
    let version = Json.as_int(Json.object_get(value, "version")?)?
    let carries = Json.object_get(value, "carries")?
    let next = Json.object_get(value, "next_carries")?
    let shares = Json.object_get(value, "shares")?
    let split = split_credit_revenue(version,
      U64.parse(field(value, "amount")?)?,
      Json.as_int(Json.array_get(carries, 0)?)?,
      Json.as_int(Json.array_get(carries, 1)?)?,
      Json.as_int(Json.array_get(carries, 2)?)?)?
    assert(split.policy == version
      && split.policy_hash == Bytes.from_hex(field(value, "policy_hash")?)?)
    assert(split.witness == U64.parse(Json.as_string(Json.array_get(shares, 0)?)?)?)
    assert(split.burn == U64.parse(Json.as_string(Json.array_get(shares, 1)?)?)?)
    assert(split.operations == U64.parse(Json.as_string(Json.array_get(shares, 2)?)?)?)
    assert(split.carry_witness == Json.as_int(Json.array_get(next, 0)?)?)
    assert(split.carry_burn == Json.as_int(Json.array_get(next, 1)?)?)
    assert(split.carry_operations == Json.as_int(Json.array_get(next, 2)?)?)
    assert(split.reserve_before == Json.as_int(Json.object_get(value, "reserve_before")?)?)
    assert(split.reserve_after == Json.as_int(Json.object_get(value, "reserve_after")?)?)
  end
  let three = split_credit_revenue(2, U64.parse("3")?, 0, 0, 0)?
  assert(three.witness == U64.parse("0")?
    && three.burn == U64.parse("0")?
    && three.operations == U64.parse("1")?
    && three.reserve_after == 2)
  let dust = split_credit_revenue(2, U64.parse("1")?, 9, 9, 2)?
  assert(dust.witness == U64.parse("1")?
    && dust.burn == U64.parse("1")?
    && dust.operations == U64.parse("0")?
    && dust.reserve_before == 2
    && dust.reserve_after == 1)
  IO.eprintln("MORSE_REVENUE_POLICY_REFERENCE exact_gross_20_30_50_u64_max_and_reserved_dust")
  Ok(true)
end

fn composition() -> Bool!String do
  for version in [1, 2] do
    for a in 0..21 do
      for b in 0..21 do
        let first = split_credit_revenue(version, U64.parse(Int.to_string(a))?, 0, 0, 0)?
        let second = split_credit_revenue(version,
          U64.parse(Int.to_string(b))?,
          first.carry_witness,
          first.carry_burn,
          first.carry_operations)?
        let total = split_credit_revenue(version, U64.parse(Int.to_string(a + b))?, 0, 0, 0)?
        assert(U64.add(first.witness, second.witness)? == total.witness)
        assert(U64.add(first.burn, second.burn)? == total.burn)
        assert(U64.add(first.operations, second.operations)? == total.operations)
        assert(second.carry_witness == total.carry_witness
          && second.carry_burn == total.carry_burn
          && second.carry_operations == total.carry_operations
          && second.reserve_after == total.reserve_after)
      end
    end
  end
  for version in [-1, 0, 3] do
    assert(Result.is_err(credit_revenue_policy_hash(version)))
  end
  for carries in [
    [-1, 0, 0],
    [10, 0, 0],
    [0, -1, 0],
    [0, 10, 0],
    [0, 0, -1],
    [0, 0, 10],
    [1, 0, 0],
    [9, 9, 9]
  ] do
    assert(Result.is_err(split_credit_revenue(2,
      U64.parse("1")?,
      List.get(carries, 0),
      List.get(carries, 1),
      List.get(carries, 2))))
  end
  assert(Result.is_err(split_credit_revenue(1, U64.parse("1")?, 5, 0, 0)))
  assert(Result.is_err(split_credit_revenue(1, U64.parse("1")?, 0, 1, 0)))
  assert(Result.is_err(split_credit_revenue(1, U64.parse("1")?, 0, 0, 1)))
  IO.eprintln("MORSE_REVENUE_POLICY_ASSOCIATIVITY exact_chunks_and_invalid_carry_states")
  Ok(true)
end

test("integer allocations match independent original-asset rational reference including N1 through20") do
  let result = reference_vectors()
  case result do
    Err(error) -> IO.eprintln(error)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end

test("chunked allocation is associative and never assigns reserved dust to operations") do
  let result = composition()
  case result do
    Err(error) -> IO.eprintln(error)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end
