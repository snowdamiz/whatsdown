from Transparency.TokenPolicy import (
  token_supply_units,
  token_initial_allocations,
  token_vested_units,
  required_token_bond,
  assess_token_bond,
  token_burn_chunks
)

fn token_test_sum(values :: List<U64>) -> U64!String do
  if List.length(values) == 0 do
    return U64.parse("0")
  end
  U64.add(List.head(values), token_test_sum(List.drop(values, 1))?)
end

fn token_allocation_proof() -> Bool!String do
  let total = token_supply_units()?
  assert(total == U64.parse("1000000000000000")?)
  let amounts = token_initial_allocations()?
  assert(List.length(amounts) == 7 && token_test_sum(amounts)? == total)
  let expected = [
    "250000000000000",
    "200000000000000",
    "180000000000000",
    "150000000000000",
    "150000000000000",
    "50000000000000",
    "20000000000000"
  ]
  for index in 0..7 do
    assert(List.get(amounts, index) == U64.parse(List.get(expected, index))?)
  end
  Ok(true)
end

fn token_vesting_proof() -> Bool!String do
  let origin = DateTime.from_iso8601("2024-01-31T12:34:56Z")?
  let started = DateTime.to_unix_secs(origin)
  let cliff = DateTime.to_unix_secs(DateTime.add_months(origin, 12)?)
  let finish = DateTime.to_unix_secs(DateTime.add_months(origin, 48)?)
  let allocation = U64.parse("180000000000000")?
  assert(token_vested_units(allocation, 48, 12, started, started - 1)? == U64.parse("0")?)
  assert(token_vested_units(allocation, 48, 12, started, cliff - 1)? == U64.parse("0")?)
  assert(token_vested_units(allocation, 48, 12, started, cliff)? == U64.parse("45000000000000")?)
  assert(token_vested_units(allocation, 48, 12, started, finish)? == allocation)
  assert(token_vested_units(allocation, 48, 12, started, finish + 100000)? == allocation)
  let feb = DateTime.to_unix_secs(DateTime.add_months(origin, 1)?)
  let march = DateTime.to_unix_secs(DateTime.add_months(origin, 2)?)
  let midpoint = feb + (march - feb) / 2
  assert(token_vested_units(U64.parse("48000000")?,
    48,
    0,
    started,
    midpoint)? == U64.parse("1500000")?)
  assert(token_vested_units(U64.parse("1")?, 48, 0, started, finish - 1)? == U64.parse("0")?)
  assert(token_vested_units(U64.parse("1")?, 48, 0, started, finish)? == U64.parse("1")?)
  assert(Result.is_err(token_vested_units(allocation, 0, 0, started, finish)))
  assert(Result.is_err(token_vested_units(allocation, 48, 49, started, finish)))
  Ok(true)
end

fn token_bond_proof() -> Bool!String do
  let price = U64.parse("10000000")?
  let target = U64.parse("10000000000")?
  assert(required_token_bond(target, price)? == U64.parse("1000000000")?)
  assert(required_token_bond(U64.parse("1")?, U64.parse("3")?)? == U64.parse("333334")?)
  assert(Result.is_err(required_token_bond(target, U64.parse("0")?)))
  let exact = assess_token_bond(U64.parse("800000000")?, price, target, 0, 1000000)?
  assert(exact.eligible && exact.underwater_since == 0)
  let below = assess_token_bond(U64.parse("799999999")?, price, target, 0, 1000000)?
  assert(below.eligible && below.underwater_since == 1000000)
  let waiting = assess_token_bond(U64.parse("900000000")?,
    price,
    target,
    below.underwater_since,
    1604799)?
  assert(waiting.eligible && waiting.underwater_since == 1000000)
  let overdue = assess_token_bond(U64.parse("900000000")?,
    price,
    target,
    below.underwater_since,
    1604800)?
  assert(!overdue.eligible && overdue.underwater_since == 1000000)
  let restored = assess_token_bond(U64.parse("1000000000")?,
    price,
    target,
    below.underwater_since,
    1604800)?
  assert(restored.eligible && restored.underwater_since == 0)
  assert(Result.is_err(assess_token_bond(U64.parse("1")?, price, target, 2000000, 1000000)))
  Ok(true)
end

test("fixed billion supply and every original allocation conserve six-decimal units") do
  assert(token_allocation_proof() == Ok(true))
end

test("inclusive vesting cliff and original UTC anniversaries preserve exact cumulative entitlement") do
  assert(token_vesting_proof() == Ok(true))
end

test("token bonds round required collateral up and never reset the seven-day topup clock below full target") do
  assert(token_bond_proof() == Ok(true))
end

fn token_chunks_proof() -> Bool!String do
  let start = U64.parse("1700000000")?
  let weights = for index in 0..24 do
    U64.parse(Int.to_string(index + 1))?
  end
  let entropy = for index in 0..24 do
    U64.parse(Int.to_string(999999999 * (index + 1)))?
  end
  let maximum = U64.parse("18446744073709551615")?
  for budget in [U64.parse("24")?, U64.parse("1000001")?, maximum] do
    let chunks = token_burn_chunks(budget, start, weights, entropy)?
    assert(List.length(chunks) == 24)
    let amounts = for row in chunks do
      row.amount
    end
    assert(token_test_sum(amounts)? == budget)
    for index in 0..24 do
      let row = List.get(chunks, index)
      assert(U64.compare(row.amount, U64.parse("0")?) > 0)
      assert(U64.compare(row.execute_at, row.window_start) >= 0
        && U64.compare(row.execute_at, row.window_end) < 0)
      if index > 0 do
        assert(List.get(chunks, index - 1).window_end == row.window_start)
      end
    end
    assert(List.head(chunks).window_start == start)
    assert(List.get(chunks, 23).window_end == U64.add(start, U64.parse("604800")?)?)
  end
  assert(Result.is_err(token_burn_chunks(U64.parse("23")?, start, weights, entropy)))
  assert(Result.is_err(token_burn_chunks(maximum,
    start,
    List.drop(weights, 1),
    List.drop(entropy, 1))))
  assert(Result.is_err(token_burn_chunks(maximum, start, weights, List.drop(entropy, 1))))
  assert(Result.is_err(token_burn_chunks(maximum,
    start,
    [U64.parse("0")?] ++ List.drop(weights, 1),
    entropy)))
  Ok(true)
end

test("randomized burn chunks conserve positive inputs inside distinct windows across the week") do
  assert(token_chunks_proof() == Ok(true))
end
