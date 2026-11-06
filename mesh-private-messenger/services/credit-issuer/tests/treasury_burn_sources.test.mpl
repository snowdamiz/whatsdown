from Payment.TreasuryBurnSources import (
  CreditBurnSource,
  credit_burn_source_id,
  select_credit_burn_sources
)

fn disjoint() -> Bool!String do
  let one = U64.parse("1")?
  assert(credit_burn_source_id(0, one)? == one)
  assert(credit_burn_source_id(1, one)? == U64.parse("9223372036854775809")?)
  assert(credit_burn_source_id(0, one)? != credit_burn_source_id(1, one)?)
  Ok(true)
end

fn boundaries() -> Bool!String do
  let maximum = U64.parse("9223372036854775807")?
  assert(credit_burn_source_id(0, maximum)? == maximum)
  assert(credit_burn_source_id(1, maximum)? == U64.parse("18446744073709551615")?)
  assert(U64.compare(credit_burn_source_id(0, maximum)?,
    credit_burn_source_id(1, U64.parse("1")?)?) < 0)
  Ok(true)
end

fn refusals() -> Bool!String do
  for source in [-1, 2, 99] do
    assert(Result.is_err(credit_burn_source_id(source, U64.parse("1")?)))
  end
  for source in [0, 1] do
    for value in ["0", "9223372036854775808", "18446744073709551615"] do
      assert(Result.is_err(credit_burn_source_id(source, U64.parse(value)?)))
    end
  end
  Ok(true)
end

fn assert_ok(result :: Bool!String) do
  case result do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

test("equal Solana and Lightning batch numbers cannot alias in burn membership") do
  assert_ok(disjoint())
end

test("both positive BIGINT namespaces fit exactly without truncation") do
  assert_ok(boundaries())
end

test("invalid source kinds and nonpositive or non-BIGINT batch IDs are refused") do
  assert_ok(refusals())
end

fn selection() -> Bool!String do
  let recent = for i in 1..65 do
    CreditBurnSource { source: 0, batch_id: U64.parse(Int.to_string(i))?, week: U64.parse("2")? }
  end
  let older = for i in 1..3 do
    CreditBurnSource { source: 1, batch_id: U64.parse(Int.to_string(i))?, week: U64.parse("1")? }
  end
  let selected = select_credit_burn_sources(recent ++ older)?
  assert(List.length(selected) == 64)
  assert(List.get(selected, 0).batch_id == U64.parse("1")?)
  assert(List.get(selected, 61).batch_id == U64.parse("62")?)
  assert(List.get(selected, 62) == List.get(older, 0))
  assert(List.get(selected, 63) == List.get(older, 1))
  assert(select_credit_burn_sources(older ++ recent)? == selected)
  assert(select_credit_burn_sources([])? == [])
  Ok(true)
end

fn selection_refusals() -> Bool!String do
  let first = CreditBurnSource { source: 0, batch_id: U64.parse("1")?, week: U64.parse("0")? }
  assert(Result.is_err(select_credit_burn_sources([first, first])))
  assert(Result.is_err(select_credit_burn_sources([first, %{first | week: U64.parse("2")?}])))
  assert(Result.is_err(select_credit_burn_sources([%{first | source: 2}])))
  assert(Result.is_err(select_credit_burn_sources([%{first | batch_id: U64.parse("0")?}])))
  let excessive = for i in 1..130 do
    %{first | batch_id: U64.parse(Int.to_string(i))?}
  end
  assert(Result.is_err(select_credit_burn_sources(excessive)))
  Ok(true)
end

test("bounded mixed burn selection takes oldest source weeks before canonical membership ordering") do
  assert_ok(selection())
end

test("duplicate source identities and unbounded candidate sets are refused before reservation") do
  assert_ok(selection_refusals())
end
