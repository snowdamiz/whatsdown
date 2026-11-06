from Mobile.NetworkCounterState import counter_fresh, network_token_value
from Mobile.NetworkCounter import counter_preserves_slash

fn proof() -> Bool!String do
  assert(network_token_value(U64.parse("18446744073709551615")?,
    U64.parse("18446744073709551615")?) == Ok(U128.parse("340282366920938463426481119284349")?))
  assert(network_token_value(U64.parse("1000001")?,
    U64.parse("1234567")?) == Ok(U128.parse("1234568")?))
  assert(counter_fresh(U64.parse("1000")?, U64.parse("1120000")?) == Ok(true))
  assert(counter_fresh(U64.parse("1000")?, U64.parse("1121000")?) == Ok(false))
  assert(counter_fresh(U64.parse("1001")?, U64.parse("1000000")?) == Ok(false))
  assert(counter_preserves_slash(3, 7))
  assert(!counter_preserves_slash(3, 5))
  assert(!counter_preserves_slash(2, 4))
  assert(counter_preserves_slash(0, 0))
  Ok(true)
end

test("counter uses full-width asset valuation, strict clock age and preserves each slash independently") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
