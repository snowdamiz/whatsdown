from Tests.HeCounterFixture import (
  counter_sender_boundary,
  counter_receive_boundary,
  counter_generation_boundary,
  counter_cached_and_reset_controls
)

test("C4 legacy HE last sender counter roundtrips and terminal send refuses") do
  assert(case counter_sender_boundary() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C4 legacy HE independently authenticated maximum n refuses with original owner and valid reset retry") do
  assert(case counter_receive_boundary() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C4 legacy HE terminal generation preserves current traffic and refuses next DH with original owner") do
  assert(case counter_generation_boundary() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C4 legacy HE cached current and retained old headers survive terminal count and PN reset") do
  assert(case counter_cached_and_reset_controls() do
    Ok(true) -> true
    _ -> false
  end)
  println("C4_COUNTER_FOUR_GROUPS_EXECUTED")
end
