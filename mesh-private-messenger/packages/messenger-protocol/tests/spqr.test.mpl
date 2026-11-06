##! Source-prepared P1 tests. Never run or called compiling until lane preflight.
from Tests.SpqrFixture import (
  literal_initial,
  literal_add,
  literal_steps_and_domains,
  actual_outputs_two_epochs_and_window,
  skip64_selected_key_and_capacity,
  actual_duplicate_gap_and_counter_limit
)

test("C1 SPQR INIT matches independent opaque-key literal tags") do
  assert(case literal_initial() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C1 SPQR ADD uses the old root as secret salt and matches literal tags") do
  assert(case literal_add() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C1 SPQR STEP binds chain counter direction epoch config and transcript") do
  assert(case literal_steps_and_domains() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C1 SPQR consumes actual two-role Braid outputs and prunes the three-slot window") do
  assert(case actual_outputs_two_epochs_and_window() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C1 SPQR accepts64 missing plus selected and rejects65 or aggregate overflow") do
  assert(case skip64_selected_key_and_capacity() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C1 SPQR real duplicate and gapped output owners plus counter overflow preserve state") do
  assert(case actual_duplicate_gap_and_counter_limit() do
    Ok(true) -> true
    _ -> false
  end)
  println("C1_SPQR_CONSUMER_P1_EXECUTED")
end
