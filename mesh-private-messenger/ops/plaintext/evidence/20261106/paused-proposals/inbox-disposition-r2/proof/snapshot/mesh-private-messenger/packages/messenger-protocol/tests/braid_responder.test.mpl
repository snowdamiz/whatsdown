##! Draft UNRUN on the composed public candidate; failures must be preserved.
from Tests.BraidResponderFixture import (
  receive_then_send_and_agreement,
  malformed_and_fatal_are_distinct,
  candidate_failure_and_borrowed_retry,
  typed_storage_phases_and_recovery
)

test("C1 complete header receives before explicit send and agrees with actual KEM") do
  assert(case receive_then_send_and_agreement() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C1 ignored malformed or wrong epoch differs from an internal MAC fatal") do
  assert(case malformed_and_fatal_are_distinct() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C1 refused vector preserves borrowed continuation and accepted-header state") do
  assert(case candidate_failure_and_borrowed_retry() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C1 three authenticated storage phases restore exact output and continuation") do
  assert(case typed_storage_phases_and_recovery() do
    Ok(true) -> true
    _ -> false
  end)
  println("C1_BRAID_PROTOCOL_ACCEPTANCE_COMPLETE")
end
