##! Source-only prepared six-group behavior suite; compiling refusing stubs must fail.
from Tests.TripleRatchetFixture import (
  triple_fixture_agreement,
  triple_fixture_current_rollback,
  triple_fixture_cached_rollback,
  triple_fixture_next_lifecycle,
  triple_fixture_scope_bounds,
  triple_fixture_progression
)

test("C1 hybrid HE Combined agreement and independent whole-body oracle") do
  assert(case triple_fixture_agreement() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C1 hybrid HE Current combined-body rejection preserves both original owners and permits retry") do
  assert(case triple_fixture_current_rollback() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C1 hybrid HE Cached and retained old-header receive rollback replay and consume-once") do
  assert(case triple_fixture_cached_rollback() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C1 hybrid HE Next combined-body authentication precedes one sending DH rotation") do
  assert(case triple_fixture_next_lifecycle() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C1 hybrid HE Composite scope AAD direct struct and exact body bounds preserve owners") do
  assert(case triple_fixture_scope_bounds() do
    Ok(true) -> true
    _ -> false
  end)
end

test("C1 hybrid HE Actual two-role epoch outputs preserve stable PQ direction and mixed cache choices") do
  assert(case triple_fixture_progression() do
    Ok(true) -> true
    _ -> false
  end)
  println("C1_HYBRID_HE_SIX_GROUPS_EXECUTED")
end
