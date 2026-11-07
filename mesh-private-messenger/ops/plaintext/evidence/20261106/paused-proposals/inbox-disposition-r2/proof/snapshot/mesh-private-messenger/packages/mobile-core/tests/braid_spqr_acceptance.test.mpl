from Tests.BraidSpqrContinuationFixture import (
  b1_accept_coherent,
  b1_accept_recovery_and_guards,
  b1_accept_transition_literals,
  b1_report
)

test("explicit request acceptance coherently reseals actual pending B0 and admits held hybrid header") do
  assert(b1_report(b1_accept_coherent()))
end

test("acceptance reply recovery is readonly and guarded sources cannot repair stale C1 metadata") do
  assert(b1_report(b1_accept_recovery_and_guards()))
end

test("independent acceptance operation4 transcript binds canonical scope sources and pending candidate") do
  assert(b1_report(b1_accept_transition_literals()))
end
