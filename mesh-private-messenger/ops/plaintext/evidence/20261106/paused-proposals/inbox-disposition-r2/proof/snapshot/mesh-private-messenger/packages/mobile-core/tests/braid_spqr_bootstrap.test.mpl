from Tests.BraidSpqrBootstrapFixture import (
  b0_mobile_durable_pair,
  b0_mobile_exact_recovery,
  b0_mobile_refusals,
  b0_mobile_report
)

test("real bootstrap atomically persists agreeing HE PQ and Braid owners") do
  assert(b0_mobile_report(b0_mobile_durable_pair()))
end

test("unknown reply and exact duplicate recover without rekey or writes") do
  assert(b0_mobile_report(b0_mobile_exact_recovery()))
end

test("bootstrap configuration selected secret and captured pool b0_mobile_refusals preserve rows") do
  assert(b0_mobile_report(b0_mobile_refusals()))
end
