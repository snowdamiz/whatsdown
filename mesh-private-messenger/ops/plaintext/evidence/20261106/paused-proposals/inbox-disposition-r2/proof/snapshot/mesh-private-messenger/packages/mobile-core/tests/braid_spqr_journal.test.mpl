from Tests.BraidSpqrJournalFixture import (
  literal_schema,
  authenticated_header,
  atomic_first_output,
  exact_recovery,
  stale_sources,
  corruption_and_terminal,
  report
)

test("C1 scheduler literal CFS1 descriptor transition and pending split are canonical") do
  assert(report(literal_schema()))
end

test("C1 authenticated Hdr words preserve rank and reseal both unchanged SPQR maps") do
  assert(report(authenticated_header()))
end

test("C1 actual first Ct1 output commits consumer kernel HE cursor and pending together") do
  assert(report(atomic_first_output()))
end

test("C1 same attempt and settled outbox recover exact pending without resealing") do
  assert(report(exact_recovery()))
end

test("C1 changed session and erased custody refuse without durable resurrection") do
  assert(report(stale_sources()))
end

test("C1 corrupt component refuses and authenticated kernel fatal commits terminal generation") do
  assert(report(corruption_and_terminal()))
  println("C1_SPQR_JOURNAL_EXECUTED")
end
