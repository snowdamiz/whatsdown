from Tests.BraidSpqrContinuationFixture import (
  b1_header_and_output,
  b1_no_ack_then_ack,
  b1_reordered_ack_conflict,
  b1_pending_provenance,
  b1_body_and_mode_refusals,
  b1_schema_and_bounds,
  b1_report
)

test("real bootstrap header scheduler and hybrid Ct1 consume actual output once") do
  assert(b1_report(b1_header_and_output()))
end

test("complete Ek waits for authenticated Ack before actual Ct2 peer agreement") do
  assert(b1_report(b1_no_ack_then_ack()))
end

test("reordered Ek retains authenticated Ack and conflicting duplicates roll back") do
  assert(b1_report(b1_reordered_ack_conflict()))
end

test("pending creation provenance survives receives and recovers exact current attempt") do
  assert(b1_report(b1_pending_provenance()))
end

test("combined body failure provenance mode refusal and actual fatal MAC preserve boundary") do
  assert(b1_report(b1_body_and_mode_refusals()))
end

test("independent CFS1 versions and finite index bounds reject malformed metadata") do
  assert(b1_report(b1_schema_and_bounds()))
end
