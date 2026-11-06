from Tests.BraidSpqrBootstrapFixture import (
  b0_protocol_roundtrip,
  b0_protocol_refusals,
  b0_protocol_report
)

test("real C1 handshake produces agreeing opaque bootstrap owners") do
  assert(b0_protocol_report(b0_protocol_roundtrip()))
end

test("C1 profile rejects changed configuration body and legacy crossover") do
  assert(b0_protocol_report(b0_protocol_refusals()))
end
