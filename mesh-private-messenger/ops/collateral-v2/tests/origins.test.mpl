from Read import validate_collateral_operator_sources

test("the same HTTPS origin cannot count twice through a default-port alias") do
  assert(Result.is_err(validate_collateral_operator_sources([
    "https://one.example",
    "https://one.example:443",
    "https://three.example"
  ])))
end

test("configured sources require three canonical origins without paths credentials or hidden aliases") do
  assert(Result.is_ok(validate_collateral_operator_sources([
    "https://one.example",
    "https://two.example:8443",
    "https://three.example"
  ])))
  for sources in [
    ["https://one.example", "https://ONE.example", "https://three.example"],
    ["https://one.example", "https://two.example/path", "https://three.example"],
    ["https://one.example", "https://user@two.example", "https://three.example"],
    ["http://untrusted.example", "https://two.example", "https://three.example"],
    ["https://one.example", "https://two.example/?query", "https://three.example"]
  ] do
    assert(Result.is_err(validate_collateral_operator_sources(sources)))
  end
end
