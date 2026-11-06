from Runtime.TreasuryCommand import parse_treasury_command

test("treasury operator commands accept only exact typed identifiers and never a refund recipient") do
  for operation in ["provision", "status", "run-once"] do
    assert(Result.is_ok(parse_treasury_command(["issuer", "treasury", operation])))
    assert(Result.is_err(parse_treasury_command(["issuer", "treasury", operation, "extra"])))
  end
  let quote = String.repeat("ab", 32)
  let signature = Bytes.to_base58(Bytes.from_utf8(String.repeat("x", 64)))
  assert(Result.is_ok(parse_treasury_command(["issuer", "treasury", "refund", quote, signature])))
  assert(Result.is_err(parse_treasury_command([
    "issuer",
    "treasury",
    "refund",
    quote,
    signature,
    "destination"
  ])))
  assert(Result.is_err(parse_treasury_command([
    "issuer",
    "treasury",
    "refund",
    String.repeat("AB", 32),
    signature
  ])))
  assert(Result.is_err(parse_treasury_command(["issuer", "treasury", "refund", quote, quote])))
  assert(Result.is_ok(parse_treasury_command(["issuer", "treasury", "weekly", "2900", "usdc"])))
  assert(Result.is_ok(parse_treasury_command(["issuer", "treasury", "weekly", "2900", "sol"])))
  assert(Result.is_err(parse_treasury_command(["issuer", "treasury", "weekly", "02900", "usdc"])))
  assert(Result.is_err(parse_treasury_command([
    "issuer",
    "treasury",
    "weekly",
    "18446744073709551616",
    "usdc"
  ])))
  assert(Result.is_err(parse_treasury_command(["issuer", "treasury", "weekly", "2900", "btc"])))
  assert(Result.is_ok(parse_treasury_command([
    "issuer",
    "treasury",
    "funding-request",
    "9007199254740993"
  ])))
  assert(Result.is_ok(parse_treasury_command(["issuer", "treasury", "funding-reconcile", quote])))
  assert(Result.is_err(parse_treasury_command(["issuer", "treasury", "sign", "arbitrary-packet"])))
end

fn policy_cli() -> Bool!String do
  assert(parse_treasury_command([
    "issuer",
    "treasury",
    "weekly-policy",
    "4000",
    "usdc",
    "2"
  ]) == Ok(TreasuryWeeklyPolicy(U64.parse("4000")?, 0, 2)))
  assert(Result.is_err(parse_treasury_command([
    "issuer",
    "treasury",
    "weekly-policy",
    "4000",
    "usdc",
    "02"
  ])))
  assert(parse_treasury_command([
    "issuer",
    "treasury",
    "burn-request",
    "2814",
    "0"
  ]) == Ok(TreasuryBurnRequest(U64.parse("2814")?, U64.parse("0")?)))
  assert(Result.is_err(parse_treasury_command([
    "issuer",
    "treasury",
    "burn-request",
    "2814",
    "-1"
  ])))
  assert(Result.is_err(parse_treasury_command([
    "issuer",
    "treasury",
    "burn-request",
    "2814",
    "0",
    "arbitrary-source"
  ])))
  Ok(true)
end

test("versioned weekly CLI requires exact explicit policy") do
  assert(policy_cli() == Ok(true))
end

fn expiry_cli() -> Bool!String do
  assert(parse_treasury_command([
    "issuer",
    "treasury",
    "burn-expire-request",
    "9007199254740993"
  ]) == Ok(TreasuryBurnExpireRequest(U64.parse("9007199254740993")?)))
  for epoch in ["01", "-1", "18446744073709551616", "1.5"] do
    assert(Result.is_err(parse_treasury_command([
      "issuer",
      "treasury",
      "burn-expire-request",
      epoch
    ])))
  end
  assert(Result.is_err(parse_treasury_command([
    "issuer",
    "treasury",
    "burn-expire-request",
    "2813",
    "arbitrary-recipient"
  ])))
  Ok(true)
end

test("unfunded expiry CLI accepts only a canonical epoch and never a chosen recipient") do
  assert(expiry_cli() == Ok(true))
end
