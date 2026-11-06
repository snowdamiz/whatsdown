from Payment.SolConversion import sol_conversion_floor, sol_conversion_identity
from Payment.RevenuePolicy import credit_revenue_policy_hash

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

fn cases() -> Bool!String do
  # Exact independent USD minimum, not a claimed conversion or credited output.
  assert(sol_conversion_floor(wide("1000000000")?,
    wide("150000000")?,
    wide("1000")?,
    wide("1000")?) == Ok(wide("148500000")?))
  assert(sol_conversion_floor(wide("1")?,
    wide("150000000")?,
    wide("1000")?,
    wide("1000")?) == Ok(wide("1")?))
  assert(Result.is_err(sol_conversion_floor(wide("0")?,
    wide("150000000")?,
    wide("1000")?,
    wide("1000")?)))
  assert(Result.is_err(sol_conversion_floor(wide("1")?, wide("0")?, wide("1000")?, wide("1000")?)))
  assert(Result.is_err(sol_conversion_floor(wide("1000000000")?,
    wide("150000000")?,
    wide("1001")?,
    wide("1000")?)))
  assert(Result.is_err(sol_conversion_floor(wide("1000000000")?,
    wide("150000000")?,
    wide("939")?,
    wide("1000")?)))
  let config = Crypto.sha256(Bytes.from_utf8("owned-conversion-config"))
  let members = Crypto.sha256(Bytes.from_utf8("immutable-original-members"))
  let first = sol_conversion_identity(config,
    wide("1")?,
    2,
    credit_revenue_policy_hash(2)?,
    members,
    0,
    wide("200000000")?)?
  let again = sol_conversion_identity(config,
    wide("1")?,
    2,
    credit_revenue_policy_hash(2)?,
    members,
    0,
    wide("200000000")?)?
  assert(first == again)
  assert(first != sol_conversion_identity(config,
      wide("1")?,
      2,
      credit_revenue_policy_hash(2)?,
      members,
      1,
      wide("200000000")?)?)
  assert(first != sol_conversion_identity(config,
      wide("2")?,
      2,
      credit_revenue_policy_hash(2)?,
      members,
      0,
      wide("200000000")?)?)
  # There is no operations conversion, and historical policy1 has no burn bucket.
  assert(Result.is_err(sol_conversion_identity(config,
    wide("1")?,
    2,
    credit_revenue_policy_hash(2)?,
    members,
    2,
    wide("200000000")?)))
  assert(Result.is_err(sol_conversion_identity(config,
    wide("1")?,
    1,
    credit_revenue_policy_hash(1)?,
    members,
    1,
    wide("200000000")?)))
  assert(Result.is_err(sol_conversion_identity(config,
    wide("1")?,
    2,
    credit_revenue_policy_hash(1)?,
    members,
    0,
    wide("200000000")?)))
  Ok(true)
end

test("SOL conversion independent minimum and permanent original-bucket identity") do
  assert(cases() == Ok(true))
end
