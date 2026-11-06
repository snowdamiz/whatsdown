from Storage.TreasuryFunding import treasury_funding_operation_id
from Payment.RevenuePolicy import credit_revenue_policy_hash

fn proof() -> Bool!String do
  let config = Bytes.from_hex(String.repeat("31", 32))?
  let members = Bytes.from_hex(String.repeat("32", 32))?
  let other = Bytes.from_hex(String.repeat("33", 32))?
  let batch = U64.parse("18446744073709551615")?
  let epoch = U64.parse("9007199254740993")?
  let amount = U64.parse("1000000")?
  let legacy = treasury_funding_operation_id(1,
    credit_revenue_policy_hash(1)?,
    members,
    config,
    batch,
    epoch,
    amount)?
  assert(Bytes.to_hex(legacy) == "0177b42610494e2d676b2f29bc947dd3d9a93435aae792c93204e56278947fe2")
  assert(treasury_funding_operation_id(1,
    credit_revenue_policy_hash(1)?,
    other,
    config,
    batch,
    epoch,
    amount)? == legacy)
  let current = treasury_funding_operation_id(2,
    credit_revenue_policy_hash(2)?,
    members,
    config,
    batch,
    epoch,
    amount)?
  assert(Bytes.to_hex(current) == "cbf64730f90f39a46b853a0b39d14d6a39752b01e8b0cfb1253d359a214eda89")
  assert(current != legacy)
  assert(treasury_funding_operation_id(2,
    credit_revenue_policy_hash(2)?,
    other,
    config,
    batch,
    epoch,
    amount)? != current)
  assert(treasury_funding_operation_id(2,
    credit_revenue_policy_hash(2)?,
    members,
    other,
    batch,
    epoch,
    amount)? != current)
  assert(treasury_funding_operation_id(2,
    credit_revenue_policy_hash(2)?,
    members,
    config,
    U64.parse("1")?,
    epoch,
    amount)? != current)
  assert(treasury_funding_operation_id(2,
    credit_revenue_policy_hash(2)?,
    members,
    config,
    batch,
    U64.add(epoch, U64.parse("1")?)?,
    amount)? != current)
  assert(treasury_funding_operation_id(2,
    credit_revenue_policy_hash(2)?,
    members,
    config,
    batch,
    epoch,
    U64.add(amount, U64.parse("1")?)?)? != current)
  assert(Result.is_err(treasury_funding_operation_id(2,
    credit_revenue_policy_hash(1)?,
    members,
    config,
    batch,
    epoch,
    amount)))
  assert(Result.is_err(treasury_funding_operation_id(3,
    credit_revenue_policy_hash(2)?,
    members,
    config,
    batch,
    epoch,
    amount)))
  IO.eprintln("MORSE_CREDIT_FUNDING_ID legacy_vector_exact_v2_policy_members_amount_and_u64_identity_bound")
  Ok(true)
end

test("post-token witness funding identity binds policy membership and amount without changing historical receipts") do
  let result = proof()
  case result do
    Err(error) -> IO.eprintln(error)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end
