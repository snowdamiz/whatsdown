pub struct CreditRevenueSplit do
  policy :: Int
  policy_hash :: Bytes
  witness :: U64
  burn :: U64
  operations :: U64
  carry_witness :: Int
  carry_burn :: Int
  carry_operations :: Int
  reserve_before :: Int
  reserve_after :: Int
end

pub fn credit_revenue_policy_hash(version :: Int) -> Bytes!String do
  let definition = case version do
    1 -> "morse-credit-revenue-split-v1:witness=floor((gross+carry)/5);operations=remainder;carry=mod5"
    2 -> "morse-credit-revenue-split-v2:gross=2/10,3/10,5/10;carry=per-share-numerator;reserve=sum-carry/10"
    _ -> return Err("invalid_credit_revenue_policy")
  end
  Ok(Crypto.sha256(Bytes.from_utf8(definition)))
end

struct RevenueShare do
  amount :: U64
  carry :: Int
end

fn share(amount :: U64,
  numerator :: Int,
  denominator :: Int,
  carry :: Int) -> RevenueShare!String do
  let wide = U128.add(U128.multiply(U128.parse(U64.to_string(amount))?,
      U128.parse(Int.to_string(numerator))?)?,
    U128.parse(Int.to_string(carry))?)?
  let divisor = U128.parse(Int.to_string(denominator))?
  let quotient = U128.divide(wide, divisor)?
  let remainder = U128.subtract(wide, U128.multiply(quotient, divisor)?)?
  let small = case String.to_int(U128.to_string(remainder)) do
    None -> return Err("invalid_credit_revenue_carry")
    Some(value) -> value
  end
  Ok(RevenueShare { amount: U64.parse(U128.to_string(quotient))?, carry: small })
end

pub fn split_credit_revenue(version :: Int,
  amount :: U64,
  carry_witness :: Int,
  carry_burn :: Int,
  carry_operations :: Int) -> CreditRevenueSplit!String do
  let hash = credit_revenue_policy_hash(version)?
  if version == 1 do
    if carry_witness < 0 || carry_witness > 4 || carry_burn != 0 || carry_operations != 0 do
      return Err("invalid_credit_revenue_carry")
    end
    let witness = share(amount, 1, 5, carry_witness)?
    return Ok(CreditRevenueSplit {
      policy: version,
      policy_hash: hash,
      witness: witness.amount,
      burn: U64.parse("0")?,
      operations: U64.subtract(amount, witness.amount)?,
      carry_witness: witness.carry,
      carry_burn: 0,
      carry_operations: 0,
      reserve_before: 0,
      reserve_after: 0
    })
  end
  let total = carry_witness + carry_burn + carry_operations
  if carry_witness < 0
    || carry_witness > 9
    || carry_burn < 0
    || carry_burn > 9
    || carry_operations < 0
    || carry_operations > 9
    || total % 10 != 0 do
    return Err("invalid_credit_revenue_carry")
  end
  let witness = share(amount, 2, 10, carry_witness)?
  let burn = share(amount, 3, 10, carry_burn)?
  let operations = share(amount, 5, 10, carry_operations)?
  let remaining = witness.carry + burn.carry + operations.carry
  Ok(CreditRevenueSplit {
    policy: version,
    policy_hash: hash,
    witness: witness.amount,
    burn: burn.amount,
    operations: operations.amount,
    carry_witness: witness.carry,
    carry_burn: burn.carry,
    carry_operations: operations.carry,
    reserve_before: total / 10,
    reserve_after: remaining / 10
  })
end

# Activation is explicit; malformed environment values cannot silently downgrade.
pub fn parse_credit_revenue_policy(value :: String) -> Int!String do
  case value do
    "1" -> Ok(1)
    "2" -> Ok(2)
    _ -> Err("invalid_credit_revenue_policy")
  end
end
