# Amounts remain in their original asset. Asset 1 results are SOL liabilities,
# never evidence that USDC was converted or deposited into the rewards pool.
pub struct TreasuryRevenueSplit do
  asset :: Int
  witness :: U64
  operations :: U64
  fifths_carry :: Int
end

pub fn split_pre_token_credit_revenue(asset :: Int,
  amount :: U64,
  fifths_carry :: Int) -> TreasuryRevenueSplit!String do
  if (asset != 0 && asset != 1) || fifths_carry < 0 || fifths_carry > 4 do
    return Err("invalid_treasury_split")
  end
  let numerator = U128.add(U128.parse(U64.to_string(amount))?,
    U128.parse(Int.to_string(fifths_carry))?)?
  let witness = U64.parse(U128.to_string(U128.divide(numerator, U128.parse("5")?)?))?
  let remainder = U128.subtract(numerator,
    U128.multiply(U128.parse(U64.to_string(witness))?, U128.parse("5")?)?)?
  let carry = case String.to_int(U128.to_string(remainder)) do
    None -> return Err("invalid_treasury_split")
    Some(value) -> value
  end
  Ok(TreasuryRevenueSplit {
    asset: asset,
    witness: witness,
    operations: U64.subtract(amount, witness)?,
    fifths_carry: carry
  })
end
