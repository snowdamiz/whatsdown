from Payment.RevenuePolicy import credit_revenue_policy_hash

fn cat(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts, Ok(Bytes.empty()), fn(total, value) do Bytes.concat(total?, value) end)
end

fn key(value :: Bytes) -> Bool do
  Bytes.length(value) == 32 && Bytes.to_hex(value) != String.repeat("00", 32)
end

# Conservative integer USDC base-unit minimum from the independently verified
# SOL/USD observation. This does not establish execution or credit any output.
pub fn sol_conversion_floor(lamports :: U64,
  usd_micros :: U64,
  published :: U64,
  now :: U64) -> U64!String do
  if lamports == U64.parse("0")?
    || usd_micros == U64.parse("0")?
    || U64.compare(published, now) > 0
    || U64.compare(U64.subtract(now, published)?, U64.parse("60")?) > 0 do
    return Err("invalid_sol_conversion_price")
  end
  let numerator = U128.multiply(U128.multiply(U128.parse(U64.to_string(lamports))?,
      U128.parse(U64.to_string(usd_micros))?)?,
    U128.parse("9900")?)?
  let denominator = U128.parse("10000000000000")?
  let rounded = U128.divide(U128.add(numerator, U128.subtract(denominator, U128.parse("1")?)?)?,
    denominator)?
  U64.parse(U128.to_string(rounded))
end

# Permanent identity commits to a single original-asset weekly liability. The
# supplied scope binds both the immutable treasury config and conversion profile.
# Bucket0 is witnesses, bucket1 burn. Operations/reserved dust are never selected.
pub fn sol_conversion_identity(scope :: Bytes,
  batch_id :: U64,
  version :: Int,
  policy_hash :: Bytes,
  membership_hash :: Bytes,
  bucket :: Int,
  lamports :: U64) -> Bytes!String do
  if !key(scope)
    || !key(membership_hash)
    || batch_id == U64.parse("0")?
    || lamports == U64.parse("0")?
    || (bucket != 0 && bucket != 1)
    || (bucket == 1 && version != 2)
    || policy_hash != credit_revenue_policy_hash(version)? do
    return Err("invalid_sol_conversion_identity")
  end
  Ok(Crypto.sha256(cat([
    Bytes.from_utf8("morse-credit-sol-conversion-v1"),
    scope,
    Bytes.write_uint_le(U64.to_string(batch_id), 8)?,
    Bytes.write_uint_le(Int.to_string(version), 1)?,
    policy_hash,
    membership_hash,
    Bytes.write_uint_le(Int.to_string(bucket), 1)?,
    Bytes.write_uint_le(U64.to_string(lamports), 8)?
  ])?))
end
