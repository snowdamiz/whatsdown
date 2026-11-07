pub struct CreditPack do
  credits :: Int
  usd_micros :: U64
end

pub fn credit_pack(credits :: Int) -> CreditPack!String do
  let price = case credits do
    100 -> "5000000"
    500 -> "25000000"
    2000 -> "100000000"
    _ -> return Err("unsupported_credit_pack")
  end
  Ok(CreditPack { credits: credits, usd_micros: U64.parse(price)? })
end

pub fn attachment_credits(plaintext_bytes :: Int) -> Int!String do
  if plaintext_bytes < 1 || plaintext_bytes > 536870912 do
    return Err("invalid_credit_attachment_size")
  end
  # The first 16 MiB are free; each started additional 16 MiB costs one.
  Ok((plaintext_bytes - 1) / 16777216)
end

pub fn retention_credits(days :: Int) -> Int!String do
  if days < 1 || days > 180 do
    return Err("invalid_credit_retention")
  end
  if days <= 31 do
    Ok(0)
  else
    Ok(((days - 31 + 29) / 30) * 10)
  end
end

pub fn postage_credits(level :: Int) -> Int!String do
  if level == 0 || level == 1 || level == 5 || level == 25 do
    Ok(level)
  else
    Err("invalid_credit_postage")
  end
end

pub fn signup_credits(base_difficulty :: Int, current_difficulty :: Int) -> Int!String do
  if base_difficulty < 1 || current_difficulty > 24 || current_difficulty < base_difficulty do
    return Err("invalid_credit_signup_difficulty")
  end
  if current_difficulty == base_difficulty do
    Ok(0)
  else
    Ok(20)
  end
end

# Fixed 30-day UTC epochs, not calendar months. All inputs here use Unix seconds.
pub fn issuer_epoch(now :: U64) -> U64!String do
  U64.divide(now, U64.parse("2592000")?)
end

pub fn issuer_epoch_accepted(epoch :: U64, now :: U64) -> Bool!String do
  let current = issuer_epoch(now)?
  if U64.compare(epoch, current) > 0 do
    Ok(false)
  else
    Ok(U64.compare(U64.subtract(current, epoch)?, U64.parse("1")?) <= 0)
  end
end

pub fn credit_spend_after(purchased_at :: U64) -> U64!String do
  U64.add(purchased_at, U64.parse("600")?)
end

pub fn credit_spend_ready(purchased_at :: U64, now :: U64) -> Bool!String do
  Ok(U64.compare(now, credit_spend_after(purchased_at)?) >= 0)
end

pub fn spent_retention_until(epoch :: U64) -> U64!String do
  U64.add(U64.multiply(U64.add(epoch, U64.parse("2")?)?, U64.parse("2592000")?)?,
    U64.parse("604800")?)
end
