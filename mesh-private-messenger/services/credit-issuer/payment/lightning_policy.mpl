from Credits.Policy import credit_pack

fn maximum() -> U64!String do
  U64.parse("2100000000000000000")
end

fn valid_amount(value :: U64) -> Result<(), String> do
  if value == U64.parse("0")? || U64.compare(value, maximum()?) > 0 do
    Err("invalid_lightning_amount")
  else
    Ok(nil)
  end
end

# One BTC is 100,000,000,000 millisatoshis. Prices are positive USD micros
# from the issuer's authenticated oracle; caller-chosen prices are never read.
pub fn lightning_amount(credits :: Int, btc_usd_micros :: U64) -> U64!String do
  let pack = credit_pack(credits)?
  if btc_usd_micros == U64.parse("0")? do
    return Err("invalid_lightning_price")
  end
  let cost = U128.multiply(U128.parse(U64.to_string(pack.usd_micros))?,
    U128.parse("100000000000")?)?
  let divisor = U128.parse(U64.to_string(btc_usd_micros))?
  let rounded = U128.divide(U128.add(cost, U128.subtract(divisor, U128.parse("1")?)?)?, divisor)?
  let amount = U64.parse(U128.to_string(rounded))?
  valid_amount(amount)?
  Ok(amount)
end

pub fn lightning_amount_accepted(quoted :: U64, paid :: U64) -> Bool!String do
  valid_amount(quoted)?
  if U64.compare(paid, quoted) < 0 || U64.compare(paid, maximum()?) > 0 do
    return Ok(false)
  end
  Ok(U128.compare(U128.multiply(U128.parse(U64.to_string(paid))?, U128.parse("100")?)?,
    U128.multiply(U128.parse(U64.to_string(quoted))?, U128.parse("101")?)?) <= 0)
end

# A hold acknowledgment is not a receipt. Only SETTLED can release signatures.
# Invalid accepted amounts are canceled without revealing a preimage; an
# unexpected already-settled mismatch is retained for operator reconciliation.
pub fn lightning_settlement_decision(state :: String,
  quoted :: U64,
  invoice_amount :: U64,
  paid :: U64) -> String!String do
  valid_amount(quoted)?
  if invoice_amount != quoted do
    return Err("lightning_invoice_amount_mismatch")
  end
  case state do
    "OPEN" -> Ok("wait")
    "CANCELED" -> Ok("canceled")
    "ACCEPTED" -> Ok(if lightning_amount_accepted(quoted, paid)? do
      "settle"
    else
      "cancel"
    end)
    "SETTLED" -> Ok(if lightning_amount_accepted(quoted, paid)? do
      "issue"
    else
      "blocked"
    end)
    _ -> Err("invalid_lightning_invoice_state")
  end
end
