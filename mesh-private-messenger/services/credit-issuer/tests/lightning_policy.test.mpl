from Payment.LightningPolicy import (
  lightning_amount,
  lightning_amount_accepted,
  lightning_settlement_decision
)

fn number(value :: String) -> U64!String do
  U64.parse(value)
end

fn prices() -> Bool!String do
  assert(lightning_amount(100, number("100000000000")?)? == number("5000000")?)
  assert(lightning_amount(500, number("100000000000")?)? == number("25000000")?)
  assert(lightning_amount(2000, number("100000000000")?)? == number("100000000")?)
  assert(lightning_amount(100, number("30000000000")?)? == number("16666667")?)
  assert(lightning_amount(100, number("18446744073709551615")?)? == number("1")?)
  assert(Result.is_err(lightning_amount(100, number("0")?)))
  assert(Result.is_err(lightning_amount(101, number("100000000000")?)))
  assert(Result.is_err(lightning_amount(2000, number("1")?)))
  assert(lightning_amount_accepted(number("10000")?, number("10000")?)?)
  assert(lightning_amount_accepted(number("10000")?, number("10100")?)?)
  assert(!lightning_amount_accepted(number("10000")?, number("9999")?)?)
  assert(!lightning_amount_accepted(number("10000")?, number("10101")?)?)
  assert(!lightning_amount_accepted(number("99")?, number("100")?)?)
  assert(Result.is_err(lightning_amount_accepted(number("0")?, number("0")?)))
  assert(Result.is_err(lightning_amount_accepted(number("18446744073709551615")?,
    number("18446744073709551615")?)))
  Ok(true)
end

fn transitions() -> Bool!String do
  let amount = number("10000")?
  assert(lightning_settlement_decision("OPEN", amount, amount, number("0")?)? == "wait")
  assert(lightning_settlement_decision("ACCEPTED", amount, amount, amount)? == "settle")
  assert(lightning_settlement_decision("ACCEPTED", amount, amount, number("10100")?)? == "settle")
  assert(lightning_settlement_decision("ACCEPTED", amount, amount, number("10101")?)? == "cancel")
  assert(lightning_settlement_decision("ACCEPTED", amount, amount, number("9999")?)? == "cancel")
  assert(lightning_settlement_decision("SETTLED", amount, amount, amount)? == "issue")
  assert(lightning_settlement_decision("SETTLED", amount, amount, number("10101")?)? == "blocked")
  assert(lightning_settlement_decision("CANCELED", amount, amount, number("0")?)? == "canceled")
  assert(Result.is_err(lightning_settlement_decision("SETTLED", amount, number("9999")?, amount)))
  assert(Result.is_err(lightning_settlement_decision("settled", amount, amount, amount)))
  Ok(true)
end

test("Lightning fixed packs use exact millisatoshis and a strict one-percent bound") do
  assert(prices() == Ok(true))
end

test("only settled valid invoices issue and invalid held amounts are canceled before collection") do
  assert(transitions() == Ok(true))
end
