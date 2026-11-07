from Credits.Policy import (
  credit_pack,
  attachment_credits,
  retention_credits,
  postage_credits,
  signup_credits,
  issuer_epoch,
  issuer_epoch_accepted,
  credit_spend_after,
  credit_spend_ready,
  spent_retention_until
)

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn prices() -> Bool!String do
  for (count, usd) in [(100, 5000000), (500, 25000000), (2000, 100000000)] do
    let pack = credit_pack(count)?
    assert(pack.credits == count && pack.usd_micros == wide(usd)?)
  end
  for count in [0, 1, 99, 101, 2001] do
    assert(Result.is_err(credit_pack(count)))
  end
  let chunk = 16777216
  for (size, cost) in [
    (1, 0),
    (chunk, 0),
    (chunk + 1, 1),
    (2 * chunk, 1),
    (2 * chunk + 1, 2),
    (512 * 1024 * 1024, 31)
  ] do
    assert(attachment_credits(size)? == cost)
  end
  assert(Result.is_err(attachment_credits(0)))
  assert(Result.is_err(attachment_credits(512 * 1024 * 1024 + 1)))
  for (days, cost) in [(1, 0), (31, 0), (32, 10), (61, 10), (62, 20), (180, 50)] do
    assert(retention_credits(days)? == cost)
  end
  assert(Result.is_err(retention_credits(0)))
  assert(Result.is_err(retention_credits(181)))
  for cost in [0, 1, 5, 25] do
    assert(postage_credits(cost)? == cost)
  end
  for cost in [-1, 2, 24, 26] do
    assert(Result.is_err(postage_credits(cost)))
  end
  assert(signup_credits(12, 12)? == 0)
  assert(signup_credits(12, 13)? == 20)
  assert(signup_credits(12, 24)? == 20)
  assert(Result.is_err(signup_credits(12, 11)))
  assert(Result.is_err(signup_credits(0, 12)))
  assert(Result.is_err(signup_credits(12, 25)))
  Ok(true)
end

test("fixed packs and launch extras use exact integer prices and hard limits") do
  case prices() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn clocks() -> Bool!String do
  let month = 30 * 86400
  assert(issuer_epoch(wide(0)?)? == wide(0)?)
  assert(issuer_epoch(wide(month - 1)?)? == wide(0)?)
  assert(issuer_epoch(wide(month)?)? == wide(1)?)
  assert(issuer_epoch(wide(2 * month)?)? == wide(2)?)
  assert(issuer_epoch_accepted(wide(0)?, wide(0)?)?)
  assert(!issuer_epoch_accepted(wide(1)?, wide(0)?)?)
  assert(issuer_epoch_accepted(wide(1)?, wide(2 * month)?)?)
  assert(issuer_epoch_accepted(wide(2)?, wide(2 * month)?)?)
  assert(!issuer_epoch_accepted(wide(0)?, wide(2 * month)?)?)
  assert(!issuer_epoch_accepted(wide(3)?, wide(2 * month)?)?)
  assert(credit_spend_after(wide(1700000000)?)? == wide(1700000600)?)
  assert(!credit_spend_ready(wide(1700000000)?, wide(1699999999)?)?)
  assert(!credit_spend_ready(wide(1700000000)?, wide(1700000599)?)?)
  assert(credit_spend_ready(wide(1700000000)?, wide(1700000600)?)?)
  assert(Result.is_err(credit_spend_after(U64.parse("18446744073709551615")?)))
  # Epoch E tokens remain valid through E+1. Keep spent records another seven
  # days beyond that absolute key expiry, even if redeemed late in E+1.
  assert(spent_retention_until(wide(10)?)? == wide(12 * month + 7 * 86400)?)
  assert(Result.is_err(spent_retention_until(U64.parse("18446744073709551615")?)))
  Ok(true)
end

test("key acceptance, spend delay and spent-set expiry have exact boundaries") do
  case clocks() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
