from Payment.BtcConversion import (
  btc_decimal_units,
  btc_decimal_text,
  btc_conversion_plan,
  btc_conversion_id,
  btc_conversion_next_action,
  btc_conversion_residuals,
  btc_conversion_refresh_plan,
  btc_order_plan_json,
  btc_order_plan_from_json
)
from Payment.BitcoinOracle import BtcPrice

fn n(value :: String) -> U64!String do
  U64.parse(value)
end

fn decimal_cases() -> Bool!String do
  assert(btc_decimal_units("0.00000001", 8)? == n("1")?)
  assert(btc_decimal_units("500.12345600", 6)? == n("500123456")?)
  assert(btc_decimal_units("18446744073709.551615", 6)? == n("18446744073709551615")?)
  assert(btc_decimal_text(n("1001")?, 8)? == "0.00001001")
  assert(btc_decimal_text(n("100000000")?, 8)? == "1")
  assert(btc_decimal_text(n("0")?, 6)? == "0")
  for text in [
    "+1",
    "-1",
    "01",
    "1e2",
    " 1",
    "1.",
    ".1",
    "0.000000001",
    "1.0000000000001",
    "18446744073709551616"
  ] do
    assert(Result.is_err(btc_decimal_units(text, 8)))
  end
  assert(Result.is_err(btc_decimal_units("500.12345601", 6)))
  assert(Result.is_err(btc_decimal_units("1", -1)))
  assert(Result.is_err(btc_decimal_units("1", 12)))
  Ok(true)
end

fn plan_cases() -> Bool!String do
  let now = n("1700000000")?
  let price = BtcPrice { usd_micros: n("100000000000")?, observed_at: now, slot: n("100")? }
  let plan = btc_conversion_plan(n("50000999")?,
    n("1000")?,
    price,
    20,
    n("100000")?,
    n("100000")?,
    now)?
  # Quote-fee preference is not a fee-asset guarantee: reserve BTC fee headroom too.
  assert(Result.is_err(btc_conversion_plan(n("50000999")?,
    n("1000")?,
    price,
    40,
    n("100000")?,
    n("100000")?,
    now)))
  assert(plan.source_msat == n("50000999")?)
  assert(plan.invoice_msat == n("49999000")?)
  assert(plan.trade_sats == n("49899")?)
  assert(plan.provider_btc_reserve_msat == n("100000")?)
  assert(plan.routing_fee_limit_msat == n("1000")?)
  assert(plan.dust_msat == n("999")?)
  assert(plan.minimum_output_usdc == n("49500000")?)
  assert(U64.compare(plan.limit_price_micros, price.usd_micros) <= 0)
  # Worst-case routing, trade and withdrawal fees all fit inside the same1% floor.
  assert(plan.source_msat == U64.add(U64.add(plan.invoice_msat, plan.routing_fee_limit_msat)?,
      plan.dust_msat)?)
  for clock in ["1699999999", "1700000061"] do
    assert(Result.is_err(btc_conversion_plan(n("50000000")?,
      n("1000")?,
      price,
      40,
      n("100000")?,
      n("100000")?,
      n(clock)?)))
  end
  assert(Result.is_err(btc_conversion_plan(n("999")?, n("0")?, price, 0, n("0")?, n("1")?, now)))
  assert(Result.is_err(btc_conversion_plan(n("50000000")?,
    n("50000000")?,
    price,
    0,
    n("0")?,
    n("1")?,
    now)))
  assert(Result.is_err(btc_conversion_plan(n("50000000")?,
    n("0")?,
    price,
    101,
    n("0")?,
    n("1")?,
    now)))
  assert(Result.is_err(btc_conversion_plan(n("50000000")?,
    n("0")?,
    price,
    99,
    n("1000000")?,
    n("1")?,
    now)))
  assert(Result.is_err(btc_conversion_plan(n("18446744073709551615")?,
    n("0")?,
    %{price | usd_micros: n("18446744073709551615")?},
    0,
    n("0")?,
    n("1")?,
    now)))
  Ok(true)
end

fn state_cases() -> Bool!String do
  assert(btc_conversion_next_action("reserved")? == "create-invoice")
  assert(btc_conversion_next_action("invoice-ready")? == "pay-same-invoice")
  assert(btc_conversion_next_action("payment-unknown")? == "reconcile-same-payment")
  assert(btc_conversion_next_action("delivered")? == "prepare-order")
  assert(btc_conversion_next_action("order-unknown")? == "reconcile-order-only")
  assert(btc_conversion_next_action("converted")? == "quote-withdrawal")
  assert(btc_conversion_next_action("withdrawal-unknown")? == "hold-withdrawal")
  assert(btc_conversion_next_action("withdrawal-known")? == "reconcile-arrival")
  assert(btc_conversion_next_action("output-reserved")? == "handoff-reserved")
  assert(Result.is_err(btc_conversion_next_action("other")))
  let key = Crypto.sha256(Bytes.from_utf8("owned-conversion-policy"))
  let first = btc_conversion_id(key, n("1")?, key, key, key, 0, n("50000999")?)?
  assert(first == btc_conversion_id(key, n("1")?, key, key, key, 0, n("50000999")?)?)
  assert(first != btc_conversion_id(key, n("1")?, key, key, key, 1, n("50000999")?)?)
  assert(Result.is_err(btc_conversion_id(key, n("1")?, key, key, key, 2, n("50000999")?)))
  Ok(true)
end

test("BTC conversion parses provider decimals exactly and refuses fractional lost precision") do
  assert(decimal_cases() == Ok(true))
end

test("BTC conversion preserves original msat and dust with a fresh full fee/slippage floor") do
  assert(plan_cases() == Ok(true))
end

test("BTC unknown effects never authorize duplicate invoice/order/withdrawal and operations are not implicit spend") do
  assert(state_cases() == Ok(true))
end

fn residual_cases() -> Bool!String do
  let now = n("1700000000")?
  let p = btc_conversion_plan(n("50000999")?,
    n("1000")?,
    BtcPrice { usd_micros: n("100000000000")?, observed_at: now, slot: n("100")? },
    20,
    n("100000")?,
    n("100000")?,
    now)?
  let quote_fee = btc_conversion_residuals(p, n("300")?, n("0")?, n("49799202")?, n("37")?)?
  assert(quote_fee.lnd_msat == n("1699")?)
  assert(quote_fee.provider_btc_msat == n("100000")?)
  assert(quote_fee.provider_usdc_100ths == n("37")?)
  let btc_fee = btc_conversion_residuals(p, n("700")?, n("99000")?, n("49899000")?, n("0")?)?
  assert(btc_fee.lnd_msat == n("1299")?)
  assert(btc_fee.provider_btc_msat == n("1000")?)
  for pair in [[n("1001")?, n("0")?], [n("0")?, n("100001")?]] do
    assert(Result.is_err(btc_conversion_residuals(p,
      List.get(pair, 0),
      List.get(pair, 1),
      n("1")?,
      n("0")?)))
  end
  assert(Result.is_err(btc_conversion_residuals(p, n("0")?, n("0")?, n("1")?, n("100")?)))
  Ok(true)
end

test("BTC actual routing/trading fees preserve same-bucket LND/provider residuals and exact sub-micro quote dust") do
  assert(residual_cases() == Ok(true))
end

fn draft_cases() -> Bool!String do
  let now = n("1700000000")?
  let price = BtcPrice { usd_micros: n("100000000000")?, observed_at: now, slot: n("100")? }
  let original = btc_conversion_plan(n("50000999")?,
    n("1000")?,
    price,
    20,
    n("100000")?,
    n("100000")?,
    now)?
  let later = U64.add(now, n("61")?)?
  let raised = btc_conversion_refresh_plan(original,
    %{price | usd_micros: n("110000000000")?, observed_at: later},
    20,
    n("100000")?,
    n("100000")?,
    later)?
  assert(raised.minimum_output_usdc == n("54450000")?)
  assert(raised.source_msat == original.source_msat
    && raised.invoice_msat == original.invoice_msat
    && raised.trade_sats == original.trade_sats)
  assert(btc_order_plan_from_json(original, btc_order_plan_json(raised))? == raised)
  assert(Result.is_err(btc_order_plan_from_json(original,
    String.replace(btc_order_plan_json(raised), "54450000", "1"))))
  assert(Result.is_err(btc_conversion_refresh_plan(original,
    %{price | usd_micros: n("95000000000")?, observed_at: later},
    20,
    n("100000")?,
    n("100000")?,
    later)))
  let recovered = btc_conversion_refresh_plan(original,
    %{price | observed_at: later},
    20,
    n("100000")?,
    n("100000")?,
    later)?
  assert(recovered.minimum_output_usdc == original.minimum_output_usdc)
  Ok(true)
end

test("BTC pre-effect refresh preserves original source and original/current independent floors across restart") do
  assert(draft_cases() == Ok(true))
end
