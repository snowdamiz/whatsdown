from Payment.BitcoinOracle import BtcPrice

pub struct BtcConversionPlan do
  source_msat :: U64
  invoice_msat :: U64
  trade_sats :: U64
  provider_btc_reserve_msat :: U64
  routing_fee_limit_msat :: U64
  dust_msat :: U64
  minimum_output_usdc :: U64
  minimum_gross_usdc :: U64
  limit_price_micros :: U64
  reference_price_micros :: U64
  reference_at :: U64
end

fn wide(value :: U64) -> U128!String do
  U128.parse(U64.to_string(value))
end

fn small(value :: U128) -> U64!String do
  U64.parse(U128.to_string(value))
end

fn zero() -> U64!String do
  U64.parse("0")
end

fn digits(value :: String) -> Bool do
  let bytes = Bytes.from_utf8(value)
  if Bytes.length(bytes) == 0 do
    return false
  end
  for index in 0..Bytes.length(bytes) do
    let byte = case Bytes.get(bytes, index) do
      Ok(value) -> value
      Err(_) -> return false
    end
    if byte < 48 || byte > 57 do
      return false
    end
  end
  true
end

fn power10(count :: Int) -> U128!String do
  if count < 0 || count > 20 do
    return Err("btc_decimal_scale")
  end
  U128.parse("1" <> String.repeat("0", count))
end

# Provider decimal text is never parsed through a floating-point number. More
# fractional digits are allowed only when every discarded digit is exactly0.
pub fn btc_decimal_units(value :: String, scale :: Int) -> U64!String do
  if scale < 0 || scale > 11 || String.length(value) > 40 do
    return Err("btc_decimal_scale")
  end
  let parts = String.split(value, ".")
  if List.length(parts) < 1 || List.length(parts) > 2 do
    return Err("btc_invalid_decimal")
  end
  let whole = List.get(parts, 0)
  if !digits(whole) || (String.length(whole) > 1 && String.starts_with(whole, "0")) do
    return Err("btc_invalid_decimal")
  end
  let fraction = if List.length(parts) == 2 do
    List.get(parts, 1)
  else
    ""
  end
  if (List.length(parts) == 2 && !digits(fraction)) || String.length(fraction) > 12 do
    return Err("btc_invalid_decimal")
  end
  let kept = if String.length(fraction) > scale do
    let tail = String.slice(fraction, scale, String.length(fraction))
    if tail != String.repeat("0", String.length(tail)) do
      return Err("btc_lost_decimal_precision")
    end
    String.slice(fraction, 0, scale)
  else
    fraction
  end
  let fractional = if kept == "" do
    U128.parse("0")?
  else
    U128.parse(kept)?
  end
  small(U128.add(U128.multiply(U128.parse(whole)?, power10(scale)?)?,
    U128.multiply(fractional, power10(scale - String.length(kept))?)?)?)
end

fn trim_fraction(value :: String) -> String do
  if String.ends_with(value, "0") do
    trim_fraction(String.slice(value, 0, String.length(value) - 1))
  else if String.ends_with(value, ".") do
    String.slice(value, 0, String.length(value) - 1)
  else
    value
  end
end

pub fn btc_decimal_text(value :: U64, scale :: Int) -> String!String do
  if scale < 0 || scale > 11 do
    return Err("btc_decimal_scale")
  end
  let raw = U64.to_string(value)
  if scale == 0 do
    return Ok(raw)
  end
  let padded = if String.length(raw) <= scale do
    String.repeat("0", scale + 1 - String.length(raw)) <> raw
  else
    raw
  end
  let at = String.length(padded) - scale
  Ok(trim_fraction(String.slice(padded, 0, at)
    <> "."
    <> String.slice(padded, at, String.length(padded))))
end

fn ceiling(numerator :: U128, denominator :: U128) -> U128!String do
  let quotient = U128.divide(numerator, denominator)?
  let remainder = U128.subtract(numerator, U128.multiply(quotient, denominator)?)?
  if remainder == U128.parse("0")? do
    Ok(quotient)
  else
    U128.add(quotient, U128.parse("1")?)
  end
end

# A source reservation includes the maximum Lightning routing fee. Fractional
# sats remain original-msat dust. The minimum output is99% of the independent
# BTC valuation of the entire possible spend, not a Kraken balance or quote.
fn plan_at_floor(source :: U64,
  routing_limit :: U64,
  price :: BtcPrice,
  trade_fee_bps :: Int,
  withdrawal_fee_cap :: U64,
  tick_micros :: U64,
  now :: U64,
  original_floor :: U64) -> BtcConversionPlan!String do
  if source == zero()?
    || U64.compare(routing_limit, source) >= 0
    || price.usd_micros == zero()?
    || price.slot == zero()?
    || U64.compare(price.observed_at, now) > 0
    || U64.compare(U64.subtract(now, price.observed_at)?, U64.parse("60")?) > 0
    || trade_fee_bps < 0
    || trade_fee_bps > 100
    || tick_micros == zero()?
    || U64.compare(tick_micros, U64.parse("1000000")?) > 0 do
    return Err("invalid_btc_conversion_plan")
  end
  let spendable = U64.subtract(source, routing_limit)?
  let sats = U64.divide(spendable, U64.parse("1000")?)?
  if sats == zero()? do
    return Err("btc_conversion_below_satoshi")
  end
  let invoice = U64.multiply(sats, U64.parse("1000")?)?
  let dust = U64.subtract(spendable, invoice)?
  let spent = U64.add(invoice, routing_limit)?
  let independent_minimum = small(ceiling(U128.multiply(U128.multiply(wide(spent)?,
        wide(price.usd_micros)?)?,
      U128.parse("99")?)?,
    U128.parse("10000000000000")?)?)?
  let minimum = if U64.compare(independent_minimum, original_floor) > 0 do
    independent_minimum
  else
    original_floor
  end
  if minimum == zero()? do
    return Err("btc_conversion_below_unit")
  end
  let gross = small(ceiling(U128.multiply(wide(U64.add(minimum, withdrawal_fee_cap)?)?,
      U128.parse("10000")?)?,
    U128.parse(Int.to_string(10000 - trade_fee_bps))?)?)?
  # fciq is a preference. Leave fee headroom in BTC so an actual BTC fee
  # cannot silently spend another conversion or the operations allocation.
  let trade_sats = small(U128.divide(U128.multiply(wide(sats)?, U128.parse("10000")?)?,
    U128.parse(Int.to_string(10000 + trade_fee_bps))?)?)?
  if trade_sats == zero()? do
    return Err("btc_conversion_below_satoshi")
  end
  let trade_msat = U64.multiply(trade_sats, U64.parse("1000")?)?
  let provider_reserve = U64.subtract(invoice, trade_msat)?
  let denominator = U128.multiply(wide(trade_msat)?, wide(tick_micros)?)?
  let price_ticks = ceiling(U128.multiply(wide(gross)?, U128.parse("100000000000")?)?, denominator)?
  let limit = small(U128.multiply(price_ticks, wide(tick_micros)?)?)?
  if U64.compare(limit, price.usd_micros) > 0 do
    return Err("btc_conversion_full_fee_floor_unavailable")
  end
  Ok(BtcConversionPlan {
    source_msat: source,
    invoice_msat: invoice,
    trade_sats: trade_sats,
    provider_btc_reserve_msat: provider_reserve,
    routing_fee_limit_msat: routing_limit,
    dust_msat: dust,
    minimum_output_usdc: minimum,
    minimum_gross_usdc: gross,
    limit_price_micros: limit,
    reference_price_micros: price.usd_micros,
    reference_at: price.observed_at
  })
end

pub fn btc_conversion_id(profile :: Bytes,
  batch :: U64,
  policy :: Bytes,
  members :: Bytes,
  backend :: Bytes,
  bucket :: Int,
  source :: U64) -> Bytes!String do
  if (bucket != 0 && bucket != 1) || batch == zero()? || source == zero()? do
    return Err("btc_conversion_source_scope")
  end
  for value in [profile, policy, members, backend] do
    if Bytes.length(value) != 32 || Bytes.to_hex(value) == String.repeat("00", 32) do
      return Err("btc_conversion_source_scope")
    end
  end
  Ok(Crypto.sha256(Bytes.from_hex(Bytes.to_hex(Bytes.from_utf8("morse-btc-conversion-original-msat-v1"))
    <> Bytes.to_hex(profile)
    <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(batch), 8)?)
    <> Bytes.to_hex(policy)
    <> Bytes.to_hex(members)
    <> Bytes.to_hex(backend)
    <> (if bucket == 0 do
      "00"
    else
      "01"
    end)
    <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(source), 8)?))?))
end

pub fn btc_conversion_next_action(stage :: String) -> String!String do
  case stage do
    "reserved" -> Ok("create-invoice")
    "invoice-unknown" -> Ok("hold-invoice")
    "invoice-ready" -> Ok("pay-same-invoice")
    "payment-unknown" -> Ok("reconcile-same-payment")
    "delivered" -> Ok("prepare-order")
    "order-ready" -> Ok("submit-committed-order")
    "order-unknown" -> Ok("reconcile-order-only")
    "order-known" -> Ok("reconcile-order-only")
    "converted" -> Ok("quote-withdrawal")
    "withdrawal-ready" -> Ok("submit-committed-withdrawal")
    "withdrawal-unknown" -> Ok("hold-withdrawal")
    "withdrawal-known" -> Ok("reconcile-arrival")
    "arrived" -> Ok("reserve-actual-output")
    "output-reserved" -> Ok("handoff-reserved")
    "held" -> Ok("hold")
    _ -> Err("invalid_btc_conversion_stage")
  end
end

pub struct BtcResiduals do
  lnd_msat :: U64
  provider_btc_msat :: U64
  provider_usdc_100ths :: U64
  provider_net_usdc :: U64
  actual_routing_fee_msat :: U64
  actual_btc_fee_msat :: U64
end

pub fn btc_conversion_residuals(plan :: BtcConversionPlan,
  routing_fee :: U64,
  btc_fee :: U64,
  net_usdc :: U64,
  dust_100ths :: U64) -> BtcResiduals!String do
  if U64.compare(routing_fee, plan.routing_fee_limit_msat) > 0
    || U64.compare(btc_fee, plan.provider_btc_reserve_msat) > 0
    || U64.compare(dust_100ths, U64.parse("100")?) >= 0
    || net_usdc == zero()? do
    return Err("btc_actual_fee_conservation_refused")
  end
  let lnd = U64.add(U64.subtract(plan.routing_fee_limit_msat, routing_fee)?, plan.dust_msat)?
  let provider = U64.subtract(plan.provider_btc_reserve_msat, btc_fee)?
  let spent = U64.add(U64.add(U64.multiply(plan.trade_sats, U64.parse("1000")?)?, btc_fee)?,
    routing_fee)?
  if U64.add(U64.add(spent, lnd)?, provider)? != plan.source_msat do
    return Err("btc_original_msat_not_conserved")
  end
  Ok(BtcResiduals {
    lnd_msat: lnd,
    provider_btc_msat: provider,
    provider_usdc_100ths: dust_100ths,
    provider_net_usdc: net_usdc,
    actual_routing_fee_msat: routing_fee,
    actual_btc_fee_msat: btc_fee
  })
end

pub fn btc_conversion_plan(source :: U64,
  routing_limit :: U64,
  price :: BtcPrice,
  fee_bps :: Int,
  withdrawal_cap :: U64,
  tick :: U64,
  now :: U64) -> BtcConversionPlan!String do
  plan_at_floor(source, routing_limit, price, fee_bps, withdrawal_cap, tick, now, U64.parse("0")?)
end

pub fn btc_conversion_refresh_plan(original :: BtcConversionPlan,
  price :: BtcPrice,
  fee_bps :: Int,
  withdrawal_cap :: U64,
  tick :: U64,
  now :: U64) -> BtcConversionPlan!String do
  plan_at_floor(original.source_msat,
    original.routing_fee_limit_msat,
    price,
    fee_bps,
    withdrawal_cap,
    tick,
    now,
    original.minimum_output_usdc)
end

pub fn btc_order_plan_json(value :: BtcConversionPlan) -> String do
  "{\"minimum_output_usdc\":"
    <> Json.encode_string(U64.to_string(value.minimum_output_usdc))
    <> ",\"minimum_gross_usdc\":"
    <> Json.encode_string(U64.to_string(value.minimum_gross_usdc))
    <> ",\"limit_price_micros\":"
    <> Json.encode_string(U64.to_string(value.limit_price_micros))
    <> ",\"reference_price_micros\":"
    <> Json.encode_string(U64.to_string(value.reference_price_micros))
    <> ",\"reference_at\":"
    <> Json.encode_string(U64.to_string(value.reference_at))
    <> "}"
end

pub fn btc_order_plan_from_json(original :: BtcConversionPlan,
  raw :: String) -> BtcConversionPlan!String do
  let root = Json.parse(raw)?
  let nums = for name in [
    "minimum_output_usdc",
    "minimum_gross_usdc",
    "limit_price_micros",
    "reference_price_micros",
    "reference_at"
  ] do
    let text = Json.as_string(Json.object_get(root, name)?)?
    let number = U64.parse(text)?
    if U64.to_string(number) != text do
      return Err("noncanonical_btc_order_draft")
    end
    number
  end
  let plan = %{original |
    minimum_output_usdc: List.get(nums, 0),
    minimum_gross_usdc: List.get(nums, 1),
    limit_price_micros: List.get(nums, 2),
    reference_price_micros: List.get(nums, 3),
    reference_at: List.get(nums, 4)
  }
  if btc_order_plan_json(plan) != raw
    || U64.compare(plan.minimum_output_usdc, original.minimum_output_usdc) < 0 do
    return Err("btc_order_draft_floor_mismatch")
  end
  Ok(plan)
end
