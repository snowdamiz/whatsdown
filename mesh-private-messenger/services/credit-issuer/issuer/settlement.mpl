##! Weekly settlement (plan §6.11): the week's credit revenue and its split,
##! for ops/drills/fund-pool.mjs (which builds, never signs, the fund_pool
##! transaction). Nothing here moves money. Revenue is each issued quote's
##! pack price in micro-USD, whatever asset paid it; a week runs Monday 00:00
##! UTC to the next Monday.
##!
##! MORSE_CREDIT_SETTLEMENT_SPLIT: 20/80 (pool / operations, before the
##! token) or 20/30/50 (pool / buy-and-burn / operations, after it).

fn text(value :: DbValue) -> String do
  case value do
    Text(output) -> output
    _ -> ""
  end
end

fn number(value :: DbValue) -> Int do
  case String.to_int(text(value)) do
    Some(parsed) -> parsed
    None -> 0
  end
end

fn asset_json(rows :: List<Map<String, DbValue>>, asset :: String) -> String do
  let row = List.find(rows, fn value -> text(Map.get(value, "asset")) == asset end)
  let (quotes, micro_usd, received) = case row do
    None -> (0, 0, 0)
    Some(found) -> (number(Map.get(found, "quotes")),
      number(Map.get(found, "micro_usd")),
      number(Map.get(found, "received")))
  end
  Json.encode_string(asset)
    <> ":{\"quotes\":"
    <> Int.to_string(quotes)
    <> ",\"revenue_micro_usd\":\""
    <> Int.to_string(micro_usd)
    <> "\",\"received_base_units\":\""
    <> Int.to_string(received)
    <> "\"}"
end

## The settlement of the week starting `week_start` (YYYY-MM-DD, a Monday),
## as JSON. Amounts are decimal strings of USDC base units (micro-USD).

pub fn issuer_settlement(pool :: PoolHandle,
  split :: String,
  week_start :: String) -> String!String do
  if split != "20/80" && split != "20/30/50" do
    return Err("the split is 20/80 or 20/30/50")
  end
  let checked = Pool.query_values(pool,
    "SELECT (extract(isodow FROM $1::date) = 1)::text AS monday, ($1::date + 7)::text AS week_end",
    [Text(week_start)])?
  let week_end = case checked do
    [row] -> if text(Map.get(row, "monday")) == "true" do
      Ok(text(Map.get(row, "week_end")))
    else
      Err("a settlement week starts on a Monday")
    end
    _ -> Err("invalid week")
  end?
  let rows = Pool.query_values(pool,
    "SELECT quote.asset, count(*)::text AS quotes, sum(quote.price_micro_usd)::text AS micro_usd, sum(payment.received)::text AS received FROM quotes AS quote JOIN payments AS payment ON payment.quote_id = quote.quote_id WHERE quote.state = 'issued' AND quote.issued_at >= ($1::date AT TIME ZONE 'UTC') AND quote.issued_at < (($1::date + 7) AT TIME ZONE 'UTC') GROUP BY quote.asset",
    [Text(week_start)])?
  let revenue = List.reduce(rows, 0, fn total, row -> total + number(Map.get(row, "micro_usd")) end)
  let quotes = List.reduce(rows, 0, fn total, row -> total + number(Map.get(row, "quotes")) end)
  let pool_share = revenue * 20 / 100
  let burn = if split == "20/30/50" do
    revenue * 30 / 100
  else
    0
  end
  let operations = revenue - pool_share - burn
  Ok("{\"week_start\":"
    <> Json.encode_string(week_start)
    <> ",\"week_end\":"
    <> Json.encode_string(week_end)
    <> ",\"split\":"
    <> Json.encode_string(split)
    <> ",\"quotes\":"
    <> Int.to_string(quotes)
    <> ",\"revenue_micro_usd\":\""
    <> Int.to_string(revenue)
    <> "\",\"by_asset\":{"
    <> asset_json(rows, "usdc")
    <> ","
    <> asset_json(rows, "sol")
    <> ","
    <> asset_json(rows, "btc")
    <> "},\"pool_usdc_base_units\":\""
    <> Int.to_string(pool_share)
    <> "\",\"burn_usdc_base_units\":\""
    <> Int.to_string(burn)
    <> "\",\"operations_usdc_base_units\":\""
    <> Int.to_string(operations)
    <> "\"}")
end
