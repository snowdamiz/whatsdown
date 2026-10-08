##! Prices from Pyth Hermes (GET /v2/updates/price/latest): SOL/USD to price
##! SOL quotes and BTC/USD to price Lightning invoices. A price older than 60
##! seconds, or with a confidence interval wider than 1% of it, is refused.

pub struct OraclePrice do
  price :: Int
  expo :: Int
  publish_time :: Int
end

fn field(value :: Json, name :: String) -> Json!String do
  Json.object_get(value, name)
end

fn feed_entry(entries :: Json, feed_id :: String, index :: Int) -> Json!String do
  if index >= Json.array_length(entries)? do
    Err("oracle answered without feed #{feed_id}")
  else
    let entry = Json.array_get(entries, index)?
    let id = String.to_lower(Json.as_string(field(entry, "id")?)?)
    if id == feed_id || id == "0x" <> feed_id do
      Ok(entry)
    else
      feed_entry(entries, feed_id, index + 1)
    end
  end
end

fn integer(value :: Json) -> Int!String do
  case Json.as_string(value) do
    Ok(text) -> case String.to_int(text) do
      Some(parsed) -> Ok(parsed)
      None -> Err("invalid oracle number")
    end
    Err(_) -> Json.as_int(value)
  end
end

## The latest price of feed `feed_id` (64 hex, no 0x), fresh at `now_s`.

pub fn issuer_price(oracle_url :: String, feed_id :: String, now_s :: Int) -> OraclePrice!String do
  let answer = Http.build(:get,
    oracle_url <> "/v2/updates/price/latest?ids%5B%5D=" <> feed_id <> "&parsed=true")
    |> Http.timeout(10000)
    |> Http.max_response_bytes(262144)
    |> Http.send()
  let response = case answer do
    Err(error) -> Err("oracle unreachable: #{error}")
    Ok(value) -> if value.status == 200 do
      Ok(value)
    else
      Err("oracle answered #{value.status}")
    end
  end?
  let entry = feed_entry(field(Json.parse(response.body)?, "parsed")?, feed_id, 0)?
  let quote = field(entry, "price")?
  let price = OraclePrice {
    price: integer(field(quote, "price")?)?,
    expo: integer(field(quote, "expo")?)?,
    publish_time: integer(field(quote, "publish_time")?)?
  }
  let confidence = integer(field(quote, "conf")?)?
  if price.price <= 0 || confidence * 100 > price.price do
    Err("oracle price unusable")
  else if now_s - price.publish_time > 60 || price.publish_time - now_s > 60 do
    Err("oracle price is not fresh")
  else if price.expo > 0 || price.expo < -18 do
    Err("oracle exponent out of range")
  else
    Ok(price)
  end
end

fn ten_to(power :: Int) -> U128!String do
  if power <= 0 do
    U128.parse("1")
  else
    U128.multiply(ten_to(power - 1)?, U128.parse("10")?)
  end
end

# ceil(micro_usd × 10^(decimals − 6 − expo) / price): base units of an asset
# with `decimals` decimals worth micro_usd at price × 10^expo USD a unit.

fn base_units(micro_usd :: Int, price :: OraclePrice, decimals :: Int) -> Int!String do
  let numerator = U128.multiply(U128.parse(Int.to_string(micro_usd))?,
    ten_to(decimals - 6 - price.expo)?)?
  let divisor = U128.parse(Int.to_string(price.price))?
  let rounded = U128.divide(U128.add(numerator, U128.subtract(divisor, U128.parse("1")?)?)?,
    divisor)?
  case String.to_int(U128.to_string(rounded)) do
    Some(value) -> Ok(value)
    None -> Err("amount out of range")
  end
end

pub fn issuer_lamports_for(micro_usd :: Int, price :: OraclePrice) -> Int!String do
  base_units(micro_usd, price, 9)
end

pub fn issuer_sats_for(micro_usd :: Int, price :: OraclePrice) -> Int!String do
  base_units(micro_usd, price, 8)
end
