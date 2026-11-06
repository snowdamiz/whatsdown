from Payment.KrakenConversion import (
  kraken_order_fields,
  kraken_client_order_id,
  kraken_order,
  kraken_fill,
  kraken_fee,
  kraken_order_ack
)
from Payment.BtcConversion import btc_conversion_plan
from Payment.BitcoinOracle import BtcPrice

fn n(value :: String) -> U64!String do
  U64.parse(value)
end

fn plan() do
  btc_conversion_plan(n("50000999")?,
    n("1000")?,
    BtcPrice { usd_micros: n("100000000000")?, observed_at: n("1700000000")?, slot: n("100")? },
    20,
    n("100000")?,
    n("100000")?,
    n("1700000000")?)
end

fn order_raw(intent :: Bytes) -> String!String do
  let p = plan()?
  Ok("{\"error\":[],\"result\":{\"ORDER-1\":{\"cl_ord_id\":"
    <> Json.encode_string(kraken_client_order_id(intent)?)
    <> ",\"time_in_force\":\"fok\",\"descr\":{\"pair\":\"XBTUSDC\",\"type\":\"sell\",\"ordertype\":\"limit\",\"price\":"
    <> Json.encode_string(U64.to_string(p.limit_price_micros))
    <> ",\"leverage\":\"none\",\"close\":\"\"},\"vol\":\"0.00049899\",\"vol_exec\":\"0.00049899\",\"status\":\"closed\",\"cost\":\"49.899\",\"trades\":[\"TRADE-1\"]}}}")
end

fn cases() -> Bool!String do
  let intent = Crypto.sha256(Bytes.from_utf8("owned BTC intent"))
  let p = plan()?
  let fields = kraken_order_fields(intent, p)?
  assert(List.get(fields, 3).value == "FOK")
  assert(List.get(fields, 5).value == "0.00049899")
  assert(String.length(kraken_client_order_id(intent)?) == 32)
  let raw = String.replace(order_raw(intent)?,
    Json.encode_string(U64.to_string(p.limit_price_micros)),
    "\"99800\"")
  let actual = %{p | limit_price_micros: n("99800000000")?}
  let order = kraken_order(raw, "ORDER-1", intent, actual)?
  let trades = "{\"error\":[],\"result\":{\"TRADE-1\":{\"ordertxid\":\"ORDER-1\",\"pair\":\"XBTUSDC\",\"type\":\"sell\",\"ordertype\":\"limit\",\"margin\":\"0\",\"vol\":\"0.00049899\",\"cost\":\"49.899\",\"fee\":\"0.099798\",\"ledgers\":[\"L-BTC\",\"L-USDC\"]}}}"
  let ledgers = "{\"error\":[],\"result\":{\"L-BTC\":{\"refid\":\"TRADE-1\",\"type\":\"trade\",\"aclass\":\"currency\",\"asset\":\"XXBT\",\"amount\":\"-0.00049899\",\"fee\":\"0\",\"balance\":\"999\"},\"L-USDC\":{\"refid\":\"TRADE-1\",\"type\":\"trade\",\"aclass\":\"currency\",\"asset\":\"USDC\",\"amount\":\"49.899\",\"fee\":\"0.099798\",\"balance\":\"999\"}}}"
  let fill = kraken_fill(order, trades, ledgers, "ORDER-1", actual, 20)?
  assert(fill.net_usdc == n("49799202")?)
  assert(fill.fee_btc_msat == n("0")?)
  assert(fill.fee_usdc_100ths == n("9979800")?)
  assert(Result.is_err(kraken_fill(order,
    trades,
    String.replace(ledgers, "TRADE-1", "TRADE-2"),
    "ORDER-1",
    actual,
    20)))
  assert(Result.is_err(kraken_fill(order,
    trades,
    String.replace(ledgers, "-0.00049899", "-0.00049900"),
    "ORDER-1",
    actual,
    20)))
  assert(Result.is_err(kraken_fill(order,
    trades,
    String.replace(ledgers, "0.099798", "0.100000"),
    "ORDER-1",
    actual,
    20)))
  for bad in [
    String.replace(raw, "fok", "gtc"),
    String.replace(raw, "closed", "open"),
    String.replace(raw, "sell", "buy"),
    String.replace(raw, "0.00049899", "0.00049898")
  ] do
    assert(Result.is_err(kraken_order(bad, "ORDER-1", intent, actual)))
  end
  assert(kraken_order_ack("{\"error\":[],\"result\":{\"txid\":[\"ORDER-1\"]}}")? == "ORDER-1")
  assert(Result.is_err(kraken_order_ack("{\"error\":[\"EOrder:Insufficient funds\"],\"result\":{\"txid\":[\"ORDER-1\"]}}")))
  Ok(true)
end

fn fee_cases() -> Bool!String do
  let amount = "{\"asset\":{\"class\":\"currency\",\"name\":\"USDC\"},\"amount\":"
  let raw = "{\"gross_amount\":"
    <> amount
    <> "\"49.799202\"},\"net_amount\":"
    <> amount
    <> "\"49.699202\"},\"fee\":"
    <> amount
    <> "\"0.1\"},\"withdrawal_fee_token\":\"exact-token\"}"
  assert(kraken_fee(raw, n("49799202")?, n("100000")?, n("49500000")?)?.net == n("49699202")?)
  assert(Result.is_err(kraken_fee(String.replace(raw, "USDC", "USDT"),
    n("49799202")?,
    n("100000")?,
    n("49500000")?)))
  assert(Result.is_err(kraken_fee(raw, n("49799203")?, n("100000")?, n("49500000")?)))
  assert(Result.is_err(kraken_fee(raw, n("49799202")?, n("99999")?, n("49500000")?)))
  assert(Result.is_err(kraken_fee(raw, n("49799202")?, n("100000")?, n("49700000")?)))
  Ok(true)
end

test("Kraken FOK fill binds intent and actual fee-asset ledgers without consulting balances") do
  case cases() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

test("Kraken withdrawal fees pin exact USDC gross/net asset and the full final floor") do
  assert(fee_cases() == Ok(true))
end

fn exact_floor_case() -> Bool!String do
  let intent = Crypto.sha256(Bytes.from_utf8("owned exact maximum fee"))
  let p = plan()?
  assert(p.limit_price_micros == n("99600000000")?)
  let raw = String.replace(String.replace(order_raw(intent)?,
      Json.encode_string(U64.to_string(p.limit_price_micros)),
      "\"99600\""),
    "49.899",
    "49.69940400")
  let order = kraken_order(raw, "ORDER-1", intent, p)?
  let trades = "{\"error\":[],\"result\":{\"TRADE-1\":{\"ordertxid\":\"ORDER-1\",\"pair\":\"XBTUSDC\",\"type\":\"sell\",\"ordertype\":\"limit\",\"margin\":\"0\",\"vol\":\"0.00049899\",\"cost\":\"49.69940400\",\"ledgers\":[\"LB\",\"LU\"]}}}"
  let ledgers = "{\"error\":[],\"result\":{\"LB\":{\"refid\":\"TRADE-1\",\"type\":\"trade\",\"aclass\":\"currency\",\"asset\":\"XXBT\",\"amount\":\"-0.00049899\",\"fee\":\"0\"},\"LU\":{\"refid\":\"TRADE-1\",\"type\":\"trade\",\"aclass\":\"currency\",\"asset\":\"USDC\",\"amount\":\"49.69940400\",\"fee\":\"0.09939880\"}}}"
  let fill = kraken_fill(order, trades, ledgers, "ORDER-1", p, 20)?
  assert(fill.net_usdc == n("49600005")?)
  assert(fill.provider_usdc_dust_100ths == n("20")?)
  assert(U64.compare(U64.subtract(fill.net_usdc, n("100000")?)?, p.minimum_output_usdc) >= 0)
  Ok(true)
end

test("Kraken exact limit and maximum quote fee preserve the full floor without charging the fee twice") do
  case exact_floor_case() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
