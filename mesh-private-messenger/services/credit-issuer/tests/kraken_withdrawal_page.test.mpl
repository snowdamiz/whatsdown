from Payment.BtcConversionConfig import parse_btc_conversion_config
from Payment.LightningBackend import LndConfig
from Payment.KrakenConversion import KrakenFee, kraken_withdrawal_page, kraken_withdrawal_cursor

fn settings() -> Map<String, String> do
  Map.new()
    |> Map.put("MESSENGER_BTC_CONVERSION_TREASURY_CONFIG_HASH_HEX", String.repeat("77", 32))
    |> Map.put("MORSE_BTC_CONVERSION_MODE", "test")
    |> Map.put("MESSENGER_BTC_CONVERSION_DEDICATED_ACCOUNT", "yes")
    |> Map.put("MESSENGER_BTC_CONVERSION_ACCOUNT_PROFILE_HEX", String.repeat("11", 32))
    |> Map.put("MESSENGER_KRAKEN_API_KEY", "owned-test-account-public-api-key")
    |> Map.put("MESSENGER_KRAKEN_ORIGIN", "http://127.0.0.1:19004")
    |> Map.put("MESSENGER_KRAKEN_LIGHTNING_PAYEE_HEX", "02" <> String.repeat("22", 32))
    |> Map.put("MESSENGER_KRAKEN_WITHDRAW_METHOD", "11111111-2222-3333-4444-555555555555")
    |> Map.put("MESSENGER_KRAKEN_WITHDRAW_NETWORK", "66666666-7777-8888-9999-aaaaaaaaaaaa")
    |> Map.put("MESSENGER_KRAKEN_WITHDRAW_ADDRESS_ID", "AB7J4FF-BGM7G-V2JMIH")
    |> Map.put("MESSENGER_BTC_CONVERSION_RPC_A", "http://127.0.0.1:19001")
    |> Map.put("MESSENGER_BTC_CONVERSION_RPC_B", "http://127.0.0.1:19002")
    |> Map.put("MESSENGER_BTC_CONVERSION_RPC_C", "http://127.0.0.1:19003")
    |> Map.put("MESSENGER_BTC_CONVERSION_GENESIS",
      Bytes.to_base58(Bytes.from_utf8(String.repeat("g", 32))))
    |> Map.put("MESSENGER_BTC_CONVERSION_ORACLE",
      Bytes.to_base58(Bytes.from_utf8(String.repeat("p", 32))))
    |> Map.put("MESSENGER_BTC_CONVERSION_OWNER",
      Bytes.to_base58(Bytes.from_utf8(String.repeat("o", 32))))
    |> Map.put("MESSENGER_BTC_CONVERSION_MAX_SOURCE_MSAT", "1000000000")
    |> Map.put("MESSENGER_BTC_CONVERSION_MIN_ORDER_SATS", "1000")
    |> Map.put("MESSENGER_BTC_CONVERSION_ROUTING_FEE_MSAT", "1000")
    |> Map.put("MESSENGER_BTC_CONVERSION_TRADE_FEE_BPS", "20")
    |> Map.put("MESSENGER_BTC_CONVERSION_WITHDRAW_FEE_UNITS", "100000")
    |> Map.put("MESSENGER_BTC_CONVERSION_PRICE_TICK_MICROS", "100000")
    |> Map.put("MESSENGER_BTC_CONVERSION_MAX_INVOICE_SECONDS", "3600")
end

fn backend() -> LndConfig do
  LndConfig {
    origin: "http://127.0.0.1:19005",
    macaroon: "aabb",
    purpose: 1,
    network: 2,
    payee: Bytes.from_utf8("\u{0002}" <> String.repeat("s", 32))
  }
end

fn page_cases() -> Bool!String do
  let config = case parse_btc_conversion_config(settings(),
    1,
    Bytes.from_utf8(String.repeat("m", 32)),
    Some(backend()))? do
    Some(value) -> value
    None -> return Err("fixture_disabled")
  end
  let quote = KrakenFee {
    gross: U64.parse("49799202")?,
    net: U64.parse("49699202")?,
    fee: U64.parse("100000")?,
    token: "owned"
  }
  let first = "{\"withdrawals\":[{\"withdrawal_id\":\"UNRELATED\"}],\"next_cursor\":\"page+/=2\"}"
  let page = kraken_withdrawal_page(first, "TARGET", config, quote)?
  assert(page.found == None && page.next_cursor == Some("page+/=2"))
  let second = "{\"withdrawals\":[{\"withdrawal_id\":\"TARGET\",\"method_id\":\"11111111-2222-3333-4444-555555555555\",\"address_id\":\"AB7J4FF-BGM7G-V2JMIH\",\"amount\":{\"asset\":{\"class\":\"currency\",\"name\":\"USDC\"},\"amount\":\"49.699202\"},\"fee\":{\"asset\":{\"class\":\"currency\",\"name\":\"USDC\"},\"amount\":\"0.1\"},\"status\":\"pending\"}]}"
  let matched = kraken_withdrawal_page(second, "TARGET", config, quote)?
  assert(matched.next_cursor == None)
  case matched.found do
    Some(value) -> assert(value.withdrawal_id == "TARGET" && value.amount == quote.net)
    None -> return Err("missing_exact_target")
  end
  assert(kraken_withdrawal_page(second, "OTHER", config, quote)?.found == None)
  for cursor in ["", "space here", "line\nfeed", "\u{0000}", String.repeat("a", 1025)] do
    assert(Result.is_err(kraken_withdrawal_cursor(cursor)))
  end
  for raw in [
    String.replace(first, "\"page+/=2\"", "null"),
    String.replace(first, "\"page+/=2\"", "42"),
    String.replace(first, "\"page+/=2\"", "\"\""),
    "{\"withdrawals\":[{\"withdrawal_id\":\"DUPLICATE\"},{\"withdrawal_id\":\"DUPLICATE\"}]}",
    "{\"withdrawals\":[{\"withdrawal_id\":\"bad id\"}]}"
  ] do
    assert(Result.is_err(kraken_withdrawal_page(raw, "TARGET", config, quote)))
  end
  assert(Result.is_err(kraken_withdrawal_page(String.replace(second, "49.699202", "49.699203"),
    "TARGET",
    config,
    quote)))
  assert(Result.is_err(kraken_withdrawal_page(String.repeat(" ", 65537), "TARGET", config, quote)))
  assert(Result.is_err(kraken_withdrawal_page("{\"withdrawals\":["
      <> String.join((for i in 0..101 do
          "{\"withdrawal_id\":\"X\"}"
        end),
        ",")
      <> "]}",
    "TARGET",
    config,
    quote)))
  Ok(true)
end

test("Kraken withdrawal pages preserve exact IDs and refuse malformed cursor or ambiguous bounded history") do
  case page_cases() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
