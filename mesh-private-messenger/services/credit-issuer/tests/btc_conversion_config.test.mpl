from Payment.BtcConversionConfig import parse_btc_conversion_config, btc_conversion_profile
from Payment.LightningBackend import LndConfig

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

fn cases() -> Bool!String do
  let mint = Bytes.from_utf8(String.repeat("m", 32))
  assert(parse_btc_conversion_config(Map.new(), 1, mint, None) == Ok(None))
  let config = case parse_btc_conversion_config(settings(), 1, mint, Some(backend()))? do
    None -> return Err("fixture_disabled")
    Some(value) -> value
  end
  let hash = btc_conversion_profile(config)?
  assert(Bytes.length(hash) == 32)
  assert(Result.is_err(parse_btc_conversion_config(settings(), 0, mint, Some(backend()))))
  assert(Result.is_err(parse_btc_conversion_config(settings(), 1, mint, None)))
  for name in [
    "MESSENGER_BTC_CONVERSION_DEDICATED_ACCOUNT",
    "MESSENGER_KRAKEN_API_KEY",
    "MESSENGER_KRAKEN_WITHDRAW_METHOD",
    "MESSENGER_BTC_CONVERSION_GENESIS",
    "MESSENGER_BTC_CONVERSION_ORACLE"
  ] do
    assert(Result.is_err(parse_btc_conversion_config(Map.put(settings(), name, ""),
      1,
      mint,
      Some(backend()))))
  end
  for origin in ["https://api.kraken.com/path", "http://example.com", "http://127.0.0.1:19004/"] do
    assert(Result.is_err(parse_btc_conversion_config(Map.put(settings(),
        "MESSENGER_KRAKEN_ORIGIN",
        origin),
      1,
      mint,
      Some(backend()))))
  end
  assert(Result.is_err(parse_btc_conversion_config(Map.put(settings(),
      "MESSENGER_BTC_CONVERSION_RPC_B",
      "http://127.0.0.1:19001"),
    1,
    mint,
    Some(backend()))))
  assert(Result.is_err(parse_btc_conversion_config(Map.put(settings(),
      "MESSENGER_BTC_CONVERSION_TRADE_FEE_BPS",
      "101"),
    1,
    mint,
    Some(backend()))))
  assert(Result.is_err(btc_conversion_profile(%{config | dedicated_account: false})))
  assert(hash != btc_conversion_profile(%{config | api_key: "another-owned-public-api-key"})?)
  Ok(true)
end

test("BTC conversion is default off and requires an explicitly pinned dedicated account, source node and distinct origins") do
  assert(cases() == Ok(true))
end
