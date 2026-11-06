from Runtime.LightningConfig import parse_lightning_config

fn values() -> Map<String, String> do
  Map.new()
    |> Map.put("MORSE_LIGHTNING_MODE", "test")
    |> Map.put("MESSENGER_CREDIT_LIGHTNING_ORIGIN", "http://127.0.0.1:18091")
    |> Map.put("MESSENGER_CREDIT_LIGHTNING_NETWORK", "regtest")
    |> Map.put("MESSENGER_CREDIT_LIGHTNING_NODE_PUBLIC_KEY",
      "03659ee9278803e3667d20d2d081dffc7d6bd6145e4e1bca9fb4a941bfd932dbc2")
    |> Map.put("MESSENGER_CREDIT_LIGHTNING_MACAROON_HEX", String.repeat("aa", 32))
    |> Map.put("MESSENGER_CREDIT_BTC_PRICE_ACCOUNT", "11111111111111111111111111111111")
end

fn proof() -> Bool!String do
  let service_key = Crypto.sha256(Bytes.from_utf8("lightning-config-test"))
  assert(case parse_lightning_config(Map.new(), 1, service_key, true, "http://127.0.0.1:18092")? do
    None -> true
    Some(_) -> false
  end)
  let input = values()
  let policy = case parse_lightning_config(input,
    1,
    service_key,
    true,
    "http://127.0.0.1:18092")? do
    Some(value) -> value
    None -> return Err("missing_configuration")
  end
  assert(policy.backend.network == 2 && policy.backend.purpose == 1 && policy.enabled)
  assert(case parse_lightning_config(input, 1, service_key, false, "http://127.0.0.1:18092")? do
    Some(value) -> !value.enabled
    None -> false
  end)
  for invalid in [
    Map.put(input, "MORSE_LIGHTNING_MODE", "live"),
    Map.put(input, "MORSE_LIGHTNING_MODE", "yes"),
    Map.put(input, "MESSENGER_CREDIT_LIGHTNING_NETWORK", "mainnet"),
    Map.put(input, "MESSENGER_CREDIT_LIGHTNING_NETWORK", "testnet4"),
    Map.put(input, "MESSENGER_CREDIT_LIGHTNING_MACAROON_HEX", ""),
    Map.put(input, "MESSENGER_CREDIT_LIGHTNING_ORIGIN", "http://node.example"),
    Map.put(input, "MESSENGER_CREDIT_LIGHTNING_ORIGIN", "https://node.example/endpoint"),
    Map.put(input, "MESSENGER_CREDIT_LIGHTNING_NODE_PUBLIC_KEY", ""),
    Map.put(input, "MESSENGER_CREDIT_BTC_PRICE_ACCOUNT", "")
  ] do
    assert(Result.is_err(parse_lightning_config(invalid,
      1,
      service_key,
      true,
      "http://127.0.0.1:18092")))
  end
  let live = input
    |> Map.put("MORSE_LIGHTNING_MODE", "live")
    |> Map.put("MESSENGER_CREDIT_LIGHTNING_NETWORK", "mainnet")
    |> Map.put("MESSENGER_CREDIT_LIGHTNING_ORIGIN", "https://node.example")
  assert(Result.is_ok(parse_lightning_config(live, 0, service_key, true, "https://rpc.example")))
  assert(Result.is_err(parse_lightning_config(live, 0, service_key, true, "http://rpc.example")))
  Ok(true)
end

test("Lightning stays off by default and pins mode, backend, credential, network and BTC price source") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
