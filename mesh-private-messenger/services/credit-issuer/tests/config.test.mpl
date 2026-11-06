from Runtime.Config import parse_server_config, issuer_admin_url

fn settings() -> Map<String, String> do
  let pin = "witness-a " <> String.repeat("33", 32) <> " Test"
  let security = String.join([
      "3",
      String.repeat("11", 32),
      String.repeat("22", 32),
      "16",
      "1",
      "1",
      pin,
      "-",
      "0",
      "https://credits.example",
      "2",
      "1",
      "1",
      pin
    ],
    "\n")
  Map.new()
    |> Map.put("MORSE_CREDITS_MODE", "test")
    |> Map.put("MESSENGER_CREDITS_PURPOSE", "test")
    |> Map.put("MESSENGER_ISSUER_DATABASE_URL", "postgres://issuer@127.0.0.1/issuer")
    |> Map.put("MESSENGER_ISSUER_SECURITY_CONFIG", security)
    |> Map.put("MESSENGER_CREDIT_STORAGE_DIR", "/private/tmp/issuer-test/key-store")
    |> Map.put("MESSENGER_CREDIT_USDC_MINT", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
    |> Map.put("MESSENGER_CREDIT_SOLANA_RPC_URL", "http://127.0.0.1:18997")
    |> Map.put("MESSENGER_DELIVERY_INTERNAL_URL", "http://127.0.0.1:18086")
    |> Map.put("MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN", String.repeat("a", 32))
    |> Map.put("MESSENGER_CREDIT_PURCHASE_INTERNAL_TOKEN", String.repeat("b", 32))
end

test("issuer configuration separates purchase authority from key publication and pins purpose") do
  let values = settings()
  let configured = parse_server_config(values)
  assert(Result.is_ok(configured))
  assert(Result.is_err(parse_server_config(Map.put(values,
    "MESSENGER_CREDIT_PURCHASE_INTERNAL_TOKEN",
    String.repeat("a", 32)))))
  assert(Result.is_err(parse_server_config(Map.put(values, "MORSE_CREDITS_MODE", "live"))))
  assert(Result.is_err(parse_server_config(Map.put(values, "MESSENGER_ISSUER_PORT", "0"))))
  assert(Result.is_err(parse_server_config(Map.put(values,
    "MESSENGER_DELIVERY_INTERNAL_URL",
    "https://core.example/path"))))
  assert(Result.is_err(parse_server_config(Map.put(values,
    "MESSENGER_CREDIT_STORAGE_DIR",
    "relative"))))
  assert(Result.is_err(parse_server_config(Map.put(values,
    "MESSENGER_CREDIT_SOLANA_RPC_URL",
    "http://rpc.example"))))
  assert(Result.is_ok(parse_server_config(Map.put(values, "MORSE_CREDITS_MODE", "off"))))
  assert(Result.is_err(parse_server_config(Map.put(values,
    "MESSENGER_CREDIT_SOL_PRICE_ACCOUNT",
    "not-a-pubkey"))))
end

test("issuer administrative transport maps only explicit admission operations") do
  let values = settings()
  let configured = parse_server_config(values)
  case configured do
    Err(_) -> assert(false)
    Ok(direct) -> do
      assert(issuer_admin_url(direct,
        "cursor") == Ok("http://127.0.0.1:18086/internal/credits/issuers/cursor"))
      assert(Result.is_err(issuer_admin_url(direct, "../prune")))
    end
  end
  let ingress = parse_server_config(Map.put(values, "MESSENGER_CREDIT_ADMIN_TRANSPORT", "ingress"))
  case ingress do
    Err(_) -> assert(false)
    Ok(value) -> assert(issuer_admin_url(value,
      "admit") == Ok("http://127.0.0.1:18086/v1/ingress/credits/issuers/admit"))
  end
  assert(Result.is_err(parse_server_config(Map.put(values,
    "MESSENGER_CREDIT_ADMIN_TRANSPORT",
    "arbitrary/path"))))
end

fn config_revenue_policy() -> Bool!String do
  let values = settings()
  assert(parse_server_config(values)?.policy.revenue_policy == 1)
  assert(parse_server_config(Map.put(values,
    "MESSENGER_CREDIT_REVENUE_POLICY",
    "2"))?.policy.revenue_policy == 2)
  for invalid in ["", "0", "3", "02", "1.0", " 2"] do
    assert(Result.is_err(parse_server_config(Map.put(values,
      "MESSENGER_CREDIT_REVENUE_POLICY",
      invalid))))
  end
  Ok(true)
end

test("revenue policy activation is explicit and never silently coerces malformed configuration") do
  assert(config_revenue_policy() == Ok(true))
end
