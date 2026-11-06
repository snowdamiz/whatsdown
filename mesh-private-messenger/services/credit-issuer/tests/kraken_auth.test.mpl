from Payment.KrakenAuth import KrakenField, kraken_form_request, kraken_funding_request

fn signing_cases() -> Bool!String do
  let key = case Env.get_secret_hex("MORSE_KRAKEN_TEST_SECRET_HEX") do
    Ok(value) -> value
    Err(_) -> return Err("fixture_key_missing")
  end
  let nonce = U64.parse("1616492376594")?
  let fields = [
    KrakenField { name: "ordertype", value: "limit" },
    KrakenField { name: "pair", value: "XBTUSD" },
    KrakenField { name: "price", value: "37500" },
    KrakenField { name: "type", value: "buy" },
    KrakenField { name: "volume", value: "1.25" }
  ]
  let request = kraken_form_request(key, "/0/private/AddOrder", nonce, fields)?
  assert(request.nonce == "1616492376594")
  assert(request.path == "/0/private/AddOrder")
  assert(request.content_type == "application/x-www-form-urlencoded")
  assert(request.body == "nonce=1616492376594&ordertype=limit&pair=XBTUSD&price=37500&type=buy&volume=1.25")
  assert(request.signature == "4/dpxb3iT4tp/ZCVEwSnEsLxx0bqyhLpdfOpc6fn7OR8+UClSV5n9E6aSS8MPtnRfp32bAb0nmbRn6H8ndwLUQ==")
  let again = kraken_form_request(key, "/0/private/AddOrder", nonce, fields)?
  assert(again.signature == request.signature)
  let changed = kraken_form_request(key,
    "/0/private/AddOrder",
    U64.parse("1616492376595")?,
    fields)?
  assert(changed.signature != request.signature)
  let funding = kraken_funding_request(key,
    "/funding/v1/withdrawals",
    nonce,
    [KrakenField { name: "account_id", value: "owned test/+é" }],
    "{\"amount\":\"5\"}")?
  assert(funding.path == "/funding/v1/withdrawals?account_id=owned+test%2F%2B%C3%A9")
  assert(funding.content_type == "application/json")
  assert(funding.body == "{\"amount\":\"5\"}")
  # Independently computed from the official Funding helper with this fixture.
  assert(funding.signature == "oxA/4Ja4XiyNyUa6RkL4ssQS4jWsL/BtESgtw5PZ8VTB6VQuzgHA8+g4OdIJgooTTUgoVXbuZqrzFBGZyxef+A==")
  let changed_query = kraken_funding_request(key,
    "/funding/v1/withdrawals",
    nonce,
    [KrakenField { name: "account_id", value: "other" }],
    funding.body)?
  assert(changed_query.signature != funding.signature)
  let read = kraken_funding_request(key,
    "/funding/v1/addresses",
    nonce,
    [KrakenField { name: "scope[method_id]", value: "pinned" }],
    "")?
  assert(read.path == "/funding/v1/addresses?scope%5Bmethod_id%5D=pinned")
  assert(read.body == "")
  for path in [
    "https://evil.test/0/private/AddOrder",
    "/0/private/AddOrder?x=1",
    "/0/private/../AddOrder",
    "/0/private/Withdraw",
    "/0/private/AddOrder#x"
  ] do
    assert(Result.is_err(kraken_form_request(key, path, nonce, fields)))
  end
  for bad in [
    [KrakenField { name: "nonce", value: "0" }],
    [KrakenField { name: "pair", value: "XBTUSDC" }, KrakenField { name: "pair", value: "XBTUSD" }],
    [KrakenField { name: "", value: "x" }],
    [KrakenField { name: "pair&nonce", value: "x" }],
    [KrakenField { name: "pair", value: String.repeat("x", 16385) }]
  ] do
    assert(Result.is_err(kraken_form_request(key, "/0/private/AddOrder", nonce, bad)))
  end
  assert(Result.is_err(kraken_form_request(key, "/0/private/AddOrder", U64.parse("0")?, fields)))
  assert(Result.is_err(kraken_funding_request(key,
    "/funding/v1/withdrawals?injected=1",
    nonce,
    [],
    "{}")))
  assert(Result.is_err(kraken_funding_request(key,
    "/funding/v1/withdrawals",
    nonce,
    [],
    "not json")))
  assert(Result.is_err(kraken_funding_request(key, "/funding/v1/withdrawals", nonce, [], "[]")))
  assert(Result.is_err(kraken_funding_request(key,
    "/funding/v1/withdrawals",
    nonce,
    [],
    String.repeat("x", 16385))))
  Secret.destroy(key)
  Ok(true)
end

test("Kraken authentication binds exact nonce path query and bytes without exporting the key") do
  case signing_cases() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
