from Payment.BtcConversionConfig import parse_btc_conversion_config, BtcConversionConfig
from Payment.LightningBackend import LndConfig
from Payment.BtcConversion import btc_conversion_plan
from Payment.BitcoinOracle import BtcPrice
from Storage.BtcConversion import (
  reserve_btc_conversion,
  load_btc_conversion,
  reserve_kraken_nonce,
  release_kraken_nonce,
  transition_btc_conversion,
  store_btc_artifact,
  btc_artifact
)
from Storage.LightningRevenue import freeze_lightning_revenue_week
from Storage.Lightning import lightning_backend_hash
from Payment.RevenuePolicy import credit_revenue_policy_hash

fn key(value :: String) -> Bytes do
  Crypto.sha256(Bytes.from_utf8("btc-storage/" <> value))
end

fn bytes(value :: String, count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, count))
end

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

fn rp_lightning_event(conn :: borrow PgConn,
  domain :: String,
  version :: Int,
  amount :: String,
  backend :: Bytes) -> Result<(), String> do
  let id = key("lightning/" <> domain)
  let key = key("lightning-key/" <> domain)
  Pg.execute_values(conn,
    "INSERT INTO issuer_keys(key_id,epoch,purpose,spki,sealed_private_key) VALUES($1,$2::numeric,1,$3,$4)",
    [
      Binary(key),
      Text(Bytes.read_uint_le(key, 0, 8)?),
      Binary(Bytes.from_hex(String.repeat(Bytes.to_hex(key), 10)
        <> Bytes.to_hex(Bytes.slice(key, 0, 22)?))?),
      Binary(bytes("11", 68)?)
    ])?
  Pg.execute_values(conn,
    "INSERT INTO issuer_lightning_quotes(quote_id,request,key_id,batch_hash,backend_hash,service_key,payment_hash,sealed_preimage,amount_msat,reserved_at,price_observed_at,policy_version,policy_hash) VALUES($1,$2,$3,$1,$4,$1,$1,$5,$6::numeric,1700000000,1700000000,$7::smallint,$8)",
    [
      Binary(id),
      Binary(bytes("01", 72)?),
      Binary(key),
      Binary(backend),
      Binary(bytes("01", 99)?),
      Text(amount),
      Text(Int.to_string(version)),
      Binary(credit_revenue_policy_hash(version)?)
    ])?
  Pg.execute_values(conn,
    "INSERT INTO issuer_lightning_revenue(quote_id,backend_hash,received_msat,settled_at,policy_version,policy_hash) SELECT quote_id,backend_hash,amount_msat,1700000010,policy_version,policy_hash FROM issuer_lightning_quotes WHERE quote_id=$1",
    [Binary(id)])?
  Ok(nil)
end

fn run(pool :: PoolHandle) -> Bool!String do
  let config = case parse_btc_conversion_config(settings(),
    1,
    bytes("44", 32)?,
    Some(backend()))? do
    Some(value) -> value
    None -> return Err("fixture_disabled")
  end
  let now = U64.parse("1700092800")?
  let batch = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      rp_lightning_event(conn,
        "actual-original",
        2,
        "250000000",
        lightning_backend_hash(config.backend)?)?
      Ok(freeze_lightning_revenue_week(conn,
        U64.parse("2810")?,
        lightning_backend_hash(config.backend)?,
        2,
        now)?.batch_id)
    end)?
  let p = btc_conversion_plan(U64.parse("50000000")?,
    config.routing_fee_limit_msat,
    BtcPrice { usd_micros: U64.parse("100000000000")?, observed_at: now, slot: U64.parse("100")? },
    config.trade_fee_bps,
    config.withdrawal_fee_cap,
    config.price_tick_micros,
    now)?
  let results = Job.map([0, 1, 2, 3],
    fn(_) do Repo.transaction(pool,
      fn(conn :: borrow PgConn) do reserve_btc_conversion(conn, config, batch, 0, p, now) end) end)
  let first = List.head(results)??
  for item in results do
    assert(item??.intent_id == first.intent_id)
  end
  let lease = key("lease")
  let first_nonce = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do reserve_kraken_nonce(conn,
      config.api_key,
      lease,
      U64.parse("1700092800000")?) end)?
  let busy = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do reserve_kraken_nonce(conn,
      config.api_key,
      key("competitor"),
      U64.parse("1700092800001")?) end)
  assert(Result.is_err(busy))
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do release_kraken_nonce(conn, config.api_key, lease) end)?
  let next = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do reserve_kraken_nonce(conn,
      config.api_key,
      lease,
      U64.parse("1700092800000")?) end)?
  assert(next == U64.add(first_nonce, U64.parse("1")?)?)
  let changed = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      store_btc_artifact(conn, first.intent_id, "owned-proof", "{\"exact\":1}")?
      transition_btc_conversion(conn, first, "invoice-unknown", Bytes.empty(), "", "")?
      Ok(true)
    end)?
  assert(changed)
  assert(Result.is_err(Repo.transaction(pool,
    fn(conn :: borrow PgConn) do transition_btc_conversion(conn,
      first,
      "invoice-unknown",
      Bytes.empty(),
      "",
      "") end)))
  assert(Result.is_err(Repo.transaction(pool,
    fn(conn :: borrow PgConn) do store_btc_artifact(conn,
      first.intent_id,
      "owned-proof",
      "{\"exact\":2}") end)))
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let recovered = case load_btc_conversion(conn, config, batch, 0)? do
        Some(value) -> value
        None -> return Err("missing_recovery")
      end
      assert(recovered.stage == "invoice-unknown")
      assert(recovered.intent_id == first.intent_id)
      assert(btc_artifact(conn, first.intent_id, "owned-proof")? == "{\"exact\":1}")
      assert(Result.is_err(load_btc_conversion(conn,
        %{config | treasury_config_hash: key("different")},
        batch,
        0)))
      Ok(true)
    end)
end

test("BTC actual journal reserves original membership once, persists unknowns and protects per-key nonce/CAS across calls") do
  let pool = case Pool.open(Env.get("MESSENGER_ISSUER_TEST_DATABASE_URL", ""), 1, 6, 5000) do
    Ok(value) -> value
    Err(error) -> do
      println(error)
      assert(false)
      return
    end
  end
  let result = run(pool)
  Pool.close(pool)
  case result do
    Ok(_) -> nil
    Err(error) -> println(error)
  end
  assert(result == Ok(true))
end
