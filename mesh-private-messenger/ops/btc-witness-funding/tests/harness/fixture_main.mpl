from Payment.Treasury import TreasuryChainConfig, treasury_config_hash
from Runtime.Treasury import treasury_provider_hash
from Runtime.BtcConversion import (
  btc_conversion_reserve,
  btc_conversion_step,
  btc_conversion_json,
  btc_conversion_status,
  refresh_btc_conversion_draft
)
from Payment.BtcConversionConfig import (
  BtcConversionConfig,
  parse_btc_conversion_config,
  btc_conversion_environment_names
)
from Payment.LightningBackend import LndConfig
from Storage.Lightning import lightning_backend_hash
from Storage.LightningRevenue import freeze_lightning_revenue_week
from Storage.BtcConversion import load_btc_conversion, reserve_btc_output_use
from Payment.RevenuePolicy import credit_revenue_policy_hash
from Runtime.KeySync import issuer_now

fn bucket() -> Int do
  if Env.get("BTC_FIXTURE_BUCKET", "witness") == "burn" do
    1
  else
    0
  end
end

fn key(value :: String) -> Bytes do
  Crypto.sha256(Bytes.from_utf8("btc-owned-integration/" <> value))
end

fn txt(value :: DbValue) -> String!String do
  case value do
    Text(raw) -> Ok(raw)
    _ -> Err("fixture_row")
  end
end

fn setting(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn config() -> BtcConversionConfig!String do
  let root = Json.parse(Bytes.to_utf8(File.read_bytes(Env.get("BTC_FIXTURE_CONFIG", ""),
    0,
    16384)?)?)?
  let values = Map.from_list(for name in btc_conversion_environment_names() do
    (name, setting(root, name)?)
  end)
  let backend = LndConfig {
    origin: setting(root, "lnd_origin")?,
    macaroon: Env.get("BTC_FIXTURE_MACAROON", ""),
    purpose: 1,
    network: 2,
    payee: Bytes.from_hex(setting(root, "lnd_payee")?)?
  }
  let config = case parse_btc_conversion_config(values,
    1,
    Bytes.from_base58(setting(root, "mint")?)?,
    Some(backend))? do
    Some(value) -> value
    None -> return Err("fixture_disabled")
  end
  case Json.object_get(root, "treasury_chain") do
    Err(_) -> nil
    Ok(chain) -> do
      let providers = Json.object_get(chain, "providers")?
      let origins = for i in 0..Json.array_length(providers)? do
        Json.as_string(Json.array_get(providers, i)?)?
      end
      let decoded = TreasuryChainConfig {
        cluster: Bytes.from_hex(setting(chain, "cluster")?)?,
        providers_hash: Bytes.from_hex(setting(chain, "providers_hash")?)?,
        mint: Bytes.from_base58(setting(chain, "usdc")?)?,
        treasury_owner: Bytes.from_base58(setting(chain, "owner")?)?,
        fee_payer: Bytes.from_base58(setting(chain, "payer")?)?,
        nonce_authority: Bytes.from_hex(setting(chain, "nonce_authority")?)?,
        nonce_address: Bytes.from_hex(setting(chain, "nonce_address")?)?,
        rewards_program: Bytes.from_hex(setting(chain, "rewards_program")?)?,
        rewards_pool: Bytes.from_hex(setting(chain, "rewards_pool")?)?
      }
      if treasury_provider_hash(origins)? != decoded.providers_hash
        || treasury_config_hash(decoded)? != config.treasury_config_hash
        || decoded.cluster != config.cluster
        || decoded.mint != config.mint
        || decoded.treasury_owner != config.owner do
        return Err("fixture_treasury_chain_mismatch")
      end
    end
  end
  Ok(config)
end

fn seed(conn :: borrow PgConn, config :: BtcConversionConfig, now :: U64) -> U64!String do
  let id = key("original-revenue")
  let issuer = key("issuer-key")
  let hash = lightning_backend_hash(config.backend)?
  let week = U64.subtract(U64.divide(now, U64.parse("604800")?)?, U64.parse("1")?)?
  let settled = U64.subtract(U64.multiply(U64.add(week, U64.parse("1")?)?, U64.parse("604800")?)?,
    U64.parse("30")?)?
  Pg.execute_values(conn,
    "INSERT INTO issuer_keys(key_id,epoch,purpose,spki,sealed_private_key) VALUES($1,1,1,$2,$3)",
    [
      Binary(issuer),
      Binary(Bytes.from_hex(String.repeat("11", 342))?),
      Binary(Bytes.from_hex(String.repeat("22", 68))?)
    ])?
  Pg.execute_values(conn,
    "INSERT INTO issuer_lightning_quotes(quote_id,request,key_id,batch_hash,backend_hash,service_key,payment_hash,sealed_preimage,amount_msat,reserved_at,price_observed_at,policy_version,policy_hash) VALUES($1,$2,$3,$1,$4,$1,$1,$5,250000000,1,1,2,$6)",
    [
      Binary(id),
      Binary(Bytes.from_hex(String.repeat("11", 72))?),
      Binary(issuer),
      Binary(hash),
      Binary(Bytes.from_hex(String.repeat("11", 99))?),
      Binary(credit_revenue_policy_hash(2)?)
    ])?
  Pg.execute_values(conn,
    "INSERT INTO issuer_lightning_revenue(quote_id,backend_hash,received_msat,settled_at,policy_version,policy_hash) VALUES($1,$2,250000000,$3::numeric,2,$4)",
    [
      Binary(id),
      Binary(hash),
      Text(U64.to_string(settled)),
      Binary(credit_revenue_policy_hash(2)?)
    ])?
  Ok(freeze_lightning_revenue_week(conn, week, hash, 2, now)?.batch_id)
end

fn execute(pool :: PoolHandle,
  config :: BtcConversionConfig,
  args :: List<String>) -> String!String do
  let operation = List.get(args, 1)
  if operation == "seed" do
    return Ok(U64.to_string(Repo.transaction(pool,
      fn(conn :: borrow PgConn) do seed(conn, config, issuer_now()?) end)?))
  end
  let batch = U64.parse(List.get(args, 2))?
  if operation == "reserve" do
    return btc_conversion_reserve(pool, config, batch, bucket())
  end
  if operation == "refresh" do
    return Ok(btc_conversion_json(refresh_btc_conversion_draft(pool, config, batch, bucket())?))
  end
  if operation == "read-status" do
    return btc_conversion_status(pool, config, batch, bucket())
  end
  if operation == "step" do
    return Ok(btc_conversion_json(btc_conversion_step(pool, config, batch, bucket())?))
  end
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let value = case load_btc_conversion(conn, config, batch, bucket())? do
        Some(record) -> record
        None -> return Err("fixture_missing")
      end
      if operation == "status" do
        return Ok(btc_conversion_json(value))
      end
      if operation == "reserve-output" || operation == "reserve-other" do
        reserve_btc_output_use(conn, value, key(operation))?
        return Ok("reserved")
      end
      let rows = Pg.query_values(conn,
        "SELECT COUNT(*)::text AS count FROM issuer_btc_conversion_outputs WHERE intent_id=$1",
        [Binary(value.intent_id)])?
      Ok("{\"stage\":"
        <> Json.encode_string(value.stage)
        <> ",\"outputs\":"
        <> txt(Map.get(List.head(rows), "count"))?
        <> "}")
    end)
end

fn run() -> String!String do
  let cfg = config()?
  let pool = Pool.open(Env.get("BTC_FIXTURE_DATABASE", ""), 1, 4, 5000)?
  let output = execute(pool, cfg, Env.args())
  Pool.close(pool)
  output
end

fn main() do
  let result = run()
  case result do
    Ok(raw) -> println(raw)
    Err(error) -> do
      IO.eprintln(error)
      Process.exit(1)
    end
  end
end
