from Payment.BitcoinOracle import BtcPrice
from Lightning.Invoice import parse_invoice, fixed_invoice_amount, invoice_expires_at
from Runtime.Config import IssuerServerConfig
from Runtime.KeySync import issuer_now
from Payment.BtcConversionConfig import (
  BtcConversionConfig,
  parse_btc_conversion_config,
  btc_conversion_environment_names,
  btc_conversion_profile
)
from Payment.BtcConversion import (
  btc_conversion_plan,
  btc_conversion_next_action,
  btc_decimal_text,
  btc_conversion_residuals,
  btc_conversion_refresh_plan,
  btc_order_plan_json,
  btc_order_plan_from_json
)
from Payment.BtcConversionRead import btc_oracle_quorum, btc_arrival_quorum
from Payment.Treasury import treasury_config_hash
from Payment.KrakenAuth import (
  KrakenField,
  KrakenSignedRequest,
  kraken_form_request,
  kraken_funding_request
)
from Payment.KrakenConversion import (
  KrakenFee,
  KrakenWithdrawal,
  kraken_withdrawal_page,
  kraken_withdrawal_cursor,
  kraken_invoice_fields,
  kraken_invoice,
  kraken_order_fields,
  kraken_order_ack,
  kraken_order,
  kraken_order_trades,
  kraken_trade_ledgers,
  kraken_fill,
  kraken_fee,
  kraken_withdrawal_body,
  kraken_withdrawal_ack,
  kraken_withdrawal_status,
  kraken_withdrawal_method,
  kraken_saved_address
)
from Payment.LightningOutbound import (
  send_outbound_payment,
  track_outbound_payment,
  outbound_payment,
  conversion_invoice
)
from Storage.BtcConversion import (
  BtcConversionIntent,
  load_btc_conversion,
  btc_conversion_source,
  reserve_btc_conversion,
  transition_btc_conversion,
  store_btc_request,
  store_btc_artifact,
  btc_artifact,
  reserve_kraken_nonce,
  release_kraken_nonce,
  store_btc_draft,
  load_btc_draft,
  BtcConversionDraft
)

pub fn configured_btc_conversion(server :: IssuerServerConfig) -> BtcConversionConfig!String do
  let entries = for name in btc_conversion_environment_names() do
    (name,
      Env.get(name,
        if name == "MORSE_BTC_CONVERSION_MODE" do
          "off"
        else
          ""
        end))
  end
  let backend = case server.lightning do
    Some(value) -> Some(value.backend)
    None
  end
  let config = case parse_btc_conversion_config(Map.from_list(entries),
    server.policy.purpose,
    server.policy.mint,
    backend)? do
    None -> return Err("btc_conversion_disabled")
    Some(value) -> value
  end
  let treasury = case server.treasury do
    Some(value) -> value
    None -> return Err("btc_existing_treasury_required")
  end
  if config.treasury_config_hash != treasury_config_hash(treasury.chain)?
    || config.cluster != treasury.chain.cluster
    || config.mint != treasury.chain.mint
    || config.owner != treasury.chain.treasury_owner do
    return Err("btc_existing_treasury_scope_mismatch")
  end
  Ok(config)
end

fn reload(pool :: PoolHandle,
  config :: BtcConversionConfig,
  batch :: U64,
  bucket :: Int) -> BtcConversionIntent!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      case load_btc_conversion(conn, config, batch, bucket)? do
        Some(value) -> Ok(value)
        None -> Err("btc_conversion_not_reserved")
      end
    end)
end

fn artifact(pool :: PoolHandle, id :: Bytes, kind :: String) -> String!String do
  Repo.transaction(pool, fn(conn :: borrow PgConn) do btc_artifact(conn, id, kind) end)
end

fn advance(pool :: PoolHandle,
  value :: BtcConversionIntent,
  stage :: String,
  kind :: String,
  raw :: String,
  hash :: Bytes,
  order_id :: String,
  withdrawal_id :: String) -> Result<(), String> do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      store_btc_artifact(conn, value.intent_id, kind, raw)?
      transition_btc_conversion(conn, value, stage, hash, order_id, withdrawal_id)
    end)
end

fn provider_transport(config :: BtcConversionConfig,
  method :: String,
  request :: KrakenSignedRequest) -> String!String do
  let verb = if method == "GET" do
    :get
  else
    :post
  end
  let builder = Http.build(verb, config.provider_origin <> request.path)
    |> Http.header("API-Key", config.api_key)
    |> Http.header("API-Sign", request.signature)
    |> Http.header("Content-Type", request.content_type)
    |> Http.header("API-Nonce", request.nonce)
    |> Http.timeout(15000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(262144)
  let response = case (if method == "GET" do
    builder
  else
    Http.body(builder, request.body)
  end)
    |> Http.send() do
    Ok(value) -> value
    Err(_) -> return Err("btc_provider_effect_unknown")
  end
  if response.status != 200 && response.status != 201 && response.status != 202 do
    return Err("btc_provider_effect_unknown")
  end
  Bytes.to_utf8(response.body_bytes)
end

fn signed_request(config :: BtcConversionConfig,
  path :: String,
  nonce :: U64,
  fields :: List<KrakenField>,
  body :: String,
  funding :: Bool) -> KrakenSignedRequest!String do
  let key = case Env.get_secret_hex("MESSENGER_KRAKEN_API_SECRET_HEX") do
    Ok(value) -> value
    Err(_) -> return Err("btc_provider_secret_unavailable")
  end
  let request = if funding do
    kraken_funding_request(key, path, nonce, fields, body)
  else
    kraken_form_request(key, path, nonce, fields)
  end
  Secret.destroy(key)
  request
end

fn provider(pool :: PoolHandle,
  config :: BtcConversionConfig,
  value :: BtcConversionIntent,
  kind :: String,
  method :: String,
  path :: String,
  fields :: List<KrakenField>,
  body :: String,
  funding :: Bool,
  next_stage :: String) -> String!String do
  let now_ms = U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))?
  let now = U64.divide(now_ms, U64.parse("1000")?)?
  let lease = case Crypto.random_bytes(32) do
    Ok(bytes) -> bytes
    Err(_) -> return Err("btc_nonce_entropy_unavailable")
  end
  let nonce = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do reserve_kraken_nonce(conn, config.api_key, lease, now_ms) end)?
  let result = provider_reserved(pool,
    config,
    value,
    kind,
    method,
    path,
    fields,
    body,
    funding,
    next_stage,
    nonce,
    now)
  # Release only our lease. A crashed call leaves the persisted expiry; it never
  # resets an unknown effect. Other profiles sharing the key cannot reset nonce.
  let released = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do release_kraken_nonce(conn, config.api_key, lease) end)
  case result do
    Err(error)
    Ok(raw) -> do
      released?
      Ok(raw)
    end
  end
end

fn provider_reserved(pool :: PoolHandle,
  config :: BtcConversionConfig,
  value :: BtcConversionIntent,
  kind :: String,
  method :: String,
  path :: String,
  fields :: List<KrakenField>,
  body :: String,
  funding :: Bool,
  next_stage :: String,
  nonce :: U64,
  now :: U64) -> String!String do
  let request = signed_request(config, path, nonce, fields, body, funding)?
  let request_kind = if next_stage == "" do
    kind <> "-" <> U64.to_string(nonce)
  else
    kind
  end
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      store_btc_request(conn, value.intent_id, request_kind, method, request, now)?
      if next_stage != "" do
        transition_btc_conversion(conn, value, next_stage, Bytes.empty(), "", "")?
      end
      Ok(nil)
    end)?
  provider_transport(config, method, request)
end

fn read_form(pool :: PoolHandle,
  config :: BtcConversionConfig,
  value :: BtcConversionIntent,
  kind :: String,
  path :: String,
  fields :: List<KrakenField>) -> String!String do
  provider(pool, config, value, kind, "POST", path, fields, "", false, "")
end

fn read_funding(pool :: PoolHandle,
  config :: BtcConversionConfig,
  value :: BtcConversionIntent,
  kind :: String,
  path :: String,
  fields :: List<KrakenField>) -> String!String do
  provider(pool, config, value, kind, "GET", path, fields, "", true, "")
end

fn preflight(pool :: PoolHandle,
  config :: BtcConversionConfig,
  value :: BtcConversionIntent) -> Result<(), String> do
  let query = [
    KrakenField { name: "asset[class]", value: "currency" },
    KrakenField { name: "asset[name]", value: "USDC" }
  ]
  let methods = read_funding(pool, config, value, "methods", "/funding/v1/methods/withdraw", query)?
  kraken_withdrawal_method(methods, config, value.plan.minimum_output_usdc)?
  let addresses = read_funding(pool,
    config,
    value,
    "address",
    "/funding/v1/addresses",
    [KrakenField { name: "scope[method_id]", value: config.withdraw_method }])?
  kraken_saved_address(addresses, config)?
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      store_btc_artifact(conn,
        value.intent_id,
        "preflight-method-"
          <> U64.to_string(value.revision)
          <> "-"
          <> Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(methods))),
        methods)?
      store_btc_artifact(conn,
        value.intent_id,
        "preflight-address-"
          <> U64.to_string(value.revision)
          <> "-"
          <> Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(addresses))),
        addresses)
    end)
end

fn invoice_text(pool :: PoolHandle,
  config :: BtcConversionConfig,
  value :: BtcConversionIntent) -> String!String do
  let raw = artifact(pool, value.intent_id, "invoice-response")?
  # Stored invoice is authenticated at creation. Reopening must retain its hash
  # and amount without requiring its creation timestamp to become fresh again.
  let root = Json.parse(raw)?
  let rows = Json.object_get(root, "result")?
  if Json.array_length(rows)? != 1 do
    return Err("btc_stored_invoice_corrupt")
  end
  let text = Json.as_string(Json.object_get(Json.array_get(rows, 0)?, "address")?)?
  let invoice = parse_invoice(text)?
  if invoice.payment_hash != value.invoice_hash
    || invoice.payee != config.provider_payee
    || invoice.network != config.backend.network
    || fixed_invoice_amount(invoice)? != value.plan.invoice_msat do
    return Err("btc_stored_invoice_corrupt")
  end
  Ok(text)
end

fn known_order(pool :: PoolHandle,
  config :: BtcConversionConfig,
  value :: BtcConversionIntent,
  id :: String) -> Result<(), String> do
  let raw = read_form(pool,
    config,
    value,
    "order-status",
    "/0/private/QueryOrders",
    [KrakenField { name: "txid", value: id }, KrakenField { name: "trades", value: "true" }])?
  let selected = selected_order_plan(pool, config, value)?
  let order = kraken_order(raw, id, value.intent_id, selected)?
  let ids = kraken_order_trades(order)?
  let trades = read_form(pool,
    config,
    value,
    "trades",
    "/0/private/QueryTrades",
    [
      KrakenField { name: "txid", value: String.join(ids, ",") },
      KrakenField { name: "ledgers", value: "true" }
    ])?
  let ledgers = kraken_trade_ledgers(trades, ids, id)?
  let ledger_raw = read_form(pool,
    config,
    value,
    "ledgers",
    "/0/private/QueryLedgers",
    [KrakenField { name: "id", value: String.join(ledgers, ",") }])?
  let fill = kraken_fill(order, trades, ledger_raw, id, selected, config.trade_fee_bps)?
  let payment = outbound_payment(artifact(pool, value.intent_id, "payment")?,
    invoice_text(pool, config, value)?,
    value.plan.routing_fee_limit_msat)?
  if payment.status != "SUCCEEDED" do
    return Err("btc_delivered_payment_missing")
  end
  let residuals = btc_conversion_residuals(value.plan,
    payment.fee_msat,
    fill.fee_btc_msat,
    fill.net_usdc,
    fill.provider_usdc_dust_100ths)?
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      store_btc_artifact(conn, value.intent_id, "order-status", raw)?
      store_btc_artifact(conn, value.intent_id, "trades", trades)?
      store_btc_artifact(conn, value.intent_id, "ledgers", ledger_raw)?
      Pg.execute_values(conn,
        "INSERT INTO issuer_btc_conversion_accounting VALUES($1,$2::numeric,$3::numeric,$4::numeric,$5::numeric,$6::numeric,$7::smallint,$8::numeric)",
        [
          Binary(value.intent_id),
          Text(U64.to_string(residuals.actual_routing_fee_msat)),
          Text(U64.to_string(residuals.actual_btc_fee_msat)),
          Text(U64.to_string(fill.fee_usdc_100ths)),
          Text(U64.to_string(residuals.lnd_msat)),
          Text(U64.to_string(residuals.provider_btc_msat)),
          Text(U64.to_string(residuals.provider_usdc_100ths)),
          Text(U64.to_string(residuals.provider_net_usdc))
        ])?
      transition_btc_conversion(conn, value, "converted", Bytes.empty(), id, "")
    end)
end

fn fill_amount(pool :: PoolHandle,
  config :: BtcConversionConfig,
  value :: BtcConversionIntent) -> U64!String do
  let selected = selected_order_plan(pool, config, value)?
  let order = kraken_order(artifact(pool, value.intent_id, "order-status")?,
    value.order_id,
    value.intent_id,
    selected)?
  Ok(kraken_fill(order,
    artifact(pool, value.intent_id, "trades")?,
    artifact(pool, value.intent_id, "ledgers")?,
    value.order_id,
    selected,
    config.trade_fee_bps)?.net_usdc)
end

fn draft(pool :: PoolHandle,
  value :: BtcConversionIntent,
  kind :: String) -> BtcConversionDraft!String do
  Repo.transaction(pool, fn(conn :: borrow PgConn) do load_btc_draft(conn, value, kind) end)
end

fn selected_order_plan(pool :: PoolHandle,
  config :: BtcConversionConfig,
  value :: BtcConversionIntent) do
  let chosen = draft(pool, value, "order")?
  let selected = btc_order_plan_from_json(value.plan, chosen.body)?
  let expected = btc_conversion_refresh_plan(value.plan,
    BtcPrice {
      usd_micros: selected.reference_price_micros,
      observed_at: selected.reference_at,
      slot: U64.parse("1")?
    },
    config.trade_fee_bps,
    config.withdrawal_fee_cap,
    config.price_tick_micros,
    chosen.observed_at)?
  if btc_order_plan_json(expected) != chosen.body do
    return Err("btc_order_draft_policy_mismatch")
  end
  Ok(selected)
end

fn fee_quote(pool :: PoolHandle,
  config :: BtcConversionConfig,
  value :: BtcConversionIntent) -> KrakenFee!String do
  let root = Json.parse(draft(pool, value, "withdrawal")?.body)?
  let selected = selected_order_plan(pool, config, value)?
  kraken_fee(Json.as_string(Json.object_get(root, "response")?)?,
    fill_amount(pool, config, value)?,
    config.withdrawal_fee_cap,
    selected.minimum_output_usdc)
end

pub fn refresh_btc_conversion_draft(pool :: PoolHandle,
  config :: BtcConversionConfig,
  batch :: U64,
  bucket :: Int) -> BtcConversionIntent!String do
  let value = reload(pool, config, batch, bucket)?
  let now = issuer_now()?
  if value.stage == "delivered" || value.stage == "order-ready" do
    let price = btc_oracle_quorum(config, now)?
    let selected = btc_conversion_refresh_plan(value.plan,
      price,
      config.trade_fee_bps,
      config.withdrawal_fee_cap,
      config.price_tick_micros,
      now)?
    Repo.transaction(pool,
      fn(conn :: borrow PgConn) do store_btc_draft(conn,
        value,
        "order",
        btc_order_plan_json(selected),
        now) end)?
  else if value.stage == "converted" || value.stage == "withdrawal-ready" do
    let selected = selected_order_plan(pool, config, value)?
    let gross = fill_amount(pool, config, value)?
    let raw = read_funding(pool,
      config,
      value,
      "fee",
      "/funding/v1/fees/" <> config.withdraw_method,
      [
        KrakenField { name: "amount", value: btc_decimal_text(gross, 6)? },
        KrakenField { name: "fee_included", value: "true" }
      ])?
    kraken_fee(raw, gross, config.withdrawal_fee_cap, selected.minimum_output_usdc)?
    let body = "{\"response\":" <> Json.encode_string(raw) <> "}"
    Repo.transaction(pool,
      fn(conn :: borrow PgConn) do store_btc_draft(conn, value, "withdrawal", body, now) end)?
  else
    return Err("btc_effect_draft_not_refreshable")
  end
  reload(pool, config, batch, bucket)
end

pub fn btc_conversion_step(pool :: PoolHandle,
  config :: BtcConversionConfig,
  batch :: U64,
  bucket :: Int) -> BtcConversionIntent!String do
  let value = reload(pool, config, batch, bucket)?
  let now = issuer_now()?
  case value.stage do
    "reserved" -> do
      preflight(pool, config, value)?
      let raw = provider(pool,
        config,
        value,
        "invoice",
        "POST",
        "/0/private/DepositAddresses",
        kraken_invoice_fields(value.plan)?,
        "",
        false,
        "invoice-unknown")?
      let invoice = kraken_invoice(raw, config, value.plan, issuer_now()?)?
      let current = reload(pool, config, batch, bucket)?
      advance(pool,
        current,
        "invoice-ready",
        "invoice-response",
        raw,
        parse_invoice(invoice)?.payment_hash,
        "",
        "")?
    end
    "invoice-ready" -> do
      let invoice = invoice_text(pool, config, value)?
      let parsed = parse_invoice(invoice)?
      if U64.compare(invoice_expires_at(parsed)?, U64.add(now, U64.parse("30")?)?) < 0 do
        return Err("btc_original_invoice_expired_hold")
      end
      Repo.transaction(pool,
        fn(conn :: borrow PgConn) do transition_btc_conversion(conn,
          value,
          "payment-unknown",
          Bytes.empty(),
          "",
          "") end)?
      let raw = send_outbound_payment(config.backend, invoice, value.plan.routing_fee_limit_msat)?
      let payment = outbound_payment(raw, invoice, value.plan.routing_fee_limit_msat)?
      if payment.status == "SUCCEEDED" do
        advance(pool,
          reload(pool, config, batch, bucket)?,
          "delivered",
          "payment",
          raw,
          Bytes.empty(),
          "",
          "")?
      end
    end
    "payment-unknown" -> do
      let invoice = invoice_text(pool, config, value)?
      let raw = track_outbound_payment(config.backend, value.invoice_hash)?
      let payment = outbound_payment(raw, invoice, value.plan.routing_fee_limit_msat)?
      if payment.status == "SUCCEEDED" do
        advance(pool, value, "delivered", "payment", raw, Bytes.empty(), "", "")?
      end
      if payment.status == "FAILED" do
        advance(pool, value, "held", "payment-failed", raw, Bytes.empty(), "", "")?
      end
    end
    "delivered" -> do
      refresh_btc_conversion_draft(pool, config, batch, bucket)?
      nil
    end
    "order-ready" -> do
      let chosen = draft(pool, value, "order")?
      let selected = selected_order_plan(pool, config, value)?
      let at = chosen.observed_at
      if U64.compare(at, now) > 0 || U64.compare(U64.subtract(now, at)?, U64.parse("60")?) > 0 do
        return Err("btc_order_draft_expired_refresh_required")
      end
      let raw = provider(pool,
        config,
        value,
        "order",
        "POST",
        "/0/private/AddOrder",
        kraken_order_fields(value.intent_id, selected)?,
        "",
        false,
        "order-unknown")?
      let id = kraken_order_ack(raw)?
      advance(pool,
        reload(pool, config, batch, bucket)?,
        "order-known",
        "order-ack",
        raw,
        Bytes.empty(),
        id,
        "")?
    end
    "order-known" -> known_order(pool, config, value, value.order_id)?
    "converted" -> do
      refresh_btc_conversion_draft(pool, config, batch, bucket)?
      nil
    end
    "withdrawal-ready" -> do
      let at = draft(pool, value, "withdrawal")?.observed_at
      if U64.compare(at, now) > 0 || U64.compare(U64.subtract(now, at)?, U64.parse("240")?) > 0 do
        return Err("btc_withdrawal_quote_expired_hold")
      end
      let quote = fee_quote(pool, config, value)?
      let raw = provider(pool,
        config,
        value,
        "withdrawal",
        "POST",
        "/funding/v1/withdrawals",
        [],
        kraken_withdrawal_body(config, quote)?,
        true,
        "withdrawal-unknown")?
      let id = kraken_withdrawal_ack(raw, quote)?
      advance(pool,
        reload(pool, config, batch, bucket)?,
        "withdrawal-known",
        "withdrawal-ack",
        raw,
        Bytes.empty(),
        "",
        id)?
    end
    "withdrawal-known" -> do
      let quote = fee_quote(pool, config, value)?
      let observation = case scan_known_withdrawal(pool, config, value, quote)? do
        Some(found) -> found
        None -> return reload(pool, config, batch, bucket)
      end
      let status = observation.status
      let raw = observation.raw
      if status.status == "success" do
        let selected = selected_order_plan(pool, config, value)?
        let order_draft = draft(pool, value, "order")?
        let arrival = btc_arrival_quorum(config,
          value.intent_id,
          value.profile_hash,
          value.withdrawal_id,
          status.signature,
          status.amount,
          selected.minimum_output_usdc,
          value.reserved_at,
          order_draft.sha256,
          now)?
        Repo.transaction(pool,
          fn(conn :: borrow PgConn) do
            store_btc_artifact(conn, value.intent_id, "withdrawal-status", raw)?
            Pg.execute_values(conn,
              "INSERT INTO issuer_btc_conversion_outputs(intent_id,mint,owner,custody,amount,transaction_signature,receipt) VALUES($1,$2,$3,$4,$5::numeric,$6,$7)",
              [
                Binary(value.intent_id),
                Binary(config.mint),
                Binary(config.owner),
                Binary(config.custody),
                Text(U64.to_string(arrival.amount)),
                Binary(arrival.signature),
                Binary(arrival.receipt)
              ])?
            transition_btc_conversion(conn, value, "arrived", Bytes.empty(), "", "")
          end)?
      end
      if status.status == "failed" do
        advance(pool, value, "held", "withdrawal-failed", raw, Bytes.empty(), "", "")?
      end
    end
    _ -> nil
  end
  reload(pool, config, batch, bucket)
end

pub fn btc_conversion_reserve(pool :: PoolHandle,
  config :: BtcConversionConfig,
  batch :: U64,
  bucket :: Int) -> String!String do
  let existing = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_btc_conversion(conn, config, batch, bucket) end)?
  case existing do
    Some(value) -> return Ok(btc_conversion_json(value))
    None -> nil
  end
  let now = issuer_now()?
  let original = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do btc_conversion_source(conn, config, batch, bucket, now) end)?
  let source = if bucket == 0 do
    original.allocation.witness
  else
    original.allocation.burn
  end
  let price = btc_oracle_quorum(config, now)?
  let result = if U64.compare(source, config.max_source_msat) > 0 do
    Err("btc_source_limit")
  else if U64.compare(source, config.routing_fee_limit_msat) <= 0 do
    Err("btc_below_lot")
  else
    btc_conversion_plan(source,
      config.routing_fee_limit_msat,
      price,
      config.trade_fee_bps,
      config.withdrawal_fee_cap,
      config.price_tick_micros,
      now)
  end
  let reason = case result do
    Err(error) -> if error == "btc_conversion_full_fee_floor_unavailable" do
      "full-fee-floor-unavailable"
    else if error == "btc_source_limit" do
      "source-limit"
    else if List.contains([
        "btc_below_lot",
        "btc_conversion_below_satoshi",
        "btc_conversion_below_unit"
      ],
      error) do
      "below-minimum-order"
    else
      return Err(error)
    end
    Ok(plan) -> if U64.compare(source, config.max_source_msat) > 0 do
      "source-limit"
    else if U64.compare(plan.trade_sats, config.min_order_sats) < 0 do
      "below-minimum-order"
    else
      ""
    end
  end
  if reason != "" do
    Repo.transaction(pool,
      fn(conn :: borrow PgConn) do
        Pg.execute_values(conn,
          "INSERT INTO issuer_btc_conversion_deferrals VALUES($1::bigint,$2::smallint,$3,$4,$5::numeric) ON CONFLICT(batch_id,bucket,profile_hash) DO UPDATE SET reason=EXCLUDED.reason,observed_at=EXCLUDED.observed_at WHERE issuer_btc_conversion_deferrals.observed_at<=EXCLUDED.observed_at",
          [
            Text(U64.to_string(batch)),
            Text(Int.to_string(bucket)),
            Binary(btc_conversion_profile(config)?),
            Text(reason),
            Text(U64.to_string(now))
          ])?
        Ok(nil)
      end)?
    return Ok("{\"state\":\"deferred\",\"reason\":" <> Json.encode_string(reason) <> "}")
  end
  let plan = result?
  let value = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do reserve_btc_conversion(conn,
      config,
      batch,
      bucket,
      plan,
      now) end)?
  Ok(btc_conversion_json(value))
end

pub fn btc_conversion_json(value :: BtcConversionIntent) -> String do
  "{\"intent_id\":"
    <> Json.encode_string(Bytes.to_hex(value.intent_id))
    <> ",\"source_kind\":\"lightning-btc-msat\",\"batch_id\":"
    <> Json.encode_string(U64.to_string(value.batch_id))
    <> ",\"bucket\":"
    <> Int.to_string(value.bucket)
    <> ",\"stage\":"
    <> Json.encode_string(value.stage)
    <> ",\"provider_credit\":\"not-independently-proven\",\"source_msat\":"
    <> Json.encode_string(U64.to_string(value.plan.source_msat))
    <> ",\"action\":"
    <> Json.encode_string(case btc_conversion_next_action(value.stage) do
      Ok(action) -> action
      Err(_) -> "hold"
    end)
    <> "}"
end

pub fn btc_conversion_status(pool :: PoolHandle,
  config :: BtcConversionConfig,
  batch :: U64,
  bucket :: Int) -> String!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let found = load_btc_conversion(conn, config, batch, bucket)?
      case found do
        None -> do
          let rows = Pg.query_values(conn,
            "SELECT reason,observed_at::text FROM issuer_btc_conversion_deferrals WHERE batch_id=$1::bigint AND bucket=$2::smallint AND profile_hash=$3",
            [
              Text(U64.to_string(batch)),
              Text(Int.to_string(bucket)),
              Binary(btc_conversion_profile(config)?)
            ])?
          if List.length(rows) == 0 do
            return Ok("{\"stage\":\"unreserved-pending\",\"source_discharge_proven\":false}")
          end
          let reason = case Map.get(List.head(rows), "reason") do
            Text(value) -> value
            _ -> return Err("invalid_btc_deferral")
          end
          Ok("{\"stage\":\"deferred\",\"source_discharge_proven\":false,\"reason\":"
            <> Json.encode_string(reason)
            <> "}")
        end
        Some(value) -> do
          let base = btc_conversion_json(value)
          let rows = Pg.query_values(conn,
            "SELECT actual_routing_fee_msat::text,actual_btc_fee_msat::text,actual_usdc_fee_100ths::text,lnd_residual_msat::text,provider_btc_residual_msat::text,provider_usdc_residual_100ths::text,provider_net_usdc::text FROM issuer_btc_conversion_accounting WHERE intent_id=$1",
            [Binary(value.intent_id)])?
          let residuals = if List.length(rows) == 0 do
            "{\"availability\":\"pending\"}"
          else
            let row = List.head(rows)
            let entries = for name in [
              "actual_routing_fee_msat",
              "actual_btc_fee_msat",
              "actual_usdc_fee_100ths",
              "lnd_residual_msat",
              "provider_btc_residual_msat",
              "provider_usdc_residual_100ths",
              "provider_net_usdc"
            ] do
              accounting_field(row, name)?
            end
            "{\"availability\":\"actual\"," <> String.join(entries, ",") <> "}"
          end
          Ok(String.slice(base, 0, String.length(base) - 1)
            <> ",\"source_discharge_proven\":false,\"same_bucket_residuals\":"
            <> residuals
            <> "}")
        end
      end
    end)
end

pub fn run_btc_conversion_operator(pool :: PoolHandle,
  server :: IssuerServerConfig,
  args :: List<String>) -> String!String do
  if List.length(args) < 5 || List.length(args) > 6 || List.get(args, 1) != "btc-conversion" do
    return Err("invalid_btc_conversion_command")
  end
  let config = configured_btc_conversion(server)?
  let batch_text = List.get(args, 3)
  let batch = U64.parse(batch_text)?
  if U64.to_string(batch) != batch_text do
    return Err("invalid_btc_conversion_batch")
  end
  let bucket = case List.get(args, 4) do
    "witness" -> 0
    "burn" -> 1
    _ -> return Err("btc_operations_not_authorized")
  end
  let op = List.get(args, 2)
  if List.length(args) == 6 do
    if op != "reconcile-order" do
      return Err("invalid_btc_conversion_command")
    end
    let value = reload(pool, config, batch, bucket)?
    if value.stage != "order-unknown" do
      return Err("btc_order_not_unknown")
    end
    known_order(pool, config, value, List.get(args, 5))?
    return Ok(btc_conversion_json(reload(pool, config, batch, bucket)?))
  end
  case op do
    "reserve" -> btc_conversion_reserve(pool, config, batch, bucket)
    "status" -> btc_conversion_status(pool, config, batch, bucket)
    "refresh" -> Ok(btc_conversion_json(refresh_btc_conversion_draft(pool, config, batch, bucket)?))
    "run-once" -> Ok(btc_conversion_json(btc_conversion_step(pool, config, batch, bucket)?))
    _ -> Err("invalid_btc_conversion_command")
  end
end

struct BtcWithdrawalFound do
  status :: KrakenWithdrawal
  raw :: String
end

struct BtcWithdrawalScan do
  index :: Int
  cursor :: String
  seen :: List<String>
end

fn withdrawal_scan_envelope(cursor :: String,
  next :: String,
  done :: Bool,
  raw :: String) -> String do
  "{\"request_cursor\":"
    <> Json.encode_string(cursor)
    <> ",\"next_cursor\":"
    <> Json.encode_string(next)
    <> ",\"done\":"
    <> (if done do
      "true"
    else
      "false"
    end)
    <> ",\"response\":"
    <> Json.encode_string(raw)
    <> "}"
end

fn scan_kind(index :: Int) -> String!String do
  if index < 0 || index >= 256 do
    return Err("btc_withdrawal_scan_capacity")
  end
  let text = Int.to_string(index)
  Ok("withdrawal-scan-" <> String.repeat("0", 3 - String.length(text)) <> text)
end

fn withdrawal_scan_pages(conn :: borrow PgConn, id :: Bytes) -> List<String>!String do
  let rows = Pg.query_values(conn,
    "SELECT kind,body,body_sha256 FROM issuer_btc_conversion_artifacts WHERE intent_id=$1 AND kind LIKE 'withdrawal-scan-%' ORDER BY kind",
    [Binary(id)])?
  if List.length(rows) > 256 do
    return Err("btc_withdrawal_scan_capacity")
  end
  let pages = for index in 0..List.length(rows) do
    let row = List.get(rows, index)
    let kind = case Map.get(row, "kind") do
      Text(value) -> value
      _ -> return Err("invalid_btc_scan_row")
    end
    let body = case Map.get(row, "body") do
      Text(value) -> value
      _ -> return Err("invalid_btc_scan_row")
    end
    let digest = case Map.get(row, "body_sha256") do
      Binary(value) -> value
      _ -> return Err("invalid_btc_scan_row")
    end
    if kind != scan_kind(index)? || digest != Crypto.sha256(Bytes.from_utf8(body)) do
      return Err("btc_withdrawal_scan_history_corrupt")
    end
    body
  end
  Ok(pages)
end

fn withdrawal_scan_state(pages :: List<String>,
  at :: Int,
  state :: BtcWithdrawalScan) -> BtcWithdrawalScan!String do
  if at == List.length(pages) do
    return Ok(state)
  end
  let text = List.get(pages, at)
  let root = Json.parse(text)?
  let cursor = Json.as_string(Json.object_get(root, "request_cursor")?)?
  let next = Json.as_string(Json.object_get(root, "next_cursor")?)?
  let done = Json.as_bool(Json.object_get(root, "done")?)?
  let response = Json.as_string(Json.object_get(root, "response")?)?
  if withdrawal_scan_envelope(cursor, next, done, response) != text || cursor != state.cursor do
    return Err("btc_withdrawal_scan_history_corrupt")
  end
  let seen = List.append(state.seen, cursor)
  if next != "" do
    kraken_withdrawal_cursor(next)?
    if List.contains(seen, next) do
      return Err("btc_withdrawal_cursor_repeated")
    end
  else if !done do
    return Err("btc_withdrawal_scan_history_corrupt")
  end
  let following = BtcWithdrawalScan {
    index: at + 1,
    cursor: if done do
      ""
    else
      next
    end,
    seen: if done do
      []
    else
      seen
    end
  }
  withdrawal_scan_state(pages, at + 1, following)
end

fn store_withdrawal_page(pool :: PoolHandle,
  value :: BtcConversionIntent,
  state :: BtcWithdrawalScan,
  envelope :: String) -> Result<(), String> do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let rows = Pg.query_values(conn,
        "SELECT stage FROM issuer_btc_conversion_intents WHERE intent_id=$1 FOR UPDATE",
        [Binary(value.intent_id)])?
      if List.length(rows) != 1 do
        return Err("btc_withdrawal_scan_conflict")
      end
      let stage = case Map.get(List.head(rows), "stage") do
        Text(value) -> value
        _ -> return Err("invalid_btc_scan_row")
      end
      if stage != "withdrawal-known"
        || List.length(withdrawal_scan_pages(conn, value.intent_id)?) != state.index do
        return Err("btc_withdrawal_scan_conflict")
      end
      store_btc_artifact(conn, value.intent_id, scan_kind(state.index)?, envelope)
    end)
end

fn refused_withdrawal_page(pool :: PoolHandle, id :: Bytes, raw :: String) -> Result<(), String> do
  let kind = "withdrawal-page-refused-"
    <> Bytes.to_hex(Bytes.slice(Crypto.sha256(Bytes.from_utf8(raw)), 0, 16)?)
  Repo.transaction(pool, fn(conn :: borrow PgConn) do store_btc_artifact(conn, id, kind, raw) end)
end

fn scan_withdrawal_pages(pool :: PoolHandle,
  config :: BtcConversionConfig,
  value :: BtcConversionIntent,
  quote :: KrakenFee,
  state :: BtcWithdrawalScan,
  left :: Int) -> Option<BtcWithdrawalFound>!String do
  if left == 0 do
    return Ok(None)
  end
  scan_kind(state.index)?
  let query = if state.cursor == "" do
    [
      KrakenField { name: "scope[method_id]", value: config.withdraw_method },
      KrakenField { name: "limit", value: "100" }
    ]
  else
    [KrakenField { name: "cursor", value: state.cursor }]
  end
  let raw = read_funding(pool,
    config,
    value,
    "withdrawal-status",
    "/funding/v1/withdrawals",
    query)?
  let page = case kraken_withdrawal_page(raw, value.withdrawal_id, config, quote) do
    Ok(value) -> value
    Err(error) -> do
      refused_withdrawal_page(pool, value.intent_id, raw)?
      return Err(error)
    end
  end
  let next = case page.next_cursor do
    Some(cursor) -> cursor
    None -> ""
  end
  let seen = List.append(state.seen, state.cursor)
  if next != "" && List.contains(seen, next) do
    refused_withdrawal_page(pool, value.intent_id, raw)?
    return Err("btc_withdrawal_cursor_repeated")
  end
  let done = Option.is_some(page.found) || next == ""
  store_withdrawal_page(pool,
    value,
    state,
    withdrawal_scan_envelope(state.cursor, next, done, raw))?
  case page.found do
    Some(status) -> return Ok(Some(BtcWithdrawalFound { status: status, raw: raw }))
    None -> nil
  end
  if done do
    return Ok(None)
  end
  scan_withdrawal_pages(pool,
    config,
    value,
    quote,
    BtcWithdrawalScan { index: state.index + 1, cursor: next, seen: seen },
    left - 1)
end

fn scan_known_withdrawal(pool :: PoolHandle,
  config :: BtcConversionConfig,
  value :: BtcConversionIntent,
  quote :: KrakenFee) -> Option<BtcWithdrawalFound>!String do
  let pages = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do withdrawal_scan_pages(conn, value.intent_id) end)?
  let state = withdrawal_scan_state(pages, 0, BtcWithdrawalScan { index: 0, cursor: "", seen: [] })?
  scan_withdrawal_pages(pool, config, value, quote, state, 4)
end

fn accounting_field(row :: Map<String, DbValue>, name :: String) -> String!String do
  let text = case Map.get(row, name) do
    Text(raw) -> raw
    _ -> return Err("invalid_btc_accounting_row")
  end
  let number = U64.parse(text)?
  Ok(Json.encode_string(name) <> ":" <> Json.encode_string(U64.to_string(number)))
end
