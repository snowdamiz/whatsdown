from Payment.KrakenAuth import KrakenField
from Payment.BtcConversion import BtcConversionPlan, btc_decimal_units, btc_decimal_text
from Payment.BtcConversionConfig import BtcConversionConfig, btc_provider_identifier
from Payment.LightningOutbound import conversion_invoice

pub struct KrakenFill do
  order_id :: String
  gross_usdc :: U64
  net_usdc :: U64
  provider_usdc_dust_100ths :: U64
  fee_usdc_100ths :: U64
  fee_btc_msat :: U64
  trades :: List<String>
end

pub struct KrakenFee do
  gross :: U64
  net :: U64
  fee :: U64
  token :: String
end

pub struct KrakenWithdrawal do
  withdrawal_id :: String
  amount :: U64
  fee :: U64
  status :: String
  signature :: Bytes
end

fn s(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn zero() -> U64!String do
  U64.parse("0")
end

fn bounded(raw :: String) -> Json!String do
  if String.length(raw) > 262144 do
    return Err("kraken_response_too_large")
  end
  Json.parse(raw)
end

pub fn kraken_result(raw :: String) -> Json!String do
  let root = bounded(raw)?
  if Json.array_length(Json.object_get(root, "error")?)? != 0 do
    return Err("kraken_request_rejected_or_unknown")
  end
  Json.object_get(root, "result")
end

pub fn kraken_client_order_id(intent :: Bytes) -> String!String do
  if Bytes.length(intent) != 32 do
    return Err("invalid_btc_intent")
  end
  let hash = Crypto.sha256(Bytes.concat(Bytes.from_utf8("morse-kraken-fok-v1"), intent)?)
  Ok(Bytes.to_hex(Bytes.slice(hash, 0, 16)?))
end

pub fn kraken_invoice_fields(plan :: BtcConversionPlan) -> List<KrakenField>!String do
  Ok([
    KrakenField { name: "asset", value: "XBT" },
    KrakenField { name: "aclass", value: "currency" },
    KrakenField { name: "method", value: "Bitcoin Lightning" },
    KrakenField { name: "new", value: "true" },
    KrakenField { name: "amount", value: btc_decimal_text(plan.invoice_msat, 11)? }
  ])
end

pub fn kraken_invoice(raw :: String,
  config :: BtcConversionConfig,
  plan :: BtcConversionPlan,
  now :: U64) -> String!String do
  let rows = kraken_result(raw)?
  if Json.array_length(rows)? != 1 do
    return Err("kraken_invoice_not_unique")
  end
  let row = Json.array_get(rows, 0)?
  let text = s(row, "address")?
  let invoice = conversion_invoice(text,
    plan.invoice_msat,
    config.backend.network,
    config.provider_payee,
    now,
    config.max_invoice_seconds)?
  let expires = U64.parse(s(row, "expiretm")?)?
  if expires != zero()? && expires != U64.add(invoice.created_at, invoice.expiry_seconds)? do
    return Err("kraken_invoice_expiry_mismatch")
  end
  Ok(text)
end

pub fn kraken_order_fields(intent :: Bytes,
  plan :: BtcConversionPlan) -> List<KrakenField>!String do
  Ok([
    KrakenField { name: "pair", value: "XBTUSDC" },
    KrakenField { name: "type", value: "sell" },
    KrakenField { name: "ordertype", value: "limit" },
    KrakenField { name: "timeinforce", value: "FOK" },
    KrakenField { name: "oflags", value: "fciq" },
    KrakenField { name: "volume", value: btc_decimal_text(plan.trade_sats, 8)? },
    KrakenField { name: "price", value: btc_decimal_text(plan.limit_price_micros, 6)? },
    KrakenField { name: "cl_ord_id", value: kraken_client_order_id(intent)? }
  ])
end

pub fn kraken_order_ack(raw :: String) -> String!String do
  let ids = Json.object_get(kraken_result(raw)?, "txid")?
  if Json.array_length(ids)? != 1 do
    return Err("kraken_order_ack_unknown")
  end
  let id = Json.as_string(Json.array_get(ids, 0)?)?
  if !btc_provider_identifier(id, 64)? do
    return Err("kraken_order_ack_unknown")
  end
  Ok(id)
end

pub fn kraken_order(raw :: String,
  id :: String,
  intent :: Bytes,
  plan :: BtcConversionPlan) -> Json!String do
  if !btc_provider_identifier(id, 64)? do
    return Err("invalid_kraken_order_id")
  end
  let order = Json.object_get(kraken_result(raw)?, id)?
  let desc = Json.object_get(order, "descr")?
  if s(order, "cl_ord_id")? != kraken_client_order_id(intent)?
    || s(order, "time_in_force")? != "fok"
    || s(desc, "pair")? != "XBTUSDC"
    || s(desc, "type")? != "sell"
    || s(desc, "ordertype")? != "limit"
    || s(desc, "leverage")? != "none"
    || s(desc, "close")? != ""
    || btc_decimal_units(s(desc, "price")?, 6)? != plan.limit_price_micros
    || btc_decimal_units(s(order, "vol")?, 8)? != plan.trade_sats do
    return Err("kraken_order_binding_mismatch")
  end
  if s(order, "status")? != "closed"
    || btc_decimal_units(s(order, "vol_exec")?, 8)? != plan.trade_sats do
    return Err("kraken_order_not_complete")
  end
  Ok(order)
end

pub fn kraken_order_trades(order :: Json) -> List<String>!String do
  let rows = Json.object_get(order, "trades")?
  if Json.array_length(rows)? < 1 || Json.array_length(rows)? > 8 do
    return Err("kraken_trade_evidence_capacity")
  end
  let ids = for i in 0..Json.array_length(rows)? do
    let id = Json.as_string(Json.array_get(rows, i)?)?
    if !btc_provider_identifier(id, 64)? do
      return Err("invalid_kraken_trade_id")
    end
    for before in 0..i do
      if id == Json.as_string(Json.array_get(rows, before)?)? do
        return Err("duplicate_kraken_trade_id")
      end
    end
    id
  end
  Ok(ids)
end

pub fn kraken_trade_ledgers(raw :: String,
  ids :: List<String>,
  order_id :: String) -> List<String>!String do
  if List.length(ids) < 1 || List.length(ids) > 8 do
    return Err("kraken_trade_evidence_capacity")
  end
  let root = kraken_result(raw)?
  let groups = for id in ids do
    let trade = Json.object_get(root, id)?
    if s(trade, "ordertxid")? != order_id
      || s(trade, "pair")? != "XBTUSDC"
      || s(trade, "type")? != "sell"
      || s(trade, "ordertype")? != "limit"
      || btc_decimal_units(s(trade, "margin")?, 8)? != zero()? do
      return Err("kraken_trade_binding_mismatch")
    end
    let ledgers = Json.object_get(trade, "ledgers")?
    if Json.array_length(ledgers)? != 2 do
      return Err("kraken_trade_ledger_capacity")
    end
    for i in 0..2 do
      let value = Json.as_string(Json.array_get(ledgers, i)?)?
      if !btc_provider_identifier(value, 64)? do
        return Err("invalid_kraken_ledger_id")
      end
      value
    end
  end
  let result = List.flat_map(groups, fn(part :: List<String>) do part end)
  for i in 0..List.length(result) do
    for j in 0..i do
      if List.get(result, i) == List.get(result, j) do
        return Err("duplicate_kraken_ledger_id")
      end
    end
  end
  Ok(result)
end

# fciq is only a preference: actual authenticated trade ledgers determine which
# asset paid fees. Balances are deliberately never consulted as output proof.
fn sum_column(parts :: List<List<U64>>, column :: Int, at :: Int, total :: U64) -> U64!String do
  if at == List.length(parts) do
    return Ok(total)
  end
  sum_column(parts, column, at + 1, U64.add(total, List.get(List.get(parts, at), column))?)
end

pub fn kraken_fill(order :: Json,
  trades_raw :: String,
  ledgers_raw :: String,
  id :: String,
  plan :: BtcConversionPlan,
  fee_bps :: Int) -> KrakenFill!String do
  let ids = kraken_order_trades(order)?
  kraken_trade_ledgers(trades_raw, ids, id)?
  let trades = kraken_result(trades_raw)?
  let ledgers = kraken_result(ledgers_raw)?
  let parts = for tid in ids do
    let trade = Json.object_get(trades, tid)?
    let volume = btc_decimal_units(s(trade, "vol")?, 11)?
    let cost = btc_decimal_units(s(trade, "cost")?, 8)?
    let refs = Json.object_get(trade, "ledgers")?
    let btc = Json.object_get(ledgers, Json.as_string(Json.array_get(refs, 0)?)?)?
    let usdc = Json.object_get(ledgers, Json.as_string(Json.array_get(refs, 1)?)?)?
    let btc_first = s(btc, "asset")? == "XXBT" || s(btc, "asset")? == "XBT"
    let debit = if btc_first do
      btc
    else
      usdc
    end
    let credit = if btc_first do
      usdc
    else
      btc
    end
    if s(debit, "refid")? != tid
      || s(credit, "refid")? != tid
      || s(debit, "type")? != "trade"
      || s(credit, "type")? != "trade"
      || s(debit, "aclass")? != "currency"
      || s(credit, "aclass")? != "currency"
      || !List.contains(["XBT", "XXBT"], s(debit, "asset")?)
      || s(credit, "asset")? != "USDC"
      || !String.starts_with(s(debit, "amount")?, "-") do
      return Err("kraken_ledger_binding_mismatch")
    end
    let negative = s(debit, "amount")?
    if btc_decimal_units(String.slice(negative, 1, String.length(negative)), 11)? != volume
      || btc_decimal_units(s(credit, "amount")?, 8)? != cost do
      return Err("kraken_trade_ledger_amount_mismatch")
    end
    [
      volume,
      cost,
      btc_decimal_units(s(debit, "fee")?, 11)?,
      btc_decimal_units(s(credit, "fee")?, 8)?
    ]
  end
  let totals = for column in 0..4 do
    sum_column(parts, column, 0, zero()?)?
  end
  let volume = List.get(totals, 0)
  let gross = List.get(totals, 1)
  let btc_fee = List.get(totals, 2)
  let usdc_fee = List.get(totals, 3)
  if volume != U64.multiply(plan.trade_sats, U64.parse("1000")?)?
    || U64.compare(U64.add(volume, btc_fee)?, plan.invoice_msat) > 0
    || gross != btc_decimal_units(s(order, "cost")?, 8)?
    || U64.compare(usdc_fee, gross) > 0
    || fee_bps < 0
    || fee_bps > 100 do
    return Err("kraken_fill_amount_mismatch")
  end
  let fee_quote = U128.add(U128.multiply(U128.parse(U64.to_string(btc_fee))?,
      U128.parse(U64.to_string(plan.reference_price_micros))?)?,
    U128.multiply(U128.parse(U64.to_string(usdc_fee))?, U128.parse("1000000000")?)?)?
  let allowed = U128.multiply(U128.multiply(U128.parse(U64.to_string(gross))?,
      U128.parse(Int.to_string(fee_bps))?)?,
    U128.parse("100000")?)?
  if U128.compare(fee_quote, allowed) > 0 do
    return Err("kraken_actual_trade_fee_over_budget")
  end
  if U128.compare(U128.multiply(U128.parse(U64.to_string(gross))?, U128.parse("1000000000")?)?,
    U128.multiply(U128.parse(U64.to_string(volume))?,
      U128.parse(U64.to_string(plan.limit_price_micros))?)?) < 0 do
    return Err("kraken_fill_below_limit_price")
  end
  let net8 = U64.subtract(gross, usdc_fee)?
  let net = U64.divide(net8, U64.parse("100")?)?
  if U64.compare(U64.divide(gross, U64.parse("100")?)?, plan.minimum_gross_usdc) < 0
    || U64.compare(net, plan.minimum_output_usdc) < 0 do
    return Err("kraken_fill_below_floor")
  end
  Ok(KrakenFill {
    order_id: id,
    gross_usdc: U64.divide(gross, U64.parse("100")?)?,
    net_usdc: net,
    provider_usdc_dust_100ths: U64.subtract(net8, U64.multiply(net, U64.parse("100")?)?)?,
    fee_usdc_100ths: usdc_fee,
    fee_btc_msat: btc_fee,
    trades: ids
  })
end

fn usdc(value :: Json) -> U64!String do
  let asset = Json.object_get(value, "asset")?
  if s(asset, "class")? != "currency" || s(asset, "name")? != "USDC" do
    return Err("kraken_withdrawal_asset_mismatch")
  end
  btc_decimal_units(s(value, "amount")?, 6)
end

pub fn kraken_fee(raw :: String,
  gross :: U64,
  maximum_fee :: U64,
  minimum :: U64) -> KrakenFee!String do
  let root = bounded(raw)?
  let fee = usdc(Json.object_get(root, "fee")?)?
  let net = usdc(Json.object_get(root, "net_amount")?)?
  let token = s(root, "withdrawal_fee_token")?
  if usdc(Json.object_get(root, "gross_amount")?)? != gross
    || U64.add(net, fee)? != gross
    || U64.compare(fee, maximum_fee) > 0
    || U64.compare(net, minimum) < 0
    || String.length(token) < 1
    || String.length(token) > 4096 do
    return Err("kraken_withdrawal_fee_refused")
  end
  Ok(KrakenFee { gross: gross, net: net, fee: fee, token: token })
end

pub fn kraken_withdrawal_body(config :: BtcConversionConfig, quote :: KrakenFee) -> String!String do
  Ok("{\"scope\":{\"method_id\":"
    <> Json.encode_string(config.withdraw_method)
    <> "},\"address_id\":"
    <> Json.encode_string(config.withdraw_address_id)
    <> ",\"amount\":{\"asset_amount\":{\"asset\":{\"class\":\"currency\",\"name\":\"USDC\"},\"amount\":"
    <> Json.encode_string(btc_decimal_text(quote.gross, 6)?)
    <> "}},\"fee\":{\"quoted_fee\":{\"token\":"
    <> Json.encode_string(quote.token)
    <> "},\"fee_included\":true},\"expected_address\":"
    <> Json.encode_string(Bytes.to_base58(config.owner))
    <> "}")
end

pub fn kraken_withdrawal_ack(raw :: String, quote :: KrakenFee) -> String!String do
  let root = bounded(raw)?
  for name in ["gross_amount", "net_amount", "fee"] do
    let expected = if name == "gross_amount" do
      quote.gross
    else if name == "net_amount" do
      quote.net
    else
      quote.fee
    end
    if usdc(Json.object_get(Json.object_get(root, name)?, "asset_amount")?)? != expected do
      return Err("kraken_withdrawal_ack_mismatch")
    end
  end
  let id = s(root, "withdrawal_id")?
  if !btc_provider_identifier(id, 64)? do
    return Err("kraken_withdrawal_ack_unknown")
  end
  Ok(id)
end

pub fn kraken_withdrawal_status(raw :: String,
  id :: String,
  config :: BtcConversionConfig,
  quote :: KrakenFee) -> KrakenWithdrawal!String do
  let rows = Json.object_get(bounded(raw)?, "withdrawals")?
  let count = Json.array_length(rows)?
  if count > 100 do
    return Err("kraken_withdrawal_history_capacity")
  end
  let matches = List.filter(for i in 0..count do
      Json.array_get(rows, i)?
    end,
    fn(row :: Json) do
      case s(row, "withdrawal_id") do
        Ok(value) -> value == id
        Err(_) -> false
      end
    end)
  if List.length(matches) != 1 do
    return Err("kraken_known_withdrawal_not_observed")
  end
  let row = List.head(matches)
  let status = s(row, "status")?
  if s(row, "method_id")? != config.withdraw_method
    || s(row, "address_id")? != config.withdraw_address_id
    || usdc(Json.object_get(row, "amount")?)? != quote.net
    || usdc(Json.object_get(row, "fee")?)? != quote.fee
    || !List.contains(["pending", "success", "failed"], status) do
    return Err("kraken_withdrawal_binding_mismatch")
  end
  let signature = if status == "success" do
    let text = s(row, "onchain_transaction")?
    let value = Bytes.from_base58(text)?
    if Bytes.length(value) != 64 || Bytes.to_base58(value) != text do
      return Err("kraken_withdrawal_invalid_signature")
    end
    value
  else
    Bytes.empty()
  end
  Ok(KrakenWithdrawal {
    withdrawal_id: id,
    amount: quote.net,
    fee: quote.fee,
    status: status,
    signature: signature
  })
end

# Appended to Payment.KrakenConversion after its current immutable test run.
pub fn kraken_withdrawal_method(raw :: String,
  config :: BtcConversionConfig,
  amount :: U64) -> Result<(), String> do
  let rows = Json.object_get(bounded(raw)?, "methods")?
  let count = Json.array_length(rows)?
  if count > 100 do
    return Err("kraken_method_capacity")
  end
  let found = List.filter(for i in 0..count do
      Json.array_get(rows, i)?
    end,
    fn(row :: Json) do
      case s(row, "method_id") do
        Ok(value) -> value == config.withdraw_method
        Err(_) -> false
      end
    end)
  if List.length(found) != 1 do
    return Err("kraken_pinned_method_unavailable")
  end
  let row = List.head(found)
  let asset = Json.object_get(row, "asset")?
  let network = Json.object_get(row, "network")?
  if s(asset, "class")? != "currency"
    || s(asset, "name")? != "USDC"
    || s(network, "network_id")? != config.withdraw_network do
    return Err("kraken_pinned_method_mismatch")
  end
  Json.object_get(row, "withdrawal")?
  case Json.object_get(network, "contract_address") do
    Ok(value) -> if Json.as_string(value)? != Bytes.to_base58(config.mint) do
      return Err("kraken_method_mint_mismatch")
    end
    Err(_) -> nil
  end
  case Json.object_get(row, "minimum_amount") do
    Ok(value) -> if U64.compare(amount, btc_decimal_units(Json.as_string(value)?, 6)?) < 0 do
      return Err("kraken_withdrawal_below_minimum")
    end
    Err(_) -> nil
  end
  case Json.object_get(row, "maximum_amount") do
    Ok(value) -> if U64.compare(amount, btc_decimal_units(Json.as_string(value)?, 6)?) > 0 do
      return Err("kraken_withdrawal_above_maximum")
    end
    Err(_) -> nil
  end
  Ok(nil)
end

pub fn kraken_saved_address(raw :: String, config :: BtcConversionConfig) -> Result<(), String> do
  let rows = Json.object_get(bounded(raw)?, "addresses")?
  let count = Json.array_length(rows)?
  if count > 100 do
    return Err("kraken_address_capacity")
  end
  let found = List.filter(for i in 0..count do
      Json.array_get(rows, i)?
    end,
    fn(row :: Json) do
      case s(row, "address_id") do
        Ok(value) -> value == config.withdraw_address_id
        Err(_) -> false
      end
    end)
  if List.length(found) != 1 do
    return Err("kraken_pinned_address_unavailable")
  end
  let row = List.head(found)
  let scope = Json.object_get(row, "scope")?
  let scope_matches = case Json.object_get(scope, "method_id") do
    Ok(value) -> Json.as_string(value)? == config.withdraw_method
    Err(_) -> case Json.object_get(scope, "network_id") do
      Ok(value) -> Json.as_string(value)? == config.withdraw_network
      Err(_) -> false
    end
  end
  let crypto = Json.object_get(Json.object_get(row, "address_details")?, "crypto")?
  if !scope_matches
    || !Json.as_bool(Json.object_get(row, "verified")?)?
    || s(crypto, "address")? != Bytes.to_base58(config.owner) do
    return Err("kraken_pinned_address_mismatch")
  end
  for field in ["tag", "memo"] do
    case Json.object_get(crypto, field) do
      Ok(value) -> if Json.as_string(value)? != "" do
        return Err("kraken_unexpected_destination_memo")
      end
      Err(_) -> nil
    end
  end
  Ok(nil)
end

pub struct KrakenWithdrawalPage do
  found :: Option<KrakenWithdrawal>
  next_cursor :: Option<String>
end

pub fn kraken_withdrawal_cursor(value :: String) -> Result<(), String> do
  let bytes = Bytes.from_utf8(value)
  if Bytes.length(bytes) < 1 || Bytes.length(bytes) > 1024 do
    return Err("kraken_withdrawal_cursor_capacity")
  end
  for index in 0..Bytes.length(bytes) do
    let byte = Bytes.get(bytes, index)?
    if byte < 33 || byte > 126 do
      return Err("kraken_withdrawal_cursor_malformed")
    end
  end
  Ok(nil)
end

pub fn kraken_withdrawal_page(raw :: String,
  id :: String,
  config :: BtcConversionConfig,
  quote :: KrakenFee) -> KrakenWithdrawalPage!String do
  if Bytes.length(Bytes.from_utf8(raw)) > 65536 do
    return Err("kraken_withdrawal_page_capacity")
  end
  let root = bounded(raw)?
  let next = case Json.object_get(root, "next_cursor") do
    Err(_) -> None
    Ok(value) -> do
      let text = Json.as_string(value)?
      kraken_withdrawal_cursor(text)?
      Some(text)
    end
  end
  let rows = Json.object_get(root, "withdrawals")?
  let count = Json.array_length(rows)?
  if count > 100 do
    return Err("kraken_withdrawal_history_capacity")
  end
  let ids = for index in 0..count do
    let found = s(Json.array_get(rows, index)?, "withdrawal_id")?
    if !btc_provider_identifier(found, 64)? do
      return Err("kraken_withdrawal_identifier_malformed")
    end
    for prior in 0..index do
      if found == s(Json.array_get(rows, prior)?, "withdrawal_id")? do
        return Err("duplicate_kraken_withdrawal_id")
      end
    end
    found
  end
  let found = if List.contains(ids, id) do
    Some(kraken_withdrawal_status(raw, id, config, quote)?)
  else
    None
  end
  Ok(KrakenWithdrawalPage { found: found, next_cursor: next })
end
