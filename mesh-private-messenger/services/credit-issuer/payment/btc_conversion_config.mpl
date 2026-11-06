from Payment.LightningBackend import LndConfig, validate_lnd_config
from Payment.Verify import payment_token_address
from Solana.Read import pubkey
from Transparency.TokenBurnRead import token_burn_rpc_sources

pub struct BtcConversionConfig do
  purpose :: Int
  dedicated_account :: Bool
  treasury_config_hash :: Bytes
  account_profile :: Bytes
  api_key :: String
  provider_origin :: String
  backend :: LndConfig
  provider_payee :: Bytes
  withdraw_method :: String
  withdraw_network :: String
  withdraw_address_id :: String
  providers :: List<String>
  cluster :: Bytes
  oracle_account :: Bytes
  owner :: Bytes
  mint :: Bytes
  custody :: Bytes
  max_source_msat :: U64
  min_order_sats :: U64
  routing_fee_limit_msat :: U64
  trade_fee_bps :: Int
  withdrawal_fee_cap :: U64
  price_tick_micros :: U64
  max_invoice_seconds :: U64
end

fn setting(values :: Map<String, String>, name :: String) -> String do
  if Map.has_key(values, name) do
    Map.get(values, name)
  else
    ""
  end
end

fn number(values :: Map<String, String>, name :: String) -> U64!String do
  let text = setting(values, name)
  let value = U64.parse(text)?
  if U64.to_string(value) != text do
    return Err("noncanonical_btc_config_number")
  end
  Ok(value)
end

fn nonzero(value :: Bytes, length :: Int) -> Result<(), String> do
  if Bytes.length(value) != length || Bytes.to_hex(value) == String.repeat("00", length) do
    Err("invalid_btc_config_key")
  else
    Ok(nil)
  end
end

pub fn btc_uuid(value :: String) -> Bool do
  let parts = String.split(value, "-")
  if List.length(parts) != 5 do
    return false
  end
  for index in 0..5 do
    if String.length(List.get(parts, index)) != List.get([8, 4, 4, 4, 12], index) do
      return false
    end
  end
  let hex = String.join(parts, "")
  case Bytes.from_hex(hex) do
    Err(_) -> false
    Ok(bytes) -> Bytes.to_hex(bytes) == hex
  end
end

pub fn btc_provider_identifier(value :: String, maximum :: Int) -> Bool!String do
  let bytes = Bytes.from_utf8(value)
  if Bytes.length(bytes) < 1 || Bytes.length(bytes) > maximum do
    return Ok(false)
  end
  for index in 0..Bytes.length(bytes) do
    let byte = Bytes.get(bytes, index)?
    if !((byte >= 48 && byte <= 57)
      || (byte >= 65 && byte <= 90)
      || (byte >= 97 && byte <= 122)
      || byte == 45
      || byte == 95) do
      return Ok(false)
    end
  end
  Ok(true)
end

pub fn validate_btc_conversion_config(config :: BtcConversionConfig) -> Result<(), String> do
  if (config.purpose != 0 && config.purpose != 1) || !config.dedicated_account do
    return Err("btc_dedicated_account_required")
  end
  if config.provider_origin != Http.url_origin(config.provider_origin)?
    || (config.purpose == 0 && config.provider_origin != "https://api.kraken.com")
    || (config.purpose == 1 && !String.starts_with(config.provider_origin, "http://127.0.0.1:")) do
    return Err("invalid_btc_provider_origin")
  end
  let key = Bytes.from_utf8(config.api_key)
  if Bytes.length(key) < 20 || Bytes.length(key) > 256 do
    return Err("invalid_kraken_api_key")
  end
  for index in 0..Bytes.length(key) do
    let byte = Bytes.get(key, index)?
    if byte < 33 || byte > 126 do
      return Err("invalid_kraken_api_key")
    end
  end
  validate_lnd_config(config.backend)?
  if config.backend.purpose != config.purpose || config.provider_payee == config.backend.payee do
    return Err("btc_backend_scope_conflict")
  end
  nonzero(config.provider_payee, 33)?
  if !List.contains([2, 3], Bytes.get(config.provider_payee, 0)?) do
    return Err("invalid_btc_provider_payee")
  end
  for value in [
    config.treasury_config_hash,
    config.account_profile,
    config.cluster,
    config.oracle_account,
    config.owner,
    config.mint
  ] do
    nonzero(value, 32)?
  end
  if config.custody != payment_token_address(config.owner, config.mint)? do
    return Err("btc_custody_pin_mismatch")
  end
  token_burn_rpc_sources(config.providers, config.purpose == 1)?
  for url in config.providers do
    if url != Http.url_origin(url)? do
      return Err("btc_rpc_canonical_origin_required")
    end
  end
  if !btc_uuid(config.withdraw_method)
    || !btc_uuid(config.withdraw_network)
    || !btc_provider_identifier(config.withdraw_address_id, 20)?
    || String.length(config.withdraw_address_id) != 20
    || !String.starts_with(config.withdraw_address_id, "AB") do
    return Err("invalid_btc_withdrawal_pins")
  end
  let zero = U64.parse("0")?
  if config.max_source_msat == zero
    || U64.compare(config.max_source_msat, U64.parse("2100000000000000000")?) > 0
    || config.min_order_sats == zero
    || U64.compare(config.routing_fee_limit_msat, config.max_source_msat) >= 0
    || config.trade_fee_bps < 0
    || config.trade_fee_bps > 100
    || config.price_tick_micros == zero
    || U64.compare(config.price_tick_micros, U64.parse("1000000")?) > 0
    || U64.compare(config.max_invoice_seconds, U64.parse("30")?) < 0
    || U64.compare(config.max_invoice_seconds, U64.parse("3600")?) > 0 do
    return Err("invalid_btc_conversion_limits")
  end
  Ok(nil)
end

# This binds the operator-pinned dedicated account and actual API-key identity.
# It does not discover or attest ownership from balances or provider responses.
pub fn btc_conversion_profile(config :: BtcConversionConfig) -> Bytes!String do
  validate_btc_conversion_config(config)?
  Ok(Crypto.sha256(Bytes.from_utf8(String.join([
      "morse-kraken-dedicated-btc-conversion-profile-v1",
      Int.to_string(config.purpose),
      Bytes.to_hex(config.treasury_config_hash),
      Bytes.to_hex(config.account_profile),
      config.api_key,
      config.provider_origin,
      config.backend.origin,
      Int.to_string(config.backend.network),
      Bytes.to_hex(config.backend.payee),
      Bytes.to_hex(config.provider_payee),
      config.withdraw_method,
      config.withdraw_network,
      config.withdraw_address_id,
      String.join(config.providers, "\n"),
      Bytes.to_hex(config.cluster),
      Bytes.to_hex(config.oracle_account),
      Bytes.to_hex(config.owner),
      Bytes.to_hex(config.mint),
      Bytes.to_hex(config.custody),
      U64.to_string(config.max_source_msat),
      U64.to_string(config.min_order_sats),
      U64.to_string(config.routing_fee_limit_msat),
      Int.to_string(config.trade_fee_bps),
      U64.to_string(config.withdrawal_fee_cap),
      U64.to_string(config.price_tick_micros),
      U64.to_string(config.max_invoice_seconds)
    ],
    "\n"))))
end

pub fn btc_conversion_environment_names() -> List<String> do
  [
    "MESSENGER_BTC_CONVERSION_TREASURY_CONFIG_HASH_HEX",
    "MORSE_BTC_CONVERSION_MODE",
    "MESSENGER_BTC_CONVERSION_DEDICATED_ACCOUNT",
    "MESSENGER_BTC_CONVERSION_ACCOUNT_PROFILE_HEX",
    "MESSENGER_KRAKEN_API_KEY",
    "MESSENGER_KRAKEN_ORIGIN",
    "MESSENGER_KRAKEN_LIGHTNING_PAYEE_HEX",
    "MESSENGER_KRAKEN_WITHDRAW_METHOD",
    "MESSENGER_KRAKEN_WITHDRAW_NETWORK",
    "MESSENGER_KRAKEN_WITHDRAW_ADDRESS_ID",
    "MESSENGER_BTC_CONVERSION_RPC_A",
    "MESSENGER_BTC_CONVERSION_RPC_B",
    "MESSENGER_BTC_CONVERSION_RPC_C",
    "MESSENGER_BTC_CONVERSION_GENESIS",
    "MESSENGER_BTC_CONVERSION_ORACLE",
    "MESSENGER_BTC_CONVERSION_OWNER",
    "MESSENGER_BTC_CONVERSION_MAX_SOURCE_MSAT",
    "MESSENGER_BTC_CONVERSION_MIN_ORDER_SATS",
    "MESSENGER_BTC_CONVERSION_ROUTING_FEE_MSAT",
    "MESSENGER_BTC_CONVERSION_TRADE_FEE_BPS",
    "MESSENGER_BTC_CONVERSION_WITHDRAW_FEE_UNITS",
    "MESSENGER_BTC_CONVERSION_PRICE_TICK_MICROS",
    "MESSENGER_BTC_CONVERSION_MAX_INVOICE_SECONDS"
  ]
end

pub fn parse_btc_conversion_config(values :: Map<String, String>,
  purpose :: Int,
  mint :: Bytes,
  lnd :: Option<LndConfig>) -> Option<BtcConversionConfig>!String do
  let mode = if Map.has_key(values, "MORSE_BTC_CONVERSION_MODE") do
    setting(values, "MORSE_BTC_CONVERSION_MODE")
  else
    "off"
  end
  if mode == "off" do
    return Ok(None)
  end
  if !((mode == "test" && purpose == 1) || (mode == "live" && purpose == 0)) do
    return Err("invalid_btc_conversion_mode")
  end
  let backend = case lnd do
    None -> return Err("btc_original_lightning_backend_required")
    Some(value) -> value
  end
  let providers = for suffix in ["A", "B", "C"] do
    setting(values, "MESSENGER_BTC_CONVERSION_RPC_" <> suffix)
  end
  let profile_text = setting(values, "MESSENGER_BTC_CONVERSION_ACCOUNT_PROFILE_HEX")
  let profile = Bytes.from_hex(profile_text)?
  let provider_payee_text = setting(values, "MESSENGER_KRAKEN_LIGHTNING_PAYEE_HEX")
  let provider_payee = Bytes.from_hex(provider_payee_text)?
  if Bytes.to_hex(profile) != profile_text || Bytes.to_hex(provider_payee) != provider_payee_text do
    return Err("invalid_btc_config_hex")
  end
  let treasury_text = setting(values, "MESSENGER_BTC_CONVERSION_TREASURY_CONFIG_HASH_HEX")
  let treasury_hash = Bytes.from_hex(treasury_text)?
  if Bytes.to_hex(treasury_hash) != treasury_text do
    return Err("invalid_btc_treasury_hash")
  end
  let owner = pubkey(setting(values, "MESSENGER_BTC_CONVERSION_OWNER"))?.bytes
  let config = BtcConversionConfig {
    treasury_config_hash: treasury_hash,
    purpose: purpose,
    dedicated_account: setting(values, "MESSENGER_BTC_CONVERSION_DEDICATED_ACCOUNT") == "yes",
    account_profile: profile,
    api_key: setting(values, "MESSENGER_KRAKEN_API_KEY"),
    provider_origin: setting(values, "MESSENGER_KRAKEN_ORIGIN"),
    backend: backend,
    provider_payee: provider_payee,
    withdraw_method: setting(values, "MESSENGER_KRAKEN_WITHDRAW_METHOD"),
    withdraw_network: setting(values, "MESSENGER_KRAKEN_WITHDRAW_NETWORK"),
    withdraw_address_id: setting(values, "MESSENGER_KRAKEN_WITHDRAW_ADDRESS_ID"),
    providers: providers,
    cluster: pubkey(setting(values, "MESSENGER_BTC_CONVERSION_GENESIS"))?.bytes,
    oracle_account: pubkey(setting(values, "MESSENGER_BTC_CONVERSION_ORACLE"))?.bytes,
    owner: owner,
    mint: mint,
    custody: payment_token_address(owner, mint)?,
    max_source_msat: number(values, "MESSENGER_BTC_CONVERSION_MAX_SOURCE_MSAT")?,
    min_order_sats: number(values, "MESSENGER_BTC_CONVERSION_MIN_ORDER_SATS")?,
    routing_fee_limit_msat: number(values, "MESSENGER_BTC_CONVERSION_ROUTING_FEE_MSAT")?,
    trade_fee_bps: U64.to_int(number(values, "MESSENGER_BTC_CONVERSION_TRADE_FEE_BPS")?)?,
    withdrawal_fee_cap: number(values, "MESSENGER_BTC_CONVERSION_WITHDRAW_FEE_UNITS")?,
    price_tick_micros: number(values, "MESSENGER_BTC_CONVERSION_PRICE_TICK_MICROS")?,
    max_invoice_seconds: number(values, "MESSENGER_BTC_CONVERSION_MAX_INVOICE_SECONDS")?
  }
  validate_btc_conversion_config(config)?
  Ok(Some(config))
end
