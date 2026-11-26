##! The issuer's configuration (README.md "Configuration"). Everything the
##! quote, issue, sweep and refund paths need is passed as one IssuerSettings,
##! so tests point it at fake RPC, oracle, Lightning and directory servers.

from Credits.CreditToken import credits_valid_host

pub struct IssuerSettings do
  mode :: String
  assets :: List<String>
  issuer_name :: String
  rpc_url :: String
  usdc_mint :: String
  oracle_url :: String
  lnd_url :: String
  lnd_macaroon :: String
  directory_url :: String
  directory_token :: String
  treasury_address :: String
  treasury_usdc_account :: String
  deposit_seed :: Bytes
  sweep_min_delay_s :: Int
  sweep_max_delay_s :: Int
  split :: String
  quote_difficulty :: Int
  max_open_quotes :: Int
end

## Pyth price feed IDs (Hermes, https://hermes.pyth.network).

pub fn issuer_sol_feed() -> String do
  "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d"
end

pub fn issuer_btc_feed() -> String do
  "e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43"
end

## Quotes last 15 minutes.

pub fn issuer_quote_lifetime_ms() -> Int do
  900000
end

## The key purpose this issuer signs for: its mode, unless off.

pub fn issuer_purpose(settings :: IssuerSettings) -> String do
  if settings.mode == "live" do
    "live"
  else
    "test"
  end
end

pub fn issuer_asset_enabled(settings :: IssuerSettings, asset :: String) -> Bool do
  List.any(settings.assets, fn value -> value == asset end)
    && (asset != "btc" || settings.lnd_url != "")
end

fn assets(text :: String) -> List<String>!String do
  let values = List.filter(List.map(String.split(text, ","), fn value -> String.trim(value) end),
    fn value -> value != "" end)
  if List.all(values, fn value -> value == "usdc" || value == "sol" || value == "btc" end) do
    Ok(values)
  else
    Err("MORSE_CREDIT_ASSETS lists only usdc, sol and btc")
  end
end

fn url(name :: String, value :: String, required :: Bool) -> String!String do
  if value == "" && !required do
    Ok(value)
  else if String.starts_with(value, "https://") || String.starts_with(value, "http://") do
    Ok(value)
  else
    Err("#{name} must be an http(s) URL")
  end
end

fn seed() -> Bytes!String do
  let text = Env.get("MORSE_CREDIT_DEPOSIT_SEED_HEX", "")
  let bytes = case Bytes.from_hex(text) do
    Err(_) -> Err("MORSE_CREDIT_DEPOSIT_SEED_HEX must be hex")
    Ok(value)
  end?
  if Bytes.length(bytes) != 0 && (Bytes.length(bytes) < 16 || Bytes.length(bytes) > 64) do
    Err("MORSE_CREDIT_DEPOSIT_SEED_HEX must hold 16 to 64 bytes")
  else
    Ok(bytes)
  end
end

## From the environment. MORSE_CREDITS_MODE off needs nothing else; test and
## live need the issuer name, and the Solana settings when a Solana asset is
## offered.

pub fn issuer_settings_from_env() -> IssuerSettings!String do
  let mode = Env.get("MORSE_CREDITS_MODE", "off")
  if mode != "off" && mode != "test" && mode != "live" do
    return Err("MORSE_CREDITS_MODE must be off, test or live")
  end
  let settings = IssuerSettings {
    mode: mode,
    assets: assets(Env.get("MORSE_CREDIT_ASSETS", "usdc,sol"))?,
    issuer_name: Env.get("MORSE_CREDIT_ISSUER_NAME", ""),
    rpc_url: url("MORSE_CREDIT_SOLANA_RPC_URL", Env.get("MORSE_CREDIT_SOLANA_RPC_URL", ""), false)?,
    usdc_mint: Env.get("MORSE_CREDIT_USDC_MINT", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
    oracle_url: url("MORSE_CREDIT_ORACLE_URL",
      Env.get("MORSE_CREDIT_ORACLE_URL", "https://hermes.pyth.network"),
      true)?,
    lnd_url: url("MORSE_CREDIT_LND_URL", Env.get("MORSE_CREDIT_LND_URL", ""), false)?,
    lnd_macaroon: Env.get("MORSE_CREDIT_LND_MACAROON_HEX", ""),
    directory_url: url("MORSE_CREDIT_DIRECTORY_URL",
      Env.get("MORSE_CREDIT_DIRECTORY_URL", ""),
      false)?,
    directory_token: Env.get("MORSE_CREDIT_ISSUER_INTERNAL_TOKEN", ""),
    treasury_address: Env.get("MORSE_CREDIT_TREASURY_ADDRESS", ""),
    treasury_usdc_account: Env.get("MORSE_CREDIT_TREASURY_USDC_ACCOUNT", ""),
    deposit_seed: seed()?,
    sweep_min_delay_s: Env.get_int("MORSE_CREDIT_SWEEP_MIN_DELAY_S", 3600),
    sweep_max_delay_s: Env.get_int("MORSE_CREDIT_SWEEP_MAX_DELAY_S", 86400),
    split: Env.get("MORSE_CREDIT_SETTLEMENT_SPLIT", "20/80"),
    quote_difficulty: Env.get_int("MESSENGER_ABUSE_DIFFICULTY", 16),
    max_open_quotes: Env.get_int("MORSE_CREDIT_MAX_OPEN_QUOTES", 1000)
  }
  issuer_settings_check(settings)
end

fn solana_offered(settings :: IssuerSettings) -> Bool do
  issuer_asset_enabled(settings, "usdc") || issuer_asset_enabled(settings, "sol")
end

pub fn issuer_settings_check(settings :: IssuerSettings) -> IssuerSettings!String do
  if settings.split != "20/80" && settings.split != "20/30/50" do
    Err("MORSE_CREDIT_SETTLEMENT_SPLIT must be 20/80 or 20/30/50")
  else if settings.quote_difficulty < 1 || settings.quote_difficulty > 24 do
    Err("MESSENGER_ABUSE_DIFFICULTY must be between 1 and 24")
  else if settings.max_open_quotes < 1 || settings.max_open_quotes > 1000000 do
    Err("MORSE_CREDIT_MAX_OPEN_QUOTES must be between 1 and 1000000")
  else if settings.sweep_min_delay_s < 0
    || settings.sweep_max_delay_s < settings.sweep_min_delay_s do
    Err("sweep delays must satisfy 0 <= MIN <= MAX")
  else if settings.mode == "off" do
    Ok(settings)
  else if !credits_valid_host(settings.issuer_name) do
    Err("MORSE_CREDIT_ISSUER_NAME must be the issuer origin's host")
  else if settings.directory_url == "" || String.length(settings.directory_token) < 32 do
    Err("MORSE_CREDIT_DIRECTORY_URL and MORSE_CREDIT_ISSUER_INTERNAL_TOKEN are required")
  else if solana_offered(settings)
    && (settings.rpc_url == "" || Bytes.length(settings.deposit_seed) == 0) do
    Err("Solana assets need MORSE_CREDIT_SOLANA_RPC_URL and MORSE_CREDIT_DEPOSIT_SEED_HEX")
  else
    Ok(settings)
  end
end
