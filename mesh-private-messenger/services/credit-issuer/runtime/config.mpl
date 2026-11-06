from Runtime.TreasuryBurnConfig import parse_burn_config, burn_environment_names
from Transparency.TokenBurnRead import TokenBurnReadPins
from Payment.RevenuePolicy import parse_credit_revenue_policy
from Api.Lightning import LightningPolicy
from Runtime.LightningConfig import parse_lightning_config, lightning_environment_names
from Api.Purchases import IssuerPolicy
from Privacy.Edge import internal_delivery_token
from Solana.Read import pubkey
from Transparency.Config import SecurityConfig, decode_security_config
from Runtime.Treasury import TreasuryWorkerConfig
from Runtime.TreasuryConfig import parse_treasury_config, treasury_environment_names

pub struct IssuerServerConfig do
  policy :: IssuerPolicy
  trust :: SecurityConfig
  database_url :: String
  key_directory :: String
  port :: Int
  directory_origin :: String
  admin_transport :: String
  issuer_admin_token :: String
  purchase_token :: String
  burn :: Option<TokenBurnReadPins>
  treasury :: Option<TreasuryWorkerConfig>
  lightning :: Option<LightningPolicy>
end

fn setting(values :: Map<String, String>, name :: String, fallback :: String) -> String do
  if Map.has_key(values, name) do
    Map.get(values, name)
  else
    fallback
  end
end

fn endpoint(value :: String, origin_only :: Bool, allow_local :: Bool) -> String!String do
  let origin = Http.url_origin(value)?
  if String.length(value) > 2048
    || String.contains(value, "@")
    || String.contains(value, "#")
    || String.contains(value, "\\")
    || (origin_only && value != origin)
    || (!String.starts_with(value, "https://")
      && !(allow_local
        && (String.starts_with(origin, "http://127.0.0.1:")
          || String.starts_with(origin, "http://localhost:")))) do
    return Err("invalid_issuer_endpoint")
  end
  Ok(value)
end

pub fn parse_server_config(values :: Map<String, String>) -> IssuerServerConfig!String do
  let mode = setting(values, "MORSE_CREDITS_MODE", "off")
  let purpose_name = setting(values, "MESSENGER_CREDITS_PURPOSE", "live")
  if !List.contains(["off", "test", "live"], mode)
    || !List.contains(["test", "live"], purpose_name)
    || (mode != "off" && mode != purpose_name) do
    return Err("invalid_credit_mode")
  end
  let purpose = if purpose_name == "test" do
    1
  else
    0
  end
  let trust = decode_security_config(Bytes.from_utf8(setting(values,
    "MESSENGER_ISSUER_SECURITY_CONFIG",
    "")))?
  if trust.log_version != 2 || (mode != "off" && trust.issuer_origin == "-") do
    return Err("credits_require_pinned_rfc6962_configuration")
  end
  let database = setting(values, "MESSENGER_ISSUER_DATABASE_URL", "")
  let directory = setting(values, "MESSENGER_CREDIT_STORAGE_DIR", "")
  if String.length(database) == 0
    || !String.starts_with(directory, "/")
    || String.ends_with(directory, "/") do
    return Err("missing_issuer_storage_configuration")
  end
  let port = case String.to_int(setting(values, "MESSENGER_ISSUER_PORT", "18096")) do
    Some(value) -> value
    None -> return Err("invalid_issuer_port")
  end
  if port < 1 || port > 65535 do
    return Err("invalid_issuer_port")
  end
  let admin = internal_delivery_token(setting(values,
    "MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN",
    ""))?
  let purchase = internal_delivery_token(setting(values,
    "MESSENGER_CREDIT_PURCHASE_INTERNAL_TOKEN",
    ""))?
  if Bytes.secure_equals(Bytes.from_utf8(admin), Bytes.from_utf8(purchase)) do
    return Err("issuer_authorities_must_be_distinct")
  end
  let transport = setting(values, "MESSENGER_CREDIT_ADMIN_TRANSPORT", "direct")
  if !List.contains(["direct", "ingress"], transport) do
    return Err("invalid_issuer_admin_transport")
  end
  let oracle = setting(values, "MESSENGER_CREDIT_SOL_PRICE_ACCOUNT", "")
  if oracle != "" do
    pubkey(oracle)?
  end
  let mint = pubkey(setting(values, "MESSENGER_CREDIT_USDC_MINT", ""))?.bytes
  if Bytes.to_hex(mint) == String.repeat("00", 32) do
    return Err("invalid_issuer_mint")
  end
  let treasury = parse_treasury_config(values, purpose, mint)?
  let burn = parse_burn_config(values, purpose, treasury)?
  Ok(IssuerServerConfig {
    policy: IssuerPolicy {
      enabled: mode != "off",
      revenue_policy: parse_credit_revenue_policy(setting(values,
        "MESSENGER_CREDIT_REVENUE_POLICY",
        "1"))?,
      purpose: purpose,
      service_key: trust.service_public_key,
      mint: mint,
      rpc_url: endpoint(setting(values, "MESSENGER_CREDIT_SOLANA_RPC_URL", ""),
        false,
        purpose == 1)?,
      oracle_account: oracle
    },
    trust: trust,
    database_url: database,
    key_directory: directory,
    port: port,
    directory_origin: endpoint(setting(values, "MESSENGER_DELIVERY_INTERNAL_URL", ""),
      true,
      purpose == 1)?,
    admin_transport: transport,
    issuer_admin_token: admin,
    purchase_token: purchase,
    burn: burn,
    treasury: treasury,
    lightning: parse_lightning_config(values,
      purpose,
      trust.service_public_key,
      mode != "off",
      endpoint(setting(values, "MESSENGER_CREDIT_SOLANA_RPC_URL", ""), false, purpose == 1)?)?
  })
end

pub fn configured_server() -> IssuerServerConfig!String do
  let names = [
    "MORSE_CREDITS_MODE",
    "MESSENGER_CREDIT_REVENUE_POLICY",
    "MESSENGER_CREDITS_PURPOSE",
    "MESSENGER_ISSUER_DATABASE_URL",
    "MESSENGER_ISSUER_SECURITY_CONFIG",
    "MESSENGER_CREDIT_STORAGE_DIR",
    "MESSENGER_ISSUER_PORT",
    "MESSENGER_CREDIT_USDC_MINT",
    "MESSENGER_CREDIT_SOLANA_RPC_URL",
    "MESSENGER_CREDIT_SOL_PRICE_ACCOUNT",
    "MESSENGER_DELIVERY_INTERNAL_URL",
    "MESSENGER_CREDIT_ADMIN_TRANSPORT",
    "MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN",
    "MESSENGER_CREDIT_PURCHASE_INTERNAL_TOKEN"
  ]
  let entries = for name in List.concat(List.concat(List.concat(names,
        treasury_environment_names()),
      lightning_environment_names()),
    burn_environment_names()) do
    (name,
      Env.get(name,
        if name == "MORSE_CREDITS_MODE"
          || name == "MORSE_TREASURY_MODE"
          || name == "MORSE_LIGHTNING_MODE"
          || name == "MORSE_BURN_MODE" do
          "off"
        else if name == "MESSENGER_CREDITS_PURPOSE" do
          "live"
        else if name == "MESSENGER_CREDIT_REVENUE_POLICY" do
          "1"
        else if name == "MESSENGER_CREDIT_ADMIN_TRANSPORT" do
          "direct"
        else if name == "MESSENGER_ISSUER_PORT" do
          "18096"
        else
          ""
        end))
  end
  parse_server_config(Map.from_list(entries))
end

pub fn open_storage_key(directory :: String) -> StorageKey!String do
  case StorageKey.file(directory) do
    Ok(value)
    Err(_) -> Err("issuer_storage_key_unavailable")
  end
end

pub fn issuer_admin_url(config :: IssuerServerConfig, operation :: String) -> String!String do
  if !List.contains(["announce", "evidence", "admit", "cursor"], operation) do
    return Err("invalid_issuer_admin_operation")
  end
  let prefix = if config.admin_transport == "ingress" do
    "/v1/ingress/credits/issuers/"
  else if config.admin_transport == "direct" do
    "/internal/credits/issuers/"
  else
    return Err("invalid_issuer_admin_transport")
  end
  Ok(config.directory_origin <> prefix <> operation)
end
