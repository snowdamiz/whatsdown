from Payment.RevenuePolicy import parse_credit_revenue_policy
from Api.Lightning import LightningPolicy
from Payment.LightningBackend import LndConfig, validate_lnd_config
from Solana.Read import pubkey

fn setting(values :: Map<String, String>, name :: String, fallback :: String) -> String do
  if Map.has_key(values, name) do
    Map.get(values, name)
  else
    fallback
  end
end

pub fn lightning_environment_names() -> List<String> do
  [
    "MORSE_LIGHTNING_MODE",
    "MESSENGER_CREDIT_LIGHTNING_ORIGIN",
    "MESSENGER_CREDIT_LIGHTNING_NETWORK",
    "MESSENGER_CREDIT_LIGHTNING_NODE_PUBLIC_KEY",
    "MESSENGER_CREDIT_LIGHTNING_MACAROON_HEX",
    "MESSENGER_CREDIT_BTC_PRICE_ACCOUNT"
  ]
end

pub fn parse_lightning_config(values :: Map<String, String>,
  purpose :: Int,
  service_key :: Bytes,
  purchases_enabled :: Bool,
  rpc_url :: String) -> Option<LightningPolicy>!String do
  let mode = setting(values, "MORSE_LIGHTNING_MODE", "off")
  if mode == "off" do
    return Ok(None)
  end
  if (mode != "test" && mode != "live")
    || (mode == "test" && purpose != 1)
    || (mode == "live" && purpose != 0)
    || Bytes.length(service_key) != 32 do
    return Err("invalid_lightning_mode")
  end
  let network = case setting(values, "MESSENGER_CREDIT_LIGHTNING_NETWORK", "") do
    "mainnet" -> 0
    "testnet" -> 1
    "regtest" -> 2
    "signet" -> 3
    "simnet" -> 4
    _ -> return Err("invalid_lightning_network")
  end
  let backend = LndConfig {
    origin: setting(values, "MESSENGER_CREDIT_LIGHTNING_ORIGIN", ""),
    macaroon: setting(values, "MESSENGER_CREDIT_LIGHTNING_MACAROON_HEX", ""),
    network: network,
    purpose: purpose,
    payee: Bytes.from_hex(setting(values, "MESSENGER_CREDIT_LIGHTNING_NODE_PUBLIC_KEY", ""))?
  }
  validate_lnd_config(backend)?
  let oracle = setting(values, "MESSENGER_CREDIT_BTC_PRICE_ACCOUNT", "")
  pubkey(oracle)?
  let origin = Http.url_origin(rpc_url)?
  if String.contains(rpc_url, "@")
    || String.contains(rpc_url, "#")
    || String.contains(rpc_url, "\\")
    || String.length(rpc_url) > 2048
    || (!String.starts_with(origin, "https://")
      && !(purpose == 1 && String.starts_with(origin, "http://127.0.0.1:"))) do
    return Err("invalid_lightning_oracle_endpoint")
  end
  Ok(Some(LightningPolicy {
    enabled: purchases_enabled,
    revenue_policy: parse_credit_revenue_policy(setting(values,
      "MESSENGER_CREDIT_REVENUE_POLICY",
      "1"))?,
    service_key: service_key,
    backend: backend,
    rpc_url: rpc_url,
    oracle_account: oracle
  }))
end
