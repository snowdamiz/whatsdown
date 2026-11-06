from Payment.Treasury import TreasuryChainConfig, treasury_config_hash
from Runtime.Treasury import TreasuryWorkerConfig, treasury_provider_hash
from Runtime.BtcConversionFunding import BtcWitnessFundingConfig
from Payment.BtcConversionConfig import (
  BtcConversionConfig,
  parse_btc_conversion_config,
  btc_conversion_environment_names
)
from Payment.LightningBackend import LndConfig

pub fn setting(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

pub fn fixture_config() -> BtcConversionConfig!String do
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

pub fn funding_config() -> BtcWitnessFundingConfig!String do
  let root = Json.parse(Bytes.to_utf8(File.read_bytes(Env.get("BTC_FIXTURE_CONFIG", ""),
    0,
    16384)?)?)?
  let c = Json.object_get(root, "treasury_chain")?
  let values = Json.object_get(c, "providers")?
  let providers = for i in 0..Json.array_length(values)? do
    Json.as_string(Json.array_get(values, i)?)?
  end
  let chain = TreasuryChainConfig {
    cluster: Bytes.from_hex(setting(c, "cluster")?)?,
    providers_hash: Bytes.from_hex(setting(c, "providers_hash")?)?,
    mint: Bytes.from_base58(setting(c, "usdc")?)?,
    treasury_owner: Bytes.from_base58(setting(c, "owner")?)?,
    fee_payer: Bytes.from_base58(setting(c, "payer")?)?,
    nonce_authority: Bytes.from_hex(setting(c, "nonce_authority")?)?,
    nonce_address: Bytes.from_hex(setting(c, "nonce_address")?)?,
    rewards_program: Bytes.from_hex(setting(c, "rewards_program")?)?,
    rewards_pool: Bytes.from_hex(setting(c, "rewards_pool")?)?
  }
  Ok(BtcWitnessFundingConfig {
    conversion: fixture_config()?,
    treasury: TreasuryWorkerConfig { chain: chain, providers: providers, test_mode: true }
  })
end
