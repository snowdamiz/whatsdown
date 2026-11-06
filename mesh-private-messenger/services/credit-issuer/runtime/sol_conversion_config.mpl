from Runtime.SolConversionNetwork import SolConversionConfig, validate_sol_conversion_config
from Payment.SolConversionPacket import SolConversionProfile
from Payment.Treasury import TreasuryChainConfig
from Solana.Read import pubkey

pub struct SolConversionOperatorConfig do
  database_url :: String
  worker :: SolConversionConfig
end

fn text(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn pin(root :: Json, name :: String) -> Bytes!String do
  Bytes.from_hex(text(root, name)?)
end

# Explicit operator file only. There is no owner key, remote signer, supplied
# transaction route, service registration, default provider, or automatic worker.
pub fn parse_sol_conversion_operator(raw :: String) -> SolConversionOperatorConfig!String do
  if Bytes.length(Bytes.from_utf8(raw)) > 16384 do
    return Err("sol_conversion_config_size")
  end
  let root = Json.parse(raw)?
  if Json.encode(Json.object_get(root, "schema")?) != "1" do
    return Err("sol_conversion_config_version")
  end
  let sources = Json.object_get(root, "providers")?
  if Json.array_length(sources)? != 2 do
    return Err("sol_conversion_provider_quorum")
  end
  let providers = for i in 0..2 do
    Json.as_string(Json.array_get(sources, i)?)?
  end
  let chain = TreasuryChainConfig {
    cluster: pin(root, "cluster")?,
    providers_hash: pin(root, "providers_hash")?,
    mint: pubkey(text(root, "usdc")?)?.bytes,
    treasury_owner: pubkey(text(root, "owner")?)?.bytes,
    fee_payer: pubkey(text(root, "payer")?)?.bytes,
    nonce_authority: pin(root, "nonce_authority")?,
    nonce_address: pin(root, "nonce_address")?,
    rewards_program: pin(root, "rewards_program")?,
    rewards_pool: pin(root, "rewards_pool")?
  }
  let profile = SolConversionProfile {
    treasury_config: pin(root, "treasury_config")?,
    owner: pubkey(text(root, "owner")?)?,
    payer: pubkey(text(root, "payer")?)?,
    usdc: pubkey(text(root, "usdc")?)?,
    pool: pubkey(text(root, "pool")?)?,
    amm_config: pubkey(text(root, "amm_config")?)?,
    authority: pubkey(text(root, "authority")?)?,
    input_vault: pubkey(text(root, "input_vault")?)?,
    output_vault: pubkey(text(root, "output_vault")?)?,
    observation: pubkey(text(root, "observation")?)?,
    oracle: pubkey(text(root, "oracle")?)?,
    amm_hash: pin(root, "amm_hash")?,
    raydium_code: pin(root, "raydium_code")?,
    token_code: pin(root, "token_code")?,
    rent: U64.parse(text(root, "rent")?)?,
    maximum_fee: U64.parse(text(root, "maximum_fee")?)?
  }
  let worker = SolConversionConfig {
    chain: chain,
    profile: profile,
    providers: providers,
    test_mode: Json.as_bool(Json.object_get(root, "owned_loopback_test")?)?
  }
  validate_sol_conversion_config(worker)?
  let database = text(root, "database_url")?
  if database == "" || Bytes.length(Bytes.from_utf8(database)) > 4096 do
    return Err("sol_conversion_database_config")
  end
  Ok(SolConversionOperatorConfig { database_url: database, worker: worker })
end
