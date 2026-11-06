from Payment.Treasury import TreasuryChainConfig, treasury_config_hash
from Runtime.Treasury import TreasuryWorkerConfig, treasury_provider_hash
from Solana.Read import Pubkey, pubkey
from Transparency.RewardsChain import reward_pool_address

fn setting(values :: Map<String, String>, name :: String, fallback :: String) -> String do
  if Map.has_key(values, name) do
    Map.get(values, name)
  else
    fallback
  end
end

fn treasury_endpoint(value :: String, test_mode :: Bool) -> String!String do
  let origin = Http.url_origin(value)?
  if String.length(value) > 2048
    || String.contains(value, "@")
    || String.contains(value, "#")
    || String.contains(value, "\\")
    || (!String.starts_with(value, "https://")
      && !(test_mode
        && (String.starts_with(origin, "http://127.0.0.1:")
          || String.starts_with(origin, "http://localhost:")))) do
    return Err("invalid_treasury_endpoint")
  end
  Ok(value)
end

fn pin(values :: Map<String, String>, name :: String) -> Bytes!String do
  Ok(pubkey(setting(values, "MESSENGER_TREASURY_" <> name, ""))?.bytes)
end

pub fn treasury_environment_names() -> List<String> do
  [
    "MORSE_TREASURY_MODE",
    "MESSENGER_TREASURY_GENESIS",
    "MESSENGER_TREASURY_OWNER",
    "MESSENGER_TREASURY_FEE_PAYER",
    "MESSENGER_TREASURY_NONCE_AUTHORITY",
    "MESSENGER_TREASURY_NONCE_ACCOUNT",
    "MESSENGER_TREASURY_REWARDS_PROGRAM",
    "MESSENGER_TREASURY_REWARDS_POOL",
    "MESSENGER_TREASURY_RPC_A",
    "MESSENGER_TREASURY_RPC_B"
  ]
end

# Settlement is independent of new quote issuance. Turning purchases off must
# not strand a previously paid deposit or a pending original-payer refund.
pub fn parse_treasury_config(values :: Map<String, String>,
  purpose :: Int,
  mint :: Bytes) -> Option<TreasuryWorkerConfig>!String do
  let mode = setting(values, "MORSE_TREASURY_MODE", "off")
  if mode == "off" do
    return Ok(None)
  end
  if !((mode == "test" && purpose == 1) || (mode == "live" && purpose == 0)) do
    return Err("invalid_treasury_mode")
  end
  let first = treasury_endpoint(setting(values, "MESSENGER_TREASURY_RPC_A", ""), purpose == 1)?
  let second = treasury_endpoint(setting(values, "MESSENGER_TREASURY_RPC_B", ""), purpose == 1)?
  if Http.url_origin(first)? == Http.url_origin(second)? do
    return Err("treasury_provider_origins_must_be_distinct")
  end
  let providers = [first, second]
  let chain = TreasuryChainConfig {
    cluster: pin(values, "GENESIS")?,
    providers_hash: treasury_provider_hash(providers)?,
    mint: mint,
    treasury_owner: pin(values, "OWNER")?,
    fee_payer: pin(values, "FEE_PAYER")?,
    nonce_authority: pin(values, "NONCE_AUTHORITY")?,
    nonce_address: pin(values, "NONCE_ACCOUNT")?,
    rewards_program: pin(values, "REWARDS_PROGRAM")?,
    rewards_pool: pin(values, "REWARDS_POOL")?
  }
  treasury_config_hash(chain)?
  if !Bytes.secure_equals(reward_pool_address(Pubkey { bytes: chain.rewards_program })?.bytes,
    chain.rewards_pool) do
    return Err("treasury_rewards_pool_mismatch")
  end
  Ok(Some(TreasuryWorkerConfig { chain: chain, providers: providers, test_mode: purpose == 1 }))
end
