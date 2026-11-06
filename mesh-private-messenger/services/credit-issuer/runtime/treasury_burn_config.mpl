from Solana.Read import Pubkey, pubkey
from Transparency.TokenChain import token_addresses
from Runtime.Treasury import TreasuryWorkerConfig
from Transparency.TokenBurnRead import TokenBurnReadPins

pub fn burn_environment_names() -> List<String> do
  [
    "MORSE_BURN_MODE",
    "MESSENGER_TREASURY_BURN_PROGRAM",
    "MESSENGER_TREASURY_BURN_GOVERNANCE",
    "MESSENGER_TREASURY_BURN_PROGRAM_SLOT",
    "MESSENGER_TREASURY_BURN_FACTORY"
  ]
end

fn setting(values :: Map<String, String>, name :: String, fallback :: String) -> String do
  if Map.has_key(values, name) do
    Map.get(values, name)
  else
    fallback
  end
end

fn key(values :: Map<String, String>, name :: String) -> Pubkey!String do
  let value = pubkey(setting(values, "MESSENGER_TREASURY_BURN_" <> name, ""))?
  if Bytes.to_hex(value.bytes) == String.repeat("00", 32) do
    return Err("invalid_treasury_burn_pin")
  end
  Ok(value)
end

pub fn parse_burn_config(values :: Map<String, String>,
  purpose :: Int,
  treasury :: Option<TreasuryWorkerConfig>) -> Option<TokenBurnReadPins>!String do
  let mode = setting(values, "MORSE_BURN_MODE", "off")
  if mode == "off" do
    return Ok(None)
  end
  if !((mode == "test" && purpose == 1) || (mode == "live" && purpose == 0)) do
    return Err("invalid_treasury_burn_mode")
  end
  let worker = case treasury do
    None -> return Err("treasury_burn_requires_pinned_treasury")
    Some(value) -> value
  end
  if worker.test_mode != (purpose == 1) do
    return Err("invalid_treasury_burn_mode")
  end
  let slot = setting(values, "MESSENGER_TREASURY_BURN_PROGRAM_SLOT", "")
  let program = key(values, "PROGRAM")?
  let parsed = U64.parse(slot)?
  if U64.to_string(parsed) != slot || token_addresses(program)?.mint.bytes == worker.chain.mint do
    return Err("invalid_treasury_burn_pin")
  end
  Ok(Some(TokenBurnReadPins {
    program: program,
    governance: key(values, "GOVERNANCE")?,
    program_slot: parsed,
    usdc: Pubkey { bytes: worker.chain.mint },
    treasury: Pubkey { bytes: worker.chain.treasury_owner },
    factory: key(values, "FACTORY")?
  }))
end
