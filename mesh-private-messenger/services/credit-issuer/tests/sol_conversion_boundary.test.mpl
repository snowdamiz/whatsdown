from Tests.SolConversionFixture import (
  conversion_fixture_config,
  conversion_fixture_text,
  conversion_fixture_raw_bank
)
from Runtime.SolConversionNetwork import SolConversionConfig, validate_sol_conversion_config
from Runtime.Treasury import treasury_provider_hash
from Payment.Treasury import treasury_config_hash
from Payment.SolConversionBank import admit_sol_conversion_bank

fn rebased(config :: SolConversionConfig,
  urls :: List<String>,
  testing :: Bool) -> SolConversionConfig!String do
  let chain = %{config.chain | providers_hash: treasury_provider_hash(urls)?}
  Ok(%{config |
    chain: chain,
    profile: %{config.profile | treasury_config: treasury_config_hash(chain)?},
    providers: urls,
    test_mode: testing
  })
end

fn eoa_case() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_SOL_CONVERSION_BANK", ""))?)?
  let config = conversion_fixture_config(root)?
  let id = Bytes.from_hex(conversion_fixture_text(root, "id")?)?
  let bank = conversion_fixture_raw_bank(root, config.profile, id)?
  let owner = case List.get(bank.accounts, 0) do
    Some(value) -> value
    None -> return Err("missing_fixture_owner")
  end
  let malformed = %{bank |
    accounts: for i in 0..List.length(bank.accounts) do
      if i == 0 do
        Some(%{owner | data: Bytes.from_hex("00")?})
      else
        List.get(bank.accounts, i)
      end
    end
  }
  assert(Result.is_err(admit_sol_conversion_bank(config.profile, id, malformed)))
  Ok(true)
end

fn mode_case() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_SOL_CONVERSION_BANK", ""))?)?
  let config = conversion_fixture_config(root)?
  let remote = ["https://one.example", "https://two.example"]
  assert(Result.is_err(validate_sol_conversion_config(rebased(config, remote, true)?)))
  assert(Result.is_ok(validate_sol_conversion_config(rebased(config, remote, false)?)))
  Ok(true)
end

fn origins_case() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_SOL_CONVERSION_BANK", ""))?)?
  let config = conversion_fixture_config(root)?
  for urls in [
    ["https://one.example", "https://one.example:443"],
    ["https://ONE.example", "https://two.example"],
    ["https://one.example/path", "https://two.example"],
    ["https://one.example?key=owned", "https://two.example"],
    ["https://name:owned@one.example", "https://two.example"],
    ["http://one.example", "http://two.example"]
  ] do
    assert(Result.is_err(validate_sol_conversion_config(rebased(config, urls, false)?)))
  end
  Ok(true)
end

test("conversion owner/payer admission requires ordinary empty-data system accounts") do
  assert(eoa_case() == Ok(true))
end

test("clock bypass is only available to explicitly owned loopback fixtures") do
  assert(mode_case() == Ok(true))
end

test("canonical distinct origins are checked even after the complete treasury hash is rebound") do
  assert(origins_case() == Ok(true))
end
