from Tests.SolConversionFixture import conversion_fixture_config, conversion_fixture_text
from Runtime.SolConversionNetwork import validate_sol_conversion_config, read_sol_conversion

fn cases() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_SOL_CONVERSION_BANK", ""))?)?
  let config = conversion_fixture_config(root)?
  let id = Bytes.from_hex(conversion_fixture_text(root, "id")?)?
  validate_sol_conversion_config(config)?
  let mode = Env.get("MORSE_SOL_CONVERSION_MODE", "")
  File.write(mode, "normal")?
  let first = read_sol_conversion(config, id, None)?
  assert(first.hash_valid && first.bank.usd_micros == U64.parse("150000000")?)
  for invalid in ["stale", "code", "disagree", "height"] do
    File.write(mode, invalid)?
    assert(Result.is_err(read_sol_conversion(config, id, None)))
  end
  File.write(mode, "expired")?
  assert(!read_sol_conversion(config, id, None)?.hash_valid)
  File.write(mode, "normal")?
  assert(Result.is_err(validate_sol_conversion_config(%{config |
    providers: [List.get(config.providers, 0), List.get(config.providers, 0)]
  })))
  assert(Result.is_err(validate_sol_conversion_config(%{config |
    profile: %{config.profile | treasury_config: Crypto.sha256(Bytes.from_utf8("other treasury"))}
  })))
  Ok(true)
end

test("conversion native RPC admits exact finalized same-bank quorum and refuses stale oracle/code/disagreement") do
  case cases() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
