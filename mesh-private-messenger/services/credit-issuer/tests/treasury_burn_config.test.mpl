from Runtime.TreasuryBurnConfig import parse_burn_config
from Runtime.Treasury import TreasuryWorkerConfig, treasury_provider_hash
from Payment.Treasury import TreasuryChainConfig

fn fixture_worker() -> TreasuryWorkerConfig!String do
  let urls = ["http://127.0.0.1:19301", "http://127.0.0.1:19302"]
  let values = for n in ["11", "12", "13", "14", "15", "16", "17", "18"] do
    Bytes.from_hex(String.repeat(n, 32))?
  end
  Ok(TreasuryWorkerConfig {
    test_mode: true,
    providers: urls,
    chain: TreasuryChainConfig {
      cluster: List.get(values, 0),
      providers_hash: treasury_provider_hash(urls)?,
      mint: List.get(values, 1),
      treasury_owner: List.get(values, 2),
      fee_payer: List.get(values, 3),
      nonce_authority: List.get(values, 4),
      nonce_address: List.get(values, 5),
      rewards_program: List.get(values, 6),
      rewards_pool: List.get(values, 7)
    }
  })
end

fn proof() -> Bool!String do
  let worker = fixture_worker()?
  assert(Option.is_none(parse_burn_config(Map.new(), 1, None)?))
  let values = Map.new()
    |> Map.put("MORSE_BURN_MODE", "test")
    |> Map.put("MESSENGER_TREASURY_BURN_PROGRAM",
      Bytes.to_base58(Bytes.from_hex(String.repeat("21", 32))?))
    |> Map.put("MESSENGER_TREASURY_BURN_GOVERNANCE",
      Bytes.to_base58(Bytes.from_hex(String.repeat("22", 32))?))
    |> Map.put("MESSENGER_TREASURY_BURN_FACTORY",
      Bytes.to_base58(Bytes.from_hex(String.repeat("23", 32))?))
    |> Map.put("MESSENGER_TREASURY_BURN_PROGRAM_SLOT", "0")
  let pins = case parse_burn_config(values, 1, Some(worker))? do
    None -> return Err("missing_burn_pins")
    Some(value) -> value
  end
  assert(pins.usdc.bytes == worker.chain.mint && pins.treasury.bytes == worker.chain.treasury_owner)
  assert(Result.is_err(parse_burn_config(values, 1, None)))
  assert(Result.is_err(parse_burn_config(values, 0, Some(worker))))
  assert(Result.is_err(parse_burn_config(values, 1, Some(%{worker | test_mode: false}))))
  for invalid in ["enabled", "", "TEST", "live"] do
    assert(Result.is_err(parse_burn_config(Map.put(values, "MORSE_BURN_MODE", invalid),
      1,
      Some(worker))))
  end
  for invalid in ["-1", "00", "", "1.0", "18446744073709551616"] do
    assert(Result.is_err(parse_burn_config(Map.put(values,
        "MESSENGER_TREASURY_BURN_PROGRAM_SLOT",
        invalid),
      1,
      Some(worker))))
  end
  for name in ["PROGRAM", "GOVERNANCE", "FACTORY"] do
    assert(Result.is_err(parse_burn_config(Map.put(values,
        "MESSENGER_TREASURY_BURN_" <> name,
        "11111111111111111111111111111111"),
      1,
      Some(worker))))
  end
  Ok(true)
end

test("burn activation stays off by default and binds explicit purpose and separately held treasury custody") do
  let result = proof()
  case result do
    Err(error) -> IO.eprintln(error)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end
