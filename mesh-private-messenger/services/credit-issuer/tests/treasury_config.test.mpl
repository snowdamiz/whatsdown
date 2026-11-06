from Runtime.TreasuryConfig import parse_treasury_config
from Runtime.Treasury import treasury_provider_hash
from Transparency.RewardsChain import reward_pool_address
from Solana.Read import Pubkey

fn treasury_settings() -> Map<String, String> do
  let names = [
    "GENESIS",
    "OWNER",
    "FEE_PAYER",
    "NONCE_AUTHORITY",
    "NONCE_ACCOUNT",
    "REWARDS_PROGRAM",
    "REWARDS_POOL"
  ]
  let entries = for index in 0..List.length(names) do
    ("MESSENGER_TREASURY_" <> List.get(names, index),
      Bytes.to_base58(Bytes.from_utf8(String.repeat(Int.to_string(index + 1), 32))))
  end
  let pool = case reward_pool_address(Pubkey { bytes: Bytes.from_utf8(String.repeat("6", 32)) }) do
    Ok(value) -> Bytes.to_base58(value.bytes)
    Err(_) -> ""
  end
  Map.from_list(entries)
    |> Map.put("MESSENGER_TREASURY_REWARDS_POOL", pool)
    |> Map.put("MORSE_TREASURY_MODE", "test")
    |> Map.put("MESSENGER_TREASURY_RPC_A", "http://127.0.0.1:19001")
    |> Map.put("MESSENGER_TREASURY_RPC_B", "http://localhost:19002/rpc")
end

test("treasury is independently disabled by default and active mode pins two distinct RPC origins") do
  let mint = Bytes.from_utf8(String.repeat("m", 32))
  assert(parse_treasury_config(Map.new(), 1, mint) == Ok(None))
  let values = treasury_settings()
  case parse_treasury_config(values, 1, mint) do
    Ok(Some(value)) -> do
      assert(value.test_mode)
      assert(Bytes.secure_equals(value.chain.mint, mint))
      assert(treasury_provider_hash(value.providers) == Ok(value.chain.providers_hash))
    end
    _ -> assert(false)
  end
  assert(Result.is_err(parse_treasury_config(values, 0, mint)))
  assert(Result.is_err(parse_treasury_config(Map.put(values, "MORSE_TREASURY_MODE", "enabled"),
    1,
    mint)))
  for invalid in [
    "http://127.0.0.1:19001/other",
    "https://user:secret@rpc.example",
    "https://rpc.example/#fragment",
    "https://rpc.example\\@elsewhere",
    "http://127.0.0.1.evil:19002",
    "http://rpc.example"
  ] do
    assert(Result.is_err(parse_treasury_config(Map.put(values, "MESSENGER_TREASURY_RPC_B", invalid),
      1,
      mint)))
  end
  let live = values
    |> Map.put("MORSE_TREASURY_MODE", "live")
    |> Map.put("MESSENGER_TREASURY_RPC_A", "https://rpc-a.example/v1?key=test")
    |> Map.put("MESSENGER_TREASURY_RPC_B", "https://rpc-b.example/v1")
  assert(Result.is_ok(parse_treasury_config(live, 0, mint)))
  assert(Result.is_err(parse_treasury_config(Map.put(live,
      "MESSENGER_TREASURY_RPC_B",
      "http://localhost:19002"),
    0,
    mint)))
  assert(Result.is_err(parse_treasury_config(Map.put(values,
      "MESSENGER_TREASURY_OWNER",
      String.repeat("1", 32)),
    1,
    mint)))
  assert(Result.is_err(parse_treasury_config(Map.put(values,
      "MESSENGER_TREASURY_REWARDS_POOL",
      Map.get(values, "MESSENGER_TREASURY_OWNER")),
    1,
    mint)))
  assert(Result.is_err(parse_treasury_config(Map.put(values,
      "MESSENGER_TREASURY_NONCE_ACCOUNT",
      Map.get(values, "MESSENGER_TREASURY_FEE_PAYER")),
    1,
    mint)))
end
