from Transparency.RewardsOperator import RewardOperatorIntent, decode_reward_intent

fn input(action :: String, extra :: String) -> String do
  let key = Bytes.to_base58(Bytes.from_utf8(String.repeat("a", 32)))
  """{"action":"#{action}","program":"#{key}","mint":"#{key}","log":"morse-main","payer":"#{key}","epoch":"2813"#{extra}}"""
end

fn proof() -> Bool!String do
  let key = Bytes.to_base58(Bytes.from_utf8(String.repeat("a", 32)))
  let extra = """, "funder":"#{key}","kind":1,"amount":"18446744073709551615","operation_id":#{Json.encode_string(String.repeat("ab",
    32))}"""
  let valid = decode_reward_intent(input("fund", extra))?
  assert(U64.to_string(valid.amount) == "18446744073709551615")
  assert(Bytes.length(valid.intent_hash) == 32)
  assert(Bytes.secure_equals(valid.intent_hash,
    decode_reward_intent("  " <> input("fund", extra))?.intent_hash))
  for bad in [
    input("withdraw", ""),
    input("fund", ""),
    input("fund", String.replace(extra, "18446744073709551615", "18446744073709551616")),
    input("fund", String.replace(extra, "18446744073709551615", "0")),
    input("fund", String.replace(extra, String.repeat("ab", 32), String.repeat("00", 32))),
    input("fund", String.replace(extra, "\"kind\":1", "\"kind\":\"1\"")),
    input("claim", ",\"row\":64"),
    input("claim", ",\"row\":-1"),
    String.replace(input("settle", ""), "\"2813\"", "2813"),
    String.replace(input("settle", ""), "\"2813\"", "\"02813\"")
  ] do
    case decode_reward_intent(bad) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  assert(decode_reward_intent(input("claim", ",\"row\":63"))?.row == 63)
  Ok(true)
end

test("operator intents preserve exact amounts and reject ambiguous funding or claim authorization") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
