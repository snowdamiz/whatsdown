from Transparency.TokenBurn import decode_token_burn_profile
from Transparency.TokenBurnRead import (
  TokenBurnReadPins,
  read_token_burn_from,
  read_token_burn_quorum
)
from Transparency.TokenChain import decode_token_config
from Solana.Read import pubkey

fn rpc_text(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn exercise_burn_transport() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_TOKEN_BURN_FIXTURES_PATH", ""))?)?
  let profile = decode_token_burn_profile(Bytes.from_hex(rpc_text(root, "profile_hex")?)?)?
  let config = decode_token_config(Bytes.from_hex(rpc_text(root, "config_hex")?)?)?
  let pins = TokenBurnReadPins {
    program: pubkey(rpc_text(root, "program")?)?,
    governance: config.governance,
    program_slot: U64.parse("0")?,
    usdc: profile.usdc,
    treasury: profile.treasury,
    factory: profile.factory
  }
  let epoch = U64.parse(rpc_text(Json.array_get(Json.object_get(root, "weeks")?, 3)?, "epoch")?)?
  let slot = U64.parse(rpc_text(root, "context_slot")?)?
  let base = Env.get("MORSE_TOKEN_TEST_RPC", "")
  if base == "" do
    return Err("MORSE_TOKEN_TEST_RPC is required; run scripts/prove-token.sh")
  end
  let client = Http.client()
  let result = read_token_burn_from(client, base <> "/good", pins, epoch, slot)
  for path in [
    "wrong-id",
    "failure",
    "stale",
    "wrong-owner",
    "reordered",
    "missing",
    "redirect",
    "oversized",
    "numeric-string"
  ] do
    assert(Result.is_err(read_token_burn_from(client, base <> "/" <> path, pins, epoch, slot)))
  end
  assert(Result.is_err(read_token_burn_from(client, base <> "/retry", pins, epoch, slot)))
  let retried = read_token_burn_from(client, base <> "/retry", pins, epoch, slot)?
  let good = result?
  assert(retried.digest == good.digest)
  let paused = read_token_burn_from(client, base <> "/paused", pins, epoch, slot)?
  assert(!paused.code_current && paused.week == good.week)
  let agreed = read_token_burn_quorum(client,
    [base <> "/good-a", base <> "/wrong-owner", base <> "/good-b"],
    true,
    pins,
    epoch,
    slot)?
  assert(agreed.digest == good.digest)
  assert(Result.is_err(read_token_burn_quorum(client,
    [base <> "/good-a", base <> "/paused", base <> "/failure"],
    true,
    pins,
    epoch,
    slot)))
  assert(Result.is_err(read_token_burn_quorum(client,
    [base <> "/good", base <> "/good", base <> "/good"],
    true,
    pins,
    epoch,
    slot)))
  assert(Result.is_err(read_token_burn_quorum(client,
    [base <> "/good-a", base <> "/good-b", base <> "/good-c"],
    false,
    pins,
    epoch,
    slot)))
  Http.client_close(client)
  Ok(true)
end

test("Actual bounded finalized RPC transport rejects equivocation and agrees on authenticated local SBF burn receipts") do
  let result = exercise_burn_transport()
  case result do
    Err(reason) -> println(reason)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end
