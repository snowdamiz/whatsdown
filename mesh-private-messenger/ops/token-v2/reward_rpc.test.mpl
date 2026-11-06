from RewardRead import (
  read_token_reward_from,
  read_token_reward_quorum,
  decode_token_reward_snapshot
)
from RewardIdentities import read_token_reward_append_from, read_token_reward_append_quorum
from RewardKeeper import plan_token_reward_step
from RewardFixture import token_reward_fixture
from Solana.Read import pubkey
from Solana.Tx import instruction_report_json

fn actual_rpc() -> Bool!String do
  let base = Env.get("MORSE_TOKEN_REWARDS_RPC", "")
  if base == "" do
    return Ok(true)
  end
  let f = token_reward_fixture("token-rewards-finalized")?
  let client = Http.client()
  let state = read_token_reward_from(client, base <> "/good", f.pins, f.epoch, f.snapshot.slot)?
  assert(state.code_current
    && state.source_current
    && state.status == "finalized"
    && state.twap == None
    && state.morse_surplus == U64.parse("19")?)
  for path in [
    "/wrong-id",
    "/failure",
    "/stale",
    "/numeric-string",
    "/wrong-owner",
    "/reordered",
    "/missing",
    "/oversized",
    "/redirect",
    "/underfunded",
    "/bad-mint",
    "/bad-receipt",
    "/wrong-space",
    "/truncated",
    "/retry"
  ] do
    assert(Result.is_err(read_token_reward_from(client,
      base <> path,
      f.pins,
      f.epoch,
      f.snapshot.slot)))
  end
  assert(read_token_reward_from(client,
    base <> "/retry",
    f.pins,
    f.epoch,
    f.snapshot.slot)?.digest == state.digest)
  let quorum = read_token_reward_quorum(client,
    [base <> "/good-a", base <> "/wrong-owner-a", base <> "/good-b"],
    true,
    f.pins,
    f.epoch,
    f.snapshot.slot)?
  assert(quorum.digest == state.digest)
  assert(Result.is_err(read_token_reward_quorum(client,
    [base <> "/wrong-owner-b", base <> "/wrong-owner-c", base <> "/good-c"],
    true,
    f.pins,
    f.epoch,
    f.snapshot.slot)))
  let partial_fixture = token_reward_fixture("token-rewards-collecting")?
  let partial = decode_token_reward_snapshot(f.pins,
    f.epoch,
    f.snapshot.slot,
    partial_fixture.snapshot)?
  let keys = read_token_reward_append_quorum(client,
    [base <> "/identity-good-a", base <> "/identity-owner-a", base <> "/identity-good-b"],
    true,
    f.pins.context,
    partial)?
  assert(List.length(keys) == 3)
  for suffix in ["owner", "key", "missing", "reordered", "id"] do
    assert(Result.is_err(read_token_reward_append_from(client,
      base <> "/identity-" <> suffix,
      f.pins.context,
      partial)))
  end
  assert(Result.is_err(read_token_reward_append_quorum(client,
    [base <> "/identity-key-a", base <> "/identity-owner-b", base <> "/identity-good-c"],
    true,
    f.pins.context,
    partial)))
  let raw = Json.parse(File.read(Env.get("MORSE_TOKEN_CUSTODY_FIXTURES_PATH", ""))?)?
  let payer = pubkey(Json.as_string(Json.object_get(Json.object_get(raw, "write_vectors")?,
    "payer")?)?)?
  assert(Result.is_err(read_token_reward_append_quorum(client,
    [base <> "/identity-good", base <> "/identity-good", base <> "/identity-good"],
    true,
    f.pins.context,
    partial)))
  assert(Result.is_err(read_token_reward_append_quorum(client,
    [base <> "/identity-good", base <> "/identity-good-a", base <> "/identity-good-b"],
    false,
    f.pins.context,
    partial)))
  let append = plan_token_reward_step(f.pins.context, payer, f.epoch, partial, keys)?
  assert(append.status == "append" && List.length(append.instructions) == 1)
  let sdk = Json.array_get(Json.object_get(Json.object_get(raw, "write_vectors")?, "append")?, 1)?
  let prepared = Json.parse(instruction_report_json(List.head(append.instructions)))?
  for field in [
    "schemaVersion",
    "programId",
    "accountCount",
    "accountKeys",
    "signerKeys",
    "writableKeys",
    "dataBase64",
    "dataBytes"
  ] do
    assert(Json.encode(Json.object_get(prepared, field)?) == Json.encode(Json.object_get(sdk,
        field)?))
  end
  assert(Result.is_err(read_token_reward_quorum(client,
    [base <> "/good-d", base <> "/donation-a", base <> "/donation-b"],
    true,
    f.pins,
    f.epoch,
    f.snapshot.slot)))
  let paused = read_token_reward_quorum(client,
    [base <> "/good-e", base <> "/upgrade-a", base <> "/upgrade-b"],
    true,
    f.pins,
    f.epoch,
    f.snapshot.slot)?
  assert(!paused.code_current && paused.source_current)
  assert(Result.is_err(read_token_reward_quorum(client,
    [base <> "/good", base <> "/good", base <> "/good"],
    true,
    f.pins,
    f.epoch,
    f.snapshot.slot)))
  assert(Result.is_err(read_token_reward_quorum(client,
    [base <> "/good", base <> "/good-a", base <> "/good-b"],
    false,
    f.pins,
    f.epoch,
    f.snapshot.slot)))
  IO.eprintln("MORSE_TOKEN_REWARDS_FINALIZED_RPC authenticated26_currentPins_separateAssets_quorum")
  Ok(true)
end

test("actual v2 rewards are read through bounded finalized RPC and strict provider agreement") do
  let result = actual_rpc()
  case result do
    Err(error) -> IO.eprintln("MORSE_TOKEN_REWARD_RPC_ERROR " <> error)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end
