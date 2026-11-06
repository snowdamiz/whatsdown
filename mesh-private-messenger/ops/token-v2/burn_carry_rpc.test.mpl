from BurnCarryFixture import token_burn_carry_fixture
from Transparency.TokenBurnCarryRead import read_token_burn_carry_from, read_token_burn_carry_quorum

fn actual_rpc() -> Bool!String do
  let base = Env.get("MORSE_TOKEN_CARRY_RPC", "")
  if base == "" do
    return Ok(true)
  end
  let f = token_burn_carry_fixture("legacy-closed")?
  let client = Http.client()
  let state = read_token_burn_carry_from(client, base <> "/good", f.pins, f.epoch, f.snapshot.slot)?
  assert(state.code_current
    && state.remaining == U64.parse("0")?
    && state.week_surplus == U64.parse("17")?
    && state.carry_surplus == U64.parse("19")?)
  for path in [
    "wrong-id",
    "failure",
    "stale",
    "numeric-string",
    "wrong-owner",
    "reordered",
    "missing",
    "bad-receipt",
    "bad-carry",
    "insufficient-carry",
    "bad-mint",
    "wrong-space",
    "truncated",
    "oversized",
    "redirect"
  ] do
    assert(Result.is_err(read_token_burn_carry_from(client,
      base <> "/" <> path,
      f.pins,
      f.epoch,
      f.snapshot.slot)))
  end
  assert(Result.is_err(read_token_burn_carry_from(client,
    base <> "/retry",
    f.pins,
    f.epoch,
    f.snapshot.slot)))
  assert(read_token_burn_carry_from(client,
    base <> "/retry",
    f.pins,
    f.epoch,
    f.snapshot.slot)?.receipt == state.receipt)
  assert(read_token_burn_carry_quorum(client,
    [base <> "/good-a", base <> "/wrong-owner-a", base <> "/good-b"],
    true,
    f.pins,
    f.epoch,
    f.snapshot.slot)?.digest == state.digest)
  assert(Result.is_err(read_token_burn_carry_quorum(client,
    [base <> "/good-c", base <> "/wrong-owner-a", base <> "/wrong-owner-b"],
    true,
    f.pins,
    f.epoch,
    f.snapshot.slot)))
  assert(Result.is_err(read_token_burn_carry_quorum(client,
    [base <> "/good-d", base <> "/donation-a", base <> "/donation-b"],
    true,
    f.pins,
    f.epoch,
    f.snapshot.slot)))
  assert(!read_token_burn_carry_quorum(client,
    [base <> "/good-e", base <> "/upgrade-a", base <> "/upgrade-b"],
    true,
    f.pins,
    f.epoch,
    f.snapshot.slot)?.code_current)
  assert(Result.is_err(read_token_burn_carry_quorum(client,
    [base <> "/good", base <> "/good", base <> "/good"],
    true,
    f.pins,
    f.epoch,
    f.snapshot.slot)))
  assert(Result.is_err(read_token_burn_carry_quorum(client,
    [base <> "/good", base <> "/good-a", base <> "/good-b"],
    false,
    f.pins,
    f.epoch,
    f.snapshot.slot)))
  Http.client_close(client)
  IO.eprintln("MORSE_TOKEN_BURN_CARRY_RPC finalized12_roles_quorum_no_market_dependency")
  Ok(true)
end

test("bounded finalized carry RPC rejects substitution and disagreement") do
  let result = actual_rpc()
  case result do
    Err(error) -> IO.eprintln(error)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end
