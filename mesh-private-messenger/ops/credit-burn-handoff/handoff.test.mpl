from Payment.TreasuryBurnHandoff import (
  CreditBurnAllocation,
  prepare_credit_burn_handoff,
  match_credit_burn_handoff_frame
)
from Payment.RevenuePolicy import credit_revenue_policy_hash
from Transparency.TokenBurn import decode_token_burn_profile
from Solana.Read import pubkey
from Solana.Tx import instruction_report_json

fn field(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn bytes(root :: Json) -> Bytes!String do
  Bytes.from_hex(field(root, "data_hex")?)
end

fn data(root :: Json, index :: Int) -> Bytes!String do
  bytes(Json.array_get(Json.object_get(root, "accounts")?, index)?)
end

fn proof() -> Bool!String do
  let fixture = Json.parse(File.read(Env.get("MORSE_TOKEN_CARRY_FIXTURES_PATH",
    "ops/credit-burn-handoff/fixtures/carry-accounts.json"))?)?
  let snapshots = Json.object_get(fixture, "snapshots")?
  let snapshot = Json.array_get(snapshots, 2)?
  let profile = decode_token_burn_profile(data(snapshot, 2)?)?
  let program = pubkey(field(snapshot, "program")?)?
  let payer = pubkey(field(snapshot, "payer")?)?
  let epoch = U64.parse(field(snapshot, "epoch")?)?
  let scope = Crypto.sha256(Bytes.from_utf8("credit-burn-handoff-scope"))
  let allocations = for index in [101, 102] do
    CreditBurnAllocation {
      batch_id: U64.parse(Int.to_string(index))?,
      policy_hash: credit_revenue_policy_hash(2)?,
      config_hash: scope,
      mint: profile.usdc,
      amount: U64.parse(if index == 101 do
        "70000000"
      else
        "50000000"
      end)?
    }
  end
  let weights = for _index in 0..24 do
    U64.parse("1")?
  end
  let entropy = for index in 0..24 do
    U64.parse(Int.to_string(index * 999999))?
  end
  let intent = prepare_credit_burn_handoff(scope,
    program,
    payer,
    profile,
    epoch,
    allocations,
    U64.parse("120000000")?,
    weights,
    entropy)?
  assert(intent.cash == U64.parse("120000000")? && intent.carry == U64.parse("120000000")?)
  let instructions = Json.object_get(fixture, "instructions")?
  let expected = Json.object_get(Json.array_get(instructions, 2)?, "instruction")?
  let actual = Json.parse(instruction_report_json(intent.instruction))?
  for key in [
    "schemaVersion",
    "programId",
    "accountCount",
    "accountKeys",
    "signerKeys",
    "writableKeys",
    "dataBase64",
    "dataBytes"
  ] do
    assert(Json.encode(Json.object_get(actual, key)?) == Json.encode(Json.object_get(expected,
        key)?))
  end
  assert(match_credit_burn_handoff_frame(intent, data(snapshot, 5)?, None)?)
  assert(match_credit_burn_handoff_frame(intent, data(Json.array_get(snapshots, 3)?, 5)?, None)?)
  let closed = Json.array_get(snapshots, 4)?
  assert(match_credit_burn_handoff_frame(intent, data(closed, 5)?, Some(data(closed, 9)?))?)
  assert(Result.is_err(match_credit_burn_handoff_frame(intent, data(closed, 5)?, None)))
  assert(Result.is_err(match_credit_burn_handoff_frame(intent,
    data(snapshot, 5)?,
    Some(data(closed, 9)?))))
  assert(Result.is_err(match_credit_burn_handoff_frame(intent,
    data(Json.array_get(snapshots, 1)?, 5)?,
    Some(data(Json.array_get(snapshots, 1)?, 9)?))))
  let changed = Bytes.concat(Bytes.concat(Bytes.slice(data(snapshot, 5)?, 0, 192)?,
      Bytes.from_hex(String.repeat("ff", 32))?)?,
    Bytes.slice(data(snapshot, 5)?, 224, 2016)?)?
  assert(Result.is_err(match_credit_burn_handoff_frame(intent, changed, None)))
  let repeat = prepare_credit_burn_handoff(scope,
    program,
    payer,
    profile,
    epoch,
    allocations,
    U64.parse("120000000")?,
    weights,
    entropy)?
  assert(repeat.intent_id == intent.intent_id && repeat.membership_hash == intent.membership_hash)
  assert(Result.is_err(prepare_credit_burn_handoff(scope,
    program,
    payer,
    profile,
    epoch,
    List.reverse(allocations),
    intent.carry,
    weights,
    entropy)))
  assert(Result.is_err(prepare_credit_burn_handoff(scope,
    program,
    payer,
    profile,
    epoch,
    [List.head(allocations), List.head(allocations)],
    intent.carry,
    weights,
    entropy)))
  assert(Result.is_err(prepare_credit_burn_handoff(scope,
    program,
    payer,
    profile,
    epoch,
    [%{List.head(allocations) | policy_hash: credit_revenue_policy_hash(1)?}],
    intent.carry,
    weights,
    entropy)))
  assert(Result.is_err(prepare_credit_burn_handoff(scope,
    program,
    payer,
    profile,
    epoch,
    [%{List.head(allocations) | config_hash: Crypto.sha256(Bytes.from_utf8("other"))}],
    intent.carry,
    weights,
    entropy)))
  IO.eprintln("MORSE_CREDIT_BURN_HANDOFF actual_sbf_cash_carry_permanent_closed_receipt_and_exact19roles")
  Ok(true)
end

test("burn handoff binds exact reserved policy2 cash and original permanent active or closed funding identity") do
  let result = proof()
  case result do
    Err(error) -> IO.eprintln(error)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end
