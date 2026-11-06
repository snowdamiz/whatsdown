from Transparency.TokenBurn import (
  decode_token_burn_profile,
  decode_token_burn_week,
  token_burn_route_minimum
)
from Transparency.TokenChain import token_addresses
from Transparency.TokenChain import decode_token_config
from Transparency.TokenBurnWrite import (
  token_burn_configure_instruction,
  token_burn_fund_instruction,
  token_burn_execute_instruction
)
from Transparency.TokenPolicy import token_burn_chunks
from Solana.Read import pubkey
from Solana.Tx import Instruction, instruction_report_json

fn field(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn change(data :: Bytes, at :: Int, value :: Bytes) -> Bytes!String do
  Bytes.concat(Bytes.concat(Bytes.slice(data, 0, at)?, value)?,
    Bytes.slice(data, at + Bytes.length(value), Bytes.length(data) - at - Bytes.length(value))?)
end

fn same_instruction(actual :: Instruction, expected :: Json) -> Bool!String do
  let report = Json.parse(instruction_report_json(actual))?
  for name in [
    "schemaVersion",
    "programId",
    "accountCount",
    "accountKeys",
    "signerKeys",
    "writableKeys",
    "dataBase64",
    "dataBytes"
  ] do
    assert(Json.encode(Json.object_get(report, name)?) == Json.encode(Json.object_get(expected,
        name)?))
  end
  Ok(true)
end

fn replay_prepared_burns() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_TOKEN_BURN_FIXTURES_PATH", ""))?)?
  let program = pubkey(field(root, "program")?)?
  let payer = pubkey(field(root, "payer")?)?
  let profile_data = Bytes.from_hex(field(root, "profile_hex")?)?
  let profile = decode_token_burn_profile(profile_data)?
  let config = decode_token_config(Bytes.from_hex(field(root, "config_hex")?)?)?
  let reports = Json.object_get(root, "instructions")?
  same_instruction(token_burn_configure_instruction(program, payer, config, profile)?,
    Json.object_get(reports, "configure")?)?
  let weeks = Json.object_get(root, "weeks")?
  let first = decode_token_burn_week(Bytes.from_hex(field(Json.array_get(weeks, 0)?,
    "data_hex")?)?)?
  let weights = for row in 0..24 do
    U64.parse("1")?
  end
  let entropy = for row in 0..24 do
    U64.parse(Int.to_string(row * 999999))?
  end
  same_instruction(token_burn_fund_instruction(program,
      payer,
      profile,
      first.epoch,
      first.budget,
      weights,
      entropy)?,
    Json.object_get(reports, "fund")?)?
  let executions = Json.object_get(reports, "execute")?
  for index in 0..96 do
    let week = decode_token_burn_week(Bytes.from_hex(field(Json.array_get(weeks, index / 24)?,
      "data_hex")?)?)?
    let expected = Json.array_get(executions, index)?
    let route = Bytes.slice(Bytes.from_base64(field(expected, "dataBase64")?)?, 2, 39)?
    same_instruction(token_burn_execute_instruction(program,
        payer,
        profile,
        week,
        index % 24,
        route,
        U64.parse("2000000")?)?,
      expected)?
    assert(Result.is_err(token_burn_execute_instruction(program,
      payer,
      profile,
      week,
      24,
      route,
      U64.parse("2000000")?)))
  end
  assert(Result.is_err(token_burn_fund_instruction(program,
    payer,
    profile,
    first.epoch,
    first.budget,
    List.take(weights, 23),
    entropy)))
  assert(Result.is_err(token_burn_fund_instruction(program,
    payer,
    profile,
    first.epoch,
    first.budget,
    [U64.parse("4294967296")?] ++ List.drop(weights, 1),
    entropy)))
  let bad_profile = decode_token_burn_profile(change(profile_data, 164, payer.bytes)?)?
  assert(Result.is_err(token_burn_configure_instruction(program, payer, config, bad_profile)))
  assert(Result.is_err(token_burn_fund_instruction(program,
    payer,
    bad_profile,
    first.epoch,
    first.budget,
    weights,
    entropy)))
  Ok(true)
end

fn replay_burns() -> Bool!String do
  let path = Env.get("MORSE_TOKEN_BURN_FIXTURES_PATH", "")
  if path == "" do
    return Err("MORSE_TOKEN_BURN_FIXTURES_PATH is required for actual four-week SBF receipt replay")
  end
  let root = Json.parse(File.read(path)?)?
  assert(field(root, "network")? == "local-sbf-qualification")
  let program = pubkey(field(root, "program")?)?
  let addresses = token_addresses(program)?
  let raw_profile = Bytes.from_hex(field(root, "profile_hex")?)?
  let profile = decode_token_burn_profile(raw_profile)?
  assert(profile.config == addresses.config
    && profile.usdc == pubkey(field(root, "usdc_mint")?)?
    && profile.treasury == pubkey(field(root, "treasury")?)?)
  assert(Result.is_err(decode_token_burn_profile(change(raw_profile, 316, Bytes.from_hex("01")?)?)))
  let weeks = Json.object_get(root, "weeks")?
  assert(Json.array_length(weeks)? == 4)
  let burned = for index in 0..4 do
    let source = Json.array_get(weeks, index)?
    let raw = Bytes.from_hex(field(source, "data_hex")?)?
    let week = decode_token_burn_week(raw)?
    assert(week.profile == pubkey(field(root, "profile_address")?)?
      && week.usdc == profile.usdc
      && week.treasury == profile.treasury)
    assert(week.budget == U64.parse("240000000")?
      && week.spent == week.budget
      && week.completion_mask == U64.parse("16777215")?)
    assert(List.length(week.rows) == 24)
    let weights = for row in 0..24 do
      U64.parse("1")?
    end
    let entropy = for row in 0..24 do
      U64.parse(Int.to_string(row * 999999))?
    end
    let planned = token_burn_chunks(week.budget,
      U64.multiply(week.epoch, U64.parse("604800")?)?,
      weights,
      entropy)?
    for row in 0..24 do
      let actual = List.get(week.rows, row)
      let expected = List.get(planned, row)
      assert(actual.amount == expected.amount
        && actual.window_start == expected.window_start
        && actual.window_end == expected.window_end
        && actual.execute_at == expected.execute_at
        && actual.complete
        && U64.compare(actual.burned, U64.parse("4950000")?) >= 0)
    end
    assert(Result.is_err(decode_token_burn_week(change(raw, 248, Bytes.from_hex("01")?)?)))
    assert(Result.is_err(decode_token_burn_week(change(raw, 227, Bytes.from_hex("01")?)?)))
    assert(Result.is_err(decode_token_burn_week(change(raw,
      296,
      Bytes.from_hex(String.repeat("00", 32))?)?)))
    assert(Result.is_err(decode_token_burn_week(change(raw, 280, Bytes.slice(raw, 272, 8)?)?)))
    week.burned
  end
  let total = List.reduce(burned,
    Ok(U64.parse("0")?),
    fn(value, item) do U64.add(value?, item) end)?
  assert(total == U64.parse(field(root, "total_burned")?)?)
  assert(U64.add(total,
    U64.parse(field(root, "supply_after")?)?)? == U64.parse("1000000000000000")?)
  let transactions = Json.object_get(root, "transactions")?
  assert(Json.array_length(transactions)? == 96)
  let instructions = Json.object_get(Json.object_get(root, "instructions")?, "execute")?
  for index in 0..96 do
    let instruction = Json.array_get(instructions, index)?
    let wire = Bytes.from_base64(field(instruction, "dataBase64")?)?
    assert(token_burn_route_minimum(Bytes.slice(wire, 2, 39)?,
      U64.parse("10000000")?,
      U64.parse("2000000")?)? == U64.parse("4950000")?)
    assert(Result.is_err(token_burn_route_minimum(change(Bytes.slice(wire, 2, 39)?,
        26,
        Bytes.from_hex("01")?)?,
      U64.parse("10000000")?,
      U64.parse("2000000")?)))
  end
  Ok(true)
end

test("Mesh verifies actual four-week SBF burn receipts, complete cash conservation and committed schedules") do
  assert(replay_burns() == Ok(true))
end

test("Mesh prepares all actual Jupiter burn metas and immutable funding intents without forwarding caller accounts") do
  assert(replay_prepared_burns() == Ok(true))
end
