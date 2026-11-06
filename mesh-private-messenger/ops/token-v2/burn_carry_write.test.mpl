from Transparency.TokenBurn import decode_token_burn_profile
from Transparency.TokenBurnCarry import decode_token_burn_carry_frame
from Transparency.TokenBurnWrite import token_burn_execute_instruction
from Transparency.TokenBurnCarryWrite import (
  token_burn_close_instruction,
  token_burn_fund_v2_instruction
)
from Solana.Read import pubkey, pubkey_string
from Solana.Tx import Instruction, instruction_report_json

struct CarryWriteAccount do
  key :: String
  signer :: Bool
  writable :: Bool
end deriving(Json)

struct CarryWriteInstruction do
  program :: String
  data_hex :: String
  accounts :: List<CarryWriteAccount>
end deriving(Json)

fn field(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn exported(ix :: Instruction) -> CarryWriteInstruction do
  CarryWriteInstruction {
    program: pubkey_string(ix.program_id),
    data_hex: Bytes.to_hex(ix.data),
    accounts: for a in ix.accounts do
      CarryWriteAccount { key: pubkey_string(a.pubkey), signer: a.signer, writable: a.writable }
    end
  }
end

fn vectors() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_TOKEN_CARRY_FIXTURES_PATH", ""))?)?
  let snapshots = Json.object_get(root, "snapshots")?
  let first = Json.array_get(snapshots, 0)?
  let accounts = Json.object_get(first, "accounts")?
  let profile = decode_token_burn_profile(Bytes.from_hex(field(Json.array_get(accounts, 2)?,
    "data_hex")?)?)?
  let program = pubkey(field(first, "program")?)?
  let payer = pubkey(field(first, "payer")?)?
  let epoch = U64.parse(field(first, "epoch")?)?
  let weights = for index in 0..24 do
    U64.parse("1")?
  end
  let entropy = for index in 0..24 do
    U64.parse(Int.to_string(index * 999999))?
  end
  let two = U64.add(epoch, U64.parse("1")?)?
  let three = U64.add(two, U64.parse("1")?)?
  let four = U64.add(three, U64.parse("1")?)?
  let expected = Json.object_get(root, "instructions")?
  let mixed = Json.array_get(snapshots, 2)?
  let mixed_accounts = Json.object_get(mixed, "accounts")?
  let mixed_frame = decode_token_burn_carry_frame(Bytes.from_hex(field(Json.array_get(mixed_accounts,
      5)?,
    "data_hex")?)?)?
  let execute_sdk = Json.object_get(Json.array_get(expected, 3)?, "instruction")?
  let route = Bytes.slice(Bytes.from_base64(field(execute_sdk, "dataBase64")?)?, 2, 39)?
  let actual = [
    token_burn_fund_v2_instruction(program,
      payer,
      profile,
      epoch,
      U64.parse("24000000")?,
      U64.parse("0")?,
      weights,
      entropy)?,
    token_burn_close_instruction(program, payer, profile, epoch)?,
    token_burn_fund_v2_instruction(program,
      payer,
      profile,
      two,
      U64.parse("120000000")?,
      U64.parse("120000000")?,
      weights,
      entropy)?,
    token_burn_execute_instruction(program,
      payer,
      profile,
      mixed_frame.week,
      0,
      route,
      U64.parse("2000000")?)?,
    token_burn_close_instruction(program, payer, profile, two)?,
    token_burn_close_instruction(program, payer, profile, three)?,
    token_burn_fund_v2_instruction(program,
      payer,
      profile,
      four,
      U64.parse("0")?,
      U64.parse("240000000")?,
      weights,
      entropy)?
  ]
  let positions = [0, 1, 2, 3, 4, 5, 6]
  for index in 0..List.length(actual) do
    let report = Json.parse(instruction_report_json(List.get(actual, index)))?
    let sdk = Json.object_get(Json.array_get(expected, List.get(positions, index))?, "instruction")?
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
      assert(Json.encode(Json.object_get(report, key)?) == Json.encode(Json.object_get(sdk, key)?))
    end
  end
  assert(Result.is_err(token_burn_fund_v2_instruction(program,
    payer,
    profile,
    four,
    U64.parse("0")?,
    U64.parse("0")?,
    weights,
    entropy)))
  assert(Result.is_err(token_burn_fund_v2_instruction(program,
    payer,
    profile,
    four,
    U64.parse("18446744073709551615")?,
    U64.parse("1")?,
    weights,
    entropy)))
  assert(Result.is_err(token_burn_fund_v2_instruction(program,
    payer,
    profile,
    four,
    U64.parse("24")?,
    U64.parse("0")?,
    List.take(weights, 23),
    entropy)))
  let target = Env.get("MORSE_TOKEN_CARRY_INSTRUCTIONS_PATH", "")
  if target != "" do
    File.write(target,
      Json.encode(json {
        instructions: for ix in actual do
          exported(ix)
        end
      }))?
  end
  IO.eprintln("MORSE_TOKEN_CARRY_WRITERS exact_sdk_roles_v1_v2_cash_carry_signer")
  Ok(true)
end

test("carry writers match independent complete SDK instruction reports") do
  if Env.get("MORSE_TOKEN_CARRY_FIXTURES_PATH", "") == "" do
    assert(true)
  else
    let result = vectors()
    case result do
      Err(error) -> IO.eprintln(error)
      Ok(_) -> nil
    end
    assert(result == Ok(true))
  end
end
