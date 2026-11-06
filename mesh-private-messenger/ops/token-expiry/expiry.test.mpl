from Transparency.TokenBurnExpiry import (
  decode_token_burn_unfunded_week,
  decode_token_burn_expiry_receipt,
  match_token_burn_unfunded,
  token_burn_expire_instruction
)
from Transparency.TokenBurn import decode_token_burn_profile
from Solana.Read import pubkey
from Solana.Tx import instruction_report_json

struct ExpiryWriterAccount do
  key :: String
  signer :: Bool
  writable :: Bool
end deriving(Json)

struct ExpiryWriterInstruction do
  program :: String
  data_hex :: String
  accounts :: List<ExpiryWriterAccount>
end deriving(Json)

fn field(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn account(root :: Json, index :: Int) -> Bytes!String do
  Bytes.from_hex(field(Json.array_get(Json.object_get(root, "accounts")?, index)?, "data_hex")?)
end

fn replace(data :: Bytes, at :: Int, part :: Bytes) -> Bytes!String do
  Bytes.from_hex(Bytes.to_hex(Bytes.slice(data, 0, at)?)
    <> Bytes.to_hex(part)
    <> Bytes.to_hex(Bytes.slice(data,
      at + Bytes.length(part),
      Bytes.length(data) - at - Bytes.length(part))?))
end

fn proof() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_TOKEN_EXPIRY_FIXTURES_PATH",
    "ops/token-expiry/fixtures/tombstone.json"))?)?
  let program = pubkey(field(root, "program")?)?
  let payer = pubkey(field(root, "payer")?)?
  let epoch = U64.parse(field(root, "epoch")?)?
  let profile = account(root, 2)?
  let raw = account(root, 5)?
  let receipt = account(root, 6)?
  let week = match_token_burn_unfunded(program, profile, epoch, raw, receipt)?
  assert(week.epoch == epoch && week.expired_at == week.funding_deadline)
  let decoded = decode_token_burn_expiry_receipt(receipt)?
  assert(decoded.tombstone_hash == Crypto.sha256(raw)
    && decoded.profile_hash == Crypto.sha256(profile))
  let instruction = token_burn_expire_instruction(program,
    payer,
    decode_token_burn_profile(profile)?,
    epoch)?
  let expected = Json.object_get(root, "instruction")?
  let report = Json.parse(instruction_report_json(instruction))?
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
  assert(Result.is_err(decode_token_burn_unfunded_week(Bytes.slice(raw, 0, 191)?)))
  assert(Result.is_err(decode_token_burn_expiry_receipt(Bytes.concat(receipt,
    Bytes.from_hex("00")?)?)))
  for at in [0, 3, 4, 36, 68, 100, 132, 140, 148, 156, 188] do
    let altered = replace(raw,
      at,
      Bytes.write_uint_le(Int.to_string((Bytes.get(raw, at)? + 1) % 256), 1)?)?
    assert(Result.is_err(match_token_burn_unfunded(program, profile, epoch, altered, receipt)))
  end
  for at in [0, 3, 4, 36, 68, 100, 132, 164, 172, 180, 188, 220, 252] do
    let altered = replace(receipt,
      at,
      Bytes.write_uint_le(Int.to_string((Bytes.get(receipt, at)? + 1) % 256), 1)?)?
    assert(Result.is_err(match_token_burn_unfunded(program, profile, epoch, raw, altered)))
  end
  assert(Result.is_err(match_token_burn_unfunded(program,
    profile,
    U64.add(epoch, U64.parse("1")?)?,
    raw,
    receipt)))
  assert(Result.is_err(token_burn_expire_instruction(program,
    payer,
    decode_token_burn_profile(profile)?,
    U64.parse("18446744073709551615")?)))
  assert(Result.is_err(token_burn_expire_instruction(program,
    %{payer | bytes: Bytes.from_hex(String.repeat("00", 32))?},
    decode_token_burn_profile(profile)?,
    epoch)))
  let target = Env.get("MORSE_TOKEN_EXPIRY_INSTRUCTIONS_PATH", "")
  if target != "" do
    File.write(target,
      Json.encode(json {
        instructions: [
          ExpiryWriterInstruction {
            program: Bytes.to_base58(instruction.program_id.bytes),
            data_hex: Bytes.to_hex(instruction.data),
            accounts: for a in instruction.accounts do
              ExpiryWriterAccount {
                key: Bytes.to_base58(a.pubkey.bytes),
                signer: a.signer,
                writable: a.writable
              }
            end
          }
        ]
      }))?
  end
  IO.eprintln("MORSE_TOKEN_EXPIRY_CODEC actual_sbf_pair_and_exact7_sdk_roles_bound_rejects_mutated_fields_padding_time_context")
  Ok(true)
end

test("permanent unfunded burn codecs and seven-role writer match actual SBF and reject changed subjects") do
  let result = proof()
  case result do
    Err(error) -> IO.eprintln(error)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end
