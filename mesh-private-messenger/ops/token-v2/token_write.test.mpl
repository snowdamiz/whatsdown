from Transparency.TokenWrite import (
  TokenRewardWriteContext,
  token_reward_write_addresses,
  token_reserve_configure_instruction,
  token_reward_activate_instruction,
  token_reward_open_instruction,
  token_reward_begin_instruction,
  token_reward_append_instruction,
  token_reward_finalize_instruction,
  token_reward_claim_instruction,
  token_reward_claim_setup_instruction,
  token_reward_claim_usdc_instruction,
  token_reward_claim_usdc_setup_instruction,
  token_reward_cancel_instruction
)
from Solana.Read import Pubkey, pubkey, pubkey_string
from Solana.Tx import Instruction, instruction_report_json
from Transparency.RewardsWrite import RewardAppendWitness
from Transparency.Merkle import WitnessKey
from Transparency.TokenRewards import decode_token_reward_epoch

fn field(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn raw(accounts :: Json, name :: String) -> Bytes!String do
  Bytes.from_hex(field(Json.object_get(accounts, name)?, "data_hex")?)
end

fn compare(actual :: Instruction, expected :: Json) -> Bool!String do
  let report = Json.parse(instruction_report_json(actual))?
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
    let actual_field = Json.encode(Json.object_get(report, key)?)
    let expected_field = Json.encode(Json.object_get(expected, key)?)
    if actual_field != expected_field do
      IO.eprintln("MORSE_TOKEN_WRITE_DIFF "
        <> key
        <> " actual="
        <> actual_field
        <> " expected="
        <> expected_field)
    end
    assert(actual_field == expected_field)
  end
  Ok(true)
end

fn final_snapshot(root :: Json) -> Json!String do
  let snapshots = Json.object_get(root, "snapshots")?
  for index in 0..Json.array_length(snapshots)? do
    let snapshot = Json.array_get(snapshots, index)?
    if field(snapshot, "name")? == "token-rewards-finalized" do
      return Ok(snapshot)
    end
  end
  Err("missing_actual_sbf_snapshot")
end

struct TokenWriteExportAccount do
  key :: String
  signer :: Bool
  writable :: Bool
end deriving(Json)

struct TokenWriteExportInstruction do
  program :: String
  data_hex :: String
  accounts :: List<TokenWriteExportAccount>
end deriving(Json)

fn exported(instruction :: Instruction) -> TokenWriteExportInstruction do
  TokenWriteExportInstruction {
    program: pubkey_string(instruction.program_id),
    data_hex: Bytes.to_hex(instruction.data),
    accounts: for item in instruction.accounts do
      TokenWriteExportAccount {
        key: pubkey_string(item.pubkey),
        signer: item.signer,
        writable: item.writable
      }
    end
  }
end

fn vectors() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_TOKEN_CUSTODY_FIXTURES_PATH", ""))?)?
  let vectors = Json.object_get(root, "write_vectors")?
  let context = TokenRewardWriteContext {
    program: pubkey(field(vectors, "program")?)?,
    judge: pubkey(field(vectors, "judge")?)?,
    token: pubkey(field(vectors, "token")?)?,
    log_name: field(vectors, "log_name")?,
    usdc_mint: pubkey(field(vectors, "mint")?)?
  }
  let epoch = U64.parse(field(vectors, "epoch")?)?
  let payer = pubkey(field(vectors, "payer")?)?
  let governance = pubkey(field(vectors, "governance")?)?
  let root_cohort = Json.object_get(vectors, "cohort")?
  let cohort = for index in 0..Json.array_length(root_cohort)? do
    let item = Json.array_get(root_cohort, index)?
    RewardAppendWitness {
      witness: pubkey(field(item, "witness")?)?,
      key: WitnessKey {
        witness_id: field(item, "id")?,
        public_key: Bytes.from_hex(field(item, "key_hex")?)?
      }
    }
  end
  let first = token_reward_append_instruction(context, epoch, List.take(cohort, 1))?
  let other = for index in 0..21 do
    token_reward_append_instruction(context, epoch, List.take(List.drop(cohort, 1 + index * 3), 3))?
  end
  let appends = [first] ++ other
  let append_vectors = Json.object_get(vectors, "append")?
  assert(List.length(appends) == Json.array_length(append_vectors)?)
  for index in 0..List.length(appends) do
    compare(List.get(appends, index), Json.array_get(append_vectors, index)?)?
  end
  let fixed = [
    token_reserve_configure_instruction(context, governance, payer)?,
    token_reward_activate_instruction(context, governance, payer)?,
    token_reward_open_instruction(context, payer, epoch)?,
    token_reward_begin_instruction(context, epoch)?,
    token_reward_finalize_instruction(context, payer, epoch)?,
    token_reward_cancel_instruction(context, epoch)?
  ]
  for index in 0..List.length(fixed) do
    let name = List.get(["reserve_configure", "activate", "open", "begin", "finalize", "cancel"],
      index)
    compare(List.get(fixed, index), Json.object_get(vectors, name)?)?
  end
  let snapshot = final_snapshot(root)?
  let accounts = Json.object_get(snapshot, "accounts")?
  let record = decode_token_reward_epoch(raw(accounts, "epoch")?, raw(accounts, "token_epoch")?)?
  let positive = List.filter(for index in 0..List.length(record.rows) do
      if List.get(record.rows, index).amount_morse != U64.parse("0")? do
        index
      else
        -1
      end
    end,
    fn(index) do index >= 0 end)
  let claims = for row in positive do
    token_reward_claim_instruction(context, record, row)?
  end
  let claim_vectors = Json.object_get(vectors, "claim")?
  assert(List.length(claims) == 2 && Json.array_length(claim_vectors)? == 2)
  for index in 0..2 do
    compare(List.get(claims, index), Json.array_get(claim_vectors, index)?)?
  end
  assert(Result.is_err(token_reward_append_instruction(context, epoch, List.new())))
  assert(Result.is_err(token_reward_append_instruction(context, epoch, List.take(cohort, 4))))
  assert(Result.is_err(token_reward_append_instruction(context,
    epoch,
    List.reverse(List.take(cohort, 3)))))
  let subject = List.head(cohort)
  assert(Result.is_err(token_reward_append_instruction(context,
    epoch,
    [%{subject | witness: payer}])))
  assert(Result.is_err(token_reward_claim_instruction(context, record, 64)))
  assert(Result.is_err(token_reward_claim_instruction(context,
    %{record | ledger: payer.bytes},
    List.head(positive))))
  let addresses = token_reward_write_addresses(context, epoch)?
  assert(Result.is_err(token_reward_begin_instruction(%{context | usdc_mint: addresses.morse},
    epoch)))
  assert(Result.is_err(token_reward_begin_instruction(%{context | token: context.judge}, epoch)))
  let dollar_claims = for row in positive do
    token_reward_claim_usdc_instruction(context, record, row)?
  end
  let dollar_vectors = Json.object_get(vectors, "claim_usdc")?
  for index in 0..List.length(dollar_claims) do
    compare(List.get(dollar_claims, index), Json.array_get(dollar_vectors, index)?)?
  end
  let setup = token_reward_claim_setup_instruction(context, payer, record, List.head(positive))?
  let dollar_setup = token_reward_claim_usdc_setup_instruction(context,
    payer,
    record,
    List.head(positive))?
  compare(setup, Json.object_get(vectors, "claim_setup")?)?
  compare(dollar_setup, Json.object_get(vectors, "claim_usdc_setup")?)?
  let output = Env.get("MORSE_TOKEN_WRITE_INSTRUCTIONS_PATH", "")
  if output != "" do
    File.write(output,
      Json.encode(json {
        instructions: for instruction in fixed
          ++ appends
          ++ claims
          ++ dollar_claims
          ++ [setup, dollar_setup] do
          exported(instruction)
        end
      }))?
  end
  Ok(true)
end

test("v2 reward instruction bytes and role flags match independent executed Rust SDK vectors") do
  assert(vectors() == Ok(true))
end
