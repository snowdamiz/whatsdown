from Transparency.TokenCollateralWrite import (
  TokenCollateralContext,
  TokenCollateralSubject,
  token_binding_propose_instruction,
  token_binding_activate_instruction,
  token_binding_activate_permissionless_instruction,
  token_collateral_migrate_instruction,
  token_collateral_deposit_instruction,
  token_collateral_activate_pending_instruction,
  token_collateral_assess_instruction,
  token_collateral_request_unbond_instruction,
  token_collateral_withdraw_instruction,
  token_collateral_propose_minimums_instruction,
  token_collateral_activate_minimums_instruction
)
from Transparency.TokenProofWrite import (
  decode_token_prepared_proof,
  token_proof_initialize_instruction,
  token_proof_append_instruction,
  token_proof_seal_instruction,
  token_proof_close_instruction,
  token_proof_signature_instructions,
  token_proof_prepare_instruction,
  token_proof_settle_instruction
)
from Transparency.Merkle import WitnessKey, checkpoint_hash
from Transparency.Fork import ForkProof, ForkTarget, ForkVerdict, decode_fork, fork_hash
from Transparency.Relay import RelayVerification
from Transparency.RelayStage import prepare_relay_stage
from Solana.Read import Pubkey, pubkey, pubkey_string
from Solana.Tx import Instruction, instruction_report_json

fn text(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn key(value :: Json) -> WitnessKey!String do
  Ok(WitnessKey {
    witness_id: text(value, "witness_id")?,
    public_key: Bytes.from_hex(text(value, "public_key")?)?
  })
end

fn optional_key(row :: Json) -> Option<WitnessKey>!String do
  let value = Json.object_get(row, "subject")?
  case Json.object_get(value, "witness_id") do
    Err(_) -> Ok(None)
    Ok(_) -> Ok(Some(key(value)?))
  end
end

fn wide(data :: Bytes, at :: Int) -> U64!String do
  U64.parse(Bytes.read_uint_le(data, at, 8)?)
end

fn fixture_preparation(row :: Json,
  context :: TokenCollateralContext,
  payer :: Pubkey,
  submitter :: Pubkey,
  wire :: Bytes) -> List<Instruction>!String do
  let proof = decode_fork(wire)?
  let selected = Json.object_get(row, "keys")?
  let keys = for at in 0..Json.array_length(selected)? do
    key(Json.array_get(selected, at)?)?
  end
  let verified = RelayVerification {
    proof: wire,
    proof_hash: fork_hash(proof)?,
    finder: proof.finder,
    verdict: ForkVerdict { service_public_key: proof.service_public_key, witnesses: keys },
    service_slashed: false,
    context_slot: U64.parse("0")?,
    anchor_header: Bytes.empty(),
    anchor_entry: Bytes.empty(),
    witness_set: Bytes.empty(),
    witness_scope: "actual-test-SDK-fixture"
  }
  let stage = prepare_relay_stage(context.judge,
    Crypto.sha256(Bytes.from_utf8(context.log_name)),
    submitter,
    verified)?
  let second = case proof.second do
    SignedCheckpoint(cp) -> checkpoint_hash(cp)?
    AnchorReference(_) -> Bytes.from_hex(text(row, "second_hash_hex")?)?
  end
  let generation = case proof.second do
    SignedCheckpoint(_) -> None
    AnchorReference(_) -> Some(Json.as_int(Json.object_get(row, "anchor_generation")?)?)
  end
  Ok([token_proof_prepare_instruction(context, payer, submitter, wire, stage, second, generation)?])
end

fn build(row :: Json) -> List<Instruction>!String do
  let raw = Json.object_get(row, "context")?
  let context = TokenCollateralContext {
    judge: pubkey(text(raw, "judge")?)?,
    token: pubkey(text(raw, "token")?)?,
    rewards: pubkey(text(raw, "rewards")?)?,
    log_name: text(raw, "log_name")?,
    usdc_mint: pubkey(text(raw, "usdc_mint")?)?
  }
  let actor_key = pubkey(text(row, "operator")?)?
  let governance = pubkey(text(row, "governance")?)?
  let submitter = pubkey(text(row, "submitter")?)?
  let payer = pubkey(text(row, "payer")?)?
  let tag = Json.as_int(Json.object_get(row, "tag")?)?
  let witness = optional_key(row)?
  let subject = case witness do
    None -> CollateralDirectory
    Some(value) -> CollateralWitness(value)
  end
  let asset = Json.as_int(Json.object_get(row, "asset")?)?
  let amount = U64.parse(text(row, "amount")?)?
  let wire = Bytes.from_hex(text(row, "wire_hex")?)?
  let sdk = Json.object_get(row, "sdk")?
  let actual = Json.array_get(sdk, Json.array_length(sdk)? - 1)?
  let payload = Bytes.from_hex(text(actual, "data_hex")?)?
  case tag do
    10 -> Ok([token_proof_initialize_instruction(context, submitter, wire)?])
    11 -> Ok([
      token_proof_append_instruction(context,
        submitter,
        wire,
        U64.to_int(U64.parse(Bytes.read_uint_le(payload, 1, 2)?)?)?)?
    ])
    12 -> Ok([token_proof_seal_instruction(context, submitter, wire)?])
    13 -> token_proof_signature_instructions(context,
      submitter,
      wire,
      Bytes.get(payload, 1)?,
      witness,
      U64.to_int(U64.parse(Bytes.read_uint_le(payload, 2, 2)?)?)?)
    14 -> Ok([token_proof_close_instruction(context, submitter, wire)?])
    31 -> Ok([token_binding_propose_instruction(context, governance, payer)?])
    32 ->
      let reports = Json.object_get(row, "sdk_reports")?
      let report = Json.array_get(reports, 0)?
      if Json.array_length(Json.object_get(report, "signerKeys")?)? == 0 do
        Ok([token_binding_activate_permissionless_instruction(context, governance, payer)?])
      else
        Ok([token_binding_activate_instruction(context, governance, payer)?])
      end
    33 -> Ok([token_collateral_migrate_instruction(context, subject)?])
    34 -> Ok([
      token_collateral_deposit_instruction(context, governance, actor_key, subject, asset, amount)?
    ])
    35 -> Ok([
      token_collateral_deposit_instruction(context, governance, actor_key, subject, asset, amount)?
    ])
    36 -> Ok([token_collateral_activate_pending_instruction(context, subject, asset)?])
    37 -> Ok([token_collateral_request_unbond_instruction(context, actor_key, subject)?])
    38 -> Ok([token_collateral_withdraw_instruction(context, actor_key, subject, asset)?])
    39 -> Ok([
      token_collateral_propose_minimums_instruction(context,
        governance,
        wide(payload, 1)?,
        wide(payload, 9)?)?
    ])
    40 -> Ok([token_collateral_activate_minimums_instruction(context)?])
    41 -> fixture_preparation(row, context, payer, submitter, wire)
    42 -> fixture_preparation(row, context, payer, submitter, wire)
    43 -> fixture_preparation(row, context, payer, submitter, wire)
    44 -> Ok([
      token_proof_settle_instruction(context,
        decode_token_prepared_proof(Bytes.from_hex(text(row, "receipt_hex")?)?)?)?
    ])
    45 -> Ok([token_collateral_assess_instruction(context, subject, asset)?])
    _ -> Err("unexpected_collateral_fixture_tag")
  end
end

struct ExportMeta do
  key :: String
  signer :: Bool
  writable :: Bool
end deriving(Json)

struct ExportInstruction do
  program :: String
  data_hex :: String
  accounts :: List<ExportMeta>
end deriving(Json)

fn exported(ix :: Instruction) -> ExportInstruction do
  ExportInstruction {
    program: pubkey_string(ix.program_id),
    data_hex: Bytes.to_hex(ix.data),
    accounts: for meta in ix.accounts do
      ExportMeta { key: pubkey_string(meta.pubkey), signer: meta.signer, writable: meta.writable }
    end
  }
end

fn vectors() -> Bool!String do
  let path = Env.get("MORSE_COLLATERAL_OPERATOR_VECTORS_PATH", "")
  if path == "" do
    return Err("actual SDK/SBF collateral vectors are mandatory")
  end
  let root = Json.parse(File.read(path)?)?
  let rows = Json.object_get(root, "cases")?
  if Json.array_length(rows)? < 40 do
    return Err("incomplete_actual_collateral_vectors")
  end
  let packets = for index in 0..Json.array_length(rows)? do
    let row = Json.array_get(rows, index)?
    let actual = build(row)?
    let expected = Json.object_get(row, "sdk_reports")?
    assert(List.length(actual) == Json.array_length(expected)?)
    for at in 0..List.length(actual) do
      let report = Json.parse(instruction_report_json(List.get(actual, at)))?
      let sdk = Json.array_get(expected, at)?
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
        let a = Json.encode(Json.object_get(report, field)?)
        let b = Json.encode(Json.object_get(sdk, field)?)
        if a != b do
          IO.eprintln("COLLATERAL_SDK_DIFF case=#{index} field=#{field} actual=#{a} expected=#{b}")
        end
        assert(a == b)
      end
    end
    let instructions = for ix in actual do
      Json.encode(exported(ix))
    end
    """{"context_digest":#{Json.encode_string(text(row,
      "context_digest")?)},"expected":#{Json.encode(Json.object_get(row,
      "sdk")?)},"instructions":[#{String.join(instructions, ",")}] }"""
  end
  let output = Env.get("MORSE_COLLATERAL_OPERATOR_INSTRUCTIONS_PATH", "")
  if output != "" do
    File.write(output, """{"schema_version":1,"packets":[#{String.join(packets, ",")}] }""")?
  end
  Ok(true)
end

test("canonical Mesh collateral/proof instructions equal actual SDK/SBF packets") do
  case vectors() do
    Ok(value) -> assert(value)
    Err(error) -> do
      IO.eprintln(error)
      assert(false)
    end
  end
end
