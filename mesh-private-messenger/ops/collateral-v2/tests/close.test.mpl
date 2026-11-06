from Tests.Fixture import (
  operator_fixture_pins,
  operator_fixture_text,
  operator_fixture_raw,
  operator_fixture_snapshot_for_keys,
  operator_fixture_snapshot_from_accounts
)
from CloseRead import (
  CollateralStageCloseIntent,
  collateral_stage_close_keys,
  decode_collateral_stage_close,
  plan_collateral_stage_close,
  collateral_stage_close_quorum
)
from ProofRead import CollateralProofIntent, collateral_proof_keys
from Transparency.TokenCollateralWrite import token_collateral_addresses
from Transparency.TokenProofWrite import token_proof_owner_close_instruction
from Transparency.Fork import decode_fork
from Solana.Read import pubkey, pubkey_string
from Solana.Tx import instruction_report_json
from Report import collateral_operation_report

fn obsolete_owner_close() -> Bool!String do
  let path = Env.get("MORSE_COLLATERAL_OPERATOR_CLOSE_VECTORS_PATH", "")
  let output = Env.get("MORSE_COLLATERAL_OPERATOR_CLOSE_INSTRUCTIONS_PATH", "")
  if path == "" || output == "" do
    return Err("actual obsolete-owner-stage fixture/output required")
  end
  let row = Json.object_get(Json.parse(File.read(path)?)?, "row")?
  let pins = operator_fixture_pins(row)?
  let intent = CollateralStageCloseIntent {
    fee_payer: pubkey(operator_fixture_text(row, "fee_payer")?)?,
    submitter: pubkey(operator_fixture_text(row, "submitter")?)?,
    full_hash: Bytes.from_hex(operator_fixture_text(row, "full_hash_hex")?)?
  }
  let keys = collateral_stage_close_keys(pins, intent)?
  assert(List.length(keys) == 7
    && intent.submitter != pins.governance
    && intent.submitter != intent.fee_payer)
  let raw = operator_fixture_snapshot_for_keys(row, keys)?
  let now = U64.parse(operator_fixture_text(row, "clock_time")?)?
  let accounts = Json.object_get(row, "accounts")?
  let a = token_collateral_addresses(pins.context)?
  let oracle = operator_fixture_raw(accounts, a.oracle)?
  assert(U64.compare(U64.subtract(now, U64.parse(Bytes.read_uint_le(oracle, 164, 8)?)?)?,
    U64.parse("3456000")?) >= 0)
  assert(Bytes.get(operator_fixture_raw(accounts,
      pubkey(operator_fixture_text(row, "withdrawn_witness")?)?)?,
    5)? == 4)
  let wire = Bytes.from_hex(operator_fixture_text(row, "wire_hex")?)?
  assert(Result.is_err(decode_fork(wire)))
  let old_intent = CollateralProofIntent {
    fee_payer: intent.fee_payer,
    submitter: intent.submitter,
    wire: wire,
    witnesses: [],
    close: true
  }
  assert(Result.is_err(collateral_proof_keys(pins, old_intent)))
  let state = decode_collateral_stage_close(pins, intent, raw.slot, now, raw)?
  let plan = plan_collateral_stage_close(pins, intent, state)?
  assert(state.present
    && plan.state == "ready"
    && !plan.governance_required
    && plan.instruction_signers == [intent.submitter])
  let actual = List.head(plan.instructions)
  let expected = Json.array_get(Json.object_get(row, "sdk_reports")?, 0)?
  let report = Json.parse(instruction_report_json(actual))?
  for field in ["programId", "accountKeys", "signerKeys", "writableKeys", "dataBase64"] do
    assert(Json.encode(Json.object_get(expected, field)?) == Json.encode(Json.object_get(report,
        field)?))
  end
  assert(Result.is_err(decode_collateral_stage_close(pins,
    %{intent | submitter: pins.governance},
    raw.slot,
    now,
    raw)))
  assert(Result.is_err(decode_collateral_stage_close(pins,
    %{intent | full_hash: Crypto.sha256(Bytes.from_utf8("wrong stage digest"))},
    raw.slot,
    now,
    raw)))
  assert(Result.is_err(decode_collateral_stage_close(pins,
    intent,
    U64.add(raw.slot, U64.parse("1")?)?,
    now,
    raw)))
  assert(Result.is_err(decode_collateral_stage_close(pins,
    intent,
    raw.slot,
    U64.add(now, U64.parse("301")?)?,
    raw)))
  assert(Result.is_err(decode_collateral_stage_close(%{pins |
      judge_slot: U64.add(pins.judge_slot, U64.parse("1")?)?
    },
    intent,
    raw.slot,
    now,
    raw)))
  assert(Result.is_err(collateral_stage_close_quorum(Ok(state),
    Err("second unavailable"),
    Err("third unavailable"))))
  let remaining = operator_fixture_snapshot_from_accounts(row,
    keys,
    Json.object_get(row, "after_accounts")?)?
  let complete = plan_collateral_stage_close(pins,
    intent,
    decode_collateral_stage_close(pins, intent, remaining.slot, now, remaining)?)?
  assert(complete.state == "complete" && List.length(complete.instructions) == 0)
  let complete_report = Json.parse(collateral_operation_report(complete))?
  assert(Json.array_length(Json.object_get(complete_report, "transaction_signers")?)? == 0)
  let ready_report = Json.parse(collateral_operation_report(plan))?
  assert(Json.array_length(Json.object_get(ready_report, "transaction_signers")?)? == 2
    && Json.array_length(Json.object_get(ready_report, "instruction_signers")?)? == 1)
  let metas = for meta in actual.accounts do
    "{\"key\":#{Json.encode_string(pubkey_string(meta.pubkey))},\"signer\":#{if meta.signer do
      "true"
    else
      "false"
    end},\"writable\":#{if meta.writable do
      "true"
    else
      "false"
    end}}"
  end
  let packet = "{\"program\":#{Json.encode_string(pubkey_string(actual.program_id))},\"data_hex\":#{Json.encode_string(Bytes.to_hex(actual.data))},\"accounts\":[#{String.join(metas,
    ",")}]}"
  File.write(output,
    "{\"packets\":[{\"context_digest\":#{Json.encode_string(operator_fixture_text(row,
      "context_digest")?)},\"expected\":#{Json.encode(Json.object_get(row,
      "sdk")?)},\"instructions\":[#{packet}]}]}")?
  Ok(true)
end

test("actual obsolete upload closes with owner authority after withdrawal and stale oracle") do
  case obsolete_owner_close() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
