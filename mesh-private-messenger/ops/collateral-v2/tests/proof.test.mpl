from Tests.Fixture import (
  operator_fixture_pins,
  operator_fixture_anchor,
  operator_fixture_text,
  operator_fixture_snapshot_for_keys
)
from ProofRead import CollateralProofIntent, collateral_proof_keys, decode_collateral_proof_snapshot
from ProofPlan import plan_collateral_proof
from Transparency.Merkle import WitnessKey
from Solana.Read import pubkey
from Solana.Tx import instruction_report_json

fn prove_preparation() -> Bool!String do
  let path = Env.get("MORSE_COLLATERAL_OPERATOR_VECTORS_PATH", "")
  if path == "" do
    return Err("actual SBF fixtures required")
  end
  let cases = Json.object_get(Json.parse(File.read(path)?)?, "cases")?
  let results = for index in 0..Json.array_length(cases)? do
    let row = Json.array_get(cases, index)?
    if List.contains([41, 42, 43], Json.as_int(Json.object_get(row, "tag")?)?) do
      let pins = operator_fixture_pins(row)?
      let selected = Json.object_get(row, "keys")?
      let keys = for at in 0..Json.array_length(selected)? do
        let value = Json.array_get(selected, at)?
        WitnessKey {
          witness_id: operator_fixture_text(value, "witness_id")?,
          public_key: Bytes.from_hex(operator_fixture_text(value, "public_key")?)?
        }
      end
      let intent = CollateralProofIntent {
        fee_payer: pubkey(operator_fixture_text(row, "payer")?)?,
        submitter: pubkey(operator_fixture_text(row, "submitter")?)?,
        wire: Bytes.from_hex(operator_fixture_text(row, "wire_hex")?)?,
        witnesses: keys,
        close: false
      }
      let snapshot = operator_fixture_snapshot_for_keys(row, collateral_proof_keys(pins, intent)?)?
      let aux = operator_fixture_anchor(row, pins, intent.wire)?
      let state = decode_collateral_proof_snapshot(pins,
        intent,
        snapshot.slot,
        U64.parse(operator_fixture_text(row, "clock_time")?)?,
        snapshot,
        aux)?
      let plan = plan_collateral_proof(pins, intent, state)?
      println("proof ordinal=#{operator_fixture_text(row, "clock_time")?} next=#{plan.reason}")
      case state.receipt do
        Some(receipt) ->
          if receipt.settled do
            assert(plan.state == "complete" && List.length(plan.instructions) == 0)
          else
            assert(plan.state == "ready"
              && (plan.reason == "payout_accounts" || plan.reason == "settle_mixed_assets"))
          end
        None -> do
          assert(plan.state == "ready"
            && plan.reason == "prepare_permanent_receipt"
            && List.length(plan.instructions) == 1)
          let expected = Json.array_get(Json.object_get(row, "sdk_reports")?, 0)?
          let actual = Json.parse(instruction_report_json(List.head(plan.instructions)))?
          for field in ["programId", "accountKeys", "signerKeys", "writableKeys", "dataBase64"] do
            assert(Json.encode(Json.object_get(expected,
              field)?) == Json.encode(Json.object_get(actual, field)?))
          end
          nil
        end
      end
      assert(Result.is_err(decode_collateral_proof_snapshot(pins,
        intent,
        U64.add(snapshot.slot, U64.parse("1")?)?,
        U64.parse(operator_fixture_text(row, "clock_time")?)?,
        snapshot,
        aux)))
      1
    else
      0
    end
  end
  let count = List.reduce(results, 0, fn(sum, n) do sum + n end)
  println("actual prepared proof snapshots=#{count}")
  assert(count >= 3)
  Ok(true)
end

test("authenticated actual SBF proof snapshots select exact canonical SDK preparation including16 targets") do
  case prove_preparation() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
