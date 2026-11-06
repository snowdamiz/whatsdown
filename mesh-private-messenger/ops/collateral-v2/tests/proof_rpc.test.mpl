from Tests.Fixture import operator_fixture_pins, operator_fixture_text
from ProofRead import CollateralProofIntent, read_collateral_proof_origin, collateral_proof_quorum
from ProofPlan import plan_collateral_proof
from Transparency.Merkle import WitnessKey
from Solana.Read import pubkey

fn actual_anchor_http() -> Bool!String do
  let row_path = Env.get("MORSE_COLLATERAL_PROOF_HTTP_ROW", "")
  let mode_path = Env.get("MORSE_COLLATERAL_PROOF_HTTP_MODE", "")
  let endpoints = Env.get("MORSE_COLLATERAL_PROOF_HTTP_SOURCES", "")
  if row_path == "" || mode_path == "" || endpoints == "" do
    return Err("owned actual anchored HTTP fixture required")
  end
  let row = Json.parse(File.read(row_path)?)?
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
  let sources_json = Json.parse(endpoints)?
  let sources = for index in 0..3 do
    Json.as_string(Json.array_get(sources_json, index)?)?
  end
  let minimum = U64.parse(operator_fixture_text(row, "clock_slot")?)?
  let now = U64.parse(operator_fixture_text(row, "clock_time")?)?
  let client = Http.client()
  for mode in 1..9 do
    File.write(mode_path, Int.to_string(mode))?
    let first = read_collateral_proof_origin(client,
      List.get(sources, 0),
      pins,
      intent,
      minimum,
      now)
    let second = read_collateral_proof_origin(client,
      List.get(sources, 1),
      pins,
      intent,
      minimum,
      now)
    let third = read_collateral_proof_origin(client,
      List.get(sources, 2),
      pins,
      intent,
      minimum,
      now)
    let outcome = collateral_proof_quorum(first, second, third)
    if mode <= 2 do
      let plan = plan_collateral_proof(pins, intent, outcome?)?
      assert(plan.state == "ready" && plan.reason == "prepare_permanent_receipt")
    else
      assert(Result.is_err(outcome))
    end
  end
  Http.client_close(client)
  Ok(true)
end

test("three owned HTTP origins bind actual anchored snapshots and all auxiliary reads to one bank") do
  case actual_anchor_http() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
