from Tests.Fixture import operator_fixture_pins, operator_fixture_text
from CloseRead import (
  CollateralStageCloseIntent,
  read_collateral_stage_close_origin,
  collateral_stage_close_quorum,
  plan_collateral_stage_close
)
from Solana.Read import pubkey

fn owner_close_http() -> Bool!String do
  let path = Env.get("MORSE_COLLATERAL_CLOSE_HTTP_ROW", "")
  let mode_path = Env.get("MORSE_COLLATERAL_CLOSE_HTTP_MODE", "")
  let endpoints = Env.get("MORSE_COLLATERAL_CLOSE_HTTP_SOURCES", "")
  if path == "" || mode_path == "" || endpoints == "" do
    return Err("actual owned stage-close HTTP fixtures required")
  end
  let row = Json.parse(File.read(path)?)?
  let pins = operator_fixture_pins(row)?
  let intent = CollateralStageCloseIntent {
    fee_payer: pubkey(operator_fixture_text(row, "fee_payer")?)?,
    submitter: pubkey(operator_fixture_text(row, "submitter")?)?,
    full_hash: Bytes.from_hex(operator_fixture_text(row, "full_hash_hex")?)?
  }
  let raw = Json.parse(endpoints)?
  let sources = for at in 0..3 do
    Json.as_string(Json.array_get(raw, at)?)?
  end
  let minimum = U64.parse(operator_fixture_text(row, "clock_slot")?)?
  let now = U64.parse(operator_fixture_text(row, "clock_time")?)?
  let client = Http.client()
  for mode in 1..9 do
    File.write(mode_path, Int.to_string(mode))?
    let a = read_collateral_stage_close_origin(client,
      List.get(sources, 0),
      pins,
      intent,
      minimum,
      now)
    let b = read_collateral_stage_close_origin(client,
      List.get(sources, 1),
      pins,
      intent,
      minimum,
      now)
    let c = read_collateral_stage_close_origin(client,
      List.get(sources, 2),
      pins,
      intent,
      minimum,
      now)
    let result = collateral_stage_close_quorum(a, b, c)
    if mode <= 2 do
      let plan = plan_collateral_stage_close(pins, intent, result?)?
      assert(plan.state == "ready"
        && plan.instruction_signers == [intent.submitter]
        && !plan.governance_required)
    else
      assert(Result.is_err(result))
    end
  end
  Http.client_close(client)
  Ok(true)
end

test("minimal owner cleanup requires current judge code and same-bank quorum but no live eligibility or price") do
  case owner_close_http() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
