from Tests.Fixture import (
  operator_fixture_pins,
  operator_fixture_anchor,
  operator_fixture_text,
  operator_fixture_snapshot_for_keys
)
from ProofRead import CollateralProofIntent, collateral_proof_keys, decode_collateral_proof_snapshot
from ProofPlan import plan_collateral_proof
from Transparency.Merkle import WitnessKey
from Transparency.Fork import decode_fork
from Solana.Read import AccountSlice, pubkey
from Solana.Tx import instruction_report_json

fn workflow_wrong_finder(value :: Option<AccountSlice>) -> Option<AccountSlice>!String do
  let entry = case value do
    None -> return Err("missing actual receipt")
    Some(v) -> v
  end
  let raw = entry.info.data
  let forged = Bytes.concat(Bytes.concat(Bytes.slice(raw, 0, 72)?,
      Crypto.sha256(Bytes.from_utf8("synthetic-negative-finder")))?,
    Bytes.slice(raw, 104, Bytes.length(raw) - 104)?)?
  Ok(Some(%{entry | info: %{entry.info | data: forged}}))
end

fn workflow_row(row :: Json, tag :: Int) -> Int!String do
  let wire = Bytes.from_hex(operator_fixture_text(row, "wire_hex")?)?
  if decode_fork(wire)?.kind != 1 do
    return Ok(0)
  end
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
    wire: wire,
    witnesses: keys,
    close: tag == 14
  }
  let snapshot = operator_fixture_snapshot_for_keys(row, collateral_proof_keys(pins, intent)?)?
  let aux = operator_fixture_anchor(row, pins, intent.wire)?
  let now = U64.parse(operator_fixture_text(row, "clock_time")?)?
  let state = case decode_collateral_proof_snapshot(pins,
    intent,
    snapshot.slot,
    now,
    snapshot,
    aux) do
    Err(error) ->
      if List.contains([
          "collateral_proof_receipt_collision",
          "collateral_proof_uncollectible_lifetime",
          "collateral_proof_expired"
        ],
        error) do
        return Ok(2)
      end
      println("proof workflow tag=#{tag} error=#{error}")
      return Err(error)
    Ok(value) -> value
  end
  if state.receipt != None do
    let receipt_index = 28 + 4 * List.length(intent.witnesses)
    let changed = for at in 0..List.length(snapshot.accounts) do
      let entry = List.get(snapshot.accounts, at)
      if at == receipt_index do
        workflow_wrong_finder(entry)?
      else
        entry
      end
    end
    assert(Result.is_err(decode_collateral_proof_snapshot(pins,
      intent,
      snapshot.slot,
      now,
      %{snapshot | accounts: changed},
      aux)))
  end
  let plan = plan_collateral_proof(pins, intent, state)?
  if plan.reason == "payout_accounts" || plan.reason == "proof_settled" do
    return Ok(3)
  end
  assert(plan.state == "ready")
  let expected = Json.object_get(row, "sdk_reports")?
  assert(Json.array_length(expected)? == List.length(plan.instructions))
  for at in 0..List.length(plan.instructions) do
    let wanted = Json.array_get(expected, at)?
    let actual = Json.parse(instruction_report_json(List.get(plan.instructions, at)))?
    for field in ["programId", "accountKeys", "signerKeys", "writableKeys", "dataBase64"] do
      assert(Json.encode(Json.object_get(wanted, field)?) == Json.encode(Json.object_get(actual,
          field)?))
    end
  end
  Ok(1)
end

fn workflow() -> Bool!String do
  let path = Env.get("MORSE_COLLATERAL_OPERATOR_VECTORS_PATH", "")
  if path == "" do
    return Err("actual SBF fixtures required")
  end
  let cases = Json.object_get(Json.parse(File.read(path)?)?, "cases")?
  let outcomes = for index in 0..Json.array_length(cases)? do
    let row = Json.array_get(cases, index)?
    let tag = Json.as_int(Json.object_get(row, "tag")?)?
    if tag < 31 || tag == 41 || tag == 44 do
      workflow_row(row, tag)?
    else
      0
    end
  end
  let matched = List.length(List.filter(outcomes, fn(v) do v == 1 end))
  let refused = List.length(List.filter(outcomes, fn(v) do v == 2 end))
  println("historical actual SBF proof transitions matched=#{matched} preflight_refused=#{refused}")
  assert(matched >= 74)
  Ok(true)
end

test("proof planner follows actual transitions and rejects substituted permanent receipt bindings") do
  case workflow() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
