from Tests.Fixture import (
  operator_fixture_pins,
  operator_fixture_subject,
  operator_fixture_snapshot,
  operator_fixture_text
)
from Read import (
  decode_collateral_operator_snapshot,
  decode_collateral_operator_unpriced_snapshot,
  collateral_operator_freshness
)
from Plan import CollateralOperation, plan_collateral_operation
from Solana.Read import pubkey

fn proof() -> Bool!String do
  let path = Env.get("MORSE_COLLATERAL_OPERATOR_VECTORS_PATH", "")
  if path == "" do
    return Err("actual SBF fixtures required")
  end
  let rows = Json.object_get(Json.parse(File.read(path)?)?, "cases")?
  let outcomes = for index in 0..Json.array_length(rows)? do
    let row = Json.array_get(rows, index)?
    let tag = Json.as_int(Json.object_get(row, "tag")?)?
    if tag >= 31 && tag <= 45 && tag != 41 && tag != 42 && tag != 43 && tag != 44 do
      let p = operator_fixture_pins(row)?
      let s = operator_fixture_subject(row)?
      let operator = pubkey(operator_fixture_text(row, "operator")?)?
      let raw = operator_fixture_snapshot(row, p, s, operator)?
      let now = U64.parse(operator_fixture_text(row, "clock_time")?)?
      let state = case decode_collateral_operator_unpriced_snapshot(p,
        s,
        operator,
        raw.slot,
        now,
        raw) do
        Err(error) -> do
          println("snapshot ordinal=#{index} #{error}")
          return Err(error)
        end
        Ok(value) -> value
      end
      assert(Result.is_err(collateral_operator_freshness(state, U64.add(now, U64.parse("301")?)?)))
      let strict = decode_collateral_operator_snapshot(p, s, operator, raw.slot, now, raw)
      assert(Result.is_ok(strict) == (state.oracle_current && state.binding_current))
      let request = CollateralOperation {
        tag: tag,
        fee_payer: pubkey(operator_fixture_text(row, "fee_payer")?)?,
        operator: operator,
        subject: s,
        asset: Json.as_int(Json.object_get(row, "asset")?)?,
        amount: U64.parse(operator_fixture_text(row, "amount")?)?,
        witness_minimum: U64.parse(operator_fixture_text(row, "policy_witness")?)?,
        directory_minimum: U64.parse(operator_fixture_text(row, "policy_directory")?)?
      }
      let plan = plan_collateral_operation(p, request, state)
      assert(Result.is_err(decode_collateral_operator_snapshot(p,
        s,
        operator,
        U64.add(raw.slot, U64.parse("1")?)?,
        now,
        raw)))
      assert(Result.is_err(decode_collateral_operator_snapshot(p,
        s,
        operator,
        raw.slot,
        U64.add(now, U64.parse("301")?)?,
        raw)))
      assert(Result.is_err(decode_collateral_operator_snapshot(%{p |
          token_slot: U64.add(p.token_slot, U64.parse("1")?)?
        },
        s,
        operator,
        raw.slot,
        now,
        raw)))
      case plan do
        Err(_) -> 4
        Ok(value) ->
          if value.state == "ready" do
            assert(List.length(value.instructions) > 0)
            assert(Json.as_bool(Json.object_get(row, "success")?)?)
            assert(tag != 32
              || (!value.governance_required && List.length(value.instruction_signers) == 0))
            1
          else if value.state == "waiting" do
            assert(List.length(value.instructions) == 0)
            2
          else
            3
          end
      end
    else
      0
    end
  end
  let count = List.length(List.filter(outcomes, fn(value) do value != 0 end))
  let ready = List.length(List.filter(outcomes, fn(value) do value == 1 end))
  let waits = List.length(List.filter(outcomes, fn(value) do value == 2 end))
  let refused = List.length(List.filter(outcomes, fn(value) do value == 4 end))
  println("actual collateral snapshots=#{count} ready=#{ready} waiting=#{waits} refused=#{refused}")
  assert(count >= 67 && ready > 20 && waits > 0 && refused > 0)
  Ok(true)
end

test("actual SBF snapshots enforce code/context/freshness and select bounded collateral steps") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
