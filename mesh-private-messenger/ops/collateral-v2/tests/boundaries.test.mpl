from Tests.Fixture import (
  operator_fixture_pins,
  operator_fixture_text,
  operator_fixture_subject,
  operator_fixture_snapshot,
  operator_fixture_snapshot_for_keys,
  operator_fixture_anchor
)
from Read import decode_collateral_operator_unpriced_snapshot, decode_collateral_operator_snapshot
from Plan import CollateralOperation, plan_collateral_operation
from ProofRead import (
  CollateralProofIntent,
  collateral_proof_keys,
  decode_collateral_proof_snapshot,
  collateral_proof_quorum
)
from Transparency.Merkle import WitnessKey, checkpoint_hash
from Transparency.Fork import decode_fork
from Solana.Read import pubkey
from Solana.Tx import instruction_report_json

fn fixture_replace(raw :: Bytes, offset :: Int, replacement :: Bytes) -> Bytes!String do
  Bytes.concat(Bytes.concat(Bytes.slice(raw, 0, offset)?, replacement)?,
    Bytes.slice(raw,
      offset + Bytes.length(replacement),
      Bytes.length(raw) - offset - Bytes.length(replacement))?)
end

fn fixture_same_instruction(wanted :: Json, actual :: Json) -> Bool!String do
  let matches = for field in [
    "programId",
    "accountKeys",
    "signerKeys",
    "writableKeys",
    "dataBase64"
  ] do
    Json.encode(Json.object_get(wanted, field)?) == Json.encode(Json.object_get(actual, field)?)
  end
  Ok(List.reduce(matches, true, fn(total, value) do total && value end))
end

fn boundaries() -> Bool!String do
  let input = Env.get("MORSE_COLLATERAL_OPERATOR_VECTORS_PATH", "")
  if input == "" do
    return Err("actual SBF input required")
  end
  let rows = Json.object_get(Json.parse(File.read(input)?)?, "cases")?
  let counts = for index in 0..Json.array_length(rows)? do
    let row = Json.array_get(rows, index)?
    let tag = Json.as_int(Json.object_get(row, "tag")?)?
    if List.contains([37, 38, 45], tag) do
      let pins = operator_fixture_pins(row)?
      let subject = operator_fixture_subject(row)?
      let operator = pubkey(operator_fixture_text(row, "operator")?)?
      let raw = operator_fixture_snapshot(row, pins, subject, operator)?
      let now = U64.parse(operator_fixture_text(row, "clock_time")?)?
      let state = decode_collateral_operator_unpriced_snapshot(pins,
        subject,
        operator,
        raw.slot,
        now,
        raw)?
      if state.oracle_current do
        0
      else
        assert(state.twap == None)
        assert(Result.is_err(decode_collateral_operator_snapshot(pins,
          subject,
          operator,
          raw.slot,
          now,
          raw)))
        let operation = CollateralOperation {
          tag: tag,
          fee_payer: pubkey(operator_fixture_text(row, "fee_payer")?)?,
          operator: operator,
          subject: subject,
          asset: Json.as_int(Json.object_get(row, "asset")?)?,
          amount: U64.parse("0")?,
          witness_minimum: U64.parse(operator_fixture_text(row, "policy_witness")?)?,
          directory_minimum: U64.parse(operator_fixture_text(row, "policy_directory")?)?
        }
        let plan = plan_collateral_operation(pins, operation, state)
        if tag == 45 do
          assert(!Json.as_bool(Json.object_get(row, "success")?)? && Result.is_err(plan))
        else
          assert(Json.as_bool(Json.object_get(row, "success")?)?)
          let plan = plan?
          assert(plan.state == "ready")
          let wanted = Json.array_get(Json.object_get(row, "sdk_reports")?, 0)?
          let actual = Json.parse(instruction_report_json(List.get(plan.instructions,
            List.length(plan.instructions) - 1)))?
          assert(fixture_same_instruction(wanted, actual)?)
          nil
        end
        1
      end
    else if List.contains([41, 42, 43], tag)
      && Result.is_ok(Json.as_int(Json.object_get(row, "anchor_generation")?)) do
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
      let now = U64.parse(operator_fixture_text(row, "clock_time")?)?
      let aux = case operator_fixture_anchor(row, pins, intent.wire)? do
        None -> return Err("actual anchor required")
        Some(v) -> v
      end
      assert(Result.is_ok(decode_collateral_proof_snapshot(pins,
        intent,
        snapshot.slot,
        now,
        snapshot,
        Some(aux))))
      assert(Result.is_err(decode_collateral_proof_snapshot(pins,
        intent,
        snapshot.slot,
        now,
        snapshot,
        None)))
      assert(Result.is_err(decode_collateral_proof_snapshot(pins,
        intent,
        snapshot.slot,
        now,
        snapshot,
        Some(%{aux | entry: %{aux.entry | slot: U64.add(snapshot.slot, U64.parse("1")?)?}}))))
      let entry = case aux.entry.account do
        None -> return Err("actual entry required")
        Some(v) -> v
      end
      for changed in [
        if tag == 43 do
          fixture_replace(entry.info.data, 48, checkpoint_hash(decode_fork(intent.wire)?.first)?)?
        else
          fixture_replace(entry.info.data, 16, Bytes.from_hex(String.repeat("03", 32))?)?
        end,
        fixture_replace(entry.info.data, 96, Bytes.from_hex("0000")?)?,
        fixture_replace(entry.info.data, 102, Bytes.from_hex("0200")?)?
      ] do
        assert(Result.is_err(decode_collateral_proof_snapshot(pins,
          intent,
          snapshot.slot,
          now,
          snapshot,
          Some(%{aux |
            entry: %{aux.entry | account: Some(%{entry | info: %{entry.info | data: changed}})}
          }))))
      end
      let original = decode_collateral_proof_snapshot(pins,
        intent,
        snapshot.slot,
        now,
        snapshot,
        Some(aux))?
      let other_data = fixture_replace(entry.info.data,
        48,
        Crypto.sha256(Bytes.from_utf8("different recorded anchor")))?
      let alternate = decode_collateral_proof_snapshot(pins,
        intent,
        snapshot.slot,
        now,
        snapshot,
        Some(%{aux |
          entry: %{aux.entry | account: Some(%{entry | info: %{entry.info | data: other_data}})}
        }))?
      assert(Result.is_err(collateral_proof_quorum(Ok(original),
        Ok(alternate),
        Err("third unavailable"))))
      let other_metadata = decode_collateral_proof_snapshot(pins,
        intent,
        snapshot.slot,
        now,
        snapshot,
        Some(%{aux |
          entry: %{aux.entry |
            account: Some(%{entry |
              info: %{entry.info | lamports: U64.add(entry.info.lamports, U64.parse("1")?)?}
            })
          }
        }))?
      assert(Result.is_err(collateral_proof_quorum(Ok(original),
        Ok(other_metadata),
        Err("third unavailable"))))
      10
    else
      0
    end
  end
  let source_count = List.length(List.filter(counts, fn(v) do v == 1 end))
  let anchors = List.length(List.filter(counts, fn(v) do v == 10 end))
  println("genuine changed-source actions=#{source_count} authenticated anchored kinds=#{anchors}")
  assert(source_count == 3 && anchors == 3)
  Ok(true)
end

test("actual changed-source owner exits and all anchored kinds preserve dependency and bank boundaries") do
  case boundaries() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
