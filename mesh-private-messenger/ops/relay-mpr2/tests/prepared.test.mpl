from Tests.RelayMpr2Fixture import (
  operator_fixture_pins,
  operator_fixture_text,
  operator_fixture_snapshot_for_keys
)
from Input import RelayConfig
from Request import CollateralOperatorConfig
from ProofRead import CollateralProofIntent, collateral_proof_keys, decode_collateral_proof_snapshot
from ProofPlan import plan_collateral_proof
from Prepared import prepared_intent
from Receipt import PermanentReceipt, receipt_keys, decode_receipt_snapshot
from Recovery import recovery_keys, decode_recovery_snapshot, effect_present
from Lookup import plan_lookup
from RelayMpr2Report import ready_report
from Transparency.Merkle import WitnessKey
from Transparency.Relay import validate_relay_submission
from Transparency.Fork import encode_fork, fork_hash
from Transparency.TokenProofWrite import token_proof_stage_address, token_proof_settle_instruction
from Transparency.RelayLookup import prepare_relay_lookup
from Solana.Read import Pubkey, OptionalAccountSlicesAtSlot, pubkey, pubkey_string

fn competing_prepared() -> Bool!String do
  let cases = Json.object_get(Json.parse(File.read(Env.get("MORSE_MPR2_TEST_FIXTURE", ""))?)?,
    "prepared_cases")?
  for index in 0..Json.array_length(cases)? do
    let row = Json.array_get(cases, index)?
    let pins = operator_fixture_pins(row)?
    let selected = Json.object_get(row, "keys")?
    let witnesses = for at in 0..Json.array_length(selected)? do
      let value = Json.array_get(selected, at)?
      WitnessKey {
        witness_id: operator_fixture_text(value, "witness_id")?,
        public_key: Bytes.from_hex(operator_fixture_text(value, "public_key")?)?
      }
    end
    let own = pubkey("E6Lu6twRJzX5iXouS9o23fBHX9upgXbApcZyRY3cLYVL")?
    let wire = Bytes.from_hex(operator_fixture_text(row, "wire_hex")?)?
    let proof = validate_relay_submission(pins.service_key, pins.log_version, wire)?
    let original = CollateralProofIntent {
      fee_payer: own,
      submitter: own,
      wire: encode_fork(%{proof | finder: own.bytes})?,
      witnesses: witnesses,
      close: false
    }
    let hash = fork_hash(proof)?
    let permanent = operator_fixture_snapshot_for_keys(row, receipt_keys(pins, hash)?)?
    let receipt = decode_receipt_snapshot(pins, hash, permanent.slot, permanent)?
    assert(receipt.status == "prepared")
    let effective = prepared_intent(pins, original, receipt)?
    assert(effective.wire == wire && effective.wire != original.wire)
    assert(effective.submitter != own && effective.fee_payer == own)
    let winner = %{effective | fee_payer: effective.submitter}
    assert(prepared_intent(pins, winner, receipt)?.wire == winner.wire)
    let snapshot = operator_fixture_snapshot_for_keys(row, collateral_proof_keys(pins, effective)?)?
    let state = decode_collateral_proof_snapshot(pins,
      effective,
      snapshot.slot,
      U64.parse(operator_fixture_text(row, "clock_time")?)?,
      snapshot,
      None)?
    let immutable = case state.receipt do
      None -> return Err("prepared fixture missing receipt")
      Some(value) -> value
    end
    let zero_wire = encode_fork(%{proof | finder: Bytes.from_hex(String.repeat("00", 32))?})?
    let default_finder = %{immutable |
      finder: effective.submitter.bytes,
      stage: token_proof_stage_address(pins.context, effective.submitter, zero_wire)?.bytes
    }
    assert(prepared_intent(pins,
      original,
      %{receipt | value: Some(MixedReceipt(default_finder))})?.wire == zero_wire)
    assert(Result.is_err(prepared_intent(pins,
      original,
      %{receipt | value: Some(MixedReceipt(%{immutable | stage: own.bytes}))})))
    assert(!immutable.settled && immutable.usdc_finder == U64.parse("0")?)
    assert(immutable.morse_finder == U64.parse("0")?)
    let config = RelayConfig {
      operator: CollateralOperatorConfig { pins: pins, sources: [] },
      submitter: own,
      fee_payer: own,
      witnesses: witnesses
    }
    let operation = plan_collateral_proof(pins, effective, state)?
    assert(operation.reason == "settle_mixed_assets")
    assert(Bytes.get(List.head(operation.instructions).data, 0)? == 44)
    assert(List.length(operation.instruction_signers) == 0 && operation.fee_payer == own)
    let lookup = plan_lookup(config, effective, state, None)?
    let expected = prepare_relay_lookup(own,
      token_proof_settle_instruction(pins.context, immutable)?,
      snapshot.slot)?
    assert(lookup.addresses == expected.addresses && lookup.table == expected.table)
    let missing = %{snapshot |
      accounts: List.take(snapshot.accounts, List.length(snapshot.accounts) - 4)
        ++ [None, None, None, None]
    }
    let unpaid = decode_collateral_proof_snapshot(pins,
      effective,
      missing.slot,
      U64.parse(operator_fixture_text(row, "clock_time")?)?,
      missing,
      None)?
    let setup = plan_collateral_proof(pins, effective, unpaid)?
    assert(setup.reason == "payout_accounts" && List.length(setup.instructions) == 4)
    for at in 0..4 do
      let ix = List.get(setup.instructions, at)
      assert(List.get(ix.accounts, 0).pubkey == own)
      if at % 2 == 0 do
        assert(List.get(ix.accounts, 2).pubkey.bytes == immutable.finder)
      end
    end
    let report = Json.parse(ready_report(config, original, unpaid, setup, lookup)?)?
    assert(operator_fixture_text(report, "proof_hex")? == Bytes.to_hex(original.wire))
    assert(operator_fixture_text(report, "proof_hash")? == Bytes.to_hex(hash))
    assert(operator_fixture_text(report, "finder")? == pubkey_string(own))
    assert(operator_fixture_text(report, "payout_finder")? == Bytes.to_base58(immutable.finder))
    assert(operator_fixture_text(report, "submitter")? == pubkey_string(own))
    let own_stage = token_proof_stage_address(pins.context, own, original.wire)?
    assert(own_stage.bytes != immutable.stage)
    let stage = Json.object_get(report, "stage")?
    assert(operator_fixture_text(stage, "address")? == pubkey_string(own_stage))
    assert(operator_fixture_text(stage, "full_hash")? == Bytes.to_hex(Crypto.sha256(original.wire)))
    let effect = Json.object_get(Json.object_get(report, "operation")?, "effect")?
    assert(operator_fixture_text(effect,
      "full_hash")? == Bytes.to_hex(Crypto.sha256(original.wire)))
    let finder = Pubkey { bytes: immutable.finder }
    let keys = recovery_keys(config, original.wire, finder)?
    assert(List.get(keys, 4) == own_stage)
    let recovery_snapshot = OptionalAccountSlicesAtSlot {
      slot: permanent.slot,
      accounts: permanent.accounts
        ++ [None]
        ++ List.drop(snapshot.accounts, List.length(snapshot.accounts) - 4)
    }
    let recovery = decode_recovery_snapshot(config,
      original.wire,
      permanent.slot,
      finder,
      recovery_snapshot)?
    assert(recovery.receipt.status == "prepared" && recovery.stage.status == "missing")
    assert(effect_present(original.wire, effect, recovery)?)
    assert(!effect_present(original.wire,
      json {
        schema_version: 1,
        full_hash: Bytes.to_hex(Crypto.sha256(original.wire)),
        reason: "settle_mixed_assets"
      },
      recovery)?)
    let absent = decode_recovery_snapshot(config,
      original.wire,
      permanent.slot,
      finder,
      %{recovery_snapshot | accounts: permanent.accounts ++ [None, None, None, None, None]})?
    assert(!effect_present(original.wire, effect, absent)?)
    assert(Result.is_err(effect_present(wire, effect, recovery)))
    assert(Result.is_err(decode_recovery_snapshot(config,
      original.wire,
      permanent.slot,
      own,
      recovery_snapshot)))
    assert(Result.is_err(decode_recovery_snapshot(config,
      original.wire,
      U64.add(permanent.slot, U64.parse("1")?)?,
      finder,
      recovery_snapshot)))
  end
  Ok(true)
end

test("another finder and wallet finish the authenticated prepared winner with original job and recovery identity") do
  case competing_prepared() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
