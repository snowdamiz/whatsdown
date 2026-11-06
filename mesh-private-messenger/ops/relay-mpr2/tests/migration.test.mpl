from Tests.RelayMpr2Fixture import (
  operator_fixture_pins,
  operator_fixture_text,
  operator_fixture_account,
  operator_fixture_snapshot_for_keys
)
from Input import RelayConfig
from Request import CollateralOperatorConfig
from ProofRead import CollateralProofIntent, collateral_proof_keys, decode_collateral_proof_snapshot
from Migration import migration_operation, migration_keys, decode_migration_snapshot
from RelayMpr2Report import effect_descriptor
from Transparency.Merkle import WitnessKey
from Solana.Read import pubkey

fn legacy_migration() -> Bool!String do
  let cases = Json.object_get(Json.parse(File.read(Env.get("MORSE_MPR2_TEST_FIXTURE", ""))?)?,
    "migration_cases")?
  let results = for index in 0..Json.array_length(cases)? do
    let row = Json.array_get(cases, index)?
    let tag = Json.as_int(Json.object_get(row, "tag")?)?
    let selected = Json.object_get(row, "keys")?
    if tag == 41
      && Json.as_bool(Json.object_get(row, "success")?)?
      && Json.array_length(selected)? == 2 do
      let pins = operator_fixture_pins(row)?
      let witnesses = for at in 0..Json.array_length(selected)? do
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
        witnesses: witnesses,
        close: false
      }
      let snapshot = operator_fixture_snapshot_for_keys(row, collateral_proof_keys(pins, intent)?)?
      let state = decode_collateral_proof_snapshot(pins,
        intent,
        snapshot.slot,
        U64.parse(operator_fixture_text(row, "clock_time")?)?,
        snapshot,
        None)?
      if List.length(state.legacy_subjects) > 0 do
        let config = RelayConfig {
          operator: CollateralOperatorConfig { pins: pins, sources: [] },
          submitter: intent.submitter,
          fee_payer: intent.fee_payer,
          witnesses: witnesses
        }
        let plan = migration_operation(config, intent, state)?
        assert(plan.reason == "migrate_legacy_bond" && !plan.governance_required)
        assert(List.length(plan.instruction_signers) == 0 && List.length(plan.rent_payers) == 0)
        assert(Bytes.get(List.head(plan.instructions).data, 0)? == 33)
        let descriptor = Json.parse(effect_descriptor(intent.wire, state, plan)?)?
        let before = operator_fixture_snapshot_for_keys(row,
          migration_keys(config, intent.wire, descriptor)?)?
        assert(!decode_migration_snapshot(config, intent.wire, descriptor, before.slot, before)?)
        # A different source revision cannot change this old migration's effect.
        let rotated = %{config |
          operator: %{config.operator | pins: %{pins | source_revision: U64.parse("999")?}}
        }
        assert(!decode_migration_snapshot(rotated, intent.wire, descriptor, before.slot, before)?)
        let bond_address = operator_fixture_text(descriptor, "bond")?
        let successor = operator_fixture_account(Json.object_get(Json.object_get(row,
            "migrated_bonds")?,
          bond_address)?)?
        # Independently observed later MBD2 account, assembled with immutable
        # loader/log identity for the old-effect decoder, not a fresh SBF bank.
        let migrated_snapshot = %{before |
          accounts: List.take(before.accounts, 4) ++ [Some(successor)]
        }
        assert(decode_migration_snapshot(rotated,
          intent.wire,
          descriptor,
          migrated_snapshot.slot,
          migrated_snapshot)?)
        let foreign = %{successor |
          info: %{successor.info | owner: pubkey("11111111111111111111111111111111")?}
        }
        assert(Result.is_err(decode_migration_snapshot(config,
          intent.wire,
          descriptor,
          migrated_snapshot.slot,
          %{migrated_snapshot |
            accounts: List.take(migrated_snapshot.accounts, 4) ++ [Some(foreign)]
          })))
        assert(Result.is_err(decode_migration_snapshot(config,
          intent.wire,
          descriptor,
          U64.add(migrated_snapshot.slot, U64.parse("1")?)?,
          migrated_snapshot)))
        1
      else
        0
      end
    else
      0
    end
  end
  assert(List.reduce(results, 0, fn(total, value) do total + value end) > 0)
  Ok(true)
end

test("actual selected legacy bonds schedule permissionless migration before MPR2 preparation") do
  case legacy_migration() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
