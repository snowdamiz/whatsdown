#!/usr/bin/env python3
"""Record a bounded local checkpoint, never a Phase5/live acceptance claim."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re

product = Path(__file__).resolve().parents[2]
proof = Path(os.environ.get("MORSE_PROOF_DIR", product.parent / ".morse/witness-proof"))
compiler = Path(os.environ.get("MESHC", product.parent / "mesh-lang/target/debug/meshc")).resolve()
dex = os.environ.get("TOKEN_INCLUDE_DEX", "1") == "1"
checks = [
    ("rust_format", "token-format.log", None),
    ("clippy", "token-clippy.log", None),
    ("math_and_oracle_route_policy", "token-math.log", "test result: ok."),
    ("versioned_bond_schema_grace_models", "token-judge-model.log", "2 passed; 0 failed"),
    ("fresh_sbf", "token-sbf-build.log", "Finished"),
    ("fresh_judge_sbf", "token-judge-sbf-build.log", "Finished"),
    ("fresh_rewards_sbf_for_legacy_claim_compatibility", "token-rewards-sbf-build.log", "Finished"),
    ("legacy_usdc_rewards_compatibility", "token-rewards-legacy.log", "14 passed; 0 failed"),
    ("actual_versioned_collateral_and_maximum_mixed_asset_proof", "token-judge.log", "MORSE_MIXED_MAXIMUM"),
    ("atomic_rollback_after_late_real_token_cpi", "token-judge.log", "MORSE_MIXED_LATE_CPI_ROLLBACK"),
    ("real_grace_assessment_during_collection", "token-judge.log", "MORSE_TOKEN_ASSESSMENT_STAGE"),
    ("versioned_rewards_activation_and_legacy_claims", "token-judge.log", "MORSE_REWARDS_V2_ACTIVATION"),
    ("real_reserve_cap_atomicity_and_64_claim_bits", "token-judge.log", "MORSE_REWARDS_RESERVE"),
    ("reserve_late_spl_cpi_and_prefunded_receipt_rollback", "token-judge.log", "MORSE_REWARDS_RESERVE_LATE_CPI"),
    ("stale_price_usdc_fallback", "token-judge.log", "MORSE_REWARDS_STALE_USD_FALLBACK"),
    ("additive_v2_codec_format", "token-v2-mesh-format.log", None),
    ("additive_v2_codec_lint", "token-v2-mesh-lint.log", None),
    ("compiled_mesh_actual_v2_sbf_accounts_writers_and_operator_policy", "token-v2-codecs.log", "12 test files passed"),
    ("actual_sbf_executes_mesh_v2_writer_packets_both_assets_and_missing_payout_atas", "token-v2-write-sbf.log", "MORSE_TOKEN_MESH_WRITE_REPLAY"),
    ("actual_sbf_staged_revision_ttl_and_separate_usdc_claim_reader", "token-v2-codecs.log", "actual staged revisions and TTL remain visible"),
    ("canonical_next_zero_weight_attendance_identity_reads", "token-v2-codecs.log", "keeper resolves the next zero-weight attendance identities"),
    ("prepared_keeper_next_stage_and_earned_claims", "token-v2-codecs.log", "MORSE_TOKEN_REWARD_KEEPER"),
    ("loopback_finalized_v2_and_identity_rpc_quorum", "token-v2-reward-rpc.log", "MORSE_TOKEN_REWARDS_FINALIZED_RPC"),
    ("actual_sbf_spl_ata_and_10080_oracle_observations", "token-program.log", None),
    ("actual_missed_burn_carry_custody_donations_terminal_replay_and_late_cpi_rollback", "token-program.log", "MORSE_BURN_CARRY"),
    ("zero_remaining_weeks_close_with_permanent_zero_receipts", "token-program.log", "MORSE_BURN_ZERO_REMAINING"),
    ("compiled_mesh_carry_v1_v2_terminal_account_units", "token-v2-codecs.log", "MORSE_TOKEN_BURN_CARRY_CODEC"),
    ("custody_only_finalized_carry_reader_and_close_planner", "token-v2-codecs.log", "MORSE_TOKEN_BURN_CARRY_READER"),
    ("carry_writers_match_independent_complete_sdk_roles", "token-v2-codecs.log", "MORSE_TOKEN_CARRY_WRITERS"),
    ("actual_sbf_executes_mesh_carry_writer_objects", "token-carry-write-sbf.log", "MORSE_TOKEN_CARRY_MESH_REPLAY tag=10"),
    ("bounded_carry_finalized_rpc_and_distinct_url_quorum", "token-carry-rpc.log", "MORSE_TOKEN_BURN_CARRY_RPC"),
    ("sealed_carry_packet_ambiguous_response_and_process_restart", "token-carry-rpc.log", "MORSE_TOKEN_CARRY_JOURNAL_RESTART"),
    ("historical_funding_execution_receipts_reconcile_after_carry_close", "token-carry-rpc.log", "MORSE_TOKEN_CARRY_HISTORICAL"),
    ("mesh_format", "token-mesh-format.log", None),
    ("mesh_lint", "token-mesh-lint.log", None),
    ("compiled_mesh_policy_and_actual_sbf_codec_instruction_replay", "token-mesh.log", "7 test files passed"),
    ("bounded_finalized_rpc_authentication_and_agreement", "token-mesh.log", "MORSE_TOKEN_FINALIZED_RPC_PROOF:"),
    ("durable_sealed_actual_sdk_packet_restart", "token-mesh.log", "MORSE_TOKEN_PACKET_JOURNAL:"),
    ("competing_mesh_process_intent_and_packet_cas", "token-mesh.log", "MORSE_TOKEN_PACKET_CONCURRENT:"),
]

# These are required safety behaviors, not a fixed total test count. Extra passing
# cases are welcome; an absent, ignored, failed or truncated case cannot qualify.
TOKEN_SBF_BASE_CASES = (
    "fixed_supply_all_allocations_and_permanent_authority_revocation_execute_atomically",
    "prefunded_metadata_preparation_never_exposes_a_mint_or_claims_bootstrap_authority",
    "original_calendar_vesting_cliff_fixed_payout_and_retry_execute_real_spl_transfers",
    "authenticated_oracle_pins_reject_wrong_owner_feed_verification_and_gaps",
    "oracle_source_rotation_is_timelocked_and_discards_old_coverage",
    "actual_sbf_accumulates_all_10080_publications_before_accepting_seven_day_twap",
)
TOKEN_SBF_DEX_CASES = (
    "dex::pinned_jupiter_v2_and_raydium_cp_execute_real_single_hop_with_classic_spl",
    "dex::weekly_funding_waits_for_qualified_profile_and_receipt_replays_without_double_transfer",
    "dex::four_local_weeks_execute_all_96_chunks_with_actual_router_dex_and_program_owned_burns",
    "dex::burn_guards_and_real_cpi_failure_preserve_escrow_while_spot_remains_distinct_from_twap",
    "dex::carry_tests::missed_input_is_closed_once_and_donations_never_become_accounted_carry",
    "dex::carry_tests::unfunded_expiry_rejects_initialized_roles_and_rolls_back_both_creations",
    "dex::carry_tests::expired_unfunded_week_is_permanent_and_cannot_capture_later_funding",
)
FAILURE_LINE = re.compile(
    r"(?m)^(error:|error\[|COMPILE ERROR:|FAILED:|failures:|test result: FAILED\.|test .+ \.\.\. FAILED\b)"
)


def token_sbf_evidence(value, require_dex):
    if FAILURE_LINE.search(value):
        raise ValueError("compiler/test failure in token SBF log")
    lines = value.splitlines()
    starts = [(i, re.fullmatch(r"running ([0-9]+) tests?", line))
              for i, line in enumerate(lines) if re.fullmatch(r"running ([0-9]+) tests?", line)]
    summaries = [(i, re.fullmatch(
        r"test result: (ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; "
        r"([0-9]+) ignored; ([0-9]+) measured; ([0-9]+) filtered out; "
        r"finished in [0-9]+(?:\.[0-9]+)?s", line))
        for i, line in enumerate(lines) if line.startswith("test result:")]
    if len(starts) != 1 or len(summaries) != 1 or summaries[0][1] is None:
        raise ValueError("token SBF log needs one complete run and result summary")
    begin, start = starts[0]
    end, summary = summaries[0]
    if begin >= end or any(line.strip() for line in lines[end + 1:]):
        raise ValueError("token SBF result is not the complete terminal run")
    counts = [int(summary.group(i)) for i in range(2, 7)]
    passed, failed, ignored, measured, filtered = counts
    if summary.group(1) != "ok" or any(counts[1:]):
        raise ValueError("token SBF run contains failed, ignored or filtered cases")
    observed = {}
    for i, line in enumerate(lines):
        case = re.fullmatch(r"test (\S+) \.\.\. (.+)", line)
        if not case:
            continue
        name, status = case.groups()
        if not begin < i < end or name in observed or status != "ok":
            raise ValueError("token SBF log has duplicate, failed or ignored case: " + name)
        observed[name] = status
    required = TOKEN_SBF_BASE_CASES + (TOKEN_SBF_DEX_CASES if require_dex else ())
    missing = sorted(set(required) - set(observed))
    if missing:
        raise ValueError("token SBF log missing required cases: " + ", ".join(missing))
    if passed != len(observed) or passed != int(start.group(1)):
        raise ValueError("token SBF summary, run header and named cases disagree")
    return {"required_cases": sorted(required), "observed_case_count": len(observed),
            "failed": failed, "ignored": ignored, "measured": measured,
            "filtered_out": filtered}


def collect_checks():
    records = []
    for name, filename, marker in checks:
        path = proof / filename
        value = path.read_text()
        if marker and marker not in value:
            raise ValueError(f"Missing required proof marker: {filename}: {marker}")
        if FAILURE_LINE.search(value):
            raise ValueError(f"Compiler/test failure in {filename}")
        record = {"name": name, "status": "passed", "log": str(path),
                  "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        if name == "actual_sbf_spl_ata_and_10080_oracle_observations":
            record["case_evidence"] = token_sbf_evidence(value, dex)
        records.append(record)
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--token-program-log", type=Path,
                      help="validate one archived SBF log without qualifying sources or artifacts")
    mode.add_argument("--validate-logs", action="store_true",
                      help="validate required logs only; do not create a fresh-source checkpoint")
    args = parser.parse_args()
    if args.token_program_log is not None:
        print(json.dumps({"schema_version": 1,
                          "scope": "archived_token_sbf_log_validation_only",
                          "phase5_complete": False,
                          **token_sbf_evidence(args.token_program_log.read_text(), dex)}, indent=2))
        return
    records = collect_checks()
    if args.validate_logs:
        print(json.dumps({"schema_version": 1, "scope": "archived_log_validation_only",
                          "phase5_complete": False, "checks": records}, indent=2))
        return

    paths = [*(product / "packages/messenger-protocol/transparency" / ("token_" + name + ".mpl") for name in ["policy","chain","burn","burn_write","burn_carry","burn_carry_write","burn_read","burn_carry_read"]), product / "packages/messenger-protocol/transparency/token_custody.mpl", product / "packages/messenger-protocol/transparency/token_rewards.mpl", product / "packages/messenger-protocol/transparency/token_write.mpl", product / "programs/Cargo.toml", product / "programs/Cargo.lock", product / "scripts/prove-token.sh", product / "protocol/token-v1.md", product / "protocol/token-burn-carry-v2.md", product / "programs/morse-judge/src/token_custody.rs", product / "programs/morse-judge/src/lib.rs"]
    for folder in ["ops/token", "ops/token-v2", "programs/morse-token", "programs/morse-token-program", "programs/morse-rewards-math", "programs/morse-judge", "programs/morse-judge-program", "programs/morse-rewards", "programs/morse-rewards-program"]:
        paths.extend(p for p in (product / folder).rglob("*") if p.is_file() and "target" not in p.parts and "__pycache__" not in p.parts and p.suffix != ".pyc")
    source_hashes = {str(p.relative_to(product)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(set(paths))}
    result = {
        "schema_version": 1,
        "status": "passed",
        "scope": "fixed_supply_vesting_oracle_actual_weekly_swap_burn_carry_versioned_collateral_and_reward_reserve",
        "actual_dex_qualified": dex,
        "phase5_complete": False,
        "compiler": {"path": str(compiler), "sha256": hashlib.sha256(compiler.read_bytes()).hexdigest()},
        "runtime_archives": {kind: {"path": os.environ[name], "sha256": hashlib.sha256(Path(os.environ[name]).read_bytes()).hexdigest()} for kind, name in [("standard", "MESH_RT_LIB_PATH"), ("test", "MESH_TEST_RT_LIB_PATH")] if name in os.environ},
        "sbf": {"path": str(product / "programs/target/deploy/morse_token.so"), "sha256": hashlib.sha256((product / "programs/target/deploy/morse_token.so").read_bytes()).hexdigest()},
        "judge_sbf": {"path": str(product / "programs/target/deploy/morse_judge.so"), "sha256": hashlib.sha256((product / "programs/target/deploy/morse_judge.so").read_bytes()).hexdigest()},
        "rewards_sbf": {"path": str(product / "programs/target/deploy/morse_rewards.so"), "sha256": hashlib.sha256((product / "programs/target/deploy/morse_rewards.so").read_bytes()).hexdigest()},
        "checks": records,
        "source_hashes": source_hashes,
        "fixture_hashes": {filename: hashlib.sha256((proof / filename).read_bytes()).hexdigest() for filename in ["token-sbf-fixtures.json", "token-burn-fixtures.json", "token-custody-fixtures.json", "token-v2-mesh-instructions.json", "token-carry-fixtures.json", "token-carry-mesh-instructions.json"]},
        "remaining": ["See separate burn-worker and public-chain checkpoints; this umbrella does not qualify scheduling/recovery/public rendering.", "Collateral/proof operator builders, continuous grace assessment and durable rewards signing/crank integration", "Original-asset SOL/BTC conversion before USDC funding; post-token20/30/50 issuer accounting and local handoffs are qualified by the separate treasury-revenue-v2 checkpoint"],
        "boundaries": ["No live mint, transfer, deployment or production activation", "Pyth source account owner/data are injected fixtures; guardian verification and live MORSE feed availability are not proved", "Jupiter/Raydium code executes only in isolated LiteSVM; no mainnet submission or real-market liquidity/oracle identity is implied", "Finalized reader/provider agreement tests use loopback fixture RPC servers, not live consensus or independent production providers", "Human multisig independence and external operator identity are not machine-proved"],
    }
    (proof / "token-local.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(str(error))
