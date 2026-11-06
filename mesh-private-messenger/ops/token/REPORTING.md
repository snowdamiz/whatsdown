# Token proof report validation

`scripts/prove-token.sh` runs the required programs, Mesh and transport checks,
then invokes `ops/token/report.py` to create its scoped local checkpoint. The
report requires named token SBF safety cases and one complete terminal Rust
result summary. All named cases must pass; failed, ignored, measured, filtered,
duplicate, missing and truncated case evidence is refused. Additional passing
cases do not require updating a magic test count. Other required proof markers
remain mandatory, and a compiler/Rust failure cannot hide behind one of them.

Run the focused report regression without any chain or service:

```sh
python3 ops/token/report.test.py
```

Two read-only validation modes are available:

```sh
python3 ops/token/report.py --token-program-log /absolute/token-program.log
MORSE_PROOF_DIR=/absolute/required-logs python3 ops/token/report.py --validate-logs
```

These modes print explicitly scoped JSON, do not write `token-local.json`, do
not execute programs and do not qualify current sources or artifacts. Successful
validation of old logs does not replace running the complete required gate.

`fixtures/report-token-program-13.txt` is the unchanged real local SBF log from
the frozen `token-unfunded-expiry-cry437q9` checkpoint's
`all-token-sbf-compatibility-and-expiry.log`, SHA-256
`2c94cc55dc43ce1888b24a7de4877ac2158c8f5c7f321267a403ea71e9e8c33b`.
It includes expected adversarial SPL/CPI failures inside passing tests. The
validator distinguishes these from a failing test or compiler run. This fixture
is parser regression input; its copy is not a fresh SBF execution.

The report-only repair is evidenced in the outer workspace under
`.morse/witness-proof/token-report-gate-drift`: the old count-based rejection,
failing and passing regression stages, and validation of the39 archived required
log checks using the actual newer13-case SBF log. Frozen checkpoints are unchanged.
The newer permanent unfunded-expiry recovery and revenue handoff have their own
scoped checkpoints; they are not requalified by this report regression.

Phase5 remains open. The report never claims a live feed, liquid market,
independent production providers, production activation or four published live
weekly burns.
