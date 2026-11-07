Run from the worktree root with the prebuilt, SHA-pinned compiler and runtimes:

```sh
python3 mesh-private-messenger/ops/plaintext/prove_cli_decoded_display.py \
  --output .morse/decoded-body-labels/cli-proof-child/new-run
```

The output directory must be new. `--privacy-only` runs the compile-only probes.
The runner needs Python 3.11+, Git, macOS `sandbox-exec`, and the pinned local
Mesh toolchain. It never builds, edits, or copies dependencies in mesh-lang.

The runner freezes a48963b4918f5fc39981176d4e46069b78dfeebb and working CLI/protocol
sources. Each compilation has its own retained Main source. Only Main's final
entrypoint is replaced; all preceding production functions are byte-preserved.
Language package sources stay in place, read-only, and are hashed before/after.

`privacy.mpl` is never executed. It requires exactly five E0093 diagnostics at
the named sinks/call: pure helper text, private decoded metadata, private decoder
error identity, UTF-8 error text, and an unrelated private flag calling display.

`driver.mpl` uses the existing header-ratchet test setup with actual CLI handshake
wrappers. It opens a real recipient-sealed initial packet, calls actual display,
then processes real encrypted ratchet packets through process_deliveries and
received_ratchet. Initial valid text, malformed inner, and invalid UTF-8 each
have a case. The valid case preserves the entire prove-m8.sh stdout contract:
initial, third, first, second, one suppressed replay, and acked=5. Both invalid
initial cases also include malformed inner and invalid UTF-8 ratchet messages,
out-of-order valid messages, and a replay under a distinct outer ID (acked=7).
Mailbox sequence numbers follow delivery order, independently of message IDs. Expected
display order and all three original stdout forms are compared byte-for-byte.
Pure identity checks compare decoded body/metadata, exact UnsupportedVersion
and MalformedEncoding errors, and the exact UTF-8 error; only a fixed expected
Boolean crosses the test assertion boundary.

Actual envelope_ids and acknowledge send three signed ACKs per binary to a
collector bound to 127.0.0.1 on an OS-assigned port. Network access is denied
except to that local port; signature verification runs with networking denied.
The harness retains each raw HTTP body, checks count and ordered IDs (including
invalid display payloads), mailbox token hash and timestamp, and verifies its
signature with the actual Mesh ACK decoder and crypto verifier. Baseline/current
body comparison excludes only timestamps and their signatures; both are retained
and checked independently. The test uses public fixture keys, never an account.

This is CLI output/receive/ACK qualification, not production server authorization,
mailbox persistence/draining, full run_device_b network setup, live delivery,
mobile/native release, or deployment qualification. The helper cannot produce
an unknown display status; its default refusal is inspected in actual source,
not forced by replacing a production function. No forbidden probe is run, no
production disclosure is added, and no disclosure inventory is regenerated.
