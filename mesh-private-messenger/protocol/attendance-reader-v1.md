# Authenticated weekly attendance reads

`morse attendance --log LOG_NAME --epoch EPOCH` reports retained weekly counts
from the judge. The epoch must be a canonical unsigned decimal integer for the
seven-day Unix-time period defined in [attendance-v1.md](attendance-v1.md). The
explicit log must match `MESSENGER_SECURITY_CONFIG`; the command uses that
configuration's service key, log version, judge program, ring, and independently
configured RPC providers. `MORSE_ATTENDANCE_MIN_CONTEXT_SLOT` optionally supplies
a canonical decimal minimum finalized context slot and defaults to `0`.
Attendance reads do not require a bond mint.

`Transparency.AttendanceRead` derives the Log, attendance clock, and epoch PDAs
locally. Each provider receives one `getMultipleAccounts` request with finalized
commitment, the minimum context slot, and a 2,640-byte prefix slice. The response
must contain those three ordered accounts in an actual JSON context object with
a numeric slot. For an enabled Log and present epoch, full account spaces must
be 352, 65,616, and 2,640 bytes. This
keeps the large clock bounded while refusing a partially allocated clock.

The reader checks program ownership, nonzero lamports, nonexecutable accounts,
exact slice sizes, the Log name/key/version/ring, the active clock's log and
activation slot, and the requested epoch's log/number and posting context. A
sealed nonempty epoch must be observed after its final signing slot. Two
independent providers must agree on the entire account batch, including presence,
bytes, owners, full spaces and lamports. The reported context is the lower of
their finalized contexts. Conflicting or unavailable providers produce an error
and no report.

The JSON report has schema version 1. Epochs, slots, post counts and signed counts
are decimal strings. `status` distinguishes:

- `disabled`: the authenticated Log has attendance disabled; no attendance counts
  are reported.
- `missing`: attendance is enabled, but this epoch account is absent or an empty
  system-owned prefunded PDA; its denominator remains unknown.
- `unsealed`: counts can still change.
- `sealed`: the judge has sealed this epoch's counts.

Missing counts and sealed state are JSON `null`, rather than zero or false.
`first_full_epoch` comes from the authenticated activation header.
`activation_partial` is true only for the activation epoch; no earlier history
is backfilled. `rows` expose Witness PDA addresses and raw signed counts. They
do not identify operators or assert independent ownership, reward eligibility,
pool funding, settlement, or payment. A sealed empty epoch is a known zero
denominator, distinct from a missing account.

Focused local verification:

```sh
../mesh-lang/target/debug/meshc test packages/messenger-protocol/tests/attendance_read.test.mpl
../mesh-lang/target/debug/meshc test clients/mesh-cli/tests/attendance.test.mpl
node --test scripts/attendance-command.test.mjs
```

These tests use local synthetic account fixtures and local HTTP providers. They
verify reader authentication and command failure boundaries, and do not attest
to deployed state, provider independence in an actual release, reward settlement,
or a funded payment.
