# Native encrypted-storage upgrade proof

These owned-app tests use the previous production 163-export native libraries
to create an account and write both sealed preferences through the real ABI.
They then replace the native code with the candidate while retaining the OS
key custody and database path. No private-key injection, database rewrite,
test-only Mesh export or live network service is involved.

Each platform verifies:

- The old library creates guessable SHA-256 labels, clear `updated_at`, and a
  table with row IDs. Replacing old code with old code still fails the new schema
  requirements (the negative control).
- Replacing the executable alone leaves the database unchanged. The candidate's
  real initialization performs the migration.
- Every encrypted record keeps identical ciphertext, while every index changes
  and no legacy index remains. The version-2 binding and strict table without
  row IDs are present.
- The public profile and both sealed preferences survive cold-process reads;
  repeated initialization leaves the migrated records unchanged.
- A different account's valid public profile cannot authorize a preference
  write. A legitimate new write survives restart and changes only its record.

The account binding intentionally permits credential/prekey renewal within the
same identity. Flipping an arbitrary profile byte is not a valid negative test
for a different account; the fixture creates a second owned account instead.

Android uses one ephemeral APK signing key and `adb install -r`; it never
uninstalls between versions. The test requires an absent owned bundle before
starting, and removes that bundle, its Keystore custody and the ephemeral APK
signing key afterward. SQLite inspection runs read-only in the owned app.

iOS `prepare` compiles both Swift apps without device access. `run` swaps only
the stopped owned Simulator app's executable and re-signs it in place, checking
that the absolute data path stays equal. Simulator reinstall may relocate the
sandbox and is not a faithful model for the existing path-bound state. Database
inspection uses read-only SQLite while the app is stopped. The proof calls the
real account-erasure export and removes its owned app afterward.

Use the scripts' `--help` for required paths. Inputs must come from the exact
qualified previous/candidate native artifacts and the matching prepared host
product. Android's candidate JNI library must be the one linked from that
candidate by the native host preparation gate. Both scripts freeze input bodies
and retain APK/executable artifacts, schema/ciphertext hashes and terminal
results. They preserve no plaintext database or private signing key in evidence.
The scripts refuse to reuse work directories. Retain unsuccessful attempts
separately; do not overwrite them with a rerun.

This covers local migration on the named device/simulator. It does not prove a
store-delivered upgrade, all legacy database versions, physical iOS execution,
or forensic erasure of old SQLite pages, snapshots or backups.
