# Local relay scheduler proof

This is a test executable, not a public relay or production configuration path.
The portable writer proof compiles it with optimization enabled and drives it
against three loopback fixture RPC endpoints backed by one LiteSVM bank.

The harness dispatches admission, Stage, receipt, destination and lookup reads
to the exact Mesh protocol functions used by `morse-fork-verifier`. It accepts
caller-owned test configuration in a temporary JSON file, has no wallet, and
never signs or submits transactions. The production verifier continues to
require its authenticated release configuration and bounded command wrapper.

`scheduler-sbf.test.mjs` runs the durable JavaScript scheduler, SQLite journal,
Kit signing and finalized RPC adapter against actual SBF accounts. It covers all
19 HTTP submissions through serialized native admission, lost acknowledgments,
restarts before reconciliation, lookup activation,
payout receipts, cooldown, rent cleanup, seven-day journal compaction and
no-spend resubmission from permanent chain receipts after another restart. The fixture providers share one bank
oracle: this proves the local native execution path, not live provider
independence, TLS configuration, funded operation or deployment.
