# RNWv2 server interoperability proof

Run `python3 scripts/prove-renewal-v2-http.py` from the product checkout. The
driver copies and hashes the current Core and declared Mesh dependencies, then
compiles an isolated production router/storage peer and a Mesh HTTP client. It
starts an owned ephemeral PostgreSQL cluster and loopback peer. No installed
mobile library, native app, production service or live funds are used.

Choose a new output with `--evidence PATH`. For client-only fixture corrections,
`--evidence PATH --resume-client` first verifies the copied sources and Core
binary, preserves the previous client/source/log/result attempt, then rebuilds
the client. It never silently recopies changed production dependencies. A
failed resumed attempt removes the previous current success report.

The client generates genuine account/device keys and starts with capability-1
credentials. It exercises device-signed RNWv2 publication, an exact capability-3
account answer, account-only and mismatched answers, retained RNWv1 requests,
byte-identical retry after a committed response is lost, and a stale answer
rebased after another directory transition. PostgreSQL and decoded stored
bundles are independent state oracles. Only public request digests, statuses,
source bodies, build reports and counts are retained; ephemeral keys and raw
directory entries remain in memory.

The server bootstrap omits background jobs while retaining the production HTTP
router, work admission, API handlers, transition classifier and transactional
storage. This is a local server-interoperability check, not native mobile
execution, witnessed client adoption, deployment or release qualification.

The initial local qualification passed five case groups and 24 real HTTP
requests. Both lost committed responses retried the exact canonical entry and
returned 200 without another log transition. Final persisted state was sequence
9, three devices, nine transparency entries and three registration prekeys.
The fixture also verified exact stored RNWv1/RNWv2 bytes, unchanged requested
prekeys during sequence rebasing, and the resulting capability masks.
