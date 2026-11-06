# Native account HTTP proof

Run from the product checkout with the owned iOS simulator and Android emulator:

```sh
python3 scripts/prove-account-http-native.py \
  --platform both \
  --evidence ../.morse/witness-proof/account-http-native162-new \
  --compiler ../.morse/native-reader-meshc.py
```

The evidence directory must be new. `--reuse-backend` permits a subsequent
platform run only after verifying the existing backend executable and frozen
source hashes. Each platform uses a fresh local PostgreSQL database. The
installed module's current generated bindings, native library, and actual OS
storage callbacks are compiled into separate owned proof apps.

The server uses the unchanged production directory-delivery router, API and
storage. A test-only bootstrap omits background witness and push workers. Its
ephemeral signing material stays in process environment and is not archived.
The localhost origin and development work difficulty are immutable app resources;
the proof does not add an application network override.

Assertions cover real registration; an accepted publication whose reply is
dropped; process restart and byte-identical pending publication replay; exactly
64 active one-time prekeys plus one reusable last-resort key; idempotent
registration; authenticated server deletion and local account-state erasure;
and a delayed old-account deletion refusing before HTTP against a replacement.
Database counts distinguish one-time keys from the reusable last-resort key.

Evidence records body hashes and lengths, canonical native results and database
counts. Client profiles contain mailbox capabilities and must not be copied from
the temporary app command files into evidence. The apps, database and services
are removed when the contexts exit. No screen capture, live funds, external
service, witnessed admission, linked-device renewal/revocation, physical-device
qualification or release claim is part of this gate.
