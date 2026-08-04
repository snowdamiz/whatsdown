# Whatsdown mobile

The Expo app calls the local `mesh-messenger` native module; private keys and protocol state never cross into TypeScript.

```sh
npm ci
EXPO_PUBLIC_MESSENGER_BASE_URL=http://YOUR-MESSENGER-HOST:18086 \
EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL=http://YOUR-EDGE-HOST:18087 \
EXPO_PUBLIC_MESSENGER_DELIVERY_PUBLIC_KEY_HEX=DELIVERY_X25519_PUBLIC_KEY \
EXPO_PUBLIC_MESSENGER_ABUSE_DIFFICULTY=16 \
EXPO_PUBLIC_MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX=SERVICE_PUBLIC_KEY \
EXPO_PUBLIC_MESSENGER_WITNESS_A_PUBLIC_KEY_HEX=WITNESS_A_PUBLIC_KEY \
EXPO_PUBLIC_MESSENGER_WITNESS_B_PUBLIC_KEY_HEX=WITNESS_B_PUBLIC_KEY \
MESSENGER_EXPO_PROJECT_ID=YOUR_EAS_PROJECT_UUID \
MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX=PUSH_BROKER_X25519_PUBLIC_KEY \
npm run ios
```

Use a LAN or deployed HTTPS URL on physical devices. `127.0.0.1` only reaches the device itself. A custom development build is required because the app contains the local native module.
New accounts stay in durable no-push mode until the user explicitly enables generic encrypted-activity notifications from the account screen.
New development accounts advertise experimental hybrid suite `0x0002`; linked
classical devices remain on suite `0x0001` until credential rotation. Suite
`0x0002` is not production-approved until the independent cryptographic review
[gate](../../protocol/hybrid-handshake-v1.md) is complete.
Transparency and witness keys are required 32-byte lowercase hex build pins; directory responses fail closed when they are absent or do not match.
The delivery X25519 key is also a required 32-byte lowercase hex build pin. Sends fail closed without the privacy-edge URL or a valid key. Abuse difficulty defaults to 16 and must stay between 1 and 24.
Generic notification enablement requires the Expo project UUID and push-broker X25519 public key together. The broker key is a 32-byte lowercase-hex public build pin. Both non-public environment variables are provisioned into signed native resources during prebuild; they are not OTA JavaScript configuration. Missing, partial, or malformed build configuration fails before notification permission is requested. No-push startup recovery remains available when both pins are absent.

Outbound session state, history, and the encrypted outbox commit atomically. Submission is at-least-once with server deduplication; only a durable 2xx response permits local acknowledgement. The iOS and Android bridges serialize native calls.

Each device keeps at most 64 server-active and 64 retired/in-flight
storage-wrapped one-time prekey secrets, indexed by their public `prekey_id`.
`mesh_messenger_replenish_prekeys` returns a canonical, device-signed `OTB`
batch for upload; a requested count of zero re-exports pending entries or sends
an authenticated empty recovery query. The server's identity-bound `OTA`
response is applied through `mesh_messenger_reconcile_prekeys` before native
code generates replacements. Foreground registration and mailbox sync perform
that recovery and refill automatically. An accepted initial message deletes
only the exact claimed secret and active marker in the same SQLite transaction
as its session and history; a failed transaction retains both, while replay
after commit fails.
When all 64 retired slots are occupied, refill evicts the oldest retired
secrets. This bounds storage, but more than 64 claimed initial messages delayed
past delivery can no longer decrypt and require a protocol-level delivery
acknowledgement before raising the limit.
Existing singleton records are opened with their historical storage context,
resealed under the per-ID context, and retained provisionally active until the
first `OTA` classifies them as active or retired. A consumed singleton remains
available for a delayed initial message but its ID is never generated again.
Bundle claim responses
must preserve the transparently verified base bundle and substitute the
server-claimed ID/public key pair without changing other fields.

Run the software acceptance proof from the repository root:

```sh
mesh-private-messenger/scripts/prove-m11.sh
```

Push payloads are accepted only when the visible body is `New encrypted activity` and the data object is exactly `{ "kind": "encrypted-wakeup" }`.
