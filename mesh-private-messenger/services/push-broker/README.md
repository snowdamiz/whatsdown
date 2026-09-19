# Push broker

The push broker is the only service that can decrypt provider tokens. It accepts
one canonical, sealed `PWK` body at `POST /internal/v1/push`, durably stores the
sealed request, and returns `204`. One worker ingests the seed directly into an
actor-owned Mesh X25519 private-key resource, opens the nested token, and sends
Expo only this generic notification:

```json
{"to":"<provider token>","body":"New encrypted activity","data":{"kind":"encrypted-wakeup"}}
```

Requests are rejected before queueing when empty, malformed, non-canonical, or
larger than 621 bytes. The endpoint requires an exact bearer credential. Its
response contract is `204` for durable acceptance (not provider delivery), `401`
for invalid service authentication, `422` for a malformed request, and `503`
when retry is safe.

The queue coalesces the same wake binding, caps new bindings at 100,000, retries
network, rate-limit, server, credential, and unknown provider failures with a
bounded backoff, and pins both Expo endpoints. A successful send ticket is not
delivery: the worker waits 15 minutes, polls its receipt, and tombstones the
binding after success or `DeviceNotRegistered`. Exact replays remain coalesced;
only a changed sealed binding resets the tombstone. Tombstones older than seven
days are purged in batches of at most 256.

## Configuration

- `MESSENGER_PUSH_BROKER_SEED_HEX` — required 32-byte X25519 seed as hex. Keep
  it secret and distribute only its derived public key to clients. Mesh ingests
  it with `Env.get_secret_hex`; it never becomes a Mesh `String` or `Bytes`.
- `MESSENGER_PUSH_BROKER_INTERNAL_TOKEN` — required 32–256 character service
  credential. Configure the exact same value on directory delivery.
- `MESSENGER_PUSH_BROKER_DATABASE_URL` — required PostgreSQL connection URL
  for the durable queue. Existing SQLite queues are not imported or deleted.
- `MESSENGER_EXPO_PUSH_URL` — optional compatibility setting. If present it
  must exactly equal `https://exp.host/--/api/v2/push/send`; redirects and
  alternate hosts are not accepted.
- `MESSENGER_EXPO_ACCESS_TOKEN` — optional Expo access token sent as a bearer
  token. Newlines, surrounding whitespace, and values over 2 KiB are rejected.
- `MESSENGER_PUSH_BROKER_PORT` — optional listen port; defaults to `18088`.
- `MESSENGER_JOBS_URL` — optional private durable scheduler. When set, queue
  changes register a wakeup before committing, and alarms run sends, receipt
  checks, retries, and tombstone expiry. The local polling worker is disabled.

Directory delivery must set `MESSENGER_PUSH_MODE=broker`,
`MESSENGER_PUSH_BROKER_URL`, and the matching
`MESSENGER_PUSH_BROKER_INTERNAL_TOKEN`. Keep the endpoint on the private service
network and give its database role access only to the queue schema. The broker stores the sealed `PWK` plus opaque hashes and
queue state. It never stores plaintext provider tokens and never logs request
bodies, hashes, provider tokens, or credentials.

## Verify

```sh
export MESSENGER_STORAGE_TEST_DATABASE_URL='postgres://localhost/morse_storage_test?sslmode=disable'
meshc test tests/broker.test.mpl
meshc test tests/queue.test.mpl
meshc build .
```

Use an isolated test database. Run one broker instance: queue processing does
not yet lease jobs across replicas.
