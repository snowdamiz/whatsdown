# Push broker

The push broker is the only service that can decrypt provider tokens. It accepts
one canonical, sealed `PWK` body at `POST /internal/v1/push`, durably stores the
sealed request, and returns `204`. One worker later opens the nested token with
its X25519 seed and sends Expo only this generic notification:

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
  it secret and distribute only its derived public key to clients.
- `MESSENGER_PUSH_BROKER_INTERNAL_TOKEN` — required 32–256 character service
  credential. Configure the exact same value on directory delivery.
- `MESSENGER_PUSH_BROKER_DB_PATH` — durable SQLite queue path; defaults to
  `push-broker.db`.
- `MESSENGER_EXPO_PUSH_URL` — optional compatibility setting. If present it
  must exactly equal `https://exp.host/--/api/v2/push/send`; redirects and
  alternate hosts are not accepted.
- `MESSENGER_EXPO_ACCESS_TOKEN` — optional Expo access token sent as a bearer
  token. Newlines, surrounding whitespace, and values over 2 KiB are rejected.
- `MESSENGER_PUSH_BROKER_PORT` — optional listen port; defaults to `18088`.

Directory delivery must set `MESSENGER_PUSH_MODE=broker`,
`MESSENGER_PUSH_BROKER_URL`, and the matching
`MESSENGER_PUSH_BROKER_INTERNAL_TOKEN`. Keep the endpoint on the private service
network, terminate TLS at its edge, and restrict filesystem access to the queue
and its WAL files. The broker stores the sealed `PWK` plus opaque hashes and
queue state. It never stores plaintext provider tokens and never logs request
bodies, hashes, provider tokens, or credentials.

## Verify

```sh
meshc test tests/broker.test.mpl
meshc test tests/queue.test.mpl
meshc build .
```
