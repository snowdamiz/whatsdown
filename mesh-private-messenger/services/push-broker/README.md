# Push broker

The push broker is the only service that can decrypt provider tokens. It accepts
one canonical, sealed `PWK` body at `POST /internal/v1/push`, opens the nested
token with its X25519 seed, and sends Expo only this generic notification:

```json
{"to":"<provider token>","body":"New encrypted activity","data":{"kind":"encrypted-wakeup"}}
```

Requests are rejected before provider I/O when empty, malformed, non-canonical,
or larger than 621 bytes. The response contract is `204` for a valid Expo
ticket, `422` for a permanent request/provider rejection, and `503` when retry
is safe. Keep this endpoint on the private service network; it has no public
authentication layer.

## Configuration

- `MESSENGER_PUSH_BROKER_SEED_HEX` — required 32-byte X25519 seed as hex. Keep
  it secret and distribute only its derived public key to clients.
- `MESSENGER_EXPO_PUSH_URL` — optional HTTPS provider URL; defaults to
  `https://exp.host/--/api/v2/push/send`.
- `MESSENGER_EXPO_ACCESS_TOKEN` — optional Expo access token sent as a bearer
  token. Newlines, surrounding whitespace, and values over 2 KiB are rejected.
- `MESSENGER_PUSH_BROKER_PORT` — optional listen port; defaults to `18088`.

Terminate TLS and enforce service identity at the private network edge. The
broker never logs request bodies, wake hashes, provider tokens, or credentials.

## Verify

```sh
meshc test tests/broker.test.mpl
meshc build .
```
