# Push Provider Token Wire Version 1

Push-token wire version `1` keeps notification provider tokens outside the
directory and delivery trust boundary. A mobile client validates its Expo token
and seals it directly to the configured push broker's X25519 public key. The
directory stores that canonical sealed value and forwards it with only the
opaque per-event wake hash. Notification payloads remain generic and
contain no sender, recipient, message, or attachment data.

This is a development profile. A production provider adapter and physical
device proof remain required.

## What the provider learns

Expo, and through it Apple or Google, necessarily learns the platform push
token, the app identifier, the connection it arrives on, and the time of each
wake. To obtain an Expo token the client also sends an installation identifier.
That identifier is 16 random bytes generated on the device, sealed in local
storage under `push-install-id/v1`, and reused so a rotated platform token
replaces the old one. It is never the protocol device ID: that ID is public in
the directory, so sending it would let the provider tie a push token, and every
wake delivered to it, to a named account.

## Sealed provider token (`SPT`)

```text
version:u8 = 1
tag:3 = "SPT"
ephemeral_x25519_public_key:32
nonce:12
ciphertext:vector (36..528 bytes)
```

The client accepts only printable Expo tokens beginning with `ExpoPushToken[`
or `ExponentPushToken[` and ending with `]`, at most 512 bytes. It creates a
fresh ephemeral X25519 key and 12-byte random nonce for each seal. The shared
secret is expanded with HKDF-SHA-256 using:

```text
salt = SHA256("mesh-msg/v1/push-provider-token-salt")
info = "mesh-msg/v1/push-provider-token" || ephemeral_public_key || broker_public_key
```

ChaCha20-Poly1305 uses the same `info` as associated data. The maximum encoded
sealed token is 580 bytes. Only the broker private key can open it; the broker
revalidates the plaintext token after authentication.

Push binding accepts provider `1` only and embeds exactly one canonical `SPT`;
arbitrary ciphertext and unsupported provider identifiers are rejected before
the binding reaches storage. The maximum signed binding is 725 bytes.

## Broker wake request (`PWK`)

```text
version:u8 = 1
tag:3 = "PWK"
wake_token_hash:32
provider:u8 = 1 (Expo)
sealed_provider_token:vector (at most 580 bytes)
```

The maximum encoded request is 621 bytes. Decoders reject malformed nested
sealed tokens, unsupported versions or providers, non-canonical encodings,
oversized input, truncation, and trailing bytes before any provider request.

For broker requests, directory delivery derives `wake_token_hash` as
`SHA256(binding.wake_token_hash || UTF8("mesh-msg/v1/push-event/" || event_id))`.
Retries of one outbox event remain identical, while a later message has a new
deduplication key. The event ID itself never leaves directory delivery.
