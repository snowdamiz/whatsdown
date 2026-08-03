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
npm run ios
```

Use a LAN or deployed HTTPS URL on physical devices. `127.0.0.1` only reaches the device itself. A custom development build is required because the app contains the local native module.
New development accounts advertise experimental hybrid suite `0x0002`; linked
classical devices remain on suite `0x0001` until credential rotation. Suite
`0x0002` is not production-approved until the independent cryptographic review
[gate](../../protocol/hybrid-handshake-v1.md) is complete.
Transparency and witness keys are required 32-byte lowercase hex build pins; directory responses fail closed when they are absent or do not match.
The delivery X25519 key is also a required 32-byte lowercase hex build pin. Sends fail closed without the privacy-edge URL or a valid key. Abuse difficulty defaults to 16 and must stay between 1 and 24.

Run the software acceptance proof from the repository root:

```sh
mesh-private-messenger/scripts/prove-m11.sh
```

Push payloads are accepted only when the visible body is `New encrypted activity` and the data object is exactly `{ "kind": "encrypted-wakeup" }`.
