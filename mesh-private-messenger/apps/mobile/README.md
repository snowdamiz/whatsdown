# Whatsdown mobile

The Expo app calls the local `mesh-messenger` native module; private keys and protocol state never cross into TypeScript.

```sh
npm ci
EXPO_PUBLIC_MESSENGER_BASE_URL=http://YOUR-MESSENGER-HOST:18086 npm run ios
```

Use a LAN or deployed HTTPS URL on physical devices. `127.0.0.1` only reaches the device itself. A custom development build is required because the app contains the local native module.

Run the software acceptance proof from the repository root:

```sh
mesh-private-messenger/scripts/prove-m11.sh
```

Push payloads are accepted only when the visible body is `New encrypted activity` and the data object is exactly `{ "kind": "encrypted-wakeup" }`.
