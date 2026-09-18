# Simulator checks

Run the local stack with `./run.sh` from the repository root, then install its iOS development build on a simulator. These flows use Maestro and the live local services. They never erase an identity or clear a keychain.

- `onboarding.yaml`: fresh device; username validation and device-link scanner navigation.
- `account.yaml`: create `QA_USERNAME` if needed, render the multipart contact code, inspect no-push mode, and reopen the saved identity.
- `navigation.yaml`: existing account; compose, groups, contact code, linked devices, and notifications.
- `send-request.yaml`: send `QA_MESSAGE` to `QA_RECIPIENT`, inspect encrypted history, and return to the inbox.
- `accept-reply.yaml`: recipient account; fetch `QA_MESSAGE` from `QA_SENDER`, accept the request, send `QA_REPLY`, block/unblock, and verify history after restart.
- `group.yaml`: create a group, inspect membership, confirm Send stays disabled until another device joins, and display the invitation code.
- `disappearing.yaml`: send a one-minute message and leave the conversation open until it disappears.
- `refresh-security.yaml`: start inside an accepted conversation saved by a pre-identity-binding build, with no safety number; send a message and confirm the safety number becomes available immediately. This needs a legacy database fixture and must run before manually syncing or reloading the conversation.

Example, with two separate test accounts already created:

```sh
maestro --udid "$ALICE_SIMULATOR" test --no-reinstall-driver \
  -e QA_RECIPIENT=qa_bob -e 'QA_MESSAGE=Hello from Alice' \
  mesh-private-messenger/apps/mobile/tests/e2e/send-request.yaml

maestro --udid "$BOB_SIMULATOR" test --no-reinstall-driver \
  -e QA_SENDER=qa_alice -e 'QA_MESSAGE=Hello from Alice' \
  -e 'QA_REPLY=Hello from Bob' \
  mesh-private-messenger/apps/mobile/tests/e2e/accept-reply.yaml
```

Run device flows sequentially. Native simulator tests do not verify physical-camera scanning or real push delivery; multipart encoding/assembly has a separate unit regression in `src/qr.test.ts`.
