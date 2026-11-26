-- The unauthenticated single-device directory is retired. Every mailbox is now
-- owned by an account-signed device in messenger_devices, whose signing key
-- authorizes mailbox reads and acknowledgements. A mailbox that was only ever
-- registered through the legacy path has no such key and can never be read
-- again, so it and its queued envelopes are removed with the table.
--
-- Each statement is self-contained so the file behaves identically under a
-- transactional runner and under psql autocommit.
DELETE FROM messenger_outbox_events
  WHERE mailbox_token_hash IN (
    SELECT mailbox_token_hash FROM messenger_directory
    EXCEPT SELECT mailbox_token_hash FROM messenger_devices
  );

DELETE FROM messenger_envelopes
  WHERE mailbox_token_hash IN (
    SELECT mailbox_token_hash FROM messenger_directory
    EXCEPT SELECT mailbox_token_hash FROM messenger_devices
  );

DELETE FROM messenger_push_bindings
  WHERE mailbox_token_hash IN (
    SELECT mailbox_token_hash FROM messenger_directory
    EXCEPT SELECT mailbox_token_hash FROM messenger_devices
  );

WITH legacy AS (
  DELETE FROM messenger_directory RETURNING mailbox_token_hash
)
DELETE FROM messenger_mailboxes
  WHERE mailbox_token_hash IN (SELECT mailbox_token_hash FROM legacy)
    AND mailbox_token_hash NOT IN (SELECT mailbox_token_hash FROM messenger_devices);

DROP TABLE messenger_directory;
