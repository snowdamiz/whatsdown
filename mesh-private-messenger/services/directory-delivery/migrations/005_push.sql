CREATE TABLE messenger_push_bindings (
  mailbox_token_hash BYTEA PRIMARY KEY
    REFERENCES messenger_mailboxes (mailbox_token_hash) ON DELETE CASCADE,
  wake_token_hash BYTEA NOT NULL UNIQUE CHECK (
    octet_length(wake_token_hash) = 32
    AND wake_token_hash <> mailbox_token_hash
  ),
  revision BIGINT NOT NULL CHECK (revision > 0),
  provider SMALLINT NOT NULL CHECK (provider BETWEEN 1 AND 255),
  provider_token_ciphertext BYTEA NOT NULL
    CHECK (octet_length(provider_token_ciphertext) BETWEEN 17 AND 4096),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  disabled_at TIMESTAMPTZ
);

CREATE FUNCTION messenger_remove_push_binding_for_inactive_mailbox() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM messenger_push_bindings
    WHERE mailbox_token_hash = NEW.mailbox_token_hash;
  RETURN NEW;
END;
$$;

CREATE TRIGGER messenger_mailboxes_remove_push_binding
  AFTER UPDATE OF active ON messenger_mailboxes
  FOR EACH ROW
  WHEN (OLD.active AND NOT NEW.active)
  EXECUTE FUNCTION messenger_remove_push_binding_for_inactive_mailbox();
