CREATE TABLE messenger_mailboxes (
  mailbox_token_hash BYTEA PRIMARY KEY CHECK (octet_length(mailbox_token_hash) = 32),
  pending_count INTEGER NOT NULL DEFAULT 0 CHECK (pending_count BETWEEN 0 AND 64)
);

CREATE TABLE messenger_directory (
  username TEXT PRIMARY KEY,
  account_identity BYTEA NOT NULL CHECK (octet_length(account_identity) BETWEEN 1 AND 16582),
  prekey_bundle BYTEA NOT NULL CHECK (octet_length(prekey_bundle) BETWEEN 1 AND 66535),
  mailbox_token BYTEA NOT NULL CHECK (octet_length(mailbox_token) = 32),
  mailbox_token_hash BYTEA NOT NULL UNIQUE REFERENCES messenger_mailboxes (mailbox_token_hash),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE messenger_envelopes (
  sequence BIGSERIAL PRIMARY KEY,
  mailbox_token_hash BYTEA NOT NULL REFERENCES messenger_mailboxes (mailbox_token_hash),
  envelope_id BYTEA NOT NULL CHECK (octet_length(envelope_id) = 16),
  suite SMALLINT NOT NULL CHECK (suite = 1),
  expiration_ms BIGINT NOT NULL CHECK (expiration_ms >= 0),
  padding_bucket INTEGER NOT NULL CHECK (padding_bucket IN (256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)),
  ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) <= padding_bucket),
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  acknowledged_at TIMESTAMPTZ,
  CONSTRAINT messenger_envelopes_mailbox_envelope_key UNIQUE (mailbox_token_hash, envelope_id)
);

CREATE FUNCTION messenger_reserve_mailbox_slot() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE messenger_mailboxes
    SET pending_count = pending_count + 1
    WHERE mailbox_token_hash = NEW.mailbox_token_hash AND pending_count < 64;
  IF NOT FOUND THEN
    IF EXISTS (SELECT 1 FROM messenger_mailboxes WHERE mailbox_token_hash = NEW.mailbox_token_hash) THEN
      RAISE EXCEPTION 'mailbox capacity reached'
        USING ERRCODE = 'P0001', CONSTRAINT = 'messenger_mailbox_capacity';
    END IF;
    RAISE EXCEPTION 'mailbox is not registered'
      USING ERRCODE = 'P0001', CONSTRAINT = 'messenger_mailbox_registration';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER messenger_envelopes_reserve_slot
  BEFORE INSERT ON messenger_envelopes
  FOR EACH ROW EXECUTE FUNCTION messenger_reserve_mailbox_slot();

CREATE FUNCTION messenger_release_mailbox_slot() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE messenger_mailboxes
    SET pending_count = pending_count - 1
    WHERE mailbox_token_hash = OLD.mailbox_token_hash AND pending_count > 0;
  RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER messenger_envelopes_release_acknowledged
  AFTER UPDATE OF acknowledged_at ON messenger_envelopes
  FOR EACH ROW
  WHEN (OLD.acknowledged_at IS NULL AND NEW.acknowledged_at IS NOT NULL)
  EXECUTE FUNCTION messenger_release_mailbox_slot();

CREATE TRIGGER messenger_envelopes_release_deleted
  AFTER DELETE ON messenger_envelopes
  FOR EACH ROW
  WHEN (OLD.acknowledged_at IS NULL)
  EXECUTE FUNCTION messenger_release_mailbox_slot();

CREATE INDEX messenger_envelopes_pending
  ON messenger_envelopes (mailbox_token_hash, sequence)
  WHERE acknowledged_at IS NULL;

CREATE INDEX messenger_envelopes_expiration
  ON messenger_envelopes (expiration_ms);
