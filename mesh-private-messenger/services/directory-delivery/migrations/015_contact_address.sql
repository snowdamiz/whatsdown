-- A mailbox's address is public, so anyone can fill it and stop a person's own
-- contacts reaching them. Every send is anonymous to the service, so it cannot
-- tell senders apart; what it can tell apart is addresses.
--
-- A device may publish the hash of one secret second deposit address and share
-- the address only with contacts. Envelopes sent to it reach the same mailbox
-- and may use all of it. Everything else, which is everyone who only knows the
-- public address, may hold at most three quarters: 3 MiB and 3,072 envelopes.
-- The last quarter is kept for contacts, so strangers can never crowd them out.
--
-- A retired address is kept for good and keeps routing, as a stranger's would.
-- Rotation therefore never makes an envelope undeliverable: a sender gives up
-- on an envelope whose mailbox refuses it for good, so an address that stopped
-- routing would lose messages. Demotion also handles a hostile former contact.
CREATE TABLE messenger_mailbox_aliases (
  alias_hash BYTEA PRIMARY KEY CHECK (octet_length(alias_hash) = 32),
  mailbox_token_hash BYTEA NOT NULL
    REFERENCES messenger_mailboxes (mailbox_token_hash) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  retired_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX messenger_mailbox_aliases_current
  ON messenger_mailbox_aliases (mailbox_token_hash)
  WHERE retired_at IS NULL;

ALTER TABLE messenger_envelopes
  ADD COLUMN contact BOOLEAN NOT NULL DEFAULT false;

-- The bounds are the whole mailbox, not the stranger share: whatever already
-- waits was sent to the public address, and a mailbox may hold more of it than
-- the share allows. The share applies to new reservations only.
ALTER TABLE messenger_mailboxes
  ADD COLUMN stranger_pending_count INTEGER NOT NULL DEFAULT 0
    CHECK (stranger_pending_count BETWEEN 0 AND 4096),
  ADD COLUMN stranger_pending_bytes BIGINT NOT NULL DEFAULT 0
    CHECK (stranger_pending_bytes BETWEEN 0 AND 4194304);

UPDATE messenger_mailboxes
  SET stranger_pending_count = pending_count,
      stranger_pending_bytes = pending_bytes;

-- Every limit raises the same error, so a sender cannot tell which one it hit.
CREATE OR REPLACE FUNCTION messenger_reserve_mailbox_slot() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE messenger_mailboxes
    SET pending_count = pending_count + 1,
        pending_bytes = pending_bytes + NEW.padding_bucket,
        stranger_pending_count = stranger_pending_count + CASE WHEN NEW.contact THEN 0 ELSE 1 END,
        stranger_pending_bytes = stranger_pending_bytes + CASE WHEN NEW.contact THEN 0 ELSE NEW.padding_bucket END
    WHERE mailbox_token_hash = NEW.mailbox_token_hash
      AND active
      AND pending_count < 4096
      AND pending_bytes + NEW.padding_bucket <= 4194304
      AND (NEW.contact OR (stranger_pending_count < 3072
        AND stranger_pending_bytes + NEW.padding_bucket <= 3145728));
  IF NOT FOUND THEN
    IF EXISTS (
      SELECT 1 FROM messenger_mailboxes
      WHERE mailbox_token_hash = NEW.mailbox_token_hash AND NOT active
    ) THEN
      RAISE EXCEPTION 'mailbox is inactive'
        USING ERRCODE = 'P0001', CONSTRAINT = 'messenger_mailbox_inactive';
    END IF;
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

CREATE OR REPLACE FUNCTION messenger_release_mailbox_slot() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE messenger_mailboxes
    SET pending_count = GREATEST(pending_count - 1, 0),
        pending_bytes = GREATEST(pending_bytes - OLD.padding_bucket, 0),
        stranger_pending_count = GREATEST(
          stranger_pending_count - CASE WHEN OLD.contact THEN 0 ELSE 1 END, 0),
        stranger_pending_bytes = GREATEST(
          stranger_pending_bytes - CASE WHEN OLD.contact THEN 0 ELSE OLD.padding_bucket END, 0)
    WHERE mailbox_token_hash = OLD.mailbox_token_hash;
  RETURN COALESCE(NEW, OLD);
END;
$$;
