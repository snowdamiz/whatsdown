ALTER TABLE messenger_mailboxes
  ADD COLUMN active BOOLEAN NOT NULL DEFAULT true;

CREATE TABLE messenger_accounts (
  username TEXT PRIMARY KEY,
  account_id BYTEA NOT NULL UNIQUE CHECK (octet_length(account_id) = 32),
  account_identity BYTEA NOT NULL CHECK (octet_length(account_identity) BETWEEN 1 AND 16582),
  sequence BIGINT NOT NULL DEFAULT 0 CHECK (sequence >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE messenger_devices (
  account_id BYTEA NOT NULL REFERENCES messenger_accounts (account_id),
  device_id BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
  prekey_bundle BYTEA NOT NULL CHECK (octet_length(prekey_bundle) BETWEEN 1 AND 16942),
  mailbox_token BYTEA NOT NULL CHECK (octet_length(mailbox_token) = 32),
  mailbox_token_hash BYTEA NOT NULL UNIQUE REFERENCES messenger_mailboxes (mailbox_token_hash),
  registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ,
  PRIMARY KEY (account_id, device_id)
);

CREATE TABLE messenger_revoked_devices (
  account_id BYTEA NOT NULL REFERENCES messenger_accounts (account_id),
  device_id BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
  sequence BIGINT NOT NULL CHECK (sequence > 0),
  revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id, device_id)
);

CREATE OR REPLACE FUNCTION messenger_reserve_mailbox_slot() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE messenger_mailboxes
    SET pending_count = pending_count + 1
    WHERE mailbox_token_hash = NEW.mailbox_token_hash
      AND active
      AND pending_count < 64;
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
