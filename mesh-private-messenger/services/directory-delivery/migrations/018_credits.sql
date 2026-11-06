-- Issuance/payment records belong in another database. These tables contain
-- public issuer announcements, verification state, nullifiers and action holds.
CREATE TABLE credit_issuer_announcements (
  epoch BIGINT NOT NULL CHECK (epoch >= 0),
  purpose SMALLINT NOT NULL CHECK (purpose IN (0, 1)),
  key_id BYTEA NOT NULL UNIQUE CHECK (octet_length(key_id) = 32),
  spki BYTEA NOT NULL CHECK (octet_length(spki) = 342),
  entry_sequence BIGINT NOT NULL UNIQUE REFERENCES transparency_entries(sequence),
  admitted_checkpoint BYTEA,
  announced_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  admitted_at TIMESTAMPTZ,
  PRIMARY KEY (epoch, purpose),
  CHECK ((admitted_at IS NULL) = (admitted_checkpoint IS NULL))
);
CREATE TABLE credit_issuer_cursor (
  singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
  checkpoint BYTEA NOT NULL
);
INSERT INTO credit_issuer_cursor (checkpoint) VALUES (''::bytea);

ALTER TABLE messenger_mailboxes ADD COLUMN postage_credits SMALLINT NOT NULL DEFAULT 0
  CHECK (postage_credits IN (0, 1, 5, 25));

CREATE TABLE credit_holds (
  hold_id BYTEA PRIMARY KEY CHECK (octet_length(hold_id) = 32),
  action BYTEA NOT NULL CHECK (octet_length(action) = 117),
  action_kind SMALLINT NOT NULL CHECK (action_kind BETWEEN 1 AND 4),
  target BYTEA NOT NULL CHECK (octet_length(target) = 32),
  request_hash BYTEA NOT NULL CHECK (octet_length(request_hash) = 32),
  frame_hash BYTEA NOT NULL CHECK (octet_length(frame_hash) = 32),
  credits SMALLINT NOT NULL CHECK (credits BETWEEN 1 AND 64),
  expires_at BIGINT NOT NULL CHECK (expires_at > 0),
  retain_until BIGINT NOT NULL CHECK (retain_until >= expires_at),
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  effect_id BYTEA CHECK (effect_id IS NULL OR octet_length(effect_id) = 32),
  consumed_at TIMESTAMPTZ,
  CHECK ((effect_id IS NULL) = (consumed_at IS NULL))
);
CREATE INDEX credit_holds_retention ON credit_holds (retain_until, hold_id);
CREATE UNIQUE INDEX credit_holds_effect ON credit_holds (effect_id) WHERE effect_id IS NOT NULL;
CREATE TABLE credit_spent (
  nullifier BYTEA PRIMARY KEY CHECK (octet_length(nullifier) = 32),
  issuer_epoch BIGINT NOT NULL CHECK (issuer_epoch >= 0),
  retain_until BIGINT NOT NULL CHECK (retain_until > 0),
  hold_id BYTEA NOT NULL REFERENCES credit_holds(hold_id),
  spent_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX credit_spent_retention ON credit_spent (retain_until, nullifier);
CREATE INDEX credit_spent_hold ON credit_spent (hold_id);
