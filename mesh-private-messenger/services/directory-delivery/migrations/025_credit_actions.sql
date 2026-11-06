-- A paid mailbox parking grant never changes the sender's original envelope.
ALTER TABLE messenger_mailboxes ADD COLUMN credit_retention_until_ms BIGINT NOT NULL DEFAULT 0
  CHECK (credit_retention_until_ms >= 0);
ALTER TABLE messenger_envelopes ADD COLUMN storage_until_ms BIGINT NOT NULL DEFAULT 0
  CHECK (storage_until_ms >= 0);
CREATE INDEX messenger_envelopes_storage_expiration
  ON messenger_envelopes ((GREATEST(expiration_ms, storage_until_ms)));

-- Keep the exact signed completion with the hold. Retention adapters extend
-- the hold's retain_until through the paid horizon plus seven recovery days.
CREATE TABLE credit_action_effects (
  hold_id BYTEA PRIMARY KEY REFERENCES credit_holds(hold_id) ON DELETE CASCADE,
  effect_id BYTEA NOT NULL UNIQUE CHECK (octet_length(effect_id) = 32),
  action_kind SMALLINT NOT NULL CHECK (action_kind BETWEEN 1 AND 4),
  receipt BYTEA NOT NULL CHECK (octet_length(receipt) BETWEEN 207 AND 462),
  applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
