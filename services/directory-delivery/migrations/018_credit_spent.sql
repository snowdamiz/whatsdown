-- Anonymous credits (protocol/credits-v1.md). The core keeps what redeeming
-- needs and nothing the issuer holds: the issuer's public keys as the log
-- carries them, the spent set, and holds. No column here names a quote, a
-- payment, a deposit or a blinded message, and the issuer's database has none
-- of these tables (services/credit-issuer/tests/linkability.test.mjs).

-- Issuer keys announced as `issuer-key-v1` leaves. Their leaves use commitments
-- no account has, so log pruning never supersedes them; they stay for good.
-- At most one unrevoked key per purpose and epoch.
CREATE TABLE credit_issuer_keys (
  token_key_id BYTEA PRIMARY KEY CHECK (octet_length(token_key_id) = 32),
  purpose TEXT NOT NULL CHECK (purpose IN ('live', 'test')),
  issuer_name TEXT NOT NULL CHECK (length(issuer_name) BETWEEN 1 AND 253),
  epoch BIGINT NOT NULL CHECK (epoch BETWEEN 0 AND 4294967295),
  spki BYTEA NOT NULL CHECK (octet_length(spki) = 342),
  entry_sequence BIGINT NOT NULL UNIQUE,
  revocation_sequence BIGINT UNIQUE,
  CHECK (token_key_id = sha256(spki))
);

CREATE UNIQUE INDEX credit_issuer_keys_current
  ON credit_issuer_keys (purpose, epoch) WHERE revocation_sequence IS NULL;

-- One row per spent token. A token is accepted only while its key is (two
-- epochs from the key's epoch), so a row goes 7 days after that.
CREATE TABLE credit_spent (
  nullifier BYTEA PRIMARY KEY CHECK (octet_length(nullifier) = 32),
  key_epoch BIGINT NOT NULL CHECK (key_epoch >= 0),
  spent_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX credit_spent_key_epoch ON credit_spent (key_epoch);

-- What a redemption entitles: written with the nullifiers, taken once by the
-- action it names (in the action's own transaction), then kept a day.
CREATE TABLE credit_holds (
  redemption_id BYTEA PRIMARY KEY CHECK (octet_length(redemption_id) = 16),
  action SMALLINT NOT NULL CHECK (action BETWEEN 1 AND 4),
  binding BYTEA NOT NULL CHECK (octet_length(binding) = 32),
  credits SMALLINT NOT NULL CHECK (credits BETWEEN 1 AND 64),
  held_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  taken_at TIMESTAMPTZ
);

-- MORSE_CREDITS_MODE as the core last started with. Switching to off keeps
-- redeeming the previous purpose's unspent tokens for 7 days from changed_at.
CREATE TABLE credit_mode (
  singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
  mode TEXT NOT NULL CHECK (mode IN ('off', 'test', 'live')),
  purpose TEXT CHECK (purpose IN ('live', 'test')),
  changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
