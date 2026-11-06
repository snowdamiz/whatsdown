-- This database belongs only to the issuer. Never add redemption nullifiers,
-- mailbox identifiers, core hold IDs or user accounts here.
CREATE TABLE issuer_keys (
  key_id BYTEA PRIMARY KEY CHECK (octet_length(key_id) = 32),
  epoch NUMERIC(20,0) NOT NULL CHECK (epoch >= 0),
  purpose SMALLINT NOT NULL CHECK (purpose IN (0,1)),
  spki BYTEA NOT NULL UNIQUE CHECK (octet_length(spki) = 342),
  sealed_private_key BYTEA NOT NULL CHECK (octet_length(sealed_private_key) BETWEEN 68 AND 8192),
  admitted_evidence BYTEA,
  UNIQUE (epoch, purpose)
);
CREATE TABLE issuer_transparency_cursor (
  singleton BOOLEAN PRIMARY KEY CHECK (singleton),
  checkpoint BYTEA NOT NULL
);
CREATE TABLE issuer_deposit_root (
  singleton BOOLEAN PRIMARY KEY CHECK (singleton),
  sealed_seed BYTEA NOT NULL CHECK (octet_length(sealed_seed) = 99)
);
CREATE TABLE issuer_quotes (
  quote_id BYTEA PRIMARY KEY CHECK (octet_length(quote_id) = 32),
  quote BYTEA NOT NULL CHECK (octet_length(quote) = 224),
  key_id BYTEA NOT NULL REFERENCES issuer_keys(key_id),
  batch_hash BYTEA NOT NULL CHECK (octet_length(batch_hash) = 32),
  deposit_owner BYTEA NOT NULL UNIQUE CHECK (octet_length(deposit_owner) = 32),
  sealed_deposit_key BYTEA NOT NULL CHECK (octet_length(sealed_deposit_key) = 99),
  price_observed_at NUMERIC(20,0) NOT NULL CHECK (price_observed_at >= 0),
  payment_signature BYTEA UNIQUE CHECK (octet_length(payment_signature) = 64),
  payment_payer BYTEA CHECK (octet_length(payment_payer) = 32),
  payment_slot NUMERIC(20,0) CHECK (payment_slot > 0),
  payment_time NUMERIC(20,0) CHECK (payment_time >= 0),
  payment_amount NUMERIC(20,0) CHECK (payment_amount > 0),
  issued_response BYTEA CHECK (octet_length(issued_response) BETWEEN 25670 AND 512070),
  UNIQUE (key_id, batch_hash),
  CHECK ((issued_response IS NULL AND payment_signature IS NULL AND payment_payer IS NULL
    AND payment_slot IS NULL AND payment_time IS NULL AND payment_amount IS NULL)
    OR (issued_response IS NOT NULL AND payment_signature IS NOT NULL AND payment_payer IS NOT NULL
    AND payment_slot IS NOT NULL AND payment_time IS NOT NULL AND payment_amount IS NOT NULL))
);
