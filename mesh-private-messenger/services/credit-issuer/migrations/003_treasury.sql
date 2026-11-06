-- Issuer-only accounting. Never add redemption identifiers or customer accounts.
-- Numeric values are exact original-asset base units, never floating point.
CREATE TABLE issuer_payment_observations (
  payment_signature BYTEA PRIMARY KEY CHECK (octet_length(payment_signature) = 64),
  quote_id BYTEA NOT NULL REFERENCES issuer_quotes(quote_id),
  payer BYTEA NOT NULL CHECK (octet_length(payer) = 32),
  slot NUMERIC(20,0) NOT NULL CHECK (slot > 0 AND slot <= 18446744073709551615),
  payment_time NUMERIC(20,0) NOT NULL CHECK (payment_time >= 0 AND payment_time <= 18446744073709551615),
  amount NUMERIC(20,0) NOT NULL CHECK (amount > 0 AND amount <= 18446744073709551615),
  wire_sha256 BYTEA NOT NULL CHECK (octet_length(wire_sha256) = 32),
  disposition SMALLINT NOT NULL CHECK (disposition IN (0,1,2))
);
CREATE INDEX issuer_payment_observations_quote ON issuer_payment_observations(quote_id);
CREATE TABLE issuer_credit_revenue (
  event_id BIGSERIAL PRIMARY KEY,
  quote_id BYTEA NOT NULL UNIQUE REFERENCES issuer_quotes(quote_id),
  payment_signature BYTEA NOT NULL UNIQUE CHECK (octet_length(payment_signature) = 64),
  asset SMALLINT NOT NULL CHECK (asset IN (0,1)),
  mint BYTEA NOT NULL CHECK (octet_length(mint) = 32),
  amount NUMERIC(20,0) NOT NULL CHECK (amount > 0 AND amount <= 18446744073709551615),
  payment_time NUMERIC(20,0) NOT NULL CHECK (payment_time >= 0 AND payment_time <= 18446744073709551615)
);
CREATE TABLE issuer_treasury_movements (
  movement_id BYTEA PRIMARY KEY CHECK (octet_length(movement_id) = 32),
  payment_signature BYTEA NOT NULL UNIQUE REFERENCES issuer_payment_observations(payment_signature),
  kind SMALLINT NOT NULL CHECK (kind IN (0,1)), -- sweep / underpayment refund
  config_hash BYTEA NOT NULL CHECK (octet_length(config_hash) = 32),
  source BYTEA NOT NULL CHECK (octet_length(source) = 32),
  destination BYTEA NOT NULL CHECK (octet_length(destination) = 32),
  destination_owner BYTEA NOT NULL CHECK (octet_length(destination_owner) = 32),
  amount NUMERIC(20,0) NOT NULL CHECK (amount > 0 AND amount <= 18446744073709551615),
  ready_at NUMERIC(20,0) NOT NULL CHECK (ready_at >= 0 AND ready_at <= 18446744073709551615),
  state SMALLINT NOT NULL DEFAULT 0 CHECK (state BETWEEN 0 AND 4),
  nonce_address BYTEA CHECK (octet_length(nonce_address) = 32),
  nonce_value BYTEA CHECK (octet_length(nonce_value) = 32),
  message BYTEA CHECK (octet_length(message) BETWEEN 1 AND 1232),
  packet BYTEA CHECK (octet_length(packet) BETWEEN 1 AND 1232),
  transaction_signature BYTEA UNIQUE CHECK (octet_length(transaction_signature) = 64),
  finalized_slot NUMERIC(20,0) CHECK (finalized_slot > 0 AND finalized_slot <= 18446744073709551615),
  execution_error TEXT CHECK (octet_length(execution_error) <= 2048),
  fee NUMERIC(20,0) CHECK (fee >= 0 AND fee <= 18446744073709551615),
  CHECK ((message IS NULL AND nonce_address IS NULL AND nonce_value IS NULL)
      OR (message IS NOT NULL AND nonce_address IS NOT NULL AND nonce_value IS NOT NULL)),
  CHECK ((state = 0 AND packet IS NULL AND transaction_signature IS NULL)
      OR (state IN (1,2,3,4) AND message IS NOT NULL AND packet IS NOT NULL AND transaction_signature IS NOT NULL)),
  CHECK ((state IN (0,1,4) AND finalized_slot IS NULL AND fee IS NULL AND execution_error IS NULL)
      OR (state = 2 AND finalized_slot IS NOT NULL AND fee IS NOT NULL AND execution_error IS NULL)
      OR (state = 3 AND finalized_slot IS NOT NULL AND fee IS NOT NULL AND execution_error IS NOT NULL))
);
-- A nonce cannot sign another intent until the previous outcome is established.
CREATE UNIQUE INDEX issuer_treasury_active_nonce ON issuer_treasury_movements(nonce_address)
  WHERE nonce_address IS NOT NULL AND state IN (0,1,4);
CREATE TABLE issuer_treasury_weekly (
  batch_id BIGSERIAL PRIMARY KEY,
  week NUMERIC(20,0) NOT NULL CHECK (week >= 0),
  asset SMALLINT NOT NULL CHECK (asset IN (0,1)),
  cutoff BIGINT NOT NULL CHECK (cutoff >= 0),
  mint BYTEA NOT NULL CHECK (octet_length(mint)=32),
  config_hash BYTEA NOT NULL CHECK (octet_length(config_hash)=32),
  amount NUMERIC(20,0) NOT NULL CHECK (amount >= 0 AND amount <= 18446744073709551615),
  witness NUMERIC(20,0) NOT NULL CHECK (witness >= 0),
  operations NUMERIC(20,0) NOT NULL CHECK (operations >= 0),
  carry_before SMALLINT NOT NULL CHECK (carry_before BETWEEN 0 AND 4),
  carry_after SMALLINT NOT NULL CHECK (carry_after BETWEEN 0 AND 4),
  membership_hash BYTEA NOT NULL CHECK (octet_length(membership_hash) = 32),
  CHECK (witness + operations = amount),
  CHECK (witness * 5 + carry_after = amount + carry_before),
  UNIQUE (week,asset)
);
CREATE TABLE issuer_treasury_weekly_events (
  event_id BIGINT PRIMARY KEY REFERENCES issuer_credit_revenue(event_id),
  batch_id BIGINT NOT NULL REFERENCES issuer_treasury_weekly(batch_id)
);
-- Every signed attempt survives explicit retry after a proved failed execution.
-- Missing history cannot enter this path. Old signatures never resolve a newer attempt.
CREATE TABLE issuer_treasury_attempts (
  transaction_signature BYTEA PRIMARY KEY CHECK (octet_length(transaction_signature)=64),
  movement_id BYTEA NOT NULL REFERENCES issuer_treasury_movements(movement_id),
  nonce_address BYTEA NOT NULL CHECK (octet_length(nonce_address)=32),
  nonce_value BYTEA NOT NULL CHECK (octet_length(nonce_value)=32),
  message BYTEA NOT NULL CHECK (octet_length(message) BETWEEN 1 AND 1232),
  packet BYTEA NOT NULL CHECK (octet_length(packet) BETWEEN 1 AND 1232),
  state SMALLINT NOT NULL CHECK (state IN (1,2,3)),
  finalized_slot NUMERIC(20,0) CHECK (finalized_slot > 0 AND finalized_slot <= 18446744073709551615),
  execution_error TEXT CHECK (octet_length(execution_error)<=2048),
  fee NUMERIC(20,0) CHECK (fee >= 0 AND fee <= 18446744073709551615),
  UNIQUE (movement_id,nonce_address,nonce_value),
  CHECK ((state=1 AND finalized_slot IS NULL AND execution_error IS NULL AND fee IS NULL)
    OR (state=2 AND finalized_slot IS NOT NULL AND execution_error IS NULL AND fee IS NOT NULL)
    OR (state=3 AND finalized_slot IS NOT NULL AND execution_error IS NOT NULL AND fee IS NOT NULL))
);
CREATE TABLE issuer_treasury_rewards_intents (
  intent_id BYTEA PRIMARY KEY CHECK (octet_length(intent_id)=32),
  batch_id BIGINT NOT NULL REFERENCES issuer_treasury_weekly(batch_id),
  epoch NUMERIC(20,0) NOT NULL CHECK (epoch>=0 AND epoch<=18446744073709551615),
  pool BYTEA NOT NULL CHECK (octet_length(pool)=32),
  funder BYTEA NOT NULL CHECK (octet_length(funder)=32),
  source BYTEA NOT NULL CHECK (octet_length(source)=32),
  mint BYTEA NOT NULL CHECK (octet_length(mint)=32),
  amount NUMERIC(20,0) NOT NULL CHECK (amount>0 AND amount<=18446744073709551615),
  state SMALLINT NOT NULL DEFAULT 0 CHECK (state IN (0,1,2)), -- pending/funded/expired-unfunded
  receipt BYTEA CHECK (octet_length(receipt)=192),
  CHECK ((state=1 AND receipt IS NOT NULL) OR (state IN (0,2) AND receipt IS NULL)),
  UNIQUE(batch_id,epoch)
);
CREATE UNIQUE INDEX issuer_treasury_rewards_active ON issuer_treasury_rewards_intents(batch_id) WHERE state IN (0,1);
