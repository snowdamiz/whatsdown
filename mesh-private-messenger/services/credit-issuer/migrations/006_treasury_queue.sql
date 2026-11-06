-- Bounded observation retries let unavailable historical payments coexist with
-- new deposits. This queue contains purchase-side identifiers only.
CREATE TABLE issuer_treasury_observation_jobs (
  config_hash BYTEA NOT NULL CHECK(octet_length(config_hash)=32),
  quote_id BYTEA NOT NULL REFERENCES issuer_quotes(quote_id),
  next_attempt NUMERIC(20,0) NOT NULL CHECK(next_attempt>=0 AND next_attempt<=18446744073709551615),
  PRIMARY KEY(config_hash,quote_id)
);
CREATE INDEX issuer_treasury_ready_movements ON issuer_treasury_movements(config_hash,ready_at,movement_id)
  WHERE state=0 AND batch_id IS NULL AND message IS NULL;
CREATE INDEX issuer_treasury_pending_batches ON issuer_treasury_batches(config_hash,batch_id)
  WHERE state IN(0,1,4);
CREATE TABLE issuer_treasury_funding_jobs (
  batch_id BIGINT PRIMARY KEY REFERENCES issuer_treasury_weekly(batch_id),
  next_attempt NUMERIC(20,0) NOT NULL CHECK(next_attempt>=0 AND next_attempt<=18446744073709551615)
);
