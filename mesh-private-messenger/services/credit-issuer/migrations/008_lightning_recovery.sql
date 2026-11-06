-- Retry leases fence bounded workers without holding a database transaction
-- across an authenticated Lightning RPC. Receipt application remains idempotent.
ALTER TABLE issuer_lightning_quotes ADD COLUMN next_attempt NUMERIC(20,0) NOT NULL DEFAULT 0
  CHECK(next_attempt>=0 AND next_attempt<=18446744073709551615);
CREATE INDEX issuer_lightning_prepared_queue ON issuer_lightning_quotes(backend_hash,service_key,next_attempt,quote_id)
  WHERE state=2;
