-- Separate invoice identities and units: never reinterpret a Solana signature,
-- deposit, or finalized receipt as a Lightning payment. No redemption data.
CREATE TABLE issuer_lightning_quotes (
  quote_id BYTEA PRIMARY KEY CHECK(octet_length(quote_id)=32),
  request BYTEA NOT NULL CHECK(octet_length(request)=72),
  key_id BYTEA NOT NULL REFERENCES issuer_keys(key_id),
  batch_hash BYTEA NOT NULL CHECK(octet_length(batch_hash)=32),
  backend_hash BYTEA NOT NULL CHECK(octet_length(backend_hash)=32),
  service_key BYTEA NOT NULL CHECK(octet_length(service_key)=32),
  payment_hash BYTEA NOT NULL UNIQUE CHECK(octet_length(payment_hash)=32),
  sealed_preimage BYTEA NOT NULL CHECK(octet_length(sealed_preimage)=99),
  amount_msat NUMERIC(20,0) NOT NULL CHECK(amount_msat>0 AND amount_msat<=2100000000000000000),
  reserved_at NUMERIC(20,0) NOT NULL CHECK(reserved_at>=0 AND reserved_at<=18446744073709551615),
  price_observed_at NUMERIC(20,0) NOT NULL CHECK(price_observed_at>=0 AND price_observed_at<=reserved_at),
  state SMALLINT NOT NULL DEFAULT 0 CHECK(state BETWEEN 0 AND 5),
  signed_quote BYTEA CHECK(octet_length(signed_quote) BETWEEN 264 AND 7352),
  prepared_response BYTEA CHECK(octet_length(prepared_response) BETWEEN 25670 AND 512070),
  prepared_signature BYTEA CHECK(octet_length(prepared_signature)=64),
  settled_amount NUMERIC(20,0) CHECK(settled_amount>0 AND settled_amount<=2100000000000000000),
  settled_at NUMERIC(20,0) CHECK(settled_at>=0 AND settled_at<=18446744073709551615),
  settle_index NUMERIC(20,0) CHECK(settle_index>0 AND settle_index<=18446744073709551615),
  UNIQUE(key_id,batch_hash),
  UNIQUE(backend_hash,settle_index),
  CHECK((state=0 AND signed_quote IS NULL AND prepared_response IS NULL AND prepared_signature IS NULL)
    OR (state=1 AND signed_quote IS NOT NULL AND prepared_response IS NULL AND prepared_signature IS NULL)
    OR (state IN(2,3) AND signed_quote IS NOT NULL AND prepared_response IS NOT NULL AND prepared_signature IS NOT NULL)
    OR state IN(4,5)),
  CHECK((state=3 AND settled_amount IS NOT NULL AND settled_at IS NOT NULL AND settle_index IS NOT NULL)
    OR (state<>3 AND settled_amount IS NULL AND settled_at IS NULL AND settle_index IS NULL))
);
-- These are actual BTC millisatoshis held by the configured node. Conversion
-- and finalized USDC funding require their own later custody/receipt journal.
CREATE TABLE issuer_lightning_revenue (
  quote_id BYTEA PRIMARY KEY REFERENCES issuer_lightning_quotes(quote_id),
  backend_hash BYTEA NOT NULL CHECK(octet_length(backend_hash)=32),
  received_msat NUMERIC(20,0) NOT NULL CHECK(received_msat>0 AND received_msat<=2100000000000000000),
  settled_at NUMERIC(20,0) NOT NULL CHECK(settled_at>=0 AND settled_at<=18446744073709551615)
);
