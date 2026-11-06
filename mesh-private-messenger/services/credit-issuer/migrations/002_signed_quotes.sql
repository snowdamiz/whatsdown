-- Legacy development keys/quotes remain stored, but cannot authorize new
-- payments until a separately witnessed quote signer exists. No automatic
-- signer substitution or rewriting of admitted history is permitted.
ALTER TABLE issuer_keys ADD COLUMN quote_public_key BYTEA
  CHECK (octet_length(quote_public_key) = 32);
ALTER TABLE issuer_keys ADD COLUMN sealed_quote_key BYTEA
  CHECK (octet_length(sealed_quote_key) = 99);
ALTER TABLE issuer_keys ADD CONSTRAINT issuer_quote_key_complete CHECK (
  (quote_public_key IS NULL AND sealed_quote_key IS NULL)
  OR (quote_public_key IS NOT NULL AND sealed_quote_key IS NOT NULL));
ALTER TABLE issuer_quotes ADD COLUMN signed_quote BYTEA
  CHECK (octet_length(signed_quote) = 292);
