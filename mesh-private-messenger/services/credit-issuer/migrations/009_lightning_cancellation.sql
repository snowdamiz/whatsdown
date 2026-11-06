-- A signed terminal response lets a client retire its exact blinded batch.
-- Existing canceled rows require fresh node reconciliation before certification.
ALTER TABLE issuer_lightning_quotes ADD COLUMN cancellation BYTEA
  CHECK(cancellation IS NULL OR (state=4 AND octet_length(cancellation)=205));
