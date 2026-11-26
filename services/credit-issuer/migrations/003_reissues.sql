-- An operator's one re-issue of an issued quote (`credit-issuer reissue`),
-- for a client that lost its blinding states mid-exchange. The row is the
-- audit record: which quote, when, the operator's note, and when the new batch
-- was signed (NULL while the re-issue is open). One per quote, ever.
CREATE TABLE reissues (
  quote_id BYTEA PRIMARY KEY REFERENCES quotes (quote_id),
  note TEXT NOT NULL CHECK (octet_length(note) <= 500),
  reissued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  signed_at TIMESTAMPTZ
);
