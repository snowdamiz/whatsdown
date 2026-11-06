-- Account-owned history is kept with the account, independent of bounded token
-- retention. A previously applied signed statement stays identifiable after a
-- later policy or device-set revision and cannot silently overwrite it.
CREATE TABLE credit_postage_policies (
  account_id BYTEA NOT NULL REFERENCES messenger_accounts(account_id) ON DELETE CASCADE,
  revision NUMERIC(20,0) NOT NULL CHECK (revision BETWEEN 1 AND 18446744073709551615),
  statement BYTEA NOT NULL CHECK (octet_length(statement) = 141),
  credits SMALLINT NOT NULL CHECK (credits IN (0, 1, 5, 25)),
  device_set_sequence BIGINT NOT NULL CHECK (device_set_sequence > 0),
  issued_at_ms NUMERIC(20,0) NOT NULL CHECK (issued_at_ms BETWEEN 1 AND 18446744073709551615),
  applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (account_id, revision)
);
