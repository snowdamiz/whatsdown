-- No guessed wall-age TTL: Mesh derives the inclusive replay boundary from
-- the exact signed response. Existing rows are checked in bounded worker batches.
ALTER TABLE messenger_one_time_prekeys
  ADD COLUMN claim_retry_until_ms NUMERIC(20, 0),
  ADD COLUMN claim_retention_checked BOOLEAN NOT NULL DEFAULT false,
  ADD CONSTRAINT messenger_one_time_prekeys_retry_until_check CHECK (
    claim_retry_until_ms IS NULL OR (
      claim_retention_checked AND consumed_at IS NOT NULL
      AND claim_retry_until_ms BETWEEN 0 AND 18446744073709551615
    )
  );

CREATE INDEX messenger_one_time_prekeys_retention_unchecked
  ON messenger_one_time_prekeys (account_id, device_id, prekey_id)
  WHERE consumed_at IS NOT NULL AND NOT claim_retention_checked;
CREATE INDEX messenger_one_time_prekeys_retention_deadline
  ON messenger_one_time_prekeys (claim_retry_until_ms, account_id, device_id, prekey_id)
  WHERE consumed_at IS NOT NULL AND claim_retry_until_ms IS NOT NULL;

-- Exact identifiers/key equality remain necessary to reject signed publication
-- reactivation. This deliberately retains no claim, creation, consumption or
-- cleanup time, reservation hash, base-bundle hash, response or replay deadline.
CREATE TABLE messenger_retired_prekeys (
  account_id BYTEA NOT NULL,
  device_id BYTEA NOT NULL,
  prekey_id BIGINT NOT NULL CHECK (prekey_id > 0),
  public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
  last_resort BOOLEAN NOT NULL,
  PRIMARY KEY (account_id, device_id, prekey_id),
  FOREIGN KEY (account_id, device_id)
    REFERENCES messenger_devices (account_id, device_id) ON DELETE CASCADE
);

CREATE OR REPLACE FUNCTION messenger_remove_prekeys_for_revoked_device() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM messenger_one_time_prekeys
    WHERE account_id = NEW.account_id AND device_id = NEW.device_id;
  DELETE FROM messenger_retired_prekeys
    WHERE account_id = NEW.account_id AND device_id = NEW.device_id;
  RETURN NEW;
END;
$$;

-- A global signed-horizon floor prevents clock rollback from making a retired
-- base usable again. It records no wall-clock cleanup time or device identity.
CREATE TABLE messenger_prekey_retention_clock (
  singleton BOOLEAN PRIMARY KEY CHECK (singleton),
  expired_before_ms NUMERIC(20, 0) NOT NULL CHECK (
    expired_before_ms BETWEEN 0 AND 18446744073709551615
  )
);
INSERT INTO messenger_prekey_retention_clock (singleton, expired_before_ms) VALUES (true, 0);
