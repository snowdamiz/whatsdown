CREATE TABLE messenger_one_time_prekeys (
  account_id BYTEA NOT NULL,
  device_id BYTEA NOT NULL,
  prekey_id BIGINT NOT NULL CHECK (prekey_id > 0),
  public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  consumed_at TIMESTAMPTZ,
  PRIMARY KEY (account_id, device_id, prekey_id),
  FOREIGN KEY (account_id, device_id)
    REFERENCES messenger_devices (account_id, device_id) ON DELETE CASCADE
);

CREATE INDEX messenger_one_time_prekeys_available
  ON messenger_one_time_prekeys (account_id, device_id, prekey_id)
  WHERE consumed_at IS NULL;

CREATE FUNCTION messenger_remove_prekeys_for_revoked_device() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM messenger_one_time_prekeys
    WHERE account_id = NEW.account_id AND device_id = NEW.device_id;
  RETURN NEW;
END;
$$;

CREATE TRIGGER messenger_devices_remove_prekeys
  AFTER UPDATE OF revoked_at ON messenger_devices
  FOR EACH ROW
  WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
  EXECUTE FUNCTION messenger_remove_prekeys_for_revoked_device();
