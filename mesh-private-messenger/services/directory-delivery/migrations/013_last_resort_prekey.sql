-- One reusable prekey per device. The directory hands it out only when the
-- one-time pool is empty and never consumes it, so draining a pool cannot stop
-- new sessions. A device retires it by publishing a newer one.
ALTER TABLE messenger_one_time_prekeys
  ADD COLUMN last_resort BOOLEAN NOT NULL DEFAULT false;

CREATE UNIQUE INDEX messenger_one_time_prekeys_last_resort
  ON messenger_one_time_prekeys (account_id, device_id)
  WHERE last_resort AND consumed_at IS NULL;
