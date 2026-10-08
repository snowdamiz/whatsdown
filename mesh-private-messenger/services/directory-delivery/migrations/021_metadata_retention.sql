-- A consumed one-time prekey kept its consumed_at and claim hashes until the
-- device was revoked: a lasting per-device record of when sessions started.
-- The scheduled job now deletes such a row a day after its claim, once no
-- retried claim can still need its exact answer (migration 009). Each device
-- keeps the highest identifier deleted so far, so replaying a publication that
-- named a deleted key cannot bring it back.
ALTER TABLE messenger_devices
  ADD COLUMN pruned_prekey_id BIGINT NOT NULL DEFAULT 0 CHECK (pruned_prekey_id >= 0);

CREATE INDEX messenger_one_time_prekeys_consumed
  ON messenger_one_time_prekeys (consumed_at)
  WHERE consumed_at IS NOT NULL AND NOT last_resort;

-- Envelope times are kept to the minute (plan D17): when an envelope arrived,
-- when it was acknowledged, when its push wake was queued and finished, and
-- when a rate window opened. A trigger rounds the envelope's own times whatever
-- the writer sends, so a directory still running the previous build keeps
-- working while this migration is ahead of it.
UPDATE messenger_envelopes
  SET received_at = date_trunc('minute', received_at, 'UTC');
UPDATE messenger_envelopes
  SET acknowledged_at = date_trunc('minute', acknowledged_at, 'UTC')
  WHERE acknowledged_at IS NOT NULL;

CREATE FUNCTION messenger_envelope_minutes() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.received_at := date_trunc('minute', NEW.received_at, 'UTC');
  NEW.acknowledged_at := date_trunc('minute', NEW.acknowledged_at, 'UTC');
  RETURN NEW;
END;
$$;

CREATE TRIGGER messenger_envelopes_minutes
  BEFORE INSERT OR UPDATE OF received_at, acknowledged_at ON messenger_envelopes
  FOR EACH ROW EXECUTE FUNCTION messenger_envelope_minutes();

UPDATE messenger_outbox_events
  SET created_at = date_trunc('minute', created_at, 'UTC'),
      completed_at = date_trunc('minute', completed_at, 'UTC'),
      available_at = CASE WHEN completed_at IS NULL THEN available_at
        ELSE date_trunc('minute', available_at, 'UTC') END;
ALTER TABLE messenger_outbox_events
  ALTER COLUMN created_at SET DEFAULT date_trunc('minute', now(), 'UTC'),
  ALTER COLUMN available_at SET DEFAULT date_trunc('minute', now(), 'UTC');

UPDATE messenger_rate_limits
  SET window_started_at = date_trunc('minute', window_started_at, 'UTC');
