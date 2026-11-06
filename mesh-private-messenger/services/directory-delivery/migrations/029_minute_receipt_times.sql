-- Receipt order uses sequence, and retention uses expiration/storage_until or
-- acknowledged_at. None needs the sub-minute arrival time retained here.
ALTER TABLE messenger_envelopes
  ALTER COLUMN received_at SET DEFAULT date_trunc('minute', now());

UPDATE messenger_envelopes
  SET received_at = date_trunc('minute', received_at)
  WHERE received_at <> date_trunc('minute', received_at);

-- Keep explicit writers from reintroducing exact arrival timestamps. ACK times
-- remain exact so rounding cannot shorten their one-hour retry retention.
ALTER TABLE messenger_envelopes
  ADD CONSTRAINT messenger_envelopes_received_minute
    CHECK (received_at = date_trunc('minute', received_at));
