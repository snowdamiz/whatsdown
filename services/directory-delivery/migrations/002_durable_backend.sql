CREATE TABLE messenger_outbox_events (
  event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  mailbox_token_hash BYTEA NOT NULL,
  envelope_id BYTEA NOT NULL,
  event_type SMALLINT NOT NULL DEFAULT 1 CHECK (event_type = 1),
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'leased', 'retryable_failure', 'delivered', 'permanent_failure')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  lease_owner TEXT CHECK (lease_owner IS NULL OR length(lease_owner) BETWEEN 1 AND 128),
  lease_expires_at TIMESTAMPTZ,
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  completed_at TIMESTAMPTZ,
  last_error_code TEXT CHECK (last_error_code IS NULL OR length(last_error_code) <= 64),
  CONSTRAINT messenger_outbox_envelope_key
    UNIQUE (mailbox_token_hash, envelope_id, event_type),
  CONSTRAINT messenger_outbox_envelope_fk
    FOREIGN KEY (mailbox_token_hash, envelope_id)
    REFERENCES messenger_envelopes (mailbox_token_hash, envelope_id)
    ON DELETE CASCADE,
  CONSTRAINT messenger_outbox_state_check CHECK (
    (status = 'leased' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL AND completed_at IS NULL)
    OR
    (status IN ('pending', 'retryable_failure') AND lease_owner IS NULL AND lease_expires_at IS NULL AND completed_at IS NULL)
    OR
    (status IN ('delivered', 'permanent_failure') AND lease_owner IS NULL AND lease_expires_at IS NULL AND completed_at IS NOT NULL)
  )
);

CREATE INDEX messenger_outbox_available
  ON messenger_outbox_events (available_at, created_at)
  WHERE completed_at IS NULL;

CREATE TABLE messenger_rate_limits (
  bucket_key BYTEA PRIMARY KEY CHECK (octet_length(bucket_key) = 32),
  window_started_at TIMESTAMPTZ NOT NULL,
  request_count INTEGER NOT NULL CHECK (request_count > 0)
);
