-- Expired non-consumed operations retain an immutable recovery receipt. The
-- fence also rejects nonce reuse with a new expiry or another token frame.
CREATE TABLE credit_cancellations (
  hold_id BYTEA PRIMARY KEY CHECK (octet_length(hold_id) = 32),
  action BYTEA NOT NULL CHECK (octet_length(action) = 117),
  frame_hash BYTEA NOT NULL CHECK (octet_length(frame_hash) = 32),
  receipt BYTEA NOT NULL CHECK (octet_length(receipt) = 172),
  retain_until BIGINT NOT NULL CHECK (retain_until > 0)
);
CREATE INDEX credit_cancellations_retention ON credit_cancellations (retain_until, hold_id);
