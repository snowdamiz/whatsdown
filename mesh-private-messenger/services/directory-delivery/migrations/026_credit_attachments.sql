-- Core authorization outlives any uncertain object-store commit. One object
-- identity cannot be charged again through a changed operation nonce/frame.
-- Hold retention is extended through object expiry plus seven recovery days.
CREATE TABLE credit_attachment_objects (
  object_id BYTEA PRIMARY KEY CHECK (octet_length(object_id) = 32),
  hold_id BYTEA NOT NULL UNIQUE REFERENCES credit_holds(hold_id) ON DELETE CASCADE,
  authorized_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
