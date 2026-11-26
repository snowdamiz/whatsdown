-- Quote requests are PWR-stamped (label mesh-msg/v1/work/credit-quote). A
-- stamp is spent once; its key is kept until well past its 5-minute window.
CREATE TABLE quote_stamps (
  stamp_key BYTEA PRIMARY KEY CHECK (octet_length(stamp_key) = 32),
  forget_after TIMESTAMPTZ NOT NULL
);

CREATE INDEX quote_stamps_forget_after ON quote_stamps (forget_after);

-- Open quotes are counted against MORSE_CREDIT_MAX_OPEN_QUOTES; expired ones
-- stop counting (their deposit address is kept for late payments).
CREATE INDEX quotes_open ON quotes (expires_at) WHERE state = 'open';
