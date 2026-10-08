-- Extras paid in credits (protocol/credits-v1.md "Extras"). No foreign keys to
-- messenger_mailboxes, so test resets that truncate it keep working; rows are
-- keyed by the mailbox's random address hash and never collide.

-- A device's signed policy for its public address: the postage (0, 1, 5 or 25
-- credits) an envelope reaching that address must carry. policy is the exact
-- MBP frame the device signed, served to senders as it is.
CREATE TABLE messenger_mailbox_policies (
  mailbox_token_hash BYTEA PRIMARY KEY CHECK (octet_length(mailbox_token_hash) = 32),
  policy BYTEA NOT NULL CHECK (octet_length(policy) = 109),
  sequence BIGINT NOT NULL CHECK (sequence >= 0),
  postage SMALLINT NOT NULL CHECK (postage IN (0, 1, 5, 25)),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT date_trunc('minute', now(), 'UTC')
);

-- Longer storage: envelopes arriving before entitled_until are kept
-- retention_days (60 to 180) from their arrival instead of the sender's 30.
CREATE TABLE messenger_mailbox_retention (
  mailbox_token_hash BYTEA PRIMARY KEY CHECK (octet_length(mailbox_token_hash) = 32),
  retention_days SMALLINT NOT NULL CHECK (retention_days IN (60, 90, 120, 150, 180)),
  entitled_until TIMESTAMPTZ NOT NULL
);

-- Credits spent per UTC week (Monday) and action, for settlement: postage goes
-- to the network, 20% of it to witnesses. Totals only, nothing per sender.
CREATE TABLE credit_spend_totals (
  week_start DATE NOT NULL CHECK (extract(isodow FROM week_start) = 1),
  action SMALLINT NOT NULL CHECK (action BETWEEN 1 AND 4),
  credits BIGINT NOT NULL CHECK (credits >= 0),
  PRIMARY KEY (week_start, action)
);

-- Priority sign-up reads the registration rate: devices registered in the
-- last 10 minutes.
CREATE INDEX messenger_devices_registered_at ON messenger_devices (registered_at);
