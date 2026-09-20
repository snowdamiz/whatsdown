-- A mailbox held 64 envelopes whatever their size. A phone that is off for a day
-- in a busy group reaches that easily, and then every sender is turned away.
--
-- What the limit protects is storage: the address is public and deposits are
-- anonymous, so without a bound anyone could make the service keep unlimited
-- data for a device. 64 envelopes of the largest size are 4 MiB. Bound that
-- instead, and an ordinary message of a few hundred bytes no longer costs as
-- much as the largest one: the same worst case now holds thousands of messages.
-- The count stays bounded too, so rows cannot pile up without limit.
ALTER TABLE messenger_mailboxes
  DROP CONSTRAINT messenger_mailboxes_pending_count_check,
  ADD CONSTRAINT messenger_mailboxes_pending_count_check
    CHECK (pending_count BETWEEN 0 AND 4096),
  ADD COLUMN pending_bytes BIGINT NOT NULL DEFAULT 0
    CHECK (pending_bytes BETWEEN 0 AND 4194304);

-- An envelope counts as its padding bucket, the size its sender declared and
-- the most its ciphertext may be. At most 64 of at most 65,536 were waiting, so
-- this cannot exceed the budget.
UPDATE messenger_mailboxes AS mailbox
  SET pending_bytes = waiting.bytes
  FROM (
    SELECT mailbox_token_hash, sum(padding_bucket) AS bytes
    FROM messenger_envelopes
    WHERE acknowledged_at IS NULL
    GROUP BY mailbox_token_hash
  ) AS waiting
  WHERE waiting.mailbox_token_hash = mailbox.mailbox_token_hash;

CREATE OR REPLACE FUNCTION messenger_reserve_mailbox_slot() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE messenger_mailboxes
    SET pending_count = pending_count + 1,
        pending_bytes = pending_bytes + NEW.padding_bucket
    WHERE mailbox_token_hash = NEW.mailbox_token_hash
      AND active
      AND pending_count < 4096
      AND pending_bytes + NEW.padding_bucket <= 4194304;
  IF NOT FOUND THEN
    IF EXISTS (
      SELECT 1 FROM messenger_mailboxes
      WHERE mailbox_token_hash = NEW.mailbox_token_hash AND NOT active
    ) THEN
      RAISE EXCEPTION 'mailbox is inactive'
        USING ERRCODE = 'P0001', CONSTRAINT = 'messenger_mailbox_inactive';
    END IF;
    IF EXISTS (SELECT 1 FROM messenger_mailboxes WHERE mailbox_token_hash = NEW.mailbox_token_hash) THEN
      RAISE EXCEPTION 'mailbox capacity reached'
        USING ERRCODE = 'P0001', CONSTRAINT = 'messenger_mailbox_capacity';
    END IF;
    RAISE EXCEPTION 'mailbox is not registered'
      USING ERRCODE = 'P0001', CONSTRAINT = 'messenger_mailbox_registration';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION messenger_release_mailbox_slot() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE messenger_mailboxes
    SET pending_count = GREATEST(pending_count - 1, 0),
        pending_bytes = GREATEST(pending_bytes - OLD.padding_bucket, 0)
    WHERE mailbox_token_hash = OLD.mailbox_token_hash;
  RETURN COALESCE(NEW, OLD);
END;
$$;
