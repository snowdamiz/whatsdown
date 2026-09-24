-- An account signed by its own key can be deleted. Every row that served it
-- goes: devices, mailboxes and what waits in them, prekeys, push bindings and
-- contact addresses, and its username is free for anyone to register again.
--
-- Its identifier is kept. A copy of the account can survive on a device that
-- was off or failed to erase it, and it would otherwise register the account
-- straight back under the free name. Registration answers 410 instead, with the
-- statement that deleted the account: a linked device checks it against the
-- account's key before it erases itself, so no server can make it forget.
CREATE TABLE messenger_deleted_accounts (
  account_id BYTEA PRIMARY KEY CHECK (octet_length(account_id) = 32),
  statement BYTEA NOT NULL CHECK (octet_length(statement) = 108),
  deleted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A removed device is told the same way, with the statement that removed it:
-- the account's revocation, or its own departure. It checks that signature
-- before it erases itself. Devices removed before this keep NULL and are only
-- refused.
ALTER TABLE messenger_revoked_devices
  ADD COLUMN statement BYTEA CHECK (statement IS NULL OR octet_length(statement) = 124);

-- The transparency log keeps every leaf hash, since each proof covers the whole
-- tree. The entries behind a deleted account's leaves are dropped: they name the
-- account and its devices, and nothing serves them once it is gone.
ALTER TABLE transparency_entries ALTER COLUMN entry_bytes DROP NOT NULL;
