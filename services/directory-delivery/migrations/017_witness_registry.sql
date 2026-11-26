-- Witnesses come from a registry instead of a hard-coded pair. A shadow entry
-- is accepted and stored but pinned by no release; a pinned one is in the
-- security config phones ship; a retired one is never accepted again. Morse
-- software signs Morse statements; C2SP software cosigns the checkpoint note
-- under its key name, c2sp_name.
CREATE TABLE transparency_witness_registry (
  witness_id TEXT PRIMARY KEY CHECK (witness_id ~ '^[a-z0-9-]{1,64}$'),
  public_key BYTEA NOT NULL UNIQUE CHECK (octet_length(public_key) = 32),
  operator TEXT NOT NULL CHECK (length(operator) BETWEEN 1 AND 48),
  status TEXT NOT NULL CHECK (status IN ('shadow', 'pinned', 'retired')),
  software TEXT NOT NULL CHECK (software IN ('mesh', 'c2sp')),
  push_url TEXT,                                   -- C2SP add-checkpoint endpoint
  morse_run BOOLEAN NOT NULL,
  added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  retired_at TIMESTAMPTZ,
  c2sp_name TEXT CHECK (c2sp_name IS NULL OR c2sp_name ~ '^[!-*,-~]{1,255}$'),
  CHECK (software <> 'c2sp' OR c2sp_name IS NOT NULL),
  CHECK (push_url IS NULL OR push_url ~ '^https://[^@?#[:space:]]+$'),
  CHECK ((status = 'retired') = (retired_at IS NOT NULL))
);

-- The anchoring transaction and ring slot of each checkpoint posted on-chain.
-- Anchored checkpoints are kept for good.
CREATE TABLE transparency_anchors (
  checkpoint_sequence BIGINT PRIMARY KEY,
  tree_size BIGINT NOT NULL,
  checkpoint_hash BYTEA NOT NULL CHECK (octet_length(checkpoint_hash) = 32),
  ring_index INTEGER NOT NULL,
  tx_signature TEXT NOT NULL,
  slot BIGINT NOT NULL,
  posted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A C2SP witness's cosignature is stored beside Morse statements: its time
-- (seconds) is what the signature covers, and a row with a time is served as
-- an attestation of kind 2. One row per witness and checkpoint, as before.
ALTER TABLE witness_signatures
  ADD COLUMN cosigned_at BIGINT CHECK (cosigned_at IS NULL OR cosigned_at >= 0);
