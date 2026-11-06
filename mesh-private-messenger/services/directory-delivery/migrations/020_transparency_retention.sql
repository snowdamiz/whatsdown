-- The Mesh backfill verifies the canonical DVS bytes and their leaf hash before
-- replacing them. Until then, readers continue to accept entry_bytes.
ALTER TABLE transparency_entries ADD COLUMN entry_header BYTEA;
ALTER TABLE transparency_entries ADD COLUMN entry_suffix BYTEA;
ALTER TABLE transparency_entries ADD COLUMN pruned_at TIMESTAMPTZ;
ALTER TABLE transparency_entries ADD CONSTRAINT transparency_entry_parts CHECK (
  (entry_header IS NULL AND entry_suffix IS NULL) OR
  (entry_header IS NOT NULL AND octet_length(entry_header) BETWEEN 23 AND 16667
    AND entry_suffix IS NOT NULL AND octet_length(entry_suffix) BETWEEN 1 AND 513
    AND entry_bytes IS NULL AND pruned_at IS NULL)
);
CREATE INDEX transparency_entries_retention ON transparency_entries (created_at, sequence)
  WHERE pruned_at IS NULL AND (entry_bytes IS NOT NULL OR entry_header IS NOT NULL);
CREATE INDEX transparency_entries_backfill ON transparency_entries (sequence)
  WHERE entry_bytes IS NOT NULL;

CREATE TABLE transparency_device_records (
  record_hash BYTEA PRIMARY KEY CHECK (octet_length(record_hash) = 32),
  record_bytes BYTEA NOT NULL CHECK (octet_length(record_bytes) BETWEEN 1 AND 36006),
  CHECK (record_hash = sha256(record_bytes))
);
CREATE TABLE transparency_entry_devices (
  entry_sequence BIGINT NOT NULL REFERENCES transparency_entries (sequence) ON DELETE CASCADE,
  position SMALLINT NOT NULL CHECK (position >= 0 AND position < 8),
  record_hash BYTEA NOT NULL REFERENCES transparency_device_records (record_hash),
  PRIMARY KEY (entry_sequence, position)
);
CREATE INDEX transparency_entry_device_hash ON transparency_entry_devices (record_hash);

-- Only a verified chain writer may add these records. Retention cannot delete
-- an anchored checkpoint, even when it predates the ordinary retention window.
CREATE TABLE transparency_anchors (
  checkpoint_sequence BIGINT PRIMARY KEY REFERENCES transparency_checkpoints (sequence),
  tree_size BIGINT NOT NULL CHECK (tree_size > 0 AND tree_size <= 4294967295),
  checkpoint_hash BYTEA NOT NULL CHECK (octet_length(checkpoint_hash) = 32),
  ring_index INTEGER NOT NULL CHECK (ring_index >= 0 AND ring_index < 4096),
  tx_signature TEXT NOT NULL,
  slot BIGINT NOT NULL CHECK (slot >= 0),
  posted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE transparency_maintenance (
  day DATE PRIMARY KEY,
  entries_pruned INTEGER NOT NULL DEFAULT 0 CHECK (entries_pruned >= 0),
  checkpoints_pruned INTEGER NOT NULL DEFAULT 0 CHECK (checkpoints_pruned >= 0)
);
