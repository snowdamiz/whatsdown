-- Installing this migration does not seal or activate a log. The explicit
-- Mesh cutover command publishes the authenticated legacy bridge first.
ALTER TABLE transparency_entries ADD COLUMN log_version SMALLINT NOT NULL DEFAULT 1
  CHECK (log_version IN (1, 2));
DROP INDEX transparency_entries_leaf_index;
CREATE UNIQUE INDEX transparency_entries_leaf_index
  ON transparency_entries (log_version, leaf_index);
CREATE INDEX transparency_entries_version_account
  ON transparency_entries (log_version, account_commitment, sequence DESC);

CREATE TABLE transparency_v2_checkpoints
  (LIKE transparency_checkpoints INCLUDING ALL);
CREATE TABLE witness_v2_signatures (
  checkpoint_sequence BIGINT NOT NULL REFERENCES transparency_v2_checkpoints (sequence) ON DELETE CASCADE,
  witness_id TEXT NOT NULL CHECK (octet_length(witness_id) BETWEEN 1 AND 64),
  witness_public_key BYTEA NOT NULL CHECK (octet_length(witness_public_key) = 32),
  checkpoint_hash BYTEA NOT NULL CHECK (octet_length(checkpoint_hash) = 32),
  signature BYTEA NOT NULL CHECK (octet_length(signature) IN (64, 72)),
  observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (checkpoint_sequence, witness_id)
);

-- The seal and its quorum are retained independently of checkpoint retention
-- and registry changes. Missing row means legacy; there is no reverse operation.
CREATE TABLE transparency_log_cutover (
  singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
  phase TEXT NOT NULL CHECK (phase IN ('sealing', 'copying', 'active')),
  legacy_checkpoint BYTEA NOT NULL CHECK (octet_length(legacy_checkpoint) = 188),
  legacy_witnesses BYTEA CHECK (octet_length(legacy_witnesses) BETWEEN 6 AND 2630),
  copied_through BIGINT NOT NULL DEFAULT 0 CHECK (copied_through >= 0),
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  activated_at TIMESTAMPTZ,
  CHECK ((phase = 'sealing' AND legacy_witnesses IS NULL AND copied_through = 0)
    OR (phase IN ('copying', 'active') AND legacy_witnesses IS NOT NULL)),
  CHECK ((phase = 'active') = (activated_at IS NOT NULL))
);
