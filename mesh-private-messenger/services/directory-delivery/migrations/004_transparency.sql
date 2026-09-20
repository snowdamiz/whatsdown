CREATE TABLE transparency_entries (
  sequence BIGSERIAL PRIMARY KEY,
  account_commitment BYTEA NOT NULL CHECK (octet_length(account_commitment) = 32),
  entry_bytes BYTEA NOT NULL CHECK (octet_length(entry_bytes) BETWEEN 1 AND 286400),
  leaf_hash BYTEA NOT NULL CHECK (octet_length(leaf_hash) = 32),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX transparency_entries_account
  ON transparency_entries (account_commitment, sequence DESC);

CREATE TABLE transparency_nodes (
  level INTEGER NOT NULL CHECK (level >= 0),
  node_index BIGINT NOT NULL CHECK (node_index >= 0),
  hash BYTEA NOT NULL CHECK (octet_length(hash) = 32),
  PRIMARY KEY (level, node_index)
);

CREATE TABLE transparency_checkpoints (
  sequence BIGINT PRIMARY KEY CHECK (sequence > 0),
  tree_size BIGINT NOT NULL UNIQUE CHECK (tree_size > 0 AND tree_size <= 4096),
  tree_root BYTEA NOT NULL CHECK (octet_length(tree_root) = 32),
  previous_checkpoint_hash BYTEA NOT NULL CHECK (octet_length(previous_checkpoint_hash) = 32),
  timestamp_ms BIGINT NOT NULL CHECK (timestamp_ms >= 0),
  service_public_key BYTEA NOT NULL CHECK (octet_length(service_public_key) = 32),
  service_signature BYTEA NOT NULL CHECK (octet_length(service_signature) = 64),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE witness_signatures (
  checkpoint_sequence BIGINT NOT NULL REFERENCES transparency_checkpoints (sequence) ON DELETE CASCADE,
  witness_id TEXT NOT NULL CHECK (length(witness_id) BETWEEN 1 AND 64),
  witness_public_key BYTEA NOT NULL CHECK (octet_length(witness_public_key) = 32),
  checkpoint_hash BYTEA NOT NULL CHECK (octet_length(checkpoint_hash) = 32),
  signature BYTEA NOT NULL CHECK (octet_length(signature) = 64),
  observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (checkpoint_sequence, witness_id)
);
