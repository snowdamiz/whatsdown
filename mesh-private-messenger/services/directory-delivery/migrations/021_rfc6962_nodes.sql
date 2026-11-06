-- The RFC 6962 log starts with an authenticated legacy bridge. Its leaf
-- positions and hashes must never overwrite or reinterpret the legacy tree.
-- This prepares storage only; it does not activate or migrate either log.
CREATE TABLE transparency_v2_nodes (
  level INTEGER NOT NULL CHECK (level BETWEEN 0 AND 32),
  node_index BIGINT NOT NULL CHECK (node_index >= 0 AND node_index < 4294967295),
  hash BYTEA NOT NULL CHECK (octet_length(hash) = 32),
  tile_index BIGINT GENERATED ALWAYS AS (node_index / 256) STORED,
  tile_offset INTEGER GENERATED ALWAYS AS ((node_index % 256)::integer) STORED,
  PRIMARY KEY (level, node_index)
);
CREATE INDEX transparency_v2_nodes_tile
  ON transparency_v2_nodes (level, tile_index, tile_offset);
