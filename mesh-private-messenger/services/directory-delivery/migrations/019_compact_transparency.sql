-- Dense leaf positions are independent of BIGSERIAL sequences, whose gaps
-- survive rolled-back transactions. Existing roots remain byte-for-byte equal.
ALTER TABLE transparency_entries ADD COLUMN leaf_index BIGINT;
WITH positions AS (
  SELECT sequence, row_number() OVER (ORDER BY sequence) - 1 AS leaf_index
  FROM transparency_entries
)
UPDATE transparency_entries e SET leaf_index = p.leaf_index
FROM positions p WHERE e.sequence = p.sequence;
ALTER TABLE transparency_entries ALTER COLUMN leaf_index SET NOT NULL;
ALTER TABLE transparency_entries ADD CONSTRAINT transparency_leaf_index_bounds
  CHECK (leaf_index >= 0 AND leaf_index < 4294967295);
CREATE UNIQUE INDEX transparency_entries_leaf_index ON transparency_entries (leaf_index);

-- Tile coordinates match immutable 256-node tiles at each tree level.
ALTER TABLE transparency_nodes ADD COLUMN tile_index BIGINT
  GENERATED ALWAYS AS (node_index / 256) STORED;
ALTER TABLE transparency_nodes ADD COLUMN tile_offset INTEGER
  GENERATED ALWAYS AS ((node_index % 256)::integer) STORED;
CREATE INDEX transparency_nodes_tile ON transparency_nodes (level, tile_index, tile_offset);

-- The old implementation did not populate this table. Rebuilding also handles
-- an installation that already cached nodes; entries are authoritative.
DELETE FROM transparency_nodes;
INSERT INTO transparency_nodes (level, node_index, hash)
SELECT 0, leaf_index, leaf_hash FROM transparency_entries;
DO $$
DECLARE current_level integer := 0; inserted_count bigint;
BEGIN
  LOOP
    INSERT INTO transparency_nodes (level, node_index, hash)
    SELECT current_level + 1, l.node_index / 2,
      sha256(convert_to('mesh-msg/v1/transparency-node', 'UTF8') || l.hash || r.hash)
    FROM transparency_nodes l JOIN transparency_nodes r
      ON r.level = l.level AND r.node_index = l.node_index + 1
    WHERE l.level = current_level AND l.node_index % 2 = 0;
    GET DIAGNOSTICS inserted_count = ROW_COUNT;
    EXIT WHEN inserted_count = 0;
    current_level := current_level + 1;
  END LOOP;
END $$;

ALTER TABLE transparency_checkpoints DROP CONSTRAINT transparency_checkpoints_tree_size_check;
ALTER TABLE transparency_checkpoints ADD CONSTRAINT transparency_checkpoints_tree_size_check
  CHECK (tree_size > 0 AND tree_size <= 4294967295);
