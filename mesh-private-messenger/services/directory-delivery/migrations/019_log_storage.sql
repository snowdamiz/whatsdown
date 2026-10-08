-- The log outgrows full-list proofs. Its size is now bounded only by the
-- 2^62 limit every proof and codec keeps.
ALTER TABLE transparency_checkpoints DROP CONSTRAINT transparency_checkpoints_tree_size_check;
ALTER TABLE transparency_checkpoints
  ADD CONSTRAINT transparency_checkpoints_tree_size_check
  CHECK (tree_size > 0 AND tree_size < 4611686018427387904);

-- Leaf positions are dense: the BIGSERIAL sequence skips a value for every
-- rolled-back append, a leaf index never does. Appends assign it under the
-- log's advisory lock.
ALTER TABLE transparency_entries ADD COLUMN leaf_index BIGINT CHECK (leaf_index >= 0);
UPDATE transparency_entries AS entry
SET leaf_index = ranked.leaf_position
FROM (SELECT sequence, row_number() OVER (ORDER BY sequence) - 1 AS leaf_position FROM transparency_entries) AS ranked
WHERE entry.sequence = ranked.sequence;
ALTER TABLE transparency_entries ALTER COLUMN leaf_index SET NOT NULL;
ALTER TABLE transparency_entries ADD CONSTRAINT transparency_entries_leaf_index_key UNIQUE (leaf_index);

-- Each device record (one device's DRE entry) is stored once, by its hash. An
-- entry keeps the device set's header, the ordered hashes of its records and
-- its revocation trailer; the canonical bytes are rebuilt from those, so leaf
-- hashes and every wire form are unchanged. pruned_at marks an entry whose
-- bytes are gone for good (superseded for 90 days, or its account deleted):
-- its leaf hash, commitment and position stay.
CREATE TABLE transparency_device_records (
  record_hash BYTEA PRIMARY KEY CHECK (octet_length(record_hash) = 32),
  record_bytes BYTEA NOT NULL CHECK (octet_length(record_bytes) BETWEEN 1 AND 36006),
  CHECK (record_hash = sha256(record_bytes))
);

ALTER TABLE transparency_entries
  ADD COLUMN pruned_at TIMESTAMPTZ,
  ADD COLUMN entry_header BYTEA CHECK (entry_header IS NULL OR octet_length(entry_header) BETWEEN 18 AND 16672),
  ADD COLUMN record_hashes BYTEA[] CHECK (record_hashes IS NULL OR cardinality(record_hashes) BETWEEN 1 AND 8),
  ADD COLUMN entry_trailer BYTEA CHECK (entry_trailer IS NULL OR octet_length(entry_trailer) BETWEEN 1 AND 513);

CREATE INDEX transparency_entries_records ON transparency_entries USING gin (record_hashes);
CREATE INDEX transparency_entries_unpruned ON transparency_entries (sequence) WHERE pruned_at IS NULL;

-- Splits a device set (DVS v1) into its header, its device records and its
-- revocation trailer. Refuses anything else.
CREATE FUNCTION transparency_entry_parts(entry BYTEA, OUT header BYTEA, OUT records BYTEA[], OUT trailer BYTEA)
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE
  total INTEGER := octet_length(entry);
  cursor_at INTEGER := 4;
  field_length BIGINT;
  device_count INTEGER;
  field INTEGER;
BEGIN
  IF total < 20 OR get_byte(entry, 0) <> 1 OR substring(entry FROM 2 FOR 3) <> 'DVS'::bytea THEN
    RAISE EXCEPTION 'transparency entry is not a device set';
  END IF;
  -- username and account identity vectors, then the u64 sequence
  FOR field IN 1..2 LOOP
    IF cursor_at + 4 > total THEN
      RAISE EXCEPTION 'transparency entry is truncated';
    END IF;
    field_length := get_byte(entry, cursor_at)::bigint * 16777216 + get_byte(entry, cursor_at + 1) * 65536
      + get_byte(entry, cursor_at + 2) * 256 + get_byte(entry, cursor_at + 3);
    IF cursor_at + 4 + field_length > total THEN
      RAISE EXCEPTION 'transparency entry is truncated';
    END IF;
    cursor_at := cursor_at + 4 + field_length::integer;
  END LOOP;
  IF cursor_at + 9 > total THEN
    RAISE EXCEPTION 'transparency entry is truncated';
  END IF;
  cursor_at := cursor_at + 8;
  device_count := get_byte(entry, cursor_at);
  cursor_at := cursor_at + 1;
  header := substring(entry FROM 1 FOR cursor_at);
  records := ARRAY[]::BYTEA[];
  FOR field IN 1..device_count LOOP
    IF cursor_at + 4 > total THEN
      RAISE EXCEPTION 'transparency entry is truncated';
    END IF;
    field_length := get_byte(entry, cursor_at)::bigint * 16777216 + get_byte(entry, cursor_at + 1) * 65536
      + get_byte(entry, cursor_at + 2) * 256 + get_byte(entry, cursor_at + 3);
    IF field_length < 1 OR cursor_at + 4 + field_length > total THEN
      RAISE EXCEPTION 'transparency entry is truncated';
    END IF;
    records := array_append(records, substring(entry FROM cursor_at + 5 FOR field_length::integer));
    cursor_at := cursor_at + 4 + field_length::integer;
  END LOOP;
  trailer := substring(entry FROM cursor_at + 1);
  IF octet_length(trailer) < 1 OR octet_length(trailer) <> 1 + 16 * get_byte(trailer, 0) THEN
    RAISE EXCEPTION 'transparency entry has an invalid trailer';
  END IF;
END
$$;

-- The canonical entry bytes again, or NULL when any record is missing.
CREATE FUNCTION transparency_entry_rebuild(header BYTEA, hashes BYTEA[], trailer BYTEA) RETURNS BYTEA
LANGUAGE sql STABLE AS $$
  SELECT CASE WHEN count(record.record_hash) = cardinality(hashes) THEN
    header || COALESCE(string_agg(int4send(octet_length(record.record_bytes)) || record.record_bytes,
      ''::bytea ORDER BY listed.ordinal), ''::bytea) || trailer
  END
  FROM unnest(hashes) WITH ORDINALITY AS listed (record_hash, ordinal)
  LEFT JOIN transparency_device_records AS record ON record.record_hash = listed.record_hash
$$;

-- Both trees keep every complete subtree's hash by (tree, level, index): tree 1
-- hashes as Morse does (what checkpoints sign), tree 2 as RFC 6962 does, over
-- the Morse leaf hashes (what C2SP witnesses cosign). Level 0 holds the leaves.
-- Nothing is ever rewritten, so tiles can move elsewhere without changing a
-- proof.
ALTER TABLE transparency_nodes DROP CONSTRAINT transparency_nodes_pkey;
ALTER TABLE transparency_nodes ADD COLUMN tree SMALLINT NOT NULL DEFAULT 1 CHECK (tree IN (1, 2));
ALTER TABLE transparency_nodes ALTER COLUMN tree DROP DEFAULT;
ALTER TABLE transparency_nodes ADD PRIMARY KEY (tree, level, node_index);

-- Rebuilds every node from the leaves, one statement per tree and level. Each
-- level pairs the one below it by grouping (an index range scan and one
-- aggregate), so the cost stays linear whatever the planner's statistics say.
-- Used to backfill a log written before nodes were kept.
CREATE FUNCTION transparency_build_nodes() RETURNS INTEGER
LANGUAGE plpgsql AS $$
DECLARE
  current_tree SMALLINT;
  current_level INTEGER;
  highest INTEGER := 0;
BEGIN
  DELETE FROM transparency_nodes;
  INSERT INTO transparency_nodes (tree, level, node_index, hash)
  SELECT 1, 0, leaf_index, leaf_hash FROM transparency_entries;
  INSERT INTO transparency_nodes (tree, level, node_index, hash)
  SELECT 2, 0, leaf_index, sha256('\x00'::bytea || leaf_hash) FROM transparency_entries;
  FOREACH current_tree IN ARRAY ARRAY[1, 2]::SMALLINT[] LOOP
    current_level := 1;
    LOOP
      INSERT INTO transparency_nodes (tree, level, node_index, hash)
      SELECT current_tree, current_level, pair.parent,
        sha256(CASE WHEN current_tree = 1 THEN 'mesh-msg/v1/transparency-node'::bytea ELSE '\x01'::bytea END
          || pair.children)
      FROM (
        SELECT node_index / 2 AS parent, string_agg(hash, ''::bytea ORDER BY node_index) AS children,
          count(*) AS present
        FROM transparency_nodes
        WHERE tree = current_tree AND level = current_level - 1
        GROUP BY node_index / 2
      ) AS pair
      WHERE pair.present = 2;
      EXIT WHEN NOT FOUND;
      highest := GREATEST(highest, current_level);
      current_level := current_level + 1;
    END LOOP;
  END LOOP;
  RETURN highest;
END
$$;

SELECT transparency_build_nodes();

-- One row per day the pruning job ran (or would have, in dry-run mode), with
-- what it removed. It runs at most once a day, up to its daily cap.
CREATE TABLE transparency_pruning_runs (
  run_day DATE PRIMARY KEY,
  mode TEXT NOT NULL CHECK (mode IN ('dry-run', 'on')),
  entries INTEGER NOT NULL DEFAULT 0 CHECK (entries >= 0),
  records INTEGER NOT NULL DEFAULT 0 CHECK (records >= 0),
  checkpoints INTEGER NOT NULL DEFAULT 0 CHECK (checkpoints >= 0),
  ran_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
