-- Moves every stored entry to the device-record layout. An entry's old bytes
-- are replaced only after the entry rebuilt from its header, records and
-- trailer hashes to its stored leaf hash. One that does not keeps its bytes
-- (and serves them as before) and is counted. Returns that count.
CREATE FUNCTION transparency_move_to_records() RETURNS INTEGER
LANGUAGE plpgsql AS $$
DECLARE
  stored RECORD;
  parts RECORD;
  unconverted INTEGER := 0;
BEGIN
  FOR stored IN
    SELECT sequence, entry_bytes FROM transparency_entries WHERE entry_bytes IS NOT NULL ORDER BY sequence
  LOOP
    BEGIN
      SELECT * INTO parts FROM transparency_entry_parts(stored.entry_bytes);
    EXCEPTION WHEN OTHERS THEN
      unconverted := unconverted + 1;
      CONTINUE;
    END;
    INSERT INTO transparency_device_records (record_hash, record_bytes)
    SELECT sha256(record), record FROM unnest(parts.records) AS record
    ON CONFLICT DO NOTHING;
    UPDATE transparency_entries
    SET entry_header = parts.header,
      record_hashes = ARRAY(SELECT sha256(listed.record)
        FROM unnest(parts.records) WITH ORDINALITY AS listed (record, ordinal) ORDER BY listed.ordinal),
      entry_trailer = parts.trailer
    WHERE sequence = stored.sequence;
    UPDATE transparency_entries
    SET entry_bytes = NULL
    WHERE sequence = stored.sequence
      AND sha256('mesh-msg/v1/transparency-leaf'::bytea
        || transparency_entry_rebuild(entry_header, record_hashes, entry_trailer)) = leaf_hash;
    IF NOT FOUND THEN
      UPDATE transparency_entries
      SET entry_header = NULL, record_hashes = NULL, entry_trailer = NULL
      WHERE sequence = stored.sequence;
      unconverted := unconverted + 1;
    END IF;
  END LOOP;
  -- Entries whose bytes were already gone (deleted accounts) are pruned.
  UPDATE transparency_entries SET pruned_at = now()
  WHERE entry_bytes IS NULL AND entry_header IS NULL AND pruned_at IS NULL;
  -- Records no entry refers to (left over from an unconverted entry) go.
  DELETE FROM transparency_device_records AS record
  WHERE NOT EXISTS (
    SELECT 1 FROM transparency_entries AS entry WHERE entry.record_hashes @> ARRAY[record.record_hash]
  );
  RETURN unconverted;
END
$$;

DO $$
DECLARE
  unconverted INTEGER := transparency_move_to_records();
BEGIN
  IF unconverted > 0 THEN
    RAISE WARNING '% transparency entries did not rebuild to their leaf hash and keep their bytes', unconverted;
  END IF;
END
$$;

-- From here on an entry holds either its parts or nothing (pruned); old bytes
-- remain only on entries that failed the check above.
ALTER TABLE transparency_entries ADD CONSTRAINT transparency_entries_parts_check CHECK (
  (entry_header IS NULL) = (record_hashes IS NULL)
  AND (entry_header IS NULL) = (entry_trailer IS NULL)
  AND (pruned_at IS NULL OR (entry_header IS NULL AND entry_bytes IS NULL))
);
