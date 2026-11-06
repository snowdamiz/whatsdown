-- Existing C2SP rows remain unready until an operator installs their exact
-- signed-note key name. An HTTP response can never supply this trust mapping.
ALTER TABLE transparency_witness_registry ADD COLUMN note_name TEXT
  CHECK (note_name IS NULL OR (octet_length(note_name) BETWEEN 1 AND 255
    AND note_name !~ '[[:space:][:cntrl:]+]'));
ALTER TABLE transparency_witness_registry ADD CONSTRAINT witness_note_software
  CHECK (software = 'c2sp' OR note_name IS NULL);

-- The signed timestamp is checked in Mesh before admission. NULL preserves
-- native signatures and makes any pre-migration C2SP row fail health freshness.
ALTER TABLE witness_v2_signatures ADD COLUMN cosigned_at_ms BIGINT
  CHECK (cosigned_at_ms IS NULL OR (cosigned_at_ms >= 0 AND octet_length(signature) = 72));
