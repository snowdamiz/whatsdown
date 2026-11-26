-- A fresh signed checkpoint may attest the same append-only tree at a new sequence.
ALTER TABLE transparency_checkpoints DROP CONSTRAINT transparency_checkpoints_tree_size_key;
