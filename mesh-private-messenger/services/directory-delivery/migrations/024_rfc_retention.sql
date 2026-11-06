-- Anchors belong to one authenticated log version. Equal sequence numbers
-- in the archived and RFC logs must never share a retention reference.
CREATE TABLE transparency_v2_anchors
  (LIKE transparency_anchors INCLUDING ALL);
ALTER TABLE transparency_v2_anchors ADD CONSTRAINT transparency_v2_anchor_checkpoint
  FOREIGN KEY (checkpoint_sequence) REFERENCES transparency_v2_checkpoints (sequence);
