ALTER TABLE messenger_one_time_prekeys
  ADD COLUMN claim_id_hash BYTEA,
  ADD COLUMN claim_base_bundle_hash BYTEA,
  ADD CONSTRAINT messenger_one_time_prekeys_claim_id_hash_check
    CHECK (claim_id_hash IS NULL OR octet_length(claim_id_hash) = 32),
  ADD CONSTRAINT messenger_one_time_prekeys_claim_base_hash_check
    CHECK (claim_base_bundle_hash IS NULL OR octet_length(claim_base_bundle_hash) = 32),
  ADD CONSTRAINT messenger_one_time_prekeys_claim_state_check
    CHECK (
      (claim_id_hash IS NULL AND claim_base_bundle_hash IS NULL)
      OR
      (claim_id_hash IS NOT NULL AND claim_base_bundle_hash IS NOT NULL)
    );

CREATE UNIQUE INDEX messenger_one_time_prekeys_claim_id
  ON messenger_one_time_prekeys (claim_id_hash)
  WHERE claim_id_hash IS NOT NULL;
