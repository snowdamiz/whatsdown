ALTER TABLE messenger_one_time_prekeys
  ADD COLUMN claim_response BYTEA;

-- Before this migration, an existing device registration could only be replayed
-- byte-for-byte; changing its normalized prekey bundle was rejected. Therefore
-- this is the exact base used by every surviving legacy claim. Keep it as a
-- migration marker so the service can overlay the claimed one-time prekey and
-- atomically promote the marker to the exact response on first replay.
UPDATE messenger_one_time_prekeys AS prekey
SET claim_response = device.prekey_bundle
FROM messenger_devices AS device
WHERE device.account_id = prekey.account_id
  AND device.device_id = prekey.device_id
  AND prekey.claim_id_hash IS NOT NULL;

ALTER TABLE messenger_one_time_prekeys
  ADD CONSTRAINT messenger_one_time_prekeys_claim_response_check
    CHECK (
      claim_response IS NULL
      OR
      (
        consumed_at IS NOT NULL
        AND claim_id_hash IS NOT NULL
        AND claim_base_bundle_hash IS NOT NULL
        AND octet_length(claim_response) BETWEEN 1 AND 19312
      )
    ) NOT VALID;

ALTER TABLE messenger_one_time_prekeys
  VALIDATE CONSTRAINT messenger_one_time_prekeys_claim_response_check;
