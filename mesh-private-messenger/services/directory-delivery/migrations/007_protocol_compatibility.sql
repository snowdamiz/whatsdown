ALTER TABLE messenger_envelopes
  DROP CONSTRAINT messenger_envelopes_suite_check,
  ADD CONSTRAINT messenger_envelopes_suite_check CHECK (suite IN (1, 2, 3));

ALTER TABLE messenger_devices
  DROP CONSTRAINT messenger_devices_prekey_bundle_check,
  ADD CONSTRAINT messenger_devices_prekey_bundle_check
    CHECK (octet_length(prekey_bundle) BETWEEN 1 AND 19312);

ALTER TABLE transparency_entries
  DROP CONSTRAINT transparency_entries_entry_bytes_check,
  ADD CONSTRAINT transparency_entries_entry_bytes_check
    CHECK (octet_length(entry_bytes) BETWEEN 1 AND 305260);
