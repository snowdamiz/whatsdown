-- Outer suite 4 marks a recipient-sealed envelope. It names the transport only:
-- delivery no longer learns whether an envelope is a classical, hybrid, or group
-- packet. Suites 1-3 stay valid for envelopes queued before clients upgraded.
ALTER TABLE messenger_envelopes
  DROP CONSTRAINT messenger_envelopes_suite_check,
  ADD CONSTRAINT messenger_envelopes_suite_check CHECK (suite IN (1, 2, 3, 4));
