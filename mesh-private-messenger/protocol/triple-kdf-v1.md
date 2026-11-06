# Inactive composite message-key combiner

`Session.TripleKdf.triple_message_material(configuration, session, ec, pq)`
consumes both opaque message-key resources and returns one opaque 32-byte
`SecretBytes`. Configuration and session must each be exactly 32 bytes.

The construction is HKDF-SHA256 with the post-quantum message key as secret
salt, the classical message key as input key material, and this exact 83-byte
info value:

`ASCII("mesh-msg/triple/v1") || 0x00 || configuration32 || session32`

The helper destroys both input owners on success or refusal. It never converts
their material into ordinary bytes. Callers must supply the actual 32-byte
ratchet keys; the helper does not establish their provenance or inspect their
lengths. The public secret-salt HKDF primitive performs the derivation.

Independent fixed test seeds pin the result through HMAC tags, including changes
to each key, key-order reversal and changes to either scope field. Scope bounds
and consumed-input misuse are separately checked.

This module is inactive. It does not extract keys from ratchet state, authenticate
a message, authorize a state transition or select a transport version. The future
whole-message operation must use one combined-key body AEAD and preserve the
original HE/SPQR states on failure. Durable coordination and native activation
remain separate requirements. This profile does not claim Signal wire
interoperability.
