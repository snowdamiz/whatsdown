##! Handshake transcript and initial-message codecs.

from Binary.Reader import finish
from Protocol.WirePrimitives import (
  protocol_append,
  protocol_byte,
  protocol_is_zero,
  protocol_join,
  protocol_open,
  protocol_require_end,
  protocol_take_fixed,
  protocol_take_suite_fixed,
  protocol_take_u16,
  protocol_take_u64,
  protocol_take_u8,
  protocol_take_vector,
  protocol_vector,
  protocol_write_builder_parts,
  protocol_write_u16,
  protocol_write_u64
)
from Protocol.ExtensionWire import protocol_encode_extensions, protocol_take_extensions, protocol_validate_extensions
from Protocol.IdentityWire import decode_device_credential
from Protocol.V1 import HandshakeTranscript, InitialMessage, ProtocolError, protocol_supported_suite

fn validate_handshake_transcript(value :: HandshakeTranscript) -> Result<(), ProtocolError> do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    if !protocol_supported_suite(value.suite) do
      Err(UnsupportedSuite)
    else
      let post_quantum_length = if value.suite == 2 do
        1184
      else
        0
      end
      if Bytes.length(value.initiator_credential_hash) != 32 || Bytes.length(value.responder_prekey_bundle_hash) != 32 || Bytes.length(value.initiator_ephemeral_public_key) != 32 || Bytes.length(value.responder_signed_prekey) != 32 || Bytes.length(value.responder_post_quantum_prekey) != post_quantum_length || protocol_is_zero(value.signed_prekey_id) || !(Bytes.length(value.responder_one_time_prekey) == 0 || Bytes.length(value.responder_one_time_prekey) == 32) do
        Err(InvalidFieldLength)
      else
        if (Bytes.length(value.responder_one_time_prekey) == 0 && !protocol_is_zero(value.one_time_prekey_id)) || (Bytes.length(value.responder_one_time_prekey) == 32 && protocol_is_zero(value.one_time_prekey_id)) do
          Err(InvalidFieldLength)
        else
          protocol_validate_extensions(value.extensions, 0, 0)
        end
      end
    end
  end
end

pub fn encode_handshake_transcript(value :: HandshakeTranscript) -> Bytes!ProtocolError do
  validate_handshake_transcript(value)?
  protocol_join([
      protocol_byte(value.version)?,
      Bytes.from_utf8("HST"),
      protocol_write_u16(value.suite)?,
      value.initiator_credential_hash,
      value.responder_prekey_bundle_hash,
      value.initiator_ephemeral_public_key,
      protocol_write_u64(value.signed_prekey_id)?,
      value.responder_signed_prekey,
      protocol_write_u64(value.one_time_prekey_id)?,
      protocol_vector(value.responder_one_time_prekey)?,
      value.responder_post_quantum_prekey,
      protocol_encode_extensions(value.extensions)?
    ],
    0,
    Bytes.empty())
end

pub fn decode_handshake_transcript(input :: Bytes) -> HandshakeTranscript!ProtocolError do
  let version = protocol_take_u8(protocol_open(input, 17868)?)?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = protocol_take_fixed(version.state, 3)?
    if !Bytes.secure_equals(magic.value, Bytes.from_utf8("HST")) do
      Err(MalformedEncoding)
    else
      let suite = protocol_take_u16(magic.state)?
      let initiator_credential_hash = protocol_take_fixed(suite.state, 32)?
      let responder_prekey_bundle_hash = protocol_take_fixed(initiator_credential_hash.state, 32)?
      let initiator_ephemeral_public_key = protocol_take_fixed(responder_prekey_bundle_hash.state,
        32)?
      let signed_prekey_id = protocol_take_u64(initiator_ephemeral_public_key.state)?
      let responder_signed_prekey = protocol_take_fixed(signed_prekey_id.state, 32)?
      let one_time_prekey_id = protocol_take_u64(responder_signed_prekey.state)?
      let responder_one_time_prekey = protocol_take_vector(one_time_prekey_id.state, 32)?
      let responder_post_quantum_prekey = protocol_take_suite_fixed(responder_one_time_prekey.state,
        suite.value,
        1184)?
      let extensions = protocol_take_extensions(responder_post_quantum_prekey.state)?
      protocol_require_end(extensions.state)?
      let value = HandshakeTranscript {
        version: version.value,
        suite: suite.value,
        initiator_credential_hash: initiator_credential_hash.value,
        responder_prekey_bundle_hash: responder_prekey_bundle_hash.value,
        initiator_ephemeral_public_key: initiator_ephemeral_public_key.value,
        signed_prekey_id: signed_prekey_id.value,
        responder_signed_prekey: responder_signed_prekey.value,
        one_time_prekey_id: one_time_prekey_id.value,
        responder_one_time_prekey: responder_one_time_prekey.value,
        responder_post_quantum_prekey: responder_post_quantum_prekey.value,
        extensions: extensions.value
      }
      validate_handshake_transcript(value)?
      Ok(value)
    end
  end
end

pub fn hash_handshake_transcript(value :: HandshakeTranscript) -> Bytes!ProtocolError do
  let encoded = encode_handshake_transcript(value)?
  Ok(Crypto.sha256(protocol_append(Bytes.from_utf8("mesh-msg/v1/handshake"), encoded)?))
end

fn validate_initial_message(value :: InitialMessage) -> Result<(), ProtocolError> do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    if !protocol_supported_suite(value.suite) do
      Err(UnsupportedSuite)
    else
      let post_quantum_length = if value.suite == 2 do
        1088
      else
        0
      end
      let credential_length = Bytes.length(value.initiator_credential)
      let invalid_credential_length = !(credential_length == 211 || credential_length == 1395)
      let invalid_lengths = invalid_credential_length || Bytes.length(value.initiator_identity_public_key.bytes) != 32 || Bytes.length(value.initiator_ephemeral_public_key.bytes) != 32 || Bytes.length(value.post_quantum_ciphertext) != post_quantum_length || Bytes.length(value.transcript_hash) != 32 || Bytes.length(value.nonce) != 12
      if invalid_lengths || protocol_is_zero(value.signed_prekey_id) || protocol_is_zero(value.one_time_prekey_id) do
        Err(InvalidFieldLength)
      else
        if Bytes.length(value.ciphertext) < 16 do
          Err(InvalidFieldLength)
        else
          let maximum_ciphertext = 65398 - credential_length - post_quantum_length
          if Bytes.length(value.ciphertext) > maximum_ciphertext do
            Err(OversizedInput)
          else
            case decode_device_credential(value.initiator_credential) do
              Err(_) -> Err(MalformedEncoding)
              Ok(credential) -> if value.suite == 2 && credential.suite != 2 do
                Err(UnsupportedSuite)
              else
                Ok(nil)
              end
            end
          end
        end
      end
    end
  end
end

pub fn encode_initial_message(value :: InitialMessage) -> Bytes!ProtocolError do
  validate_initial_message(value)?
  let parts = [
    protocol_byte(value.version)?,
    Bytes.from_utf8("INI"),
    protocol_write_u16(value.suite)?,
    protocol_write_u64(value.signed_prekey_id)?,
    protocol_write_u64(value.one_time_prekey_id)?,
    protocol_vector(value.initiator_credential)?,
    value.initiator_identity_public_key.bytes,
    value.initiator_ephemeral_public_key.bytes,
    value.post_quantum_ciphertext,
    value.transcript_hash,
    value.nonce,
    protocol_vector(value.ciphertext)?
  ]
  let builder = case BytesBuilder.new(65536) do
    Err(_) -> Err(OversizedInput)
    Ok(value)
  end?
  protocol_write_builder_parts(builder, parts, 0)?
  case BytesBuilder.finish(builder) do
    Err(_) -> Err(OversizedInput)
    Ok(encoded)
  end
end

pub fn decode_initial_message(input :: Bytes) -> InitialMessage!ProtocolError do
  let version = protocol_take_u8(protocol_open(input, 65536)?)?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = protocol_take_fixed(version.state, 3)?
    if !Bytes.secure_equals(magic.value, Bytes.from_utf8("INI")) do
      Err(MalformedEncoding)
    else
      let suite = protocol_take_u16(magic.state)?
      let signed_prekey_id = protocol_take_u64(suite.state)?
      let one_time_prekey_id = protocol_take_u64(signed_prekey_id.state)?
      let initiator_credential = protocol_take_vector(one_time_prekey_id.state, 1395)?
      let initiator_identity_public_key = protocol_take_fixed(initiator_credential.state, 32)?
      let initiator_ephemeral_public_key = protocol_take_fixed(initiator_identity_public_key.state,
        32)?
      let post_quantum_ciphertext = protocol_take_suite_fixed(initiator_ephemeral_public_key.state,
        suite.value,
        1088)?
      let transcript_hash = protocol_take_fixed(post_quantum_ciphertext.state, 32)?
      let nonce = protocol_take_fixed(transcript_hash.state, 12)?
      let ciphertext = protocol_take_vector(nonce.state, 65187)?
      protocol_require_end(ciphertext.state)?
      let value = InitialMessage {
        version: version.value,
        suite: suite.value,
        signed_prekey_id: signed_prekey_id.value,
        one_time_prekey_id: one_time_prekey_id.value,
        initiator_credential: initiator_credential.value,
        initiator_identity_public_key: X25519PublicKey { bytes: initiator_identity_public_key.value },
        initiator_ephemeral_public_key: X25519PublicKey { bytes: initiator_ephemeral_public_key.value },
        post_quantum_ciphertext: post_quantum_ciphertext.value,
        transcript_hash: transcript_hash.value,
        nonce: nonce.value,
        ciphertext: ciphertext.value
      }
      validate_initial_message(value)?
      Ok(value)
    end
  end
end
