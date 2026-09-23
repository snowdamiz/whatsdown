##! Prekey-bundle validation and codecs.

from Protocol.WirePrimitives import (
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
  protocol_write_u16,
  protocol_write_u64
)
from Protocol.ExtensionWire import (
  protocol_encode_extensions,
  protocol_encode_suites,
  protocol_take_extensions,
  protocol_take_suites,
  protocol_validate_extensions
)
from Protocol.IdentityWire import decode_device_credential
from Protocol.V1 import PrekeyBundle, ProtocolError, protocol_contains_suite, protocol_supported_suite, protocol_validate_suite_list

fn validate_prekey_bundle(value :: PrekeyBundle) -> Result<(), ProtocolError> do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    if !protocol_supported_suite(value.suite) do
      Err(UnsupportedSuite)
    else
      let credential_length = if value.suite == 2 do
        1395
      else
        211
      end
      let post_quantum_length = if value.suite == 2 do
        1184
      else
        0
      end
      if Bytes.length(value.device_credential) != credential_length || Bytes.length(value.identity_dh_public_key) != 32 || Bytes.length(value.signing_public_key) != 32 || Bytes.length(value.signed_prekey) != 32 || Bytes.length(value.signed_prekey_signature) != 64 || Bytes.length(value.post_quantum_prekey) != post_quantum_length do
        Err(InvalidFieldLength)
      else
        if protocol_is_zero(value.signed_prekey_id) || !(Bytes.length(value.one_time_prekey) == 0 || Bytes.length(value.one_time_prekey) == 32) do
          Err(InvalidFieldLength)
        else
          if (Bytes.length(value.one_time_prekey) == 0 && !protocol_is_zero(value.one_time_prekey_id)) || (Bytes.length(value.one_time_prekey) == 32 && protocol_is_zero(value.one_time_prekey_id)) do
            Err(InvalidFieldLength)
          else
            protocol_validate_suite_list(value.supported_suites, 0)?
            if !protocol_contains_suite(value.supported_suites, value.suite, 0) do
              Err(UnsupportedSuite)
            else
              case decode_device_credential(value.device_credential) do
                Err(_) -> Err(MalformedEncoding)
                Ok(credential) -> if credential.suite != value.suite || !Bytes.secure_equals(credential.signing_public_key,
                  value.signing_public_key) || !Bytes.secure_equals(credential.dh_public_key,
                  value.identity_dh_public_key) || !Bytes.secure_equals(credential.post_quantum_public_key,
                  value.post_quantum_prekey) do
                  Err(MalformedEncoding)
                else
                  protocol_validate_extensions(value.extensions, 0, 0)
                end
              end
            end
          end
        end
      end
    end
  end
end

pub fn encode_prekey_bundle(value :: PrekeyBundle) -> Bytes!ProtocolError do
  validate_prekey_bundle(value)?
  protocol_join([
      protocol_byte(value.version)?,
      Bytes.from_utf8("PKB"),
      protocol_write_u16(value.suite)?,
      protocol_vector(value.device_credential)?,
      value.identity_dh_public_key,
      value.signing_public_key,
      protocol_write_u64(value.signed_prekey_id)?,
      value.signed_prekey,
      value.signed_prekey_signature,
      protocol_write_u64(value.one_time_prekey_id)?,
      protocol_vector(value.one_time_prekey)?,
      value.post_quantum_prekey,
      protocol_encode_suites(value.supported_suites)?,
      protocol_write_u64(value.expires_at)?,
      protocol_encode_extensions(value.extensions)?
    ],
    0,
    Bytes.empty())
end

pub fn decode_prekey_bundle(input :: Bytes) -> PrekeyBundle!ProtocolError do
  let version = protocol_take_u8(protocol_open(input, 19312)?)?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = protocol_take_fixed(version.state, 3)?
    if !Bytes.secure_equals(magic.value, Bytes.from_utf8("PKB")) do
      Err(MalformedEncoding)
    else
      let suite = protocol_take_u16(magic.state)?
      let device_credential = protocol_take_vector(suite.state, 4096)?
      let identity_dh_public_key = protocol_take_fixed(device_credential.state, 32)?
      let signing_public_key = protocol_take_fixed(identity_dh_public_key.state, 32)?
      let signed_prekey_id = protocol_take_u64(signing_public_key.state)?
      let signed_prekey = protocol_take_fixed(signed_prekey_id.state, 32)?
      let signed_prekey_signature = protocol_take_fixed(signed_prekey.state, 64)?
      let one_time_prekey_id = protocol_take_u64(signed_prekey_signature.state)?
      let one_time_prekey = protocol_take_vector(one_time_prekey_id.state, 32)?
      let post_quantum_prekey = protocol_take_suite_fixed(one_time_prekey.state, suite.value, 1184)?
      let supported_suites = protocol_take_suites(post_quantum_prekey.state)?
      let expires_at = protocol_take_u64(supported_suites.state)?
      let extensions = protocol_take_extensions(expires_at.state)?
      protocol_require_end(extensions.state)?
      let value = PrekeyBundle {
        version: version.value,
        suite: suite.value,
        device_credential: device_credential.value,
        identity_dh_public_key: identity_dh_public_key.value,
        signing_public_key: signing_public_key.value,
        signed_prekey_id: signed_prekey_id.value,
        signed_prekey: signed_prekey.value,
        signed_prekey_signature: signed_prekey_signature.value,
        one_time_prekey_id: one_time_prekey_id.value,
        one_time_prekey: one_time_prekey.value,
        post_quantum_prekey: post_quantum_prekey.value,
        supported_suites: supported_suites.value,
        expires_at: expires_at.value,
        extensions: extensions.value
      }
      validate_prekey_bundle(value)?
      Ok(value)
    end
  end
end
