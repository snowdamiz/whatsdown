##! Account and device-credential codecs.

from Protocol.WirePrimitives import (
  protocol_byte,
  protocol_join,
  protocol_open,
  protocol_require_end,
  protocol_take_fixed,
  protocol_take_u16,
  protocol_take_u32,
  protocol_take_u64,
  protocol_take_u8,
  protocol_take_vector,
  protocol_vector,
  protocol_write_u16,
  protocol_write_u32,
  protocol_write_u64
)
from Protocol.ExtensionWire import protocol_encode_extensions, protocol_take_extensions, protocol_validate_extensions
from Protocol.V1 import AccountIdentity, DeviceCredential, ProtocolError, protocol_supported_suite

fn validate_account(value :: AccountIdentity) -> Result <(), ProtocolError > do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    if Bytes.length(value.account_id) != 32 || Bytes.length(value.authorization_public_key) != 32 do
      Err(InvalidFieldLength)
    else
      protocol_validate_extensions(value.extensions, 0, 0)
    end
  end
end

pub fn encode_account_identity(value :: AccountIdentity) -> Bytes ! ProtocolError do
  validate_account(value) ?
  protocol_join([protocol_byte(value.version) ?, Bytes.from_utf8("ACT"), value.account_id, value.authorization_public_key, protocol_write_u64(value.created_at) ?, protocol_write_u64(value.directory_sequence) ?, protocol_encode_extensions(value.extensions) ?],
  0,
  Bytes.empty())
end

pub fn decode_account_identity(input :: Bytes) -> AccountIdentity ! ProtocolError do
  let version = protocol_take_u8(protocol_open(input, 16582) ?) ?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = protocol_take_fixed(version.state, 3) ?
    if !Bytes.secure_equals(magic.value, Bytes.from_utf8("ACT")) do
      Err(MalformedEncoding)
    else
      let account_id = protocol_take_fixed(magic.state, 32) ?
      let authorization_public_key = protocol_take_fixed(account_id.state, 32) ?
      let created_at = protocol_take_u64(authorization_public_key.state) ?
      let directory_sequence = protocol_take_u64(created_at.state) ?
      let extensions = protocol_take_extensions(directory_sequence.state) ?
      protocol_require_end(extensions.state) ?
      let value = AccountIdentity {
        version : version.value,
        account_id : account_id.value,
        authorization_public_key : authorization_public_key.value,
        created_at : created_at.value,
        directory_sequence : directory_sequence.value,
        extensions : extensions.value
      }
      validate_account(value) ?
      Ok(value)
    end
  end
end

fn validate_credential(value :: DeviceCredential) -> Result <(), ProtocolError > do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    if !protocol_supported_suite(value.suite) do
      Err(UnsupportedSuite)
    else
      if Bytes.length(value.account_id) != 32 || Bytes.length(value.device_id) != 16 || Bytes.length(value.signing_public_key) != 32 || Bytes.length(value.dh_public_key) != 32 || Bytes.length(value.signature) != 64 do
        Err(InvalidFieldLength)
      else
        let post_quantum_length = if value.suite == 2 do
          1184
        else
          0
        end
        if Bytes.length(value.post_quantum_public_key) != post_quantum_length do
          Err(InvalidFieldLength)
        else
          if U64.compare(value.expires_at, value.created_at) < 0 do
            Err(InvalidExpiration)
          else
            Ok(nil)
          end
        end
      end
    end
  end
end

pub fn encode_device_credential(value :: DeviceCredential) -> Bytes ! ProtocolError do
  validate_credential(value) ?
  protocol_join([protocol_byte(value.version) ?, protocol_write_u16(value.suite) ?, value.account_id, value.device_id, value.signing_public_key, value.dh_public_key, protocol_vector(value.post_quantum_public_key) ?, protocol_write_u32(value.capabilities) ?, protocol_write_u64(value.created_at) ?, protocol_write_u64(value.expires_at) ?, protocol_write_u64(value.directory_sequence) ?, value.signature],
  0,
  Bytes.empty())
end

pub fn decode_device_credential(input :: Bytes) -> DeviceCredential ! ProtocolError do
  let version = protocol_take_u8(protocol_open(input, 1395) ?) ?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let suite = protocol_take_u16(version.state) ?
    let account_id = protocol_take_fixed(suite.state, 32) ?
    let device_id = protocol_take_fixed(account_id.state, 16) ?
    let signing_public_key = protocol_take_fixed(device_id.state, 32) ?
    let dh_public_key = protocol_take_fixed(signing_public_key.state, 32) ?
    let post_quantum_public_key = protocol_take_vector(dh_public_key.state, 1184) ?
    let capabilities = protocol_take_u32(post_quantum_public_key.state) ?
    let created_at = protocol_take_u64(capabilities.state) ?
    let expires_at = protocol_take_u64(created_at.state) ?
    let directory_sequence = protocol_take_u64(expires_at.state) ?
    let signature = protocol_take_fixed(directory_sequence.state, 64) ?
    protocol_require_end(signature.state) ?
    let value = DeviceCredential {
      version : version.value,
      suite : suite.value,
      account_id : account_id.value,
      device_id : device_id.value,
      signing_public_key : signing_public_key.value,
      dh_public_key : dh_public_key.value,
      post_quantum_public_key : post_quantum_public_key.value,
      capabilities : capabilities.value,
      created_at : created_at.value,
      expires_at : expires_at.value,
      directory_sequence : directory_sequence.value,
      signature : signature.value
    }
    validate_credential(value) ?
    Ok(value)
  end
end
