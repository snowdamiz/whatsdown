##! Directory, device linking, sets, revocation, departure, and account deletion codecs.

from Binary.Reader import BinaryReader
from Protocol.WirePrimitives import (
  ProtocolReadDirectoryEntries,
  ProtocolReadInt,
  protocol_append,
  protocol_byte,
  protocol_join,
  protocol_open,
  protocol_read_ack_ids,
  protocol_require_end,
  protocol_take_fixed,
  protocol_take_suite_fixed,
  protocol_take_u16,
  protocol_take_u64,
  protocol_take_u8,
  protocol_take_vector,
  protocol_valid_magic,
  protocol_vector,
  protocol_write_u16,
  protocol_write_u64
)
from Protocol.V1 import (
  AccountDeletion,
  DeviceDeparture,
  DeviceLinkAuthorization,
  DeviceLinkRequest,
  DeviceRevocation,
  DeviceSet,
  DirectoryEntry,
  ProtocolError
)

fn valid_username_byte(value :: Int) -> Bool do
  (value >= 97 && value <= 122) || (value >= 48 && value <= 57) || value == 45 || value == 46 || value == 95
end

fn validate_username_bytes(value :: Bytes, index :: Int) -> Result<(), ProtocolError> do
  if index >= Bytes.length(value) do
    Ok(nil)
  else
    case Bytes.get(value, index) do
      Err(_) -> Err(MalformedEncoding)
      Ok(next) -> if valid_username_byte(next) do
        validate_username_bytes(value, index + 1)
      else
        Err(InvalidFieldLength)
      end
    end
  end
end

fn encode_username(value :: String) -> Bytes!ProtocolError do
  let encoded = Bytes.from_utf8(value)
  if Bytes.length(encoded) == 0 || Bytes.length(encoded) > 64 do
    Err(InvalidFieldLength)
  else
    validate_username_bytes(encoded, 0)?
    Ok(encoded)
  end
end

fn decode_username(value :: Bytes) -> String!ProtocolError do
  if Bytes.length(value) == 0 || Bytes.length(value) > 64 do
    Err(InvalidFieldLength)
  else
    validate_username_bytes(value, 0)?
    case Bytes.to_utf8(value) do
      Err(_) -> Err(MalformedEncoding)
      Ok(decoded)
    end
  end
end

pub fn encode_directory_lookup(username :: String) -> Bytes!ProtocolError do
  protocol_join([
      protocol_byte(1)?,
      Bytes.from_utf8("DLK"),
      protocol_vector(encode_username(username)?)?
    ],
    0,
    Bytes.empty())
end

pub fn decode_directory_lookup(input :: Bytes) -> String!ProtocolError do
  let version = protocol_take_u8(protocol_open(input, 72)?)?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = protocol_take_fixed(version.state, 3)?
    protocol_valid_magic(magic.value, "DLK")?
    let username = protocol_take_vector(magic.state, 64)?
    protocol_require_end(username.state)?
    decode_username(username.value)
  end
end

fn validate_directory_entry(value :: DirectoryEntry) -> Result<(), ProtocolError> do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    encode_username(value.username)?
    if Bytes.length(value.account_identity) == 0 || Bytes.length(value.account_identity) > 16582 || Bytes.length(value.prekey_bundle) == 0 || Bytes.length(value.prekey_bundle) > 19312 || Bytes.length(value.mailbox_token) != 32 do
      Err(InvalidFieldLength)
    else
      Ok(nil)
    end
  end
end

pub fn encode_directory_entry(value :: DirectoryEntry) -> Bytes!ProtocolError do
  validate_directory_entry(value)?
  protocol_join([
      protocol_byte(value.version)?,
      Bytes.from_utf8("DRE"),
      protocol_vector(encode_username(value.username)?)?,
      protocol_vector(value.account_identity)?,
      protocol_vector(value.prekey_bundle)?,
      value.mailbox_token
    ],
    0,
    Bytes.empty())
end

pub fn decode_directory_entry(input :: Bytes) -> DirectoryEntry!ProtocolError do
  let version = protocol_take_u8(protocol_open(input, 36006)?)?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = protocol_take_fixed(version.state, 3)?
    protocol_valid_magic(magic.value, "DRE")?
    let username = protocol_take_vector(magic.state, 64)?
    let account_identity = protocol_take_vector(username.state, 16582)?
    let prekey_bundle = protocol_take_vector(account_identity.state, 19312)?
    let mailbox_token = protocol_take_fixed(prekey_bundle.state, 32)?
    protocol_require_end(mailbox_token.state)?
    let value = DirectoryEntry {
      version: version.value,
      username: decode_username(username.value)?,
      account_identity: account_identity.value,
      prekey_bundle: prekey_bundle.value,
      mailbox_token: mailbox_token.value
    }
    validate_directory_entry(value)?
    Ok(value)
  end
end

fn validate_device_link_request(value :: DeviceLinkRequest) -> Result<(), ProtocolError> do
  if value.version != 1 && value.version != 2 do
    Err(UnsupportedVersion)
  else if (value.version == 1 && value.suite != 1) || (value.version == 2 && value.suite != 2) do
    Err(UnsupportedSuite)
  else if Bytes.length(value.nonce) != 32 || Bytes.length(value.device_id) != 16 || Bytes.length(value.signing_public_key) != 32 || Bytes.length(value.dh_public_key) != 32 do
    Err(InvalidFieldLength)
  else if (value.suite == 1 && Bytes.length(value.post_quantum_public_key) != 0) || (value.suite == 2 && Bytes.length(value.post_quantum_public_key) != 1184) do
    Err(InvalidFieldLength)
  else if U64.compare(value.created_at, value.expires_at) > 0 do
    Err(InvalidExpiration)
  else
    Ok(nil)
  end
end

pub fn encode_device_link_request(value :: DeviceLinkRequest) -> Bytes!ProtocolError do
  validate_device_link_request(value)?
  let suite = if value.version == 2 do
    protocol_write_u16(value.suite)?
  else
    Bytes.empty()
  end
  protocol_join([
      protocol_byte(value.version)?,
      Bytes.from_utf8("LNK"),
      suite,
      value.nonce,
      value.device_id,
      value.signing_public_key,
      value.dh_public_key,
      value.post_quantum_public_key,
      protocol_write_u64(value.capabilities)?,
      protocol_write_u64(value.created_at)?,
      protocol_write_u64(value.expires_at)?
    ],
    0,
    Bytes.empty())
end

pub fn decode_device_link_request(input :: Bytes) -> DeviceLinkRequest!ProtocolError do
  let version = protocol_take_u8(protocol_open(input, 1326)?)?
  if version.value != 1 && version.value != 2 do
    Err(UnsupportedVersion)
  else
    let magic = protocol_take_fixed(version.state, 3)?
    protocol_valid_magic(magic.value, "LNK")?
    let suite = if version.value == 2 do
      protocol_take_u16(magic.state)?
    else
      ProtocolReadInt {
        state: magic.state,
        value: 1
      }
    end
    let nonce = protocol_take_fixed(suite.state, 32)?
    let device_id = protocol_take_fixed(nonce.state, 16)?
    let signing_public_key = protocol_take_fixed(device_id.state, 32)?
    let dh_public_key = protocol_take_fixed(signing_public_key.state, 32)?
    let post_quantum_public_key = protocol_take_suite_fixed(dh_public_key.state, suite.value, 1184)?
    let capabilities = protocol_take_u64(post_quantum_public_key.state)?
    let created_at = protocol_take_u64(capabilities.state)?
    let expires_at = protocol_take_u64(created_at.state)?
    protocol_require_end(expires_at.state)?
    let value = DeviceLinkRequest {
      version: version.value,
      suite: suite.value,
      nonce: nonce.value,
      device_id: device_id.value,
      signing_public_key: signing_public_key.value,
      dh_public_key: dh_public_key.value,
      post_quantum_public_key: post_quantum_public_key.value,
      capabilities: capabilities.value,
      created_at: created_at.value,
      expires_at: expires_at.value
    }
    validate_device_link_request(value)?
    Ok(value)
  end
end

fn validate_device_link_authorization(value :: DeviceLinkAuthorization) -> Result<(), ProtocolError> do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    encode_username(value.username)?
    if Bytes.length(value.request_hash) != 32 || Bytes.length(value.account_identity) == 0 || Bytes.length(value.account_identity) > 16582 || Bytes.length(value.device_credential) == 0 || Bytes.length(value.device_credential) > 4096 || Bytes.length(value.authorization_signature) != 64 do
      Err(InvalidFieldLength)
    else
      Ok(nil)
    end
  end
end

pub fn encode_device_link_authorization(value :: DeviceLinkAuthorization) -> Bytes!ProtocolError do
  validate_device_link_authorization(value)?
  protocol_join([
      protocol_byte(value.version)?,
      Bytes.from_utf8("LNA"),
      value.request_hash,
      protocol_vector(encode_username(value.username)?)?,
      protocol_vector(value.account_identity)?,
      protocol_vector(value.device_credential)?,
      value.authorization_signature
    ],
    0,
    Bytes.empty())
end

pub fn decode_device_link_authorization(input :: Bytes) -> DeviceLinkAuthorization!ProtocolError do
  let version = protocol_take_u8(protocol_open(input, 20864)?)?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = protocol_take_fixed(version.state, 3)?
    protocol_valid_magic(magic.value, "LNA")?
    let request_hash = protocol_take_fixed(magic.state, 32)?
    let username = protocol_take_vector(request_hash.state, 64)?
    let account_identity = protocol_take_vector(username.state, 16582)?
    let device_credential = protocol_take_vector(account_identity.state, 4096)?
    let authorization_signature = protocol_take_fixed(device_credential.state, 64)?
    protocol_require_end(authorization_signature.state)?
    let value = DeviceLinkAuthorization {
      version: version.value,
      request_hash: request_hash.value,
      username: decode_username(username.value)?,
      account_identity: account_identity.value,
      device_credential: device_credential.value,
      authorization_signature: authorization_signature.value
    }
    validate_device_link_authorization(value)?
    Ok(value)
  end
end

fn contains_bytes(values :: List<Bytes>, target :: Bytes, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else if Bytes.secure_equals(List.get(values, index), target) do
    true
  else
    contains_bytes(values, target, index + 1)
  end
end

fn contains_mailbox(values :: List<DirectoryEntry>, target :: Bytes, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else if Bytes.secure_equals(List.get(values, index).mailbox_token, target) do
    true
  else
    contains_mailbox(values, target, index + 1)
  end
end

fn validate_device_entries(value :: DeviceSet, index :: Int) -> Result<(), ProtocolError> do
  if List.length(value.devices) == 0 || List.length(value.devices) > 8 do
    Err(InvalidFieldLength)
  else if index >= List.length(value.devices) do
    Ok(nil)
  else
    let entry = List.get(value.devices, index)
    validate_directory_entry(entry)?
    if entry.username != value.username || !Bytes.secure_equals(entry.account_identity,
      value.account_identity) do
      Err(InvalidPolicy)
    else if contains_mailbox(value.devices, entry.mailbox_token, index + 1) do
      Err(NonCanonicalEncoding)
    else
      validate_device_entries(value, index + 1)
    end
  end
end

fn validate_revoked_ids(values :: List<Bytes>, index :: Int) -> Result<(), ProtocolError> do
  if List.length(values) > 32 do
    Err(OversizedInput)
  else if index >= List.length(values) do
    Ok(nil)
  else if Bytes.length(List.get(values, index)) != 16 do
    Err(InvalidFieldLength)
  else if contains_bytes(List.drop(values, index + 1), List.get(values, index), 0) do
    Err(NonCanonicalEncoding)
  else
    validate_revoked_ids(values, index + 1)
  end
end

fn validate_device_set(value :: DeviceSet) -> Result<(), ProtocolError> do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    encode_username(value.username)?
    if Bytes.length(value.account_identity) == 0 || Bytes.length(value.account_identity) > 16582 do
      Err(InvalidFieldLength)
    else
      validate_device_entries(value, 0)?
      validate_revoked_ids(value.revoked_device_ids, 0)
    end
  end
end

fn encode_device_entries(values :: List<DirectoryEntry>, index :: Int, output :: Bytes) -> Bytes!ProtocolError do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_device_entries(values,
      index + 1,
      protocol_append(output, protocol_vector(encode_directory_entry(List.get(values, index))?)?)?)
  end
end

fn read_device_entries(state :: BinaryReader,
  count :: Int,
  index :: Int,
  output :: List<DirectoryEntry>) -> ProtocolReadDirectoryEntries!ProtocolError do
  if index >= count do
    Ok(ProtocolReadDirectoryEntries {
      state: state,
      value: output
    })
  else
    let entry = protocol_take_vector(state, 36006)?
    read_device_entries(entry.state,
      count,
      index + 1,
      List.append(output, decode_directory_entry(entry.value)?))
  end
end

fn encode_fixed_ids(values :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!ProtocolError do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_fixed_ids(values, index + 1, protocol_append(output, List.get(values, index))?)
  end
end

pub fn encode_device_set(value :: DeviceSet) -> Bytes!ProtocolError do
  validate_device_set(value)?
  let header = protocol_join([
      protocol_byte(value.version)?,
      Bytes.from_utf8("DVS"),
      protocol_vector(encode_username(value.username)?)?,
      protocol_vector(value.account_identity)?,
      protocol_write_u64(value.sequence)?,
      protocol_byte(List.length(value.devices))?
    ],
    0,
    Bytes.empty())?
  let devices = encode_device_entries(value.devices, 0, header)?
  encode_fixed_ids(value.revoked_device_ids,
    0,
    protocol_append(devices, protocol_byte(List.length(value.revoked_device_ids))?)?)
end

pub fn decode_device_set(input :: Bytes) -> DeviceSet!ProtocolError do
  let version = protocol_take_u8(protocol_open(input, 305260)?)?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = protocol_take_fixed(version.state, 3)?
    protocol_valid_magic(magic.value, "DVS")?
    let username = protocol_take_vector(magic.state, 64)?
    let account_identity = protocol_take_vector(username.state, 16582)?
    let sequence = protocol_take_u64(account_identity.state)?
    let device_count = protocol_take_u8(sequence.state)?
    if device_count.value == 0 || device_count.value > 8 do
      Err(InvalidFieldLength)
    else
      let devices = read_device_entries(device_count.state, device_count.value, 0, List.new())?
      let revoked_count = protocol_take_u8(devices.state)?
      if revoked_count.value > 32 do
        Err(OversizedInput)
      else
        let revoked = protocol_read_ack_ids(revoked_count.state, revoked_count.value, 0, List.new())?
        protocol_require_end(revoked.state)?
        let value = DeviceSet {
          version: version.value,
          username: decode_username(username.value)?,
          account_identity: account_identity.value,
          sequence: sequence.value,
          devices: devices.value,
          revoked_device_ids: revoked.value
        }
        validate_device_set(value)?
        Ok(value)
      end
    end
  end
end

fn validate_device_revocation(value :: DeviceRevocation) -> Result<(), ProtocolError> do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else if Bytes.length(value.account_id) != 32 || Bytes.length(value.device_id) != 16 || Bytes.length(value.signature) != 64 do
    Err(InvalidFieldLength)
  else
    Ok(nil)
  end
end

pub fn encode_device_revocation(value :: DeviceRevocation) -> Bytes!ProtocolError do
  validate_device_revocation(value)?
  protocol_join([
      protocol_byte(value.version)?,
      Bytes.from_utf8("DVR"),
      value.account_id,
      value.device_id,
      protocol_write_u64(value.sequence)?,
      value.signature
    ],
    0,
    Bytes.empty())
end

pub fn decode_device_revocation(input :: Bytes) -> DeviceRevocation!ProtocolError do
  let version = protocol_take_u8(protocol_open(input, 256)?)?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = protocol_take_fixed(version.state, 3)?
    protocol_valid_magic(magic.value, "DVR")?
    let account_id = protocol_take_fixed(magic.state, 32)?
    let device_id = protocol_take_fixed(account_id.state, 16)?
    let sequence = protocol_take_u64(device_id.state)?
    let signature = protocol_take_fixed(sequence.state, 64)?
    protocol_require_end(signature.state)?
    let value = DeviceRevocation {
      version: version.value,
      account_id: account_id.value,
      device_id: device_id.value,
      sequence: sequence.value,
      signature: signature.value
    }
    validate_device_revocation(value)?
    Ok(value)
  end
end

fn validate_account_deletion(value :: AccountDeletion) -> Result<(), ProtocolError> do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else if Bytes.length(value.account_id) != 32 || Bytes.length(value.signature) != 64 do
    Err(InvalidFieldLength)
  else
    Ok(nil)
  end
end

pub fn encode_account_deletion(value :: AccountDeletion) -> Bytes!ProtocolError do
  validate_account_deletion(value)?
  protocol_join([
      protocol_byte(value.version)?,
      Bytes.from_utf8("ADL"),
      value.account_id,
      protocol_write_u64(value.issued_at)?,
      value.signature
    ],
    0,
    Bytes.empty())
end

pub fn decode_account_deletion(input :: Bytes) -> AccountDeletion!ProtocolError do
  let version = protocol_take_u8(protocol_open(input, 108)?)?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = protocol_take_fixed(version.state, 3)?
    protocol_valid_magic(magic.value, "ADL")?
    let account_id = protocol_take_fixed(magic.state, 32)?
    let issued_at = protocol_take_u64(account_id.state)?
    let signature = protocol_take_fixed(issued_at.state, 64)?
    protocol_require_end(signature.state)?
    let value = AccountDeletion {
      version: version.value,
      account_id: account_id.value,
      issued_at: issued_at.value,
      signature: signature.value
    }
    validate_account_deletion(value)?
    Ok(value)
  end
end

fn validate_device_departure(value :: DeviceDeparture) -> Result<(), ProtocolError> do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else if Bytes.length(value.account_id) != 32 || Bytes.length(value.device_id) != 16 || Bytes.length(value.signature) != 64 do
    Err(InvalidFieldLength)
  else
    Ok(nil)
  end
end

pub fn encode_device_departure(value :: DeviceDeparture) -> Bytes!ProtocolError do
  validate_device_departure(value)?
  protocol_join([
      protocol_byte(value.version)?,
      Bytes.from_utf8("DPT"),
      value.account_id,
      value.device_id,
      protocol_write_u64(value.issued_at)?,
      value.signature
    ],
    0,
    Bytes.empty())
end

pub fn decode_device_departure(input :: Bytes) -> DeviceDeparture!ProtocolError do
  let version = protocol_take_u8(protocol_open(input, 124)?)?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = protocol_take_fixed(version.state, 3)?
    protocol_valid_magic(magic.value, "DPT")?
    let account_id = protocol_take_fixed(magic.state, 32)?
    let device_id = protocol_take_fixed(account_id.state, 16)?
    let issued_at = protocol_take_u64(device_id.state)?
    let signature = protocol_take_fixed(issued_at.state, 64)?
    protocol_require_end(signature.state)?
    let value = DeviceDeparture {
      version: version.value,
      account_id: account_id.value,
      device_id: device_id.value,
      issued_at: issued_at.value,
      signature: signature.value
    }
    validate_device_departure(value)?
    Ok(value)
  end
end
