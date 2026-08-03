from Binary.Reader import BinaryReader, finish, read_fixed, read_u16_be, read_u8, read_vector, reader

pub type ProtocolError do
  UnsupportedVersion

  UnsupportedSuite

  InvalidSuiteList

  DuplicateSuite

  InvalidSuiteHistory

  DowngradeDetected

  TooManyExtensions

  InvalidExtension

  UnknownMandatoryExtension

  NonCanonicalEncoding

  InvalidPolicy

  InvalidFieldLength

  InvalidPaddingBucket

  InvalidExpiration

  PostQuantumNotSupported

  OversizedInput

  MalformedEncoding
end deriving(Eq, Debug)

pub struct OuterEnvelope do
  version :: Int
  envelope_id :: Bytes
  mailbox_token :: Bytes
  suite :: Int
  expiration :: U64
  padding_bucket :: Int
  ciphertext :: Bytes
end

pub struct DeviceCredential do
  version :: Int
  suite :: Int
  account_id :: Bytes
  device_id :: Bytes
  signing_public_key :: Bytes
  dh_public_key :: Bytes
  post_quantum_public_key :: Bytes
  capabilities :: U64
  created_at :: U64
  expires_at :: U64
  directory_sequence :: U64
  signature :: Bytes
end

pub struct ProtocolExtension do
  id :: Int
  mandatory :: Bool
  value :: Bytes
end

pub struct AccountIdentity do
  version :: Int
  account_id :: Bytes
  authorization_public_key :: Bytes
  created_at :: U64
  directory_sequence :: U64
  extensions :: List < ProtocolExtension >
end

pub struct PrekeyBundle do
  version :: Int
  suite :: Int
  device_credential :: Bytes
  identity_dh_public_key :: Bytes
  signing_public_key :: Bytes
  signed_prekey_id :: U64
  signed_prekey :: Bytes
  signed_prekey_signature :: Bytes
  one_time_prekey_id :: U64
  one_time_prekey :: Bytes
  supported_suites :: List < Int >
  expires_at :: U64
  extensions :: List < ProtocolExtension >
end

pub struct InnerEnvelope do
  version :: Int
  sender_account_id :: Bytes
  sender_device_id :: Bytes
  recipient_device_id :: Bytes
  conversation_id :: Bytes
  client_message_id :: Bytes
  client_timestamp :: U64
  message_type :: Int
  body :: Bytes
  reply_reference :: Bytes
  attachment_manifest :: Bytes
  receipt_policy :: Int
  disappearing_seconds :: Int
  extensions :: List < ProtocolExtension >
end

pub struct HandshakeTranscript do
  version :: Int
  suite :: Int
  initiator_credential_hash :: Bytes
  responder_prekey_bundle_hash :: Bytes
  initiator_ephemeral_public_key :: Bytes
  signed_prekey_id :: U64
  responder_signed_prekey :: Bytes
  one_time_prekey_id :: U64
  responder_one_time_prekey :: Bytes
  extensions :: List < ProtocolExtension >
end

pub struct InitialMessage do
  version :: Int
  suite :: Int
  signed_prekey_id :: U64
  one_time_prekey_id :: U64
  initiator_credential :: Bytes
  initiator_identity_public_key :: X25519PublicKey
  initiator_ephemeral_public_key :: X25519PublicKey
  transcript_hash :: Bytes
  nonce :: Bytes
  ciphertext :: Bytes
end

pub struct DirectoryEntry do
  version :: Int
  username :: String
  account_identity :: Bytes
  prekey_bundle :: Bytes
  mailbox_token :: Bytes
end

pub struct DeviceLinkRequest do
  version :: Int
  nonce :: Bytes
  device_id :: Bytes
  signing_public_key :: Bytes
  dh_public_key :: Bytes
  capabilities :: U64
  created_at :: U64
  expires_at :: U64
end

pub struct DeviceLinkAuthorization do
  version :: Int
  request_hash :: Bytes
  username :: String
  account_identity :: Bytes
  device_credential :: Bytes
  authorization_signature :: Bytes
end

pub struct DeviceSet do
  version :: Int
  username :: String
  account_identity :: Bytes
  sequence :: U64
  devices :: List < DirectoryEntry >
  revoked_device_ids :: List < Bytes >
end

pub struct DeviceRevocation do
  version :: Int
  account_id :: Bytes
  device_id :: Bytes
  sequence :: U64
  signature :: Bytes
end

pub struct MailboxFetch do
  version :: Int
  mailbox_token :: Bytes
  after_sequence :: U64
end

pub struct DeliveredEnvelope do
  sequence :: U64
  envelope :: Bytes
end

pub struct MailboxAck do
  version :: Int
  mailbox_token :: Bytes
  envelope_ids :: List < Bytes >
end

struct ReadInt do
  state :: BinaryReader
  value :: Int
end

struct ReadWide do
  state :: BinaryReader
  value :: U64
end

struct ReadBytes do
  state :: BinaryReader
  value :: Bytes
end

struct ReadExtensions do
  state :: BinaryReader
  value :: List < ProtocolExtension >
end

struct ReadSuites do
  state :: BinaryReader
  value :: List < Int >
end

struct ReadDeliveries do
  state :: BinaryReader
  value :: List < DeliveredEnvelope >
end

struct ReadIds do
  state :: BinaryReader
  value :: List < Bytes >
end

struct ReadDirectoryEntries do
  state :: BinaryReader
  value :: List < DirectoryEntry >
end

fn contains_suite(values :: List < Int >, target :: Int, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else
    List.get(values, index) == target || contains_suite(values, target, index + 1)
  end
end

fn validate_suite_list(values :: List < Int >, index :: Int) -> Result <(), ProtocolError > do
  if List.length(values) == 0 || List.length(values) > 8 do
    Err(InvalidSuiteList)
  else
    if index >= List.length(values) do
      Ok(nil)
    else
      let suite = List.get(values, index)
      if contains_suite(values, suite, index + 1) do
        Err(DuplicateSuite)
      else
        if suite != 1 do
          Err(UnsupportedSuite)
        else
          validate_suite_list(values, index + 1)
        end
      end
    end
  end
end

fn encode_suite_entries(values :: List < Int >, index :: Int, output :: Bytes) -> Bytes ! ProtocolError do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_suite_entries(values, index + 1, append(output, write_u16(List.get(values, index)) ?) ?)
  end
end

fn encode_suites(values :: List < Int >) -> Bytes ! ProtocolError do
  validate_suite_list(values, 0) ?
  join([byte(List.length(values)) ?, encode_suite_entries(values, 0, Bytes.empty()) ?],
  0,
  Bytes.empty())
end

fn read_suite_entries(state :: BinaryReader, count :: Int, index :: Int, output :: List < Int >) -> ReadSuites ! ProtocolError do
  if index >= count do
    validate_suite_list(output, 0) ?
    Ok(ReadSuites {
      state : state,
      value : output
    })
  else
    let suite = take_u16(state) ?
    read_suite_entries(suite.state, count, index + 1, List.append(output, suite.value))
  end
end

fn take_suites(state :: BinaryReader) -> ReadSuites ! ProtocolError do
  let count = take_u8(state) ?
  if count.value == 0 || count.value > 8 do
    Err(InvalidSuiteList)
  else
    read_suite_entries(count.state, count.value, 0, List.new())
  end
end

fn validate_extensions(values :: List < ProtocolExtension >, index :: Int, previous_id :: Int) -> Result <(), ProtocolError > do
  if List.length(values) > 16 do
    Err(TooManyExtensions)
  else
    if index >= List.length(values) do
      Ok(nil)
    else
      let extension = List.get(values, index)
      if extension.id <= previous_id || extension.id > 65535 do
        Err(NonCanonicalEncoding)
      else
        if extension.mandatory do
          Err(UnknownMandatoryExtension)
        else
          if Bytes.length(extension.value) > 1024 do
            Err(InvalidExtension)
          else
            validate_extensions(values, index + 1, extension.id)
          end
        end
      end
    end
  end
end

fn encode_extension_entries(values :: List < ProtocolExtension >, index :: Int, output :: Bytes) -> Bytes ! ProtocolError do
  if index >= List.length(values) do
    Ok(output)
  else
    let extension = List.get(values, index)
    let encoded = join([write_u16(extension.id) ?, byte(0) ?, vector(extension.value) ?],
    0,
    Bytes.empty()) ?
    encode_extension_entries(values, index + 1, append(output, encoded) ?)
  end
end

fn encode_extensions(values :: List < ProtocolExtension >) -> Bytes ! ProtocolError do
  validate_extensions(values, 0, 0) ?
  join([write_u16(List.length(values)) ?, encode_extension_entries(values, 0, Bytes.empty()) ?],
  0,
  Bytes.empty())
end

fn read_extension_entries(state :: BinaryReader,
count :: Int,
index :: Int,
previous_id :: Int,
output :: List < ProtocolExtension >) -> ReadExtensions ! ProtocolError do
  if index >= count do
    Ok(ReadExtensions {
      state : state,
      value : output
    })
  else
    let id = take_u16(state) ?
    let flag = take_u8(id.state) ?
    if id.value <= previous_id do
      Err(NonCanonicalEncoding)
    else
      if flag.value == 1 do
        Err(UnknownMandatoryExtension)
      else
        if flag.value != 0 do
          Err(InvalidExtension)
        else
          let value = take_vector(flag.state, 1024) ?
          read_extension_entries(value.state,
          count,
          index + 1,
          id.value,
          List.append(output,
          ProtocolExtension {
            id : id.value,
            mandatory : false,
            value : value.value
          }))
        end
      end
    end
  end
end

fn take_extensions(state :: BinaryReader) -> ReadExtensions ! ProtocolError do
  let count = take_u16(state) ?
  if count.value > 16 do
    Err(TooManyExtensions)
  else
    read_extension_entries(count.state, count.value, 0, 0, List.new())
  end
end

pub fn negotiate_profile_a(local_suites :: List < Int >,
remote_suites :: List < Int >,
strongest_authenticated_suite :: Int) -> Int ! ProtocolError do
  validate_suite_list(local_suites, 0) ?
  validate_suite_list(remote_suites, 0) ?
  if strongest_authenticated_suite < 0 do
    Err(InvalidSuiteHistory)
  else
    if strongest_authenticated_suite > 1 do
      Err(DowngradeDetected)
    else
      Ok(1)
    end
  end
end

fn validate_account(value :: AccountIdentity) -> Result <(), ProtocolError > do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    if Bytes.length(value.account_id) != 32 || Bytes.length(value.authorization_public_key) != 32 do
      Err(InvalidFieldLength)
    else
      validate_extensions(value.extensions, 0, 0)
    end
  end
end

pub fn encode_account_identity(value :: AccountIdentity) -> Bytes ! ProtocolError do
  validate_account(value) ?
  join([byte(value.version) ?, Bytes.from_utf8("ACT"), value.account_id, value.authorization_public_key, write_u64(value.created_at) ?, write_u64(value.directory_sequence) ?, encode_extensions(value.extensions) ?],
  0,
  Bytes.empty())
end

pub fn decode_account_identity(input :: Bytes) -> AccountIdentity ! ProtocolError do
  let version = take_u8(open(input, 16582) ?) ?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = take_fixed(version.state, 3) ?
    if !Bytes.secure_equals(magic.value, Bytes.from_utf8("ACT")) do
      Err(MalformedEncoding)
    else
      let account_id = take_fixed(magic.state, 32) ?
      let authorization_public_key = take_fixed(account_id.state, 32) ?
      let created_at = take_u64(authorization_public_key.state) ?
      let directory_sequence = take_u64(created_at.state) ?
      let extensions = take_extensions(directory_sequence.state) ?
      require_end(extensions.state) ?
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

fn is_zero(value :: U64) -> Bool do
  case U64.to_int(value) do
    Err( _) -> false
    Ok( number) -> number == 0
  end
end

fn validate_prekey_bundle(value :: PrekeyBundle) -> Result <(), ProtocolError > do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    if value.suite != 1 do
      Err(UnsupportedSuite)
    else
      if Bytes.length(value.device_credential) != 211 || Bytes.length(value.identity_dh_public_key) != 32 || Bytes.length(value.signing_public_key) != 32 || Bytes.length(value.signed_prekey) != 32 || Bytes.length(value.signed_prekey_signature) != 64 do
        Err(InvalidFieldLength)
      else
        if is_zero(value.signed_prekey_id) || !(Bytes.length(value.one_time_prekey) == 0 || Bytes.length(value.one_time_prekey) == 32) do
          Err(InvalidFieldLength)
        else
          if (Bytes.length(value.one_time_prekey) == 0 && !is_zero(value.one_time_prekey_id)) || (Bytes.length(value.one_time_prekey) == 32 && is_zero(value.one_time_prekey_id)) do
            Err(InvalidFieldLength)
          else
            validate_suite_list(value.supported_suites, 0) ?
            if !contains_suite(value.supported_suites, value.suite, 0) do
              Err(UnsupportedSuite)
            else
              case decode_device_credential(value.device_credential) do
                Err( _) -> Err(MalformedEncoding)
                Ok( credential) -> if credential.suite != value.suite || !Bytes.secure_equals(credential.signing_public_key,
                value.signing_public_key) || !Bytes.secure_equals(credential.dh_public_key,
                value.identity_dh_public_key) do
                  Err(MalformedEncoding)
                else
                  validate_extensions(value.extensions, 0, 0)
                end
              end
            end
          end
        end
      end
    end
  end
end

pub fn encode_prekey_bundle(value :: PrekeyBundle) -> Bytes ! ProtocolError do
  validate_prekey_bundle(value) ?
  join([byte(value.version) ?, Bytes.from_utf8("PKB"), write_u16(value.suite) ?, vector(value.device_credential) ?, value.identity_dh_public_key, value.signing_public_key, write_u64(value.signed_prekey_id) ?, value.signed_prekey, value.signed_prekey_signature, write_u64(value.one_time_prekey_id) ?, vector(value.one_time_prekey) ?, encode_suites(value.supported_suites) ?, write_u64(value.expires_at) ?, encode_extensions(value.extensions) ?],
  0,
  Bytes.empty())
end

pub fn decode_prekey_bundle(input :: Bytes) -> PrekeyBundle ! ProtocolError do
  let version = take_u8(open(input, 16942) ?) ?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = take_fixed(version.state, 3) ?
    if !Bytes.secure_equals(magic.value, Bytes.from_utf8("PKB")) do
      Err(MalformedEncoding)
    else
      let suite = take_u16(magic.state) ?
      let device_credential = take_vector(suite.state, 4096) ?
      let identity_dh_public_key = take_fixed(device_credential.state, 32) ?
      let signing_public_key = take_fixed(identity_dh_public_key.state, 32) ?
      let signed_prekey_id = take_u64(signing_public_key.state) ?
      let signed_prekey = take_fixed(signed_prekey_id.state, 32) ?
      let signed_prekey_signature = take_fixed(signed_prekey.state, 64) ?
      let one_time_prekey_id = take_u64(signed_prekey_signature.state) ?
      let one_time_prekey = take_vector(one_time_prekey_id.state, 32) ?
      let supported_suites = take_suites(one_time_prekey.state) ?
      let expires_at = take_u64(supported_suites.state) ?
      let extensions = take_extensions(expires_at.state) ?
      require_end(extensions.state) ?
      let value = PrekeyBundle {
        version : version.value,
        suite : suite.value,
        device_credential : device_credential.value,
        identity_dh_public_key : identity_dh_public_key.value,
        signing_public_key : signing_public_key.value,
        signed_prekey_id : signed_prekey_id.value,
        signed_prekey : signed_prekey.value,
        signed_prekey_signature : signed_prekey_signature.value,
        one_time_prekey_id : one_time_prekey_id.value,
        one_time_prekey : one_time_prekey.value,
        supported_suites : supported_suites.value,
        expires_at : expires_at.value,
        extensions : extensions.value
      }
      validate_prekey_bundle(value) ?
      Ok(value)
    end
  end
end

fn validate_inner_envelope(value :: InnerEnvelope) -> Result <(), ProtocolError > do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    if Bytes.length(value.sender_account_id) != 32 || Bytes.length(value.sender_device_id) != 16 || Bytes.length(value.recipient_device_id) != 16 || Bytes.length(value.conversation_id) != 16 || Bytes.length(value.client_message_id) != 16 || !(Bytes.length(value.reply_reference) == 0 || Bytes.length(value.reply_reference) == 16) do
      Err(InvalidFieldLength)
    else
      if Bytes.length(value.body) > 32768 || Bytes.length(value.attachment_manifest) > 16384 do
        Err(OversizedInput)
      else
        if value.message_type <= 0 || value.message_type > 65535 || value.receipt_policy < 0 || value.receipt_policy > 2 || value.disappearing_seconds < 0 || value.disappearing_seconds > 4294967295 do
          Err(InvalidPolicy)
        else
          validate_extensions(value.extensions, 0, 0)
        end
      end
    end
  end
end

pub fn encode_inner_envelope(value :: InnerEnvelope) -> Bytes ! ProtocolError do
  validate_inner_envelope(value) ?
  let encoded = join([byte(value.version) ?, Bytes.from_utf8("PAY"), value.sender_account_id, value.sender_device_id, value.recipient_device_id, value.conversation_id, value.client_message_id, write_u64(value.client_timestamp) ?, write_u16(value.message_type) ?, vector(value.body) ?, vector(value.reply_reference) ?, vector(value.attachment_manifest) ?, byte(value.receipt_policy) ?, write_length(value.disappearing_seconds) ?, encode_extensions(value.extensions) ?],
  0,
  Bytes.empty()) ?
  if Bytes.length(encoded) > 65536 do
    Err(OversizedInput)
  else
    Ok(encoded)
  end
end

pub fn decode_inner_envelope(input :: Bytes) -> InnerEnvelope ! ProtocolError do
  let version = take_u8(open(input, 65536) ?) ?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = take_fixed(version.state, 3) ?
    if !Bytes.secure_equals(magic.value, Bytes.from_utf8("PAY")) do
      Err(MalformedEncoding)
    else
      let sender_account_id = take_fixed(magic.state, 32) ?
      let sender_device_id = take_fixed(sender_account_id.state, 16) ?
      let recipient_device_id = take_fixed(sender_device_id.state, 16) ?
      let conversation_id = take_fixed(recipient_device_id.state, 16) ?
      let client_message_id = take_fixed(conversation_id.state, 16) ?
      let client_timestamp = take_u64(client_message_id.state) ?
      let message_type = take_u16(client_timestamp.state) ?
      let body = take_vector(message_type.state, 32768) ?
      let reply_reference = take_vector(body.state, 16) ?
      let attachment_manifest = take_vector(reply_reference.state, 16384) ?
      let receipt_policy = take_u8(attachment_manifest.state) ?
      let disappearing_seconds = take_u32(receipt_policy.state) ?
      let extensions = take_extensions(disappearing_seconds.state) ?
      require_end(extensions.state) ?
      let value = InnerEnvelope {
        version : version.value,
        sender_account_id : sender_account_id.value,
        sender_device_id : sender_device_id.value,
        recipient_device_id : recipient_device_id.value,
        conversation_id : conversation_id.value,
        client_message_id : client_message_id.value,
        client_timestamp : client_timestamp.value,
        message_type : message_type.value,
        body : body.value,
        reply_reference : reply_reference.value,
        attachment_manifest : attachment_manifest.value,
        receipt_policy : receipt_policy.value,
        disappearing_seconds : as_int(disappearing_seconds.value) ?,
        extensions : extensions.value
      }
      validate_inner_envelope(value) ?
      Ok(value)
    end
  end
end

fn validate_handshake_transcript(value :: HandshakeTranscript) -> Result <(), ProtocolError > do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    if value.suite != 1 do
      Err(UnsupportedSuite)
    else
      if Bytes.length(value.initiator_credential_hash) != 32 || Bytes.length(value.responder_prekey_bundle_hash) != 32 || Bytes.length(value.initiator_ephemeral_public_key) != 32 || Bytes.length(value.responder_signed_prekey) != 32 || is_zero(value.signed_prekey_id) || !(Bytes.length(value.responder_one_time_prekey) == 0 || Bytes.length(value.responder_one_time_prekey) == 32) do
        Err(InvalidFieldLength)
      else
        if (Bytes.length(value.responder_one_time_prekey) == 0 && !is_zero(value.one_time_prekey_id)) || (Bytes.length(value.responder_one_time_prekey) == 32 && is_zero(value.one_time_prekey_id)) do
          Err(InvalidFieldLength)
        else
          validate_extensions(value.extensions, 0, 0)
        end
      end
    end
  end
end

pub fn encode_handshake_transcript(value :: HandshakeTranscript) -> Bytes ! ProtocolError do
  validate_handshake_transcript(value) ?
  join([byte(value.version) ?, Bytes.from_utf8("HST"), write_u16(value.suite) ?, value.initiator_credential_hash, value.responder_prekey_bundle_hash, value.initiator_ephemeral_public_key, write_u64(value.signed_prekey_id) ?, value.responder_signed_prekey, write_u64(value.one_time_prekey_id) ?, vector(value.responder_one_time_prekey) ?, encode_extensions(value.extensions) ?],
  0,
  Bytes.empty())
end

pub fn decode_handshake_transcript(input :: Bytes) -> HandshakeTranscript ! ProtocolError do
  let version = take_u8(open(input, 16684) ?) ?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = take_fixed(version.state, 3) ?
    if !Bytes.secure_equals(magic.value, Bytes.from_utf8("HST")) do
      Err(MalformedEncoding)
    else
      let suite = take_u16(magic.state) ?
      let initiator_credential_hash = take_fixed(suite.state, 32) ?
      let responder_prekey_bundle_hash = take_fixed(initiator_credential_hash.state, 32) ?
      let initiator_ephemeral_public_key = take_fixed(responder_prekey_bundle_hash.state, 32) ?
      let signed_prekey_id = take_u64(initiator_ephemeral_public_key.state) ?
      let responder_signed_prekey = take_fixed(signed_prekey_id.state, 32) ?
      let one_time_prekey_id = take_u64(responder_signed_prekey.state) ?
      let responder_one_time_prekey = take_vector(one_time_prekey_id.state, 32) ?
      let extensions = take_extensions(responder_one_time_prekey.state) ?
      require_end(extensions.state) ?
      let value = HandshakeTranscript {
        version : version.value,
        suite : suite.value,
        initiator_credential_hash : initiator_credential_hash.value,
        responder_prekey_bundle_hash : responder_prekey_bundle_hash.value,
        initiator_ephemeral_public_key : initiator_ephemeral_public_key.value,
        signed_prekey_id : signed_prekey_id.value,
        responder_signed_prekey : responder_signed_prekey.value,
        one_time_prekey_id : one_time_prekey_id.value,
        responder_one_time_prekey : responder_one_time_prekey.value,
        extensions : extensions.value
      }
      validate_handshake_transcript(value) ?
      Ok(value)
    end
  end
end

pub fn hash_handshake_transcript(value :: HandshakeTranscript) -> Bytes ! ProtocolError do
  let encoded = encode_handshake_transcript(value) ?
  Ok(Crypto.sha256(append(Bytes.from_utf8("mesh-msg/v1/handshake"), encoded) ?))
end

fn append(output :: Bytes, value :: Bytes) -> Bytes ! ProtocolError do
  case Bytes.concat(output, value) do
    Err( _) -> Err(OversizedInput)
    Ok( bytes) -> Ok(bytes)
  end
end

fn join(parts :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! ProtocolError do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, append(output, List.get(parts, index)) ?)
  end
end

fn write_builder_parts(builder :: borrow BytesBuilder, parts :: List < Bytes >, index :: Int) -> Result <(), ProtocolError > do
  if index >= List.length(parts) do
    Ok(nil)
  else
    case BytesBuilder.write_bytes(builder, List.get(parts, index)) do
      Err( _) -> Err(OversizedInput)
      Ok( _) -> write_builder_parts(builder, parts, index + 1)
    end
  end
end

fn byte(value :: Int) -> Bytes ! ProtocolError do
  case Bytes.from_list([value]) do
    Err( _) -> Err(MalformedEncoding)
    Ok( bytes) -> Ok(bytes)
  end
end

fn write_u16(value :: Int) -> Bytes ! ProtocolError do
  case Bytes.write_u16_be(value) do
    Err( _) -> Err(MalformedEncoding)
    Ok( bytes) -> Ok(bytes)
  end
end

fn write_u32(value :: U64) -> Bytes ! ProtocolError do
  case Bytes.write_u32_be(value) do
    Err( _) -> Err(MalformedEncoding)
    Ok( bytes) -> Ok(bytes)
  end
end

fn write_length(value :: Int) -> Bytes ! ProtocolError do
  case value
    |> Int.to_string()
    |> U64.parse() do
    Err( _) -> Err(MalformedEncoding)
    Ok( parsed) -> write_u32(parsed)
  end
end

fn write_u64(value :: U64) -> Bytes ! ProtocolError do
  case Bytes.write_u64_be(value) do
    Err( _) -> Err(MalformedEncoding)
    Ok( bytes) -> Ok(bytes)
  end
end

fn vector(value :: Bytes) -> Bytes ! ProtocolError do
  join([write_length(Bytes.length(value)) ?, value], 0, Bytes.empty())
end

fn open(input :: Bytes, maximum :: Int) -> BinaryReader ! ProtocolError do
  if Bytes.length(input) > maximum do
    Err(OversizedInput)
  else
    case reader(input, maximum) do
      Err( _) -> Err(MalformedEncoding)
      Ok( state) -> Ok(state)
    end
  end
end

fn take_u8(state :: BinaryReader) -> ReadInt ! ProtocolError do
  case read_u8(state) do
    Err( _) -> Err(MalformedEncoding)
    Ok( ( next, value)) -> Ok(ReadInt {
      state : next,
      value : value
    })
    Ok( _) -> Err(MalformedEncoding)
  end
end

fn take_u16(state :: BinaryReader) -> ReadInt ! ProtocolError do
  case read_u16_be(state) do
    Err( _) -> Err(MalformedEncoding)
    Ok( ( next, value)) -> Ok(ReadInt {
      state : next,
      value : value
    })
    Ok( _) -> Err(MalformedEncoding)
  end
end

fn take_fixed(state :: BinaryReader, length :: Int) -> ReadBytes ! ProtocolError do
  case read_fixed(state, length) do
    Err( _) -> Err(MalformedEncoding)
    Ok( ( next, value)) -> Ok(ReadBytes {
      state : next,
      value : value
    })
    Ok( _) -> Err(MalformedEncoding)
  end
end

fn take_vector(state :: BinaryReader, maximum :: Int) -> ReadBytes ! ProtocolError do
  case read_vector(state, maximum) do
    Err( _) -> Err(MalformedEncoding)
    Ok( ( next, value)) -> Ok(ReadBytes {
      state : next,
      value : value
    })
    Ok( _) -> Err(MalformedEncoding)
  end
end

fn take_u32(state :: BinaryReader) -> ReadWide ! ProtocolError do
  let bytes = take_fixed(state, 4) ?
  case Bytes.read_u32_be(bytes.value, 0) do
    Err( _) -> Err(MalformedEncoding)
    Ok( value) -> Ok(ReadWide {
      state : bytes.state,
      value : value
    })
  end
end

fn take_u64(state :: BinaryReader) -> ReadWide ! ProtocolError do
  let bytes = take_fixed(state, 8) ?
  case Bytes.read_u64_be(bytes.value, 0) do
    Err( _) -> Err(MalformedEncoding)
    Ok( value) -> Ok(ReadWide {
      state : bytes.state,
      value : value
    })
  end
end

fn as_int(value :: U64) -> Int ! ProtocolError do
  case U64.to_int(value) do
    Err( _) -> Err(MalformedEncoding)
    Ok( result) -> Ok(result)
  end
end

fn require_end(state :: BinaryReader) -> Result <(), ProtocolError > do
  case finish(state) do
    Err( _) -> Err(MalformedEncoding)
    Ok( _) -> Ok(nil)
  end
end

fn supported_bucket(value :: Int) -> Bool do
  value == 256 || value == 512 || value == 1024 || value == 2048 || value == 4096 || value == 8192 || value == 16384 || value == 32768 || value == 65536
end

fn validate_outer(value :: OuterEnvelope) -> Result <(), ProtocolError > do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    if value.suite != 1 do
      Err(UnsupportedSuite)
    else
      if Bytes.length(value.envelope_id) != 16 || Bytes.length(value.mailbox_token) != 32 do
        Err(InvalidFieldLength)
      else
        if !supported_bucket(value.padding_bucket) || Bytes.length(value.ciphertext) > value.padding_bucket do
          Err(InvalidPaddingBucket)
        else
          Ok(nil)
        end
      end
    end
  end
end

pub fn encode_outer_envelope(value :: OuterEnvelope) -> Bytes ! ProtocolError do
  validate_outer(value) ?
  join([byte(value.version) ?, Bytes.from_utf8("MSG"), value.envelope_id, value.mailbox_token, write_u16(value.suite) ?, write_u64(value.expiration) ?, write_length(value.padding_bucket) ?, vector(value.ciphertext) ?],
  0,
  Bytes.empty())
end

pub fn decode_outer_envelope(input :: Bytes) -> OuterEnvelope ! ProtocolError do
  let version = take_u8(open(input, 65606) ?) ?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = take_fixed(version.state, 3) ?
    if !Bytes.secure_equals(magic.value, Bytes.from_utf8("MSG")) do
      Err(MalformedEncoding)
    else
      let envelope_id = take_fixed(magic.state, 16) ?
      let mailbox_token = take_fixed(envelope_id.state, 32) ?
      let suite = take_u16(mailbox_token.state) ?
      let expiration = take_u64(suite.state) ?
      let padding = take_u32(expiration.state) ?
      let padding_bucket = as_int(padding.value) ?
      let ciphertext = take_vector(padding.state, 65536) ?
      require_end(ciphertext.state) ?
      let value = OuterEnvelope {
        version : version.value,
        envelope_id : envelope_id.value,
        mailbox_token : mailbox_token.value,
        suite : suite.value,
        expiration : expiration.value,
        padding_bucket : padding_bucket,
        ciphertext : ciphertext.value
      }
      validate_outer(value) ?
      Ok(value)
    end
  end
end

fn validate_initial_message(value :: InitialMessage) -> Result <(), ProtocolError > do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    if value.suite != 1 do
      Err(UnsupportedSuite)
    else
      let invalid_lengths = Bytes.length(value.initiator_credential) != 211 || Bytes.length(value.initiator_identity_public_key.bytes) != 32 || Bytes.length(value.initiator_ephemeral_public_key.bytes) != 32 || Bytes.length(value.transcript_hash) != 32 || Bytes.length(value.nonce) != 12
      if invalid_lengths || is_zero(value.signed_prekey_id) || is_zero(value.one_time_prekey_id) do
        Err(InvalidFieldLength)
      else
        if Bytes.length(value.ciphertext) < 16 do
          Err(InvalidFieldLength)
        else
          if Bytes.length(value.ciphertext) > 65187 do
            Err(OversizedInput)
          else
            case decode_device_credential(value.initiator_credential) do
              Err( _) -> Err(MalformedEncoding)
              Ok( _) -> Ok(nil)
            end
          end
        end
      end
    end
  end
end

pub fn encode_initial_message(value :: InitialMessage) -> Bytes ! ProtocolError do
  validate_initial_message(value) ?
  let parts = [byte(value.version) ?, Bytes.from_utf8("INI"), write_u16(value.suite) ?, write_u64(value.signed_prekey_id) ?, write_u64(value.one_time_prekey_id) ?, vector(value.initiator_credential) ?, value.initiator_identity_public_key.bytes, value.initiator_ephemeral_public_key.bytes, value.transcript_hash, value.nonce, vector(value.ciphertext) ?]
  let builder = case BytesBuilder.new(65536) do
    Err( _) -> Err(OversizedInput)
    Ok( value) -> Ok(value)
  end ?
  write_builder_parts(builder, parts, 0) ?
  case BytesBuilder.finish(builder) do
    Err( _) -> Err(OversizedInput)
    Ok( encoded) -> Ok(encoded)
  end
end

pub fn decode_initial_message(input :: Bytes) -> InitialMessage ! ProtocolError do
  let version = take_u8(open(input, 65536) ?) ?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = take_fixed(version.state, 3) ?
    if !Bytes.secure_equals(magic.value, Bytes.from_utf8("INI")) do
      Err(MalformedEncoding)
    else
      let suite = take_u16(magic.state) ?
      let signed_prekey_id = take_u64(suite.state) ?
      let one_time_prekey_id = take_u64(signed_prekey_id.state) ?
      let initiator_credential = take_vector(one_time_prekey_id.state, 211) ?
      let initiator_identity_public_key = take_fixed(initiator_credential.state, 32) ?
      let initiator_ephemeral_public_key = take_fixed(initiator_identity_public_key.state, 32) ?
      let transcript_hash = take_fixed(initiator_ephemeral_public_key.state, 32) ?
      let nonce = take_fixed(transcript_hash.state, 12) ?
      let ciphertext = take_vector(nonce.state, 65187) ?
      require_end(ciphertext.state) ?
      let value = InitialMessage {
        version : version.value,
        suite : suite.value,
        signed_prekey_id : signed_prekey_id.value,
        one_time_prekey_id : one_time_prekey_id.value,
        initiator_credential : initiator_credential.value,
        initiator_identity_public_key : X25519PublicKey { bytes : initiator_identity_public_key.value },
        initiator_ephemeral_public_key : X25519PublicKey { bytes : initiator_ephemeral_public_key.value },
        transcript_hash : transcript_hash.value,
        nonce : nonce.value,
        ciphertext : ciphertext.value
      }
      validate_initial_message(value) ?
      Ok(value)
    end
  end
end

fn validate_credential(value :: DeviceCredential) -> Result <(), ProtocolError > do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    if value.suite != 1 do
      Err(UnsupportedSuite)
    else
      if Bytes.length(value.account_id) != 32 || Bytes.length(value.device_id) != 16 || Bytes.length(value.signing_public_key) != 32 || Bytes.length(value.dh_public_key) != 32 || Bytes.length(value.signature) != 64 do
        Err(InvalidFieldLength)
      else
        if Bytes.length(value.post_quantum_public_key) != 0 do
          Err(PostQuantumNotSupported)
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
  join([byte(value.version) ?, write_u16(value.suite) ?, value.account_id, value.device_id, value.signing_public_key, value.dh_public_key, vector(value.post_quantum_public_key) ?, write_u32(value.capabilities) ?, write_u64(value.created_at) ?, write_u64(value.expires_at) ?, write_u64(value.directory_sequence) ?, value.signature],
  0,
  Bytes.empty())
end

pub fn decode_device_credential(input :: Bytes) -> DeviceCredential ! ProtocolError do
  let version = take_u8(open(input, 4307) ?) ?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let suite = take_u16(version.state) ?
    let account_id = take_fixed(suite.state, 32) ?
    let device_id = take_fixed(account_id.state, 16) ?
    let signing_public_key = take_fixed(device_id.state, 32) ?
    let dh_public_key = take_fixed(signing_public_key.state, 32) ?
    let post_quantum_public_key = take_vector(dh_public_key.state, 4096) ?
    let capabilities = take_u32(post_quantum_public_key.state) ?
    let created_at = take_u64(capabilities.state) ?
    let expires_at = take_u64(created_at.state) ?
    let directory_sequence = take_u64(expires_at.state) ?
    let signature = take_fixed(directory_sequence.state, 64) ?
    require_end(signature.state) ?
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

fn valid_username_byte(value :: Int) -> Bool do
  (value >= 97 && value <= 122) || (value >= 48 && value <= 57) || value == 45 || value == 46 || value == 95
end

fn validate_username_bytes(value :: Bytes, index :: Int) -> Result <(), ProtocolError > do
  if index >= Bytes.length(value) do
    Ok(nil)
  else
    case Bytes.get(value, index) do
      Err( _) -> Err(MalformedEncoding)
      Ok( next) -> if valid_username_byte(next) do
        validate_username_bytes(value, index + 1)
      else
        Err(InvalidFieldLength)
      end
    end
  end
end

fn encode_username(value :: String) -> Bytes ! ProtocolError do
  let encoded = Bytes.from_utf8(value)
  if Bytes.length(encoded) == 0 || Bytes.length(encoded) > 64 do
    Err(InvalidFieldLength)
  else
    validate_username_bytes(encoded, 0) ?
    Ok(encoded)
  end
end

fn decode_username(value :: Bytes) -> String ! ProtocolError do
  if Bytes.length(value) == 0 || Bytes.length(value) > 64 do
    Err(InvalidFieldLength)
  else
    validate_username_bytes(value, 0) ?
    case Bytes.to_utf8(value) do
      Err( _) -> Err(MalformedEncoding)
      Ok( decoded) -> Ok(decoded)
    end
  end
end

fn valid_magic(value :: Bytes, expected :: String) -> Result <(), ProtocolError > do
  if Bytes.secure_equals(value, Bytes.from_utf8(expected)) do
    Ok(nil)
  else
    Err(MalformedEncoding)
  end
end

pub fn encode_directory_lookup(username :: String) -> Bytes ! ProtocolError do
  join([byte(1) ?, Bytes.from_utf8("DLK"), vector(encode_username(username) ?) ?], 0, Bytes.empty())
end

pub fn decode_directory_lookup(input :: Bytes) -> String ! ProtocolError do
  let version = take_u8(open(input, 72) ?) ?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = take_fixed(version.state, 3) ?
    valid_magic(magic.value, "DLK") ?
    let username = take_vector(magic.state, 64) ?
    require_end(username.state) ?
    decode_username(username.value)
  end
end

fn validate_directory_entry(value :: DirectoryEntry) -> Result <(), ProtocolError > do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    let _ = encode_username(value.username) ?
    if Bytes.length(value.account_identity) == 0 || Bytes.length(value.account_identity) > 16582 || Bytes.length(value.prekey_bundle) == 0 || Bytes.length(value.prekey_bundle) > 16942 || Bytes.length(value.mailbox_token) != 32 do
      Err(InvalidFieldLength)
    else
      Ok(nil)
    end
  end
end

pub fn encode_directory_entry(value :: DirectoryEntry) -> Bytes ! ProtocolError do
  validate_directory_entry(value) ?
  join([byte(value.version) ?, Bytes.from_utf8("DRE"), vector(encode_username(value.username) ?) ?, vector(value.account_identity) ?, vector(value.prekey_bundle) ?, value.mailbox_token],
  0,
  Bytes.empty())
end

pub fn decode_directory_entry(input :: Bytes) -> DirectoryEntry ! ProtocolError do
  let version = take_u8(open(input, 33636) ?) ?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = take_fixed(version.state, 3) ?
    valid_magic(magic.value, "DRE") ?
    let username = take_vector(magic.state, 64) ?
    let account_identity = take_vector(username.state, 16582) ?
    let prekey_bundle = take_vector(account_identity.state, 16942) ?
    let mailbox_token = take_fixed(prekey_bundle.state, 32) ?
    require_end(mailbox_token.state) ?
    let value = DirectoryEntry {
      version : version.value,
      username : decode_username(username.value) ?,
      account_identity : account_identity.value,
      prekey_bundle : prekey_bundle.value,
      mailbox_token : mailbox_token.value
    }
    validate_directory_entry(value) ?
    Ok(value)
  end
end

fn validate_device_link_request(value :: DeviceLinkRequest) -> Result <(), ProtocolError > do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else if Bytes.length(value.nonce) != 32 || Bytes.length(value.device_id) != 16 || Bytes.length(value.signing_public_key) != 32 || Bytes.length(value.dh_public_key) != 32 do
    Err(InvalidFieldLength)
  else if U64.compare(value.created_at, value.expires_at) > 0 do
    Err(InvalidExpiration)
  else
    Ok(nil)
  end
end

pub fn encode_device_link_request(value :: DeviceLinkRequest) -> Bytes ! ProtocolError do
  validate_device_link_request(value) ?
  join([byte(value.version) ?, Bytes.from_utf8("LNK"), value.nonce, value.device_id, value.signing_public_key, value.dh_public_key, write_u64(value.capabilities) ?, write_u64(value.created_at) ?, write_u64(value.expires_at) ?],
  0,
  Bytes.empty())
end

pub fn decode_device_link_request(input :: Bytes) -> DeviceLinkRequest ! ProtocolError do
  let version = take_u8(open(input, 140) ?) ?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = take_fixed(version.state, 3) ?
    valid_magic(magic.value, "LNK") ?
    let nonce = take_fixed(magic.state, 32) ?
    let device_id = take_fixed(nonce.state, 16) ?
    let signing_public_key = take_fixed(device_id.state, 32) ?
    let dh_public_key = take_fixed(signing_public_key.state, 32) ?
    let capabilities = take_u64(dh_public_key.state) ?
    let created_at = take_u64(capabilities.state) ?
    let expires_at = take_u64(created_at.state) ?
    require_end(expires_at.state) ?
    let value = DeviceLinkRequest {
      version : version.value,
      nonce : nonce.value,
      device_id : device_id.value,
      signing_public_key : signing_public_key.value,
      dh_public_key : dh_public_key.value,
      capabilities : capabilities.value,
      created_at : created_at.value,
      expires_at : expires_at.value
    }
    validate_device_link_request(value) ?
    Ok(value)
  end
end

fn validate_device_link_authorization(value :: DeviceLinkAuthorization) -> Result <(), ProtocolError > do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    let _ = encode_username(value.username) ?
    if Bytes.length(value.request_hash) != 32 || Bytes.length(value.account_identity) == 0 || Bytes.length(value.account_identity) > 16582 || Bytes.length(value.device_credential) == 0 || Bytes.length(value.device_credential) > 4096 || Bytes.length(value.authorization_signature) != 64 do
      Err(InvalidFieldLength)
    else
      Ok(nil)
    end
  end
end

pub fn encode_device_link_authorization(value :: DeviceLinkAuthorization) -> Bytes ! ProtocolError do
  validate_device_link_authorization(value) ?
  join([byte(value.version) ?, Bytes.from_utf8("LNA"), value.request_hash, vector(encode_username(value.username) ?) ?, vector(value.account_identity) ?, vector(value.device_credential) ?, value.authorization_signature],
  0,
  Bytes.empty())
end

pub fn decode_device_link_authorization(input :: Bytes) -> DeviceLinkAuthorization ! ProtocolError do
  let version = take_u8(open(input, 20864) ?) ?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = take_fixed(version.state, 3) ?
    valid_magic(magic.value, "LNA") ?
    let request_hash = take_fixed(magic.state, 32) ?
    let username = take_vector(request_hash.state, 64) ?
    let account_identity = take_vector(username.state, 16582) ?
    let device_credential = take_vector(account_identity.state, 4096) ?
    let authorization_signature = take_fixed(device_credential.state, 64) ?
    require_end(authorization_signature.state) ?
    let value = DeviceLinkAuthorization {
      version : version.value,
      request_hash : request_hash.value,
      username : decode_username(username.value) ?,
      account_identity : account_identity.value,
      device_credential : device_credential.value,
      authorization_signature : authorization_signature.value
    }
    validate_device_link_authorization(value) ?
    Ok(value)
  end
end

fn contains_bytes(values :: List < Bytes >, target :: Bytes, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else if Bytes.secure_equals(List.get(values, index), target) do
    true
  else
    contains_bytes(values, target, index + 1)
  end
end

fn contains_mailbox(values :: List < DirectoryEntry >, target :: Bytes, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else if Bytes.secure_equals(List.get(values, index).mailbox_token, target) do
    true
  else
    contains_mailbox(values, target, index + 1)
  end
end

fn validate_device_entries(value :: DeviceSet, index :: Int) -> Result <(), ProtocolError > do
  if List.length(value.devices) == 0 || List.length(value.devices) > 8 do
    Err(InvalidFieldLength)
  else if index >= List.length(value.devices) do
    Ok(nil)
  else
    let entry = List.get(value.devices, index)
    validate_directory_entry(entry) ?
    if entry.username != value.username || !Bytes.secure_equals(entry.account_identity,
    value.account_identity) do
      Err(InvalidPolicy)
    else
      if contains_mailbox(value.devices, entry.mailbox_token, index + 1) do
        Err(NonCanonicalEncoding)
      else
        validate_device_entries(value, index + 1)
      end
    end
  end
end

fn validate_revoked_ids(values :: List < Bytes >, index :: Int) -> Result <(), ProtocolError > do
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

fn validate_device_set(value :: DeviceSet) -> Result <(), ProtocolError > do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    let _ = encode_username(value.username) ?
    if Bytes.length(value.account_identity) == 0 || Bytes.length(value.account_identity) > 16582 do
      Err(InvalidFieldLength)
    else
      validate_device_entries(value, 0) ?
      validate_revoked_ids(value.revoked_device_ids, 0)
    end
  end
end

fn encode_device_entries(values :: List < DirectoryEntry >, index :: Int, output :: Bytes) -> Bytes ! ProtocolError do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_device_entries(values,
    index + 1,
    append(output, vector(encode_directory_entry(List.get(values, index)) ?) ?) ?)
  end
end

fn read_device_entries(state :: BinaryReader,
count :: Int,
index :: Int,
output :: List < DirectoryEntry >) -> ReadDirectoryEntries ! ProtocolError do
  if index >= count do
    Ok(ReadDirectoryEntries {
      state : state,
      value : output
    })
  else
    let entry = take_vector(state, 33636) ?
    read_device_entries(entry.state,
    count,
    index + 1,
    List.append(output, decode_directory_entry(entry.value) ?))
  end
end

fn encode_fixed_ids(values :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! ProtocolError do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_fixed_ids(values, index + 1, append(output, List.get(values, index)) ?)
  end
end

pub fn encode_device_set(value :: DeviceSet) -> Bytes ! ProtocolError do
  validate_device_set(value) ?
  let header = join([byte(value.version) ?, Bytes.from_utf8("DVS"), vector(encode_username(value.username) ?) ?, vector(value.account_identity) ?, write_u64(value.sequence) ?, byte(List.length(value.devices)) ?],
  0,
  Bytes.empty()) ?
  let devices = encode_device_entries(value.devices, 0, header) ?
  encode_fixed_ids(value.revoked_device_ids,
  0,
  append(devices, byte(List.length(value.revoked_device_ids)) ?) ?)
end

pub fn decode_device_set(input :: Bytes) -> DeviceSet ! ProtocolError do
  let version = take_u8(open(input, 286400) ?) ?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = take_fixed(version.state, 3) ?
    valid_magic(magic.value, "DVS") ?
    let username = take_vector(magic.state, 64) ?
    let account_identity = take_vector(username.state, 16582) ?
    let sequence = take_u64(account_identity.state) ?
    let device_count = take_u8(sequence.state) ?
    if device_count.value == 0 || device_count.value > 8 do
      Err(InvalidFieldLength)
    else
      let devices = read_device_entries(device_count.state, device_count.value, 0, List.new()) ?
      let revoked_count = take_u8(devices.state) ?
      if revoked_count.value > 32 do
        Err(OversizedInput)
      else
        let revoked = read_ack_ids(revoked_count.state, revoked_count.value, 0, List.new()) ?
        require_end(revoked.state) ?
        let value = DeviceSet {
          version : version.value,
          username : decode_username(username.value) ?,
          account_identity : account_identity.value,
          sequence : sequence.value,
          devices : devices.value,
          revoked_device_ids : revoked.value
        }
        validate_device_set(value) ?
        Ok(value)
      end
    end
  end
end

fn validate_device_revocation(value :: DeviceRevocation) -> Result <(), ProtocolError > do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else if Bytes.length(value.account_id) != 32 || Bytes.length(value.device_id) != 16 || Bytes.length(value.signature) != 64 do
    Err(InvalidFieldLength)
  else
    Ok(nil)
  end
end

pub fn encode_device_revocation(value :: DeviceRevocation) -> Bytes ! ProtocolError do
  validate_device_revocation(value) ?
  join([byte(value.version) ?, Bytes.from_utf8("DVR"), value.account_id, value.device_id, write_u64(value.sequence) ?, value.signature],
  0,
  Bytes.empty())
end

pub fn decode_device_revocation(input :: Bytes) -> DeviceRevocation ! ProtocolError do
  let version = take_u8(open(input, 256) ?) ?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = take_fixed(version.state, 3) ?
    valid_magic(magic.value, "DVR") ?
    let account_id = take_fixed(magic.state, 32) ?
    let device_id = take_fixed(account_id.state, 16) ?
    let sequence = take_u64(device_id.state) ?
    let signature = take_fixed(sequence.state, 64) ?
    require_end(signature.state) ?
    let value = DeviceRevocation {
      version : version.value,
      account_id : account_id.value,
      device_id : device_id.value,
      sequence : sequence.value,
      signature : signature.value
    }
    validate_device_revocation(value) ?
    Ok(value)
  end
end

pub fn encode_mailbox_fetch(value :: MailboxFetch) -> Bytes ! ProtocolError do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    if Bytes.length(value.mailbox_token) != 32 do
      Err(InvalidFieldLength)
    else
      join([byte(value.version) ?, Bytes.from_utf8("FET"), value.mailbox_token, write_u64(value.after_sequence) ?],
      0,
      Bytes.empty())
    end
  end
end

pub fn decode_mailbox_fetch(input :: Bytes) -> MailboxFetch ! ProtocolError do
  let version = take_u8(open(input, 44) ?) ?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = take_fixed(version.state, 3) ?
    valid_magic(magic.value, "FET") ?
    let mailbox_token = take_fixed(magic.state, 32) ?
    let after_sequence = take_u64(mailbox_token.state) ?
    require_end(after_sequence.state) ?
    Ok(MailboxFetch {
      version : version.value,
      mailbox_token : mailbox_token.value,
      after_sequence : after_sequence.value
    })
  end
end

fn validate_delivery_entries(values :: List < DeliveredEnvelope >, index :: Int) -> Result <(), ProtocolError > do
  if List.length(values) > 8 do
    Err(OversizedInput)
  else
    if index >= List.length(values) do
      Ok(nil)
    else
      let _ = decode_outer_envelope(List.get(values, index).envelope) ?
      validate_delivery_entries(values, index + 1)
    end
  end
end

fn encode_delivery_entries(values :: List < DeliveredEnvelope >, index :: Int, output :: Bytes) -> Bytes ! ProtocolError do
  if index >= List.length(values) do
    Ok(output)
  else
    let value = List.get(values, index)
    let next = join([output, write_u64(value.sequence) ?, vector(value.envelope) ?],
    0,
    Bytes.empty()) ?
    encode_delivery_entries(values, index + 1, next)
  end
end

pub fn encode_delivery_batch(values :: List < DeliveredEnvelope >) -> Bytes ! ProtocolError do
  validate_delivery_entries(values, 0) ?
  encode_delivery_entries(values,
  0,
  join([byte(1) ?, Bytes.from_utf8("BAT"), byte(List.length(values)) ?], 0, Bytes.empty()) ?)
end

fn read_delivery_entries(state :: BinaryReader,
count :: Int,
index :: Int,
output :: List < DeliveredEnvelope >) -> ReadDeliveries ! ProtocolError do
  if index >= count do
    Ok(ReadDeliveries {
      state : state,
      value : output
    })
  else
    let sequence = take_u64(state) ?
    let envelope = take_vector(sequence.state, 65606) ?
    let _ = decode_outer_envelope(envelope.value) ?
    read_delivery_entries(envelope.state,
    count,
    index + 1,
    List.append(output,
    DeliveredEnvelope {
      sequence : sequence.value,
      envelope : envelope.value
    }))
  end
end

pub fn decode_delivery_batch(input :: Bytes) -> List < DeliveredEnvelope > ! ProtocolError do
  let version = take_u8(open(input, 524949) ?) ?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = take_fixed(version.state, 3) ?
    valid_magic(magic.value, "BAT") ?
    let count = take_u8(magic.state) ?
    if count.value > 8 do
      Err(OversizedInput)
    else
      let values = read_delivery_entries(count.state, count.value, 0, List.new()) ?
      require_end(values.state) ?
      Ok(values.value)
    end
  end
end

fn validate_ack_ids(values :: List < Bytes >, index :: Int) -> Result <(), ProtocolError > do
  if List.length(values) == 0 || List.length(values) > 8 do
    Err(InvalidFieldLength)
  else
    if index >= List.length(values) do
      Ok(nil)
    else
      if Bytes.length(List.get(values, index)) != 16 do
        Err(InvalidFieldLength)
      else
        validate_ack_ids(values, index + 1)
      end
    end
  end
end

fn encode_ack_ids(values :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! ProtocolError do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_ack_ids(values, index + 1, join([output, List.get(values, index)], 0, Bytes.empty()) ?)
  end
end

pub fn encode_mailbox_ack(value :: MailboxAck) -> Bytes ! ProtocolError do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else
    if Bytes.length(value.mailbox_token) != 32 do
      Err(InvalidFieldLength)
    else
      validate_ack_ids(value.envelope_ids, 0) ?
      encode_ack_ids(value.envelope_ids,
      0,
      join([byte(value.version) ?, Bytes.from_utf8("ACK"), value.mailbox_token, byte(List.length(value.envelope_ids)) ?],
      0,
      Bytes.empty()) ?)
    end
  end
end

fn read_ack_ids(state :: BinaryReader, count :: Int, index :: Int, output :: List < Bytes >) -> ReadIds ! ProtocolError do
  if index >= count do
    Ok(ReadIds {
      state : state,
      value : output
    })
  else
    let id = take_fixed(state, 16) ?
    read_ack_ids(id.state, count, index + 1, List.append(output, id.value))
  end
end

pub fn decode_mailbox_ack(input :: Bytes) -> MailboxAck ! ProtocolError do
  let version = take_u8(open(input, 165) ?) ?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = take_fixed(version.state, 3) ?
    valid_magic(magic.value, "ACK") ?
    let mailbox_token = take_fixed(magic.state, 32) ?
    let count = take_u8(mailbox_token.state) ?
    if count.value == 0 || count.value > 8 do
      Err(InvalidFieldLength)
    else
      let ids = read_ack_ids(count.state, count.value, 0, List.new()) ?
      require_end(ids.state) ?
      Ok(MailboxAck {
        version : version.value,
        mailbox_token : mailbox_token.value,
        envelope_ids : ids.value
      })
    end
  end
end
