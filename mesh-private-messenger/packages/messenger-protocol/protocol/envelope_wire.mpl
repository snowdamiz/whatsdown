##! Inner and outer envelope codecs.

from Protocol.WirePrimitives import (
  protocol_as_int,
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
  protocol_write_length,
  protocol_write_u16,
  protocol_write_u64
)
from Protocol.ExtensionWire import (
  protocol_encode_extensions,
  protocol_take_extensions,
  protocol_validate_extensions
)
from Protocol.V1 import (
  InnerEnvelope,
  OuterEnvelope,
  ProtocolError,
  protocol_sealed_outer_suite,
  protocol_supported_suite
)

fn validate_inner_fields(value :: InnerEnvelope) -> Result<(), ProtocolError> do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else if Bytes.length(value.sender_account_id) != 32
    || Bytes.length(value.sender_device_id) != 16
    || Bytes.length(value.recipient_device_id) != 16
    || Bytes.length(value.conversation_id) != 16
    || Bytes.length(value.client_message_id) != 16
    || !(Bytes.length(value.reply_reference) == 0 || Bytes.length(value.reply_reference) == 16) do
    Err(InvalidFieldLength)
  else if Bytes.length(value.body) > 32768 || Bytes.length(value.attachment_manifest) > 16384 do
    Err(OversizedInput)
  else if value.message_type <= 0
    || value.message_type > 65535
    || value.receipt_policy < 0
    || value.receipt_policy > 2
    || value.disappearing_seconds < 0
    || value.disappearing_seconds > 4294967295 do
    Err(InvalidPolicy)
  else
    protocol_validate_extensions(value.extensions, 0, 0)
  end
end

fn encode_inner_fields(value :: InnerEnvelope) -> Bytes!ProtocolError do
  validate_inner_envelope(value)?
  let encoded = protocol_join([
      protocol_byte(value.version)?,
      Bytes.from_utf8("PAY"),
      value.sender_account_id,
      value.sender_device_id,
      value.recipient_device_id,
      value.conversation_id,
      value.client_message_id,
      protocol_write_u64(value.client_timestamp)?,
      protocol_write_u16(value.message_type)?,
      protocol_vector(value.body)?,
      protocol_vector(value.reply_reference)?,
      protocol_vector(value.attachment_manifest)?,
      protocol_byte(value.receipt_policy)?,
      protocol_write_length(value.disappearing_seconds)?,
      protocol_encode_extensions(value.extensions)?
    ],
    0,
    Bytes.empty())?
  if Bytes.length(encoded) > 65536 do
    Err(OversizedInput)
  else
    Ok(encoded)
  end
end

pub fn decode_inner_envelope(input :: Bytes) -> InnerEnvelope!ProtocolError do
  let version = protocol_take_u8(protocol_open(input, 65536)?)?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = protocol_take_fixed(version.state, 3)?
    if !Bytes.secure_equals(magic.value, Bytes.from_utf8("PAY")) do
      Err(MalformedEncoding)
    else
      let sender_account_id = protocol_take_fixed(magic.state, 32)?
      let sender_device_id = protocol_take_fixed(sender_account_id.state, 16)?
      let recipient_device_id = protocol_take_fixed(sender_device_id.state, 16)?
      let conversation_id = protocol_take_fixed(recipient_device_id.state, 16)?
      let client_message_id = protocol_take_fixed(conversation_id.state, 16)?
      let client_timestamp = protocol_take_u64(client_message_id.state)?
      let message_type = protocol_take_u16(client_timestamp.state)?
      let body = protocol_take_vector(message_type.state, 32768)?
      let reply_reference = protocol_take_vector(body.state, 16)?
      let attachment_manifest = protocol_take_vector(reply_reference.state, 16384)?
      let receipt_policy = protocol_take_u8(attachment_manifest.state)?
      let disappearing_seconds = protocol_take_u32(receipt_policy.state)?
      let extensions = protocol_take_extensions(disappearing_seconds.state)?
      protocol_require_end(extensions.state)?
      let value = InnerEnvelope {
        version: version.value,
        sender_account_id: sender_account_id.value,
        sender_device_id: sender_device_id.value,
        recipient_device_id: recipient_device_id.value,
        conversation_id: conversation_id.value,
        client_message_id: client_message_id.value,
        client_timestamp: client_timestamp.value,
        message_type: message_type.value,
        body: body.value,
        reply_reference: reply_reference.value,
        attachment_manifest: attachment_manifest.value,
        receipt_policy: receipt_policy.value,
        disappearing_seconds: protocol_as_int(disappearing_seconds.value)?,
        extensions: extensions.value
      }
      validate_inner_envelope(value)?
      Ok(value)
    end
  end
end

fn supported_bucket(value :: Int) -> Bool do
  value == 256
    || value == 512
    || value == 1024
    || value == 2048
    || value == 4096
    || value == 8192
    || value == 16384
    || value == 32768
    || value == 65536
end

# 1-3 are the legacy outer suites that named the protocol in the clear; they
# remain decodable for queued envelopes. New envelopes are always suite 4.

fn supported_outer_suite(value :: Int) -> Bool do
  protocol_supported_suite(value) || value == 3 || value == protocol_sealed_outer_suite()
end

fn validate_outer(value :: OuterEnvelope) -> Result<(), ProtocolError> do
  if value.version != 1 do
    Err(UnsupportedVersion)
  else if !supported_outer_suite(value.suite) do
    Err(UnsupportedSuite)
  else if Bytes.length(value.envelope_id) != 16 || Bytes.length(value.mailbox_token) != 32 do
    Err(InvalidFieldLength)
  else if !supported_bucket(value.padding_bucket)
    || Bytes.length(value.ciphertext) > value.padding_bucket do
    Err(InvalidPaddingBucket)
  else
    Ok(nil)
  end
end

pub fn encode_outer_envelope(value :: OuterEnvelope) -> Bytes!ProtocolError do
  validate_outer(value)?
  protocol_join([
      protocol_byte(value.version)?,
      Bytes.from_utf8("MSG"),
      value.envelope_id,
      value.mailbox_token,
      protocol_write_u16(value.suite)?,
      protocol_write_u64(value.expiration)?,
      protocol_write_length(value.padding_bucket)?,
      protocol_vector(value.ciphertext)?
    ],
    0,
    Bytes.empty())
end

pub fn decode_outer_envelope(input :: Bytes) -> OuterEnvelope!ProtocolError do
  let version = protocol_take_u8(protocol_open(input, 65606)?)?
  if version.value != 1 do
    Err(UnsupportedVersion)
  else
    let magic = protocol_take_fixed(version.state, 3)?
    if !Bytes.secure_equals(magic.value, Bytes.from_utf8("MSG")) do
      Err(MalformedEncoding)
    else
      let envelope_id = protocol_take_fixed(magic.state, 16)?
      let mailbox_token = protocol_take_fixed(envelope_id.state, 32)?
      let suite = protocol_take_u16(mailbox_token.state)?
      let expiration = protocol_take_u64(suite.state)?
      let padding = protocol_take_u32(expiration.state)?
      let padding_bucket = protocol_as_int(padding.value)?
      let ciphertext = protocol_take_vector(padding.state, 65536)?
      protocol_require_end(ciphertext.state)?
      let value = OuterEnvelope {
        version: version.value,
        envelope_id: envelope_id.value,
        mailbox_token: mailbox_token.value,
        suite: suite.value,
        expiration: expiration.value,
        padding_bucket: padding_bucket,
        ciphertext: ciphertext.value
      }
      validate_outer(value)?
      Ok(value)
    end
  end
end

# This exhaustive classifier is the complete reviewed disclosure surface. A new
# ProtocolError variant must fail compilation until its fixed status is reviewed.
fn inner_protocol_error_code(error :: ProtocolError) -> Int do
  case error do
    UnsupportedVersion -> 1
    UnsupportedSuite -> 2
    InvalidSuiteList -> 3
    DuplicateSuite -> 4
    InvalidSuiteHistory -> 5
    DowngradeDetected -> 6
    TooManyExtensions -> 7
    InvalidExtension -> 8
    UnknownMandatoryExtension -> 9
    NonCanonicalEncoding -> 10
    InvalidPolicy -> 11
    InvalidFieldLength -> 12
    InvalidPaddingBucket -> 13
    InvalidExpiration -> 14
    PostQuantumNotSupported -> 15
    OversizedInput -> 16
    MalformedEncoding -> 17
  end
end

fn inner_protocol_error_from_code(code :: Int) -> ProtocolError do
  case code do
    1 -> UnsupportedVersion
    2 -> UnsupportedSuite
    3 -> InvalidSuiteList
    4 -> DuplicateSuite
    5 -> InvalidSuiteHistory
    6 -> DowngradeDetected
    7 -> TooManyExtensions
    8 -> InvalidExtension
    9 -> UnknownMandatoryExtension
    10 -> NonCanonicalEncoding
    11 -> InvalidPolicy
    12 -> InvalidFieldLength
    13 -> InvalidPaddingBucket
    14 -> InvalidExpiration
    15 -> PostQuantumNotSupported
    16 -> OversizedInput
    17 -> MalformedEncoding
    _ -> MalformedEncoding
  end
end

fn validate_inner_envelope(value :: InnerEnvelope) -> Result<(), ProtocolError> do
  let checked = validate_inner_fields(value)
  let status = case checked do
    Err(error) -> inner_protocol_error_code(error)
    Ok(_) -> 0
  end
  let published = declassify(status,
    "inner envelope admission discloses only its reviewed fixed0..17 status classifier, including bounds and policy failures; no ProtocolError payload is released")
  if published == 0 do
    Ok(nil)
  else
    Err(inner_protocol_error_from_code(published))
  end
end

pub fn encode_inner_envelope(value :: InnerEnvelope) -> Plaintext<Bytes>!ProtocolError do
  let encoded = encode_inner_fields(value)
  let status = case encoded do
    Err(error) -> inner_protocol_error_code(error)
    Ok(_) -> 0
  end
  let published = declassify(status,
    "inner envelope encoding discloses only its reviewed fixed0..17 status classifier; encoded bytes and ProtocolError payloads remain private")
  if published == 0 do
    Ok(Result.unwrap_or(encoded, Bytes.empty()))
  else
    Err(inner_protocol_error_from_code(published))
  end
end
