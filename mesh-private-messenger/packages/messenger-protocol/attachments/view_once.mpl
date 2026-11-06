##! Canonical per-device image references. Sender admission belongs to transport.
from Identity.Device import DeviceKeys
from Protocol.V1 import ProtocolError
from Protocol.WirePrimitives import (
  protocol_byte,
  protocol_join,
  protocol_vector,
  protocol_open,
  protocol_take_fixed,
  protocol_take_vector,
  protocol_require_end
)

pub struct ViewOnceBinding do
  sender_account_id :: Bytes
  sender_device_id :: Bytes
  receiver_account_id :: Bytes
  receiver_device_id :: Bytes
  conversation_id :: Bytes
  message_id :: Bytes
end

pub struct ViewOnceReference do
  binding :: ViewOnceBinding
  object_id :: Bytes
  download_capability :: Bytes
  encrypted_manifest :: Bytes
  wrapped_key :: Bytes
end

fn valid_binding(value :: ViewOnceBinding) -> Bool do
  Bytes.length(value.sender_account_id) == 32
    && Bytes.length(value.sender_device_id) == 16
    && Bytes.length(value.receiver_account_id) == 32
    && Bytes.length(value.receiver_device_id) == 16
    && Bytes.length(value.conversation_id) == 16
    && Bytes.length(value.message_id) == 16
end

fn binding_bytes(value :: ViewOnceBinding) -> Bytes!ProtocolError do
  if !valid_binding(value) do
    Err(InvalidFieldLength)
  else
    protocol_join([
        value.sender_account_id,
        value.sender_device_id,
        value.receiver_account_id,
        value.receiver_device_id,
        value.conversation_id,
        value.message_id
      ],
      0,
      Bytes.empty())
  end
end

pub fn view_once_binding_digest(value :: ViewOnceBinding) -> Bytes!String do
  case binding_bytes(value) do
    Err(_) -> Err("view_once_reference_refused")
    Ok(bytes) -> Ok(Crypto.sha256(bytes))
  end
end

fn valid_fields(value :: ViewOnceReference) -> Bool do
  valid_binding(value.binding)
    && Bytes.length(value.object_id) == 32
    && Bytes.length(value.download_capability) == 32
    && Bytes.length(value.encrypted_manifest) > 0
    && Bytes.length(value.encrypted_manifest) <= 640
end

fn encode_reference(value :: ViewOnceReference) -> Bytes!ProtocolError do
  if !valid_fields(value)
    || Bytes.length(value.wrapped_key) == 0
    || Bytes.length(value.wrapped_key) > 160 do
    return Err(InvalidFieldLength)
  end
  protocol_join([
      protocol_byte(1)?,
      Bytes.from_utf8("VOR"),
      binding_bytes(value.binding)?,
      value.object_id,
      value.download_capability,
      protocol_vector(value.encrypted_manifest)?,
      protocol_vector(value.wrapped_key)?
    ],
    0,
    Bytes.empty())
end

pub fn encode_view_once_reference(value :: ViewOnceReference) -> Bytes!String do
  case encode_reference(value) do
    Err(_) -> Err("view_once_reference_refused")
    Ok(bytes)
  end
end

fn decode_reference(wire :: Bytes) -> ViewOnceReference!ProtocolError do
  let header = protocol_take_fixed(protocol_open(wire, 1024)?, 4)?
  let expected = protocol_join([protocol_byte(1)?, Bytes.from_utf8("VOR")], 0, Bytes.empty())?
  if !Bytes.secure_equals(header.value, expected) do
    return Err(MalformedEncoding)
  end
  let sender_account = protocol_take_fixed(header.state, 32)?
  let sender_device = protocol_take_fixed(sender_account.state, 16)?
  let receiver_account = protocol_take_fixed(sender_device.state, 32)?
  let receiver_device = protocol_take_fixed(receiver_account.state, 16)?
  let conversation = protocol_take_fixed(receiver_device.state, 16)?
  let message = protocol_take_fixed(conversation.state, 16)?
  let object = protocol_take_fixed(message.state, 32)?
  let capability = protocol_take_fixed(object.state, 32)?
  let manifest = protocol_take_vector(capability.state, 640)?
  let wrapped = protocol_take_vector(manifest.state, 160)?
  protocol_require_end(wrapped.state)?
  let value = ViewOnceReference {
    binding: ViewOnceBinding {
      sender_account_id: sender_account.value,
      sender_device_id: sender_device.value,
      receiver_account_id: receiver_account.value,
      receiver_device_id: receiver_device.value,
      conversation_id: conversation.value,
      message_id: message.value
    },
    object_id: object.value,
    download_capability: capability.value,
    encrypted_manifest: manifest.value,
    wrapped_key: wrapped.value
  }
  if !valid_fields(value) || Bytes.length(value.wrapped_key) == 0 do
    Err(InvalidFieldLength)
  else
    Ok(value)
  end
end

pub fn decode_view_once_reference(wire :: Bytes) -> ViewOnceReference!String do
  case decode_reference(wire) do
    Err(_) -> Err("view_once_reference_refused")
    Ok(value)
  end
end

fn reference_aad_bytes(value :: ViewOnceReference) -> Bytes!ProtocolError do
  protocol_join([
      Bytes.from_utf8("morse/view-once/v1/reference\n"),
      binding_bytes(value.binding)?,
      value.object_id,
      value.download_capability,
      Crypto.sha256(value.encrypted_manifest)
    ],
    0,
    Bytes.empty())
end

fn reference_aad(value :: ViewOnceReference) -> Bytes!String do
  case reference_aad_bytes(value) do
    Err(_) -> Err("view_once_reference_refused")
    Ok(bytes)
  end
end

pub fn wrap_view_once_reference(secret :: borrow SecretBytes,
  recipient :: X25519PublicKey,
  binding :: ViewOnceBinding,
  object_id :: Bytes,
  download_capability :: Bytes,
  encrypted_manifest :: Bytes) -> Bytes!String do
  let value = ViewOnceReference {
    binding: binding,
    object_id: object_id,
    download_capability: download_capability,
    encrypted_manifest: encrypted_manifest,
    wrapped_key: Bytes.empty()
  }
  if !valid_fields(value) || Bytes.length(recipient.bytes) != 32 do
    return Err("view_once_reference_refused")
  end
  let wrapped = case Crypto.hpke_seal_secret(recipient,
    Bytes.from_utf8("morse/view-once/v1/image-key"),
    reference_aad(value)?,
    secret) do
    Err(_) -> return Err("view_once_reference_refused")
    Ok(bytes) -> bytes
  end
  encode_view_once_reference(%{value | wrapped_key: wrapped})
end

pub fn open_view_once_key(device :: borrow DeviceKeys,
  expected :: ViewOnceBinding,
  wire :: Bytes) -> SecretBytes!String do
  let value = decode_view_once_reference(wire)?
  let expected_bytes = case binding_bytes(expected) do
    Err(_) -> return Err("view_once_reference_refused")
    Ok(bytes) -> bytes
  end
  let actual_bytes = case binding_bytes(value.binding) do
    Err(_) -> return Err("view_once_reference_refused")
    Ok(bytes) -> bytes
  end
  if !Bytes.secure_equals(expected_bytes, actual_bytes)
    || !Bytes.secure_equals(device.device_id, expected.receiver_device_id) do
    return Err("view_once_reference_refused")
  end
  case Crypto.hpke_open_secret(device.identity_private_key,
    Bytes.from_utf8("morse/view-once/v1/image-key"),
    reference_aad(value)?,
    value.wrapped_key) do
    Err(_) -> Err("view_once_reference_refused")
    Ok(secret)
  end
end
