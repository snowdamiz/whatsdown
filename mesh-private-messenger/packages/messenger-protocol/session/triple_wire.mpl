##! Inactive composite wire syntax. No authentication or ratchet admission authority.
from Protocol.V1 import ProtocolError
from Session.HeaderWire import OpenedHeader, encode_header, decode_header
from Session.BraidFragment import BraidFragment, encode_braid_fragment, decode_braid_fragment
from Protocol.WirePrimitives import (
  protocol_byte,
  protocol_is_zero,
  protocol_open,
  protocol_require_end,
  protocol_take_fixed,
  protocol_take_u16,
  protocol_take_u64,
  protocol_take_u8,
  protocol_take_vector,
  protocol_valid_magic,
  protocol_write_length,
  protocol_write_u16,
  protocol_write_u64
)

pub struct TripleHeader do
  ec :: OpenedHeader
  pq_message_number :: U64
  fragment :: BraidFragment
end

pub struct TripleMessage do
  header_nonce :: Bytes
  encrypted_header :: Bytes
  nonce :: Bytes
  ciphertext :: Bytes
end

fn join(parts :: List<Bytes>, limit :: Int) -> Bytes!ProtocolError do
  case Bytes.concat_many(parts, limit) do
    Err(_) -> Err(OversizedInput)
    Ok(value)
  end
end

fn scope(configuration :: Bytes, session :: Bytes) -> Unit!ProtocolError do
  if Bytes.length(configuration) != 32 || Bytes.length(session) != 32 do
    Err(InvalidFieldLength)
  else
    Ok(nil)
  end
end

fn valid_header(value :: TripleHeader) -> Unit!ProtocolError do
  scope(value.fragment.configuration, value.fragment.session)?
  if value.ec.suite != 2 do
    Err(UnsupportedSuite)
  else if protocol_is_zero(value.pq_message_number)
    || !Bytes.secure_equals(value.ec.session_id, value.fragment.session) do
    Err(InvalidPolicy)
  else
    Ok(nil)
  end
end

fn valid_encrypted_length(length :: Int) -> Unit!ProtocolError do
  if length == 183 || length == 253 do
    Ok(nil)
  else
    Err(InvalidFieldLength)
  end
end

fn valid_framing(value :: TripleMessage) -> Unit!ProtocolError do
  valid_encrypted_length(Bytes.length(value.encrypted_header))?
  if Bytes.length(value.header_nonce) != 24 || Bytes.length(value.nonce) != 12 do
    Err(InvalidFieldLength)
  else
    Ok(nil)
  end
end

pub fn encode_triple_header(value :: TripleHeader) -> Bytes!ProtocolError do
  valid_header(value)?
  let ec = case encode_header(value.ec) do
    Err(_) -> return Err(MalformedEncoding)
    Ok(encoded) -> encoded
  end
  let fragment = encode_braid_fragment(value.fragment)?
  join([
      Bytes.from_utf8("CHP1"),
      protocol_byte(1)?,
      ec,
      protocol_write_u64(value.pq_message_number)?,
      protocol_write_u16(Bytes.length(fragment))?,
      fragment
    ],
    237)
end

pub fn decode_triple_header(input :: Bytes,
  configuration :: Bytes,
  session :: Bytes) -> TripleHeader!ProtocolError do
  scope(configuration, session)?
  if Bytes.length(input) != 167 && Bytes.length(input) != 237 do
    return Err(MalformedEncoding)
  end
  let magic = protocol_take_fixed(protocol_open(input, 237)?, 4)?
  protocol_valid_magic(magic.value, "CHP1")?
  let profile = protocol_take_u8(magic.state)?
  if profile.value != 1 do
    return Err(UnsupportedVersion)
  end
  let ec_bytes = protocol_take_fixed(profile.state, 74)?
  let ec = case decode_header(ec_bytes.value) do
    Err(_) -> return Err(MalformedEncoding)
    Ok(value) -> value
  end
  let number = protocol_take_u64(ec_bytes.state)?
  let length = protocol_take_u16(number.state)?
  if length.value != 78 && length.value != 148 do
    return Err(MalformedEncoding)
  end
  let fragment = protocol_take_fixed(length.state, length.value)?
  protocol_require_end(fragment.state)?
  let value = TripleHeader {
    ec: ec,
    pq_message_number: number.value,
    fragment: decode_braid_fragment(fragment.value, configuration, session)?
  }
  valid_header(value)?
  Ok(value)
end

pub fn encode_triple_message(value :: TripleMessage) -> Bytes!ProtocolError do
  valid_framing(value)?
  let size = Bytes.length(value.ciphertext)
  if size < 16 || size > 65168 do
    return Err(InvalidFieldLength)
  end
  join([
      Bytes.from_utf8("CHF1"),
      value.header_nonce,
      protocol_write_u16(Bytes.length(value.encrypted_header))?,
      value.encrypted_header,
      value.nonce,
      protocol_write_length(size)?,
      value.ciphertext
    ],
    65467)
end

pub fn decode_triple_message(input :: Bytes) -> TripleMessage!ProtocolError do
  if Bytes.length(input) < 245 || Bytes.length(input) > 65467 do
    return Err(MalformedEncoding)
  end
  let magic = protocol_take_fixed(protocol_open(input, 65467)?, 4)?
  protocol_valid_magic(magic.value, "CHF1")?
  let header_nonce = protocol_take_fixed(magic.state, 24)?
  let length = protocol_take_u16(header_nonce.state)?
  valid_encrypted_length(length.value)?
  let header = protocol_take_fixed(length.state, length.value)?
  let nonce = protocol_take_fixed(header.state, 12)?
  let body = protocol_take_vector(nonce.state, 65168)?
  protocol_require_end(body.state)?
  if Bytes.length(body.value) < 16 do
    return Err(InvalidFieldLength)
  end
  Ok(TripleMessage {
    header_nonce: header_nonce.value,
    encrypted_header: header.value,
    nonce: nonce.value,
    ciphertext: body.value
  })
end

fn domain(configuration :: Bytes, session :: Bytes) -> Bytes!ProtocolError do
  scope(configuration, session)?
  join([Bytes.from_utf8("mesh-msg/spqr/v1"), protocol_byte(0)?, configuration, session], 81)
end

pub fn triple_header_aad(configuration :: Bytes,
  session :: Bytes,
  encrypted_header_length :: Int,
  caller :: Bytes) -> Bytes!ProtocolError do
  valid_encrypted_length(encrypted_header_length)?
  join([
      Bytes.from_utf8("mesh-msg/triple/v1/header-aad"),
      protocol_byte(0)?,
      domain(configuration, session)?,
      Bytes.from_utf8("CHF1"),
      protocol_write_u16(encrypted_header_length)?,
      caller
    ],
    131072)
end

pub fn triple_body_aad(configuration :: Bytes,
  session :: Bytes,
  message :: TripleMessage,
  caller :: Bytes) -> Bytes!ProtocolError do
  valid_framing(message)?
  join([
      Bytes.from_utf8("mesh-msg/triple/v1/body-aad"),
      protocol_byte(0)?,
      domain(configuration, session)?,
      Bytes.from_utf8("CHF1"),
      message.header_nonce,
      protocol_write_u16(Bytes.length(message.encrypted_header))?,
      message.encrypted_header,
      message.nonce,
      caller
    ],
    131072)
end
