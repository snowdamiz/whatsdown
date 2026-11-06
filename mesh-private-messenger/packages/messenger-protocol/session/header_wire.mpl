##! Fixed HE wire framing. No session identifier is exposed before header authentication.
from Session.State import RatchetError, RatchetMessage

pub struct OpenedHeader do
  suite :: Int
  session_id :: Bytes
  ratchet_public_key :: X25519PublicKey
  previous_chain_length :: Int
  message_number :: Int
end

pub fn he_join(parts :: List<Bytes>) -> Bytes!RatchetError do
  case Bytes.concat_many(parts, 131072) do
    Err(_) -> Err(InvalidMessage)
    Ok(value)
  end
end

pub fn he_u32(value :: Int) -> Bytes!RatchetError do
  case U64.parse(Int.to_string(value)) do
    Err(_) -> Err(InvalidMessage)
    Ok(wide) -> case Bytes.write_u32_be(wide) do
      Err(_) -> Err(InvalidMessage)
      Ok(encoded)
    end
  end
end

fn u16(value :: Int) -> Bytes!RatchetError do
  case Bytes.write_u16_be(value) do
    Err(_) -> Err(InvalidMessage)
    Ok(encoded)
  end
end

pub fn he_slice(value :: Bytes, offset :: Int, length :: Int) -> Bytes!RatchetError do
  case Bytes.slice(value, offset, length) do
    Err(_) -> Err(InvalidMessage)
    Ok(part)
  end
end

pub fn he_read_u32(value :: Bytes, offset :: Int) -> Int!RatchetError do
  case Bytes.read_u32_be(value, offset) do
    Err(_) -> Err(InvalidMessage)
    Ok(wide) -> case U64.to_int(wide) do
      Err(_) -> Err(InvalidMessage)
      Ok(number)
    end
  end
end

pub fn encode_header(value :: OpenedHeader) -> Bytes!RatchetError do
  if (value.suite != 1 && value.suite != 2)
    || Bytes.length(value.session_id) != 32
    || Bytes.length(value.ratchet_public_key.bytes) != 32
    || value.previous_chain_length < 0
    || value.message_number < 0 do
    return Err(InvalidMessage)
  end
  he_join([
    u16(value.suite)?,
    value.session_id,
    value.ratchet_public_key.bytes,
    he_u32(value.previous_chain_length)?,
    he_u32(value.message_number)?
  ])
end

pub fn decode_header(input :: Bytes) -> OpenedHeader!RatchetError do
  if Bytes.length(input) != 74 do
    return Err(InvalidMessage)
  end
  let suite = case Bytes.read_u16_be(input, 0) do
    Err(_) -> Err(InvalidMessage)
    Ok(value)
  end?
  let value = OpenedHeader {
    suite: suite,
    session_id: he_slice(input, 2, 32)?,
    ratchet_public_key: X25519PublicKey { bytes: he_slice(input, 34, 32)? },
    previous_chain_length: he_read_u32(input, 66)?,
    message_number: he_read_u32(input, 70)?
  }
  encode_header(value)?
  Ok(value)
end

fn prefix() -> Bytes!RatchetError do
  case Bytes.from_list([4, 82, 65, 84]) do
    Err(_) -> Err(InvalidMessage)
    Ok(value)
  end
end

pub fn he_header_aad(caller :: Bytes) -> Bytes!RatchetError do
  he_join([Bytes.from_utf8("mesh-msg/v2/header-aad"), prefix()?, caller])
end

pub fn he_body_aad(message :: RatchetMessage, caller :: Bytes) -> Bytes!RatchetError do
  he_join([
    Bytes.from_utf8("mesh-msg/v2/body-aad"),
    caller,
    prefix()?,
    message.header_nonce,
    message.encrypted_header,
    message.nonce
  ])
end

pub fn he_encode_message(value :: RatchetMessage) -> Bytes!RatchetError do
  if value.version != 4
    || Bytes.length(value.header_nonce) != 24
    || Bytes.length(value.encrypted_header) != 90
    || Bytes.length(value.nonce) != 12
    || Bytes.length(value.ciphertext) < 16
    || Bytes.length(value.ciphertext) > 65333 do
    return Err(InvalidMessage)
  end
  he_join([
    prefix()?,
    value.header_nonce,
    value.encrypted_header,
    value.nonce,
    he_u32(Bytes.length(value.ciphertext))?,
    value.ciphertext
  ])
end

pub fn he_decode_message(input :: Bytes) -> RatchetMessage!RatchetError do
  if Bytes.length(input) < 150
    || Bytes.length(input) > 65467
    || !Bytes.secure_equals(he_slice(input, 0, 4)?, prefix()?) do
    return Err(InvalidMessage)
  end
  let length = he_read_u32(input, 130)?
  if length < 16 || length > 65333 || length != Bytes.length(input) - 134 do
    return Err(InvalidMessage)
  end
  Ok(RatchetMessage {
    version: 4,
    suite: 0,
    session_id: Bytes.empty(),
    ratchet_public_key: X25519PublicKey { bytes: Bytes.empty() },
    previous_chain_length: 0,
    message_number: 0,
    header_nonce: he_slice(input, 4, 24)?,
    encrypted_header: he_slice(input, 28, 90)?,
    nonce: he_slice(input, 118, 12)?,
    ciphertext: he_slice(input, 134, length)?
  })
end
