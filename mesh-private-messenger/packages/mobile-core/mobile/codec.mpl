from Binary.Reader import BinaryReader, finish, reader, read_fixed, read_vector
from Mobile.Types import MobileReadBytes
from Protocol.EnvelopeWire import decode_outer_envelope, encode_outer_envelope
from Protocol.V1 import OuterEnvelope

##! Mobile.Codec implementation.

pub fn take_vector(state :: BinaryReader, maximum :: Int) -> MobileReadBytes!String do
  case read_vector(state, maximum) do
    Err(_) -> Err("invalid_store_request")
    Ok((next, value)) -> Ok(MobileReadBytes { state: next, value: value })
  end
end

pub fn take_vector_error(state :: BinaryReader, maximum :: Int, error :: String) -> MobileReadBytes!String do
  case read_vector(state, maximum) do
    Err(_) -> Err(error)
    Ok((next, value)) -> Ok(MobileReadBytes { state: next, value: value })
  end
end

pub fn take_fixed(state :: BinaryReader, length :: Int) -> MobileReadBytes!String do
  case read_fixed(state, length) do
    Err(_) -> Err("invalid_fixed_value")
    Ok((next, value)) -> Ok(MobileReadBytes { state: next, value: value })
  end
end

pub fn take_group_vector(state :: BinaryReader, maximum :: Int) -> MobileReadBytes!String do
  case read_vector(state, maximum) do
    Err(_) -> Err("invalid_group_request")
    Ok((next, value)) -> Ok(MobileReadBytes { state: next, value: value })
  end
end

pub fn mobile_wide(value :: String) -> U64!String do
  case U64.parse(value) do
    Err(_) -> Err("invalid_wide_integer")
    Ok(parsed)
  end
end

pub fn mobile_append(left :: Bytes, right :: Bytes) -> Bytes!String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("byte_concatenation_failed")
    Ok(value)
  end
end

pub fn mobile_join(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    mobile_join(parts, index + 1, mobile_append(output, List.get(parts, index))?)
  end
end

pub fn mobile_write_u16(value :: Int) -> Bytes!String do
  case Bytes.write_u16_be(value) do
    Err(_) -> Err("integer_encoding_failed")
    Ok(encoded)
  end
end

pub fn mobile_byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("integer_encoding_failed")
    Ok(encoded)
  end
end

pub fn mobile_zeroes(length :: Int) -> Bytes!String do
  case Bytes.repeat(0, length) do
    Err(_) -> Err("storage_context_failed")
    Ok(value)
  end
end

pub fn mobile_write_u32(value :: Int) -> Bytes!String do
  case Bytes.write_u32_be(mobile_wide(Int.to_string(value))?) do
    Err(_) -> Err("integer_encoding_failed")
    Ok(encoded)
  end
end

pub fn mobile_write_u64(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err("integer_encoding_failed")
    Ok(encoded)
  end
end

pub fn mobile_read_byte(value :: Bytes) -> Int!String do
  if Bytes.length(value) != 1 do
    Err("invalid_integer")
  else
    Ok(List.head(Bytes.to_list(value)))
  end
end

pub fn mobile_read_u32(value :: Bytes) -> Int!String do
  if Bytes.length(value) != 4 do
    Err("invalid_integer")
  else
    case Bytes.read_u32_be(value, 0) do
      Err(_) -> Err("invalid_integer")
      Ok(wide) -> case U64.to_int(wide) do
        Err(_) -> Err("invalid_integer")
        Ok(number)
      end
    end
  end
end

pub fn mobile_read_u64(value :: Bytes) -> U64!String do
  if Bytes.length(value) != 8 do
    Err("invalid_integer")
  else
    case Bytes.read_u64_be(value, 0) do
      Err(_) -> Err("invalid_integer")
      Ok(wide)
    end
  end
end

pub fn mobile_vector(value :: Bytes) -> Bytes!String do
  mobile_append(mobile_write_u32(Bytes.length(value))?, value)
end

pub fn mobile_utf8(value :: Bytes, error :: String) -> String!String do
  case Bytes.to_utf8(value) do
    Err(_) -> Err(error)
    Ok(text)
  end
end

pub fn current_time() -> U64!String do
  mobile_wide(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

pub fn random_bytes(length :: Int) -> Bytes!String do
  case Crypto.random_bytes(length) do
    Err(_) -> Err("random_generation_failed")
    Ok(value)
  end
end

fn encode_output_parts(values :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_output_parts(values,
      index + 1,
      mobile_append(output, mobile_vector(List.get(values, index))?)?)
  end
end

pub fn encode_output_list(values :: List<Bytes>) -> Bytes!String do
  encode_output_parts(values, 0, mobile_vector(mobile_write_u32(List.length(values))?)?)
end

fn padding_bucket(length :: Int) -> Int!String do
  if length <= 256 do
    Ok(256)
  else if length <= 512 do
    Ok(512)
  else if length <= 1024 do
    Ok(1024)
  else if length <= 2048 do
    Ok(2048)
  else if length <= 4096 do
    Ok(4096)
  else if length <= 8192 do
    Ok(8192)
  else if length <= 16384 do
    Ok(16384)
  else if length <= 32768 do
    Ok(32768)
  else if length <= 65536 do
    Ok(65536)
  else
    Err("message_too_large")
  end
end

pub fn outer_bytes(mailbox_token :: Bytes, suite :: Int, packet :: Bytes, now :: U64) -> Bytes!String do
  let expiration = U64.add(now, mobile_wide("2592000000")?)?
  case encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: random_bytes(16)?,
    mailbox_token: mailbox_token,
    suite: suite,
    expiration: expiration,
    padding_bucket: padding_bucket(Bytes.length(packet))?,
    ciphertext: packet
  }) do
    Err(_) -> Err("outer_encoding_failed")
    Ok(encoded) -> if Bytes.length(encoded) > 65606 do
      Err("message_too_large")
    else
      Ok(encoded)
    end
  end
end

pub fn canonical_outer(input :: Bytes) -> OuterEnvelope!String do
  case decode_outer_envelope(input) do
    Err(_) -> Err("invalid_outer_envelope")
    Ok(value) -> case encode_outer_envelope(value) do
      Err(_) -> Err("invalid_outer_envelope")
      Ok(encoded) -> if Bytes.secure_equals(encoded, input) do
        Ok(value)
      else
        Err("noncanonical_outer_envelope")
      end
    end
  end
end

## Keep the caller's boundary error while using linear propagation in request decoders.

pub fn mobile_reader(input :: Bytes, maximum :: Int, error :: String) -> BinaryReader!String do
  case reader(input, maximum) do
    Err(_) -> Err(error)
    Ok(state)
  end
end

pub fn mobile_finish(state :: BinaryReader, error :: String) -> Result<(), String> do
  case finish(state) do
    Err(_) -> Err(error)
    Ok(_) -> Ok(nil)
  end
end

## Trailing vectors added after a format shipped are optional: absent input reads as empty.

pub fn take_optional_vector(state :: BinaryReader, maximum :: Int, error :: String) -> MobileReadBytes!String do
  if state.offset >= Bytes.length(state.input) do
    Ok(MobileReadBytes { state: state, value: Bytes.empty() })
  else
    take_vector_error(state, maximum, error)
  end
end
