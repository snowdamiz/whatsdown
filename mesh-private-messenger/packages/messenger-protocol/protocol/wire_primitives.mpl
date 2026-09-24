##! Shared bounded binary primitives for protocol records.

from Binary.Reader import BinaryReader, finish, read_fixed, read_u16_be, read_u8, read_vector, reader
from Protocol.V1 import DeliveredEnvelope, DirectoryEntry, ProtocolError, ProtocolExtension

pub struct ProtocolReadInt do
  state :: BinaryReader
  value :: Int
end

pub struct ProtocolReadWide do
  state :: BinaryReader
  value :: U64
end

pub struct ProtocolReadBytes do
  state :: BinaryReader
  value :: Bytes
end

pub struct ProtocolReadExtensions do
  state :: BinaryReader
  value :: List<ProtocolExtension>
end

pub struct ProtocolReadSuites do
  state :: BinaryReader
  value :: List<Int>
end

pub struct ProtocolReadDeliveries do
  state :: BinaryReader
  value :: List<DeliveredEnvelope>
end

pub struct ProtocolReadIds do
  state :: BinaryReader
  value :: List<Bytes>
end

pub struct ProtocolReadDirectoryEntries do
  state :: BinaryReader
  value :: List<DirectoryEntry>
end

pub fn protocol_is_zero(value :: U64) -> Bool do
  case U64.to_int(value) do
    Err(_) -> false
    Ok(number) -> number == 0
  end
end

pub fn protocol_append(output :: Bytes, value :: Bytes) -> Bytes!ProtocolError do
  case Bytes.concat(output, value) do
    Err(_) -> Err(OversizedInput)
    Ok(bytes)
  end
end

pub fn protocol_join(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!ProtocolError do
  if index >= List.length(parts) do
    Ok(output)
  else
    protocol_join(parts, index + 1, protocol_append(output, List.get(parts, index))?)
  end
end

pub fn protocol_write_builder_parts(builder :: borrow BytesBuilder,
  parts :: List<Bytes>,
  index :: Int) -> Result<(), ProtocolError> do
  if index >= List.length(parts) do
    Ok(nil)
  else
    case BytesBuilder.write_bytes(builder, List.get(parts, index)) do
      Err(_) -> Err(OversizedInput)
      Ok(_) -> protocol_write_builder_parts(builder, parts, index + 1)
    end
  end
end

pub fn protocol_byte(value :: Int) -> Bytes!ProtocolError do
  case Bytes.from_list([value]) do
    Err(_) -> Err(MalformedEncoding)
    Ok(bytes)
  end
end

pub fn protocol_write_u16(value :: Int) -> Bytes!ProtocolError do
  case Bytes.write_u16_be(value) do
    Err(_) -> Err(MalformedEncoding)
    Ok(bytes)
  end
end

pub fn protocol_write_u32(value :: U64) -> Bytes!ProtocolError do
  case Bytes.write_u32_be(value) do
    Err(_) -> Err(MalformedEncoding)
    Ok(bytes)
  end
end

pub fn protocol_write_length(value :: Int) -> Bytes!ProtocolError do
  case value
    |> Int.to_string()
    |> U64.parse() do
    Err(_) -> Err(MalformedEncoding)
    Ok(parsed) -> protocol_write_u32(parsed)
  end
end

pub fn protocol_write_u64(value :: U64) -> Bytes!ProtocolError do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err(MalformedEncoding)
    Ok(bytes)
  end
end

pub fn protocol_vector(value :: Bytes) -> Bytes!ProtocolError do
  protocol_join([protocol_write_length(Bytes.length(value))?, value], 0, Bytes.empty())
end

pub fn protocol_open(input :: Bytes, maximum :: Int) -> BinaryReader!ProtocolError do
  if Bytes.length(input) > maximum do
    Err(OversizedInput)
  else
    case reader(input, maximum) do
      Err(_) -> Err(MalformedEncoding)
      Ok(state)
    end
  end
end

pub fn protocol_take_u8(state :: BinaryReader) -> ProtocolReadInt!ProtocolError do
  case read_u8(state) do
    Err(_) -> Err(MalformedEncoding)
    Ok((next, value)) -> Ok(ProtocolReadInt {
      state: next,
      value: value
    })
  end
end

pub fn protocol_take_u16(state :: BinaryReader) -> ProtocolReadInt!ProtocolError do
  case read_u16_be(state) do
    Err(_) -> Err(MalformedEncoding)
    Ok((next, value)) -> Ok(ProtocolReadInt {
      state: next,
      value: value
    })
  end
end

pub fn protocol_take_fixed(state :: BinaryReader, length :: Int) -> ProtocolReadBytes!ProtocolError do
  case read_fixed(state, length) do
    Err(_) -> Err(MalformedEncoding)
    Ok((next, value)) -> Ok(ProtocolReadBytes {
      state: next,
      value: value
    })
  end
end

pub fn protocol_take_suite_fixed(state :: BinaryReader, suite :: Int, length :: Int) -> ProtocolReadBytes!ProtocolError do
  if suite == 2 do
    protocol_take_fixed(state, length)
  else if suite == 1 do
    Ok(ProtocolReadBytes {
      state: state,
      value: Bytes.empty()
    })
  else
    Err(UnsupportedSuite)
  end
end

pub fn protocol_take_vector(state :: BinaryReader, maximum :: Int) -> ProtocolReadBytes!ProtocolError do
  case read_vector(state, maximum) do
    Err(_) -> Err(MalformedEncoding)
    Ok((next, value)) -> Ok(ProtocolReadBytes {
      state: next,
      value: value
    })
  end
end

pub fn protocol_take_u32(state :: BinaryReader) -> ProtocolReadWide!ProtocolError do
  let bytes = protocol_take_fixed(state, 4)?
  case Bytes.read_u32_be(bytes.value, 0) do
    Err(_) -> Err(MalformedEncoding)
    Ok(value) -> Ok(ProtocolReadWide {
      state: bytes.state,
      value: value
    })
  end
end

pub fn protocol_take_u64(state :: BinaryReader) -> ProtocolReadWide!ProtocolError do
  let bytes = protocol_take_fixed(state, 8)?
  case Bytes.read_u64_be(bytes.value, 0) do
    Err(_) -> Err(MalformedEncoding)
    Ok(value) -> Ok(ProtocolReadWide {
      state: bytes.state,
      value: value
    })
  end
end

pub fn protocol_as_int(value :: U64) -> Int!ProtocolError do
  case U64.to_int(value) do
    Err(_) -> Err(MalformedEncoding)
    Ok(result)
  end
end

pub fn protocol_require_end(state :: BinaryReader) -> Result<(), ProtocolError> do
  case finish(state) do
    Err(_) -> Err(MalformedEncoding)
    Ok(_) -> Ok(nil)
  end
end

pub fn protocol_valid_magic(value :: Bytes, expected :: String) -> Result<(), ProtocolError> do
  if Bytes.secure_equals(value, Bytes.from_utf8(expected)) do
    Ok(nil)
  else
    Err(MalformedEncoding)
  end
end

pub fn protocol_read_ack_ids(state :: BinaryReader,
  count :: Int,
  index :: Int,
  output :: List<Bytes>) -> ProtocolReadIds!ProtocolError do
  if index >= count do
    Ok(ProtocolReadIds {
      state: state,
      value: output
    })
  else
    let id = protocol_take_fixed(state, 16)?
    protocol_read_ack_ids(id.state, count, index + 1, List.append(output, id.value))
  end
end
