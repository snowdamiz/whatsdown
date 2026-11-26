##! Binary helpers shared by the transparency v2, fork evidence and gossip
##! codecs. Integers are big-endian; vectors carry a u32 length.

from Binary.Reader import (
  BinaryReader,
  finish,
  read_fixed,
  read_u16_be,
  read_u8,
  read_vector,
  reader
)

pub struct TcodecInt do
  state :: BinaryReader
  value :: Int
end

pub struct TcodecBytes do
  state :: BinaryReader
  value :: Bytes
end

pub struct TcodecHashes do
  state :: BinaryReader
  value :: List<Bytes>
end

fn join_from(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    case Bytes.concat(output, List.get(parts, index)) do
      Err(_) -> Err("transparency wire allocation failed")
      Ok(next) -> join_from(parts, index + 1, next)
    end
  end
end

pub fn tcodec_join(parts :: List<Bytes>) -> Bytes!String do
  join_from(parts, 0, Bytes.empty())
end

pub fn tcodec_u8(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("invalid transparency wire integer")
    Ok(output)
  end
end

pub fn tcodec_u16(value :: Int) -> Bytes!String do
  case Bytes.write_u16_be(value) do
    Err(_) -> Err("invalid transparency wire integer")
    Ok(output)
  end
end

pub fn tcodec_wide(value :: Int) -> U64!String do
  if value < 0 do
    Err("invalid transparency wire integer")
  else
    U64.parse(Int.to_string(value))
  end
end

pub fn tcodec_u32(value :: Int) -> Bytes!String do
  case Bytes.write_u32_be(tcodec_wide(value)?) do
    Err(_) -> Err("invalid transparency wire integer")
    Ok(output)
  end
end

pub fn tcodec_u64(value :: Int) -> Bytes!String do
  case Bytes.write_u64_be(tcodec_wide(value)?) do
    Err(_) -> Err("invalid transparency wire integer")
    Ok(output)
  end
end

pub fn tcodec_vector(value :: Bytes) -> Bytes!String do
  tcodec_join([tcodec_u32(Bytes.length(value))?, value])
end

# Hashes are written back to back; every one must be 32 bytes.

pub fn tcodec_hashes(values :: List<Bytes>) -> Bytes!String do
  if List.all(values, fn value -> Bytes.length(value) == 32 end) do
    tcodec_join(values)
  else
    Err("invalid transparency hashes")
  end
end

pub fn tcodec_take_u8(state :: BinaryReader) -> TcodecInt!String do
  case read_u8(state) do
    Err(_) -> Err("invalid transparency wire")
    Ok((next, value)) -> Ok(TcodecInt { state: next, value: value })
  end
end

pub fn tcodec_take_u16(state :: BinaryReader) -> TcodecInt!String do
  case read_u16_be(state) do
    Err(_) -> Err("invalid transparency wire")
    Ok((next, value)) -> Ok(TcodecInt { state: next, value: value })
  end
end

pub fn tcodec_take_fixed(state :: BinaryReader, length :: Int) -> TcodecBytes!String do
  case read_fixed(state, length) do
    Err(_) -> Err("invalid transparency wire")
    Ok((next, value)) -> Ok(TcodecBytes { state: next, value: value })
  end
end

pub fn tcodec_take_vector(state :: BinaryReader, maximum :: Int) -> TcodecBytes!String do
  case read_vector(state, maximum) do
    Err(_) -> Err("invalid transparency wire")
    Ok((next, value)) -> Ok(TcodecBytes { state: next, value: value })
  end
end

pub fn tcodec_take_u32(state :: BinaryReader) -> TcodecInt!String do
  let value = tcodec_take_fixed(state, 4)?
  case Bytes.read_u32_be(value.value, 0) do
    Err(_) -> Err("invalid transparency wire integer")
    Ok(wide) -> case U64.to_int(wide) do
      Err(_) -> Err("invalid transparency wire integer")
      Ok(parsed) -> Ok(TcodecInt { state: value.state, value: parsed })
    end
  end
end

# A u64 that does not fit Int (2^63 and above) is refused.

pub fn tcodec_take_u64(state :: BinaryReader) -> TcodecInt!String do
  let value = tcodec_take_fixed(state, 8)?
  case Bytes.read_u64_be(value.value, 0) do
    Err(_) -> Err("invalid transparency wire integer")
    Ok(wide) -> case U64.to_int(wide) do
      Err(_) -> Err("invalid transparency wire integer")
      Ok(parsed) -> Ok(TcodecInt { state: value.state, value: parsed })
    end
  end
end

fn hashes_from(state :: BinaryReader, count :: Int, output :: List<Bytes>) -> TcodecHashes!String do
  if List.length(output) >= count do
    Ok(TcodecHashes { state: state, value: output })
  else
    let value = tcodec_take_fixed(state, 32)?
    hashes_from(value.state, count, List.append(output, value.value))
  end
end

pub fn tcodec_take_hashes(state :: BinaryReader, count :: Int) -> TcodecHashes!String do
  hashes_from(state, count, List.new())
end

# A u8 count (at most maximum) followed by that many 32-byte hashes.

pub fn tcodec_take_path(state :: BinaryReader, maximum :: Int) -> TcodecHashes!String do
  let count = tcodec_take_u8(state)?
  if count.value > maximum do
    Err("invalid transparency hashes")
  else
    tcodec_take_hashes(count.state, count.value)
  end
end

pub fn tcodec_path(values :: List<Bytes>, maximum :: Int) -> Bytes!String do
  if List.length(values) > maximum do
    Err("invalid transparency hashes")
  else
    tcodec_join([tcodec_u8(List.length(values))?, tcodec_hashes(values)?])
  end
end

pub fn tcodec_start(input :: Bytes,
  maximum :: Int,
  version :: Int,
  tag :: String) -> BinaryReader!String do
  if Bytes.length(input) > maximum do
    Err("transparency wire oversized")
  else
    let state = case reader(input, maximum) do
      Err(_) -> Err("invalid transparency wire")
      Ok(value)
    end?
    let found = tcodec_take_u8(state)?
    let magic = tcodec_take_fixed(found.state, 3)?
    if found.value != version do
      Err("unsupported transparency wire version")
    else if !Bytes.secure_equals(magic.value, Bytes.from_utf8(tag)) do
      Err("invalid transparency wire")
    else
      Ok(magic.state)
    end
  end
end

pub fn tcodec_done(state :: BinaryReader) -> Result<(), String> do
  case finish(state) do
    Err(_) -> Err("invalid transparency wire")
    Ok(_) -> Ok(nil)
  end
end

# Canonical ASCII decimal: digits only, no sign, no leading zero, fits Int.

pub fn tcodec_decimal(text :: String) -> Int!String do
  let digits = Bytes.to_list(Bytes.from_utf8(text))
  let canonical = List.length(digits) > 0
    && List.length(digits) <= 18
    && List.all(digits, fn digit -> digit >= 48 && digit <= 57 end)
    && (List.length(digits) == 1 || List.get(digits, 0) != 48)
  case String.to_int(text) do
    Some(value) -> if canonical do
      Ok(value)
    else
      Err("invalid decimal")
    end
    None -> Err("invalid decimal")
  end
end

# The version byte of a frame, so a server can answer v1 with v1 and v2 with v2.

pub fn transparency_frame_version(input :: Bytes) -> Int!String do
  case Bytes.get(input, 0) do
    Err(_) -> Err("invalid transparency wire")
    Ok(value)
  end
end
