from Binary.Reader import BinaryReader, finish, read_fixed, read_u8, read_vector, reader

pub type TransportPacket do
  InitialPacket( account_identity :: Bytes, message :: Bytes)

  RatchetPacket( message :: Bytes)
end deriving(Eq, Debug)

struct ReadInt do
  state :: BinaryReader
  value :: Int
end

struct ReadBytes do
  state :: BinaryReader
  value :: Bytes
end

fn append(left :: Bytes, right :: Bytes) -> Bytes ! String do
  case Bytes.concat(left, right) do
    Err( _) -> Err("transport packet too large")
    Ok( value) -> Ok(value)
  end
end

fn join(parts :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, append(output, List.get(parts, index)) ?)
  end
end

fn byte(value :: Int) -> Bytes ! String do
  case Bytes.from_list([value]) do
    Err( _) -> Err("invalid transport packet")
    Ok( encoded) -> Ok(encoded)
  end
end

fn vector(value :: Bytes) -> Bytes ! String do
  let length = case U64.parse(Int.to_string(Bytes.length(value))) do
    Err( _) -> Err("invalid transport packet length")
    Ok( parsed) -> Ok(parsed)
  end ?
  let encoded = case Bytes.write_u32_be(length) do
    Err( _) -> Err("invalid transport packet length")
    Ok( output) -> Ok(output)
  end ?
  append(encoded, value)
end

pub fn encode_packet(value :: TransportPacket) -> Bytes ! String do
  let encoded = case value do
    InitialPacket( account_identity, message) -> if Bytes.length(account_identity) == 0 || Bytes.length(account_identity) > 16582 || Bytes.length(message) == 0 || Bytes.length(message) > 48800 do
      Err("invalid initial transport packet")
    else
      join([byte(1) ?, Bytes.from_utf8("M8P"), byte(1) ?, vector(account_identity) ?, vector(message) ?],
      0,
      Bytes.empty())
    end
    RatchetPacket( message) -> if Bytes.length(message) == 0 || Bytes.length(message) > 48800 do
      Err("invalid ratchet transport packet")
    else
      join([byte(1) ?, Bytes.from_utf8("M8P"), byte(2) ?, vector(Bytes.empty()) ?, vector(message) ?],
      0,
      Bytes.empty())
    end
  end ?
  if Bytes.length(encoded) > 65536 do
    Err("transport packet too large")
  else
    Ok(encoded)
  end
end

fn take_u8(state :: BinaryReader) -> ReadInt ! String do
  case read_u8(state) do
    Err( _) -> Err("invalid transport packet")
    Ok( ( next, value)) -> Ok(ReadInt {
      state : next,
      value : value
    })
    Ok( _) -> Err("invalid transport packet")
  end
end

fn take_fixed(state :: BinaryReader, length :: Int) -> ReadBytes ! String do
  case read_fixed(state, length) do
    Err( _) -> Err("invalid transport packet")
    Ok( ( next, value)) -> Ok(ReadBytes {
      state : next,
      value : value
    })
    Ok( _) -> Err("invalid transport packet")
  end
end

fn take_vector(state :: BinaryReader, maximum :: Int) -> ReadBytes ! String do
  case read_vector(state, maximum) do
    Err( _) -> Err("invalid transport packet")
    Ok( ( next, value)) -> Ok(ReadBytes {
      state : next,
      value : value
    })
    Ok( _) -> Err("invalid transport packet")
  end
end

pub fn decode_packet(input :: Bytes) -> TransportPacket ! String do
  let state = case reader(input, 65536) do
    Err( _) -> Err("invalid transport packet")
    Ok( value) -> Ok(value)
  end ?
  let version = take_u8(state) ?
  let magic = take_fixed(version.state, 3) ?
  let kind = take_u8(magic.state) ?
  let account = take_vector(kind.state, 16582) ?
  let message = take_vector(account.state, 48800) ?
  let _ = case finish(message.state) do
    Err( _) -> Err("invalid transport packet")
    Ok( _) -> Ok(nil)
  end ?
  if version.value != 1 || !Bytes.secure_equals(magic.value, Bytes.from_utf8("M8P")) || Bytes.length(message.value) == 0 do
    Err("invalid transport packet")
  else
    if kind.value == 1 && Bytes.length(account.value) > 0 do
      Ok(InitialPacket(account.value, message.value))
    else
      if kind.value == 2 && Bytes.length(account.value) == 0 do
        Ok(RatchetPacket(message.value))
      else
        Err("invalid transport packet")
      end
    end
  end
end
