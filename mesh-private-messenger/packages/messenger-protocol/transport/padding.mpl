# The length and padding are encrypted together. Overhead includes the complete
# client packet header and authentication tag, so only its bucket is visible.

fn bucket(length :: Int, candidate :: Int) -> Int ! String do
  if length > 65536 do
    Err("padded message too large")
  else if length <= candidate do
    Ok(candidate)
  else
    bucket(length, candidate * 2)
  end
end

pub fn pad_message(value :: Bytes, overhead :: Int) -> Bytes ! String do
  if overhead < 0 || overhead > 65532 do
    Err("invalid padding overhead")
  else
    let size = bucket(Bytes.length(value) + 4 + overhead, 256) ?
    let wide = case U64.parse(Int.to_string(Bytes.length(value))) do
      Err(_) -> Err("invalid padded message")
      Ok(parsed) -> Ok(parsed)
    end ?
    let length = case Bytes.write_u32_be(wide) do
      Err(_) -> Err("invalid padded message")
      Ok(bytes) -> Ok(bytes)
    end ?
    let padding = case Bytes.repeat(0, size - overhead - 4 - Bytes.length(value)) do
      Err(_) -> Err("invalid padded message")
      Ok(bytes) -> Ok(bytes)
    end ?
    Bytes.concat(Bytes.concat(length, value) ?, padding)
  end
end

pub fn unpad_message(value :: Bytes, overhead :: Int) -> Bytes ! String do
  let size = Bytes.length(value)
  if overhead < 0 || overhead > 65532 || size < 4 || size + overhead > 65536 do
    Err("invalid padded message")
  else
    let length = case Bytes.read_u32_be(value, 0) do
      Err(_) -> Err("invalid padded message")
      Ok(wide) -> case U64.to_int(wide) do
        Err(_) -> Err("invalid padded message")
        Ok(parsed) -> Ok(parsed)
      end
    end ?
    if length > size - 4 || (bucket(length + 4 + overhead, 256) ?) != size + overhead do
      Err("invalid padded message")
    else
      let padding = Bytes.slice(value, length + 4, size - length - 4) ?
      let zeroes = case Bytes.repeat(0, Bytes.length(padding)) do
        Err(_) -> Err("invalid padded message")
        Ok(bytes) -> Ok(bytes)
      end ?
      if !Bytes.secure_equals(padding, zeroes) do
        Err("invalid padded message")
      else
        Bytes.slice(value, 4, length)
      end
    end
  end
end
