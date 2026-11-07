##! Bounded RFC 9458 key encoding for Morse's selected suite. Parsing confers no trust.

pub struct OhttpKeyConfig do
  key_id :: Int
  public_key :: X25519PublicKey
end

fn invalid() -> String do
  "ohttp_invalid_key_configuration"
end

fn byte_at(input :: Bytes, offset :: Int) -> Int!String do
  case Bytes.get(input, offset) do
    Err(_) -> Err(invalid())
    Ok(value)
  end
end

fn u16_at(input :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u16_be(input, offset) do
    Err(_) -> Err(invalid())
    Ok(value)
  end
end

fn take(input :: Bytes, offset :: Int, count :: Int) -> Bytes!String do
  case Bytes.slice(input, offset, count) do
    Err(_) -> Err(invalid())
    Ok(value)
  end
end

fn join(parts :: List<Bytes>, maximum :: Int) -> Bytes!String do
  case Bytes.concat_many(parts, maximum) do
    Err(_) -> Err(invalid())
    Ok(value)
  end
end

fn u16(value :: Int) -> Bytes!String do
  case Bytes.write_u16_be(value) do
    Err(_) -> Err(invalid())
    Ok(output)
  end
end

fn offered(input :: Bytes, offset :: Int, found :: Bool) -> Bool!String do
  if offset == Bytes.length(input) do
    Ok(found)
  else
    let kdf = u16_at(input, offset)?
    let aead = u16_at(input, offset + 2)?
    offered(input, offset + 4, found || (kdf == 1 && aead == 3))
  end
end

# This is a bounded application profile, not a universal HPKE key parser.
# A valid configuration for another KEM or suite can be unsupported here.
pub fn decode_key_config(input :: Bytes) -> OhttpKeyConfig!String do
  let size = Bytes.length(input)
  if size < 41 || size > 101 do
    return Err(invalid())
  end
  if u16_at(input, 1)? != 32 do
    return Err("ohttp_unsupported_key_configuration")
  end
  let algorithms = u16_at(input, 35)?
  if algorithms < 4 || algorithms > 64 || algorithms % 4 != 0 || algorithms != size - 37 do
    return Err(invalid())
  end
  if !offered(input, 37, false)? do
    return Err("ohttp_unsupported_key_configuration")
  end
  Ok(OhttpKeyConfig {
    key_id: byte_at(input, 0)?,
    public_key: X25519PublicKey { bytes: take(input, 3, 32)? }
  })
end

pub fn encode_key_config(value :: OhttpKeyConfig) -> Bytes!String do
  if value.key_id < 0 || value.key_id > 255 || Bytes.length(value.public_key.bytes) != 32 do
    return Err(invalid())
  end
  let id = case Bytes.from_list([value.key_id]) do
    Err(_) -> return Err(invalid())
    Ok(bytes) -> bytes
  end
  join([id, u16(32)?, value.public_key.bytes, u16(4)?, u16(1)?, u16(3)?], 41)
end

fn distinct(previous :: List<OhttpKeyConfig>, next :: OhttpKeyConfig) -> Result<(), String> do
  for value in previous do
    if value.key_id == next.key_id
      || Bytes.secure_equals(value.public_key.bytes, next.public_key.bytes) do
      return Err("ohttp_duplicate_key_configuration")
    end
  end
  Ok(nil)
end

fn collection(input :: Bytes,
  offset :: Int,
  values :: List<OhttpKeyConfig>) -> List<OhttpKeyConfig>!String do
  if offset == Bytes.length(input) do
    return Ok(values)
  end
  if List.length(values) >= 2 || Bytes.length(input) - offset < 2 do
    return Err(invalid())
  end
  let length = u16_at(input, offset)?
  let start = offset + 2
  if length < 41 || length > 101 || length > Bytes.length(input) - start do
    return Err(invalid())
  end
  let next = decode_key_config(take(input, start, length)?)?
  distinct(values, next)?
  collection(input, start + length, List.append(values, next))
end

# Validate the entire collection before returning even the first key. There is
# no partial recovery, trust acquisition, preferred-key selection or rotation.
pub fn decode_key_configs(input :: Bytes) -> List<OhttpKeyConfig>!String do
  if Bytes.length(input) < 43 || Bytes.length(input) > 206 do
    return Err(invalid())
  end
  collection(input, 0, [])
end

pub fn encode_key_configs(values :: List<OhttpKeyConfig>) -> Bytes!String do
  if List.length(values) < 1 || List.length(values) > 2 do
    return Err(invalid())
  end
  let first = encode_key_config(List.get(values, 0))?
  if List.length(values) == 1 do
    return join([u16(41)?, first], 43)
  end
  let second = List.get(values, 1)
  distinct([List.get(values, 0)], second)?
  join([u16(41)?, first, u16(41)?, encode_key_config(second)?], 86)
end
