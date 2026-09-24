from Binary.Reader import BinaryReader, finish, read_fixed, reader

pub struct ObjectGrantRequest do
  object_id :: Bytes
  part_count :: Int
  expires_at :: U64
  work_expires_at :: U64
  nonce :: Int
  upload_capability :: Bytes
  download_capability :: Bytes
end

pub struct ObjectGrantResponse do
  object_id :: Bytes
end

pub struct ObjectControl do
  object_id :: Bytes
  capability :: Bytes
end

struct ReadBytes do
  state :: BinaryReader
  value :: Bytes
end

struct ReadInt do
  state :: BinaryReader
  value :: Int
end

struct ReadWide do
  state :: BinaryReader
  value :: U64
end

fn append(left :: Bytes, right :: Bytes) -> Bytes!String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("object grant allocation failed")
    Ok(output)
  end
end

fn join(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, append(output, List.get(parts, index))?)
  end
end

fn byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("invalid object grant integer")
    Ok(output)
  end
end

fn write_u32(value :: Int) -> Bytes!String do
  if value < 0 do
    Err("invalid object grant integer")
  else
    let wide = U64.parse(Int.to_string(value))?
    case Bytes.write_u32_be(wide) do
      Err(_) -> Err("invalid object grant integer")
      Ok(output)
    end
  end
end

fn write_u64(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err("invalid object grant integer")
    Ok(output)
  end
end

fn take_fixed(state :: BinaryReader, length :: Int) -> ReadBytes!String do
  case read_fixed(state, length) do
    Err(_) -> Err("invalid object wire")
    Ok((next, value)) -> Ok(ReadBytes {
      state: next,
      value: value
    })
  end
end

fn take_u32(state :: BinaryReader) -> ReadInt!String do
  let encoded = take_fixed(state, 4)?
  let wide = case Bytes.read_u32_be(encoded.value, 0) do
    Err(_) -> Err("invalid object integer")
    Ok(output)
  end?
  case U64.to_int(wide) do
    Err(_) -> Err("invalid object integer")
    Ok(value) -> Ok(ReadInt {
      state: encoded.state,
      value: value
    })
  end
end

fn take_u64(state :: BinaryReader) -> ReadWide!String do
  let encoded = take_fixed(state, 8)?
  case Bytes.read_u64_be(encoded.value, 0) do
    Err(_) -> Err("invalid object integer")
    Ok(value) -> Ok(ReadWide {
      state: encoded.state,
      value: value
    })
  end
end

fn start(input :: Bytes, size :: Int, magic_value :: String) -> BinaryReader!String do
  if Bytes.length(input) != size do
    Err("invalid object wire")
  else
    let initial = case reader(input, size) do
      Err(_) -> Err("invalid object wire")
      Ok(output)
    end?
    let version = take_fixed(initial, 1)?
    let magic = take_fixed(version.state, 3)?
    if Bytes.secure_equals(version.value, byte(1)?) && Bytes.secure_equals(magic.value,
      Bytes.from_utf8(magic_value)) do
      Ok(magic.state)
    else
      Err("invalid object wire")
    end
  end
end

fn done(state :: BinaryReader) -> Result<(), String> do
  case finish(state) do
    Err(_) -> Err("invalid object wire")
    Ok(_) -> Ok(nil)
  end
end

fn valid_shape(value :: ObjectGrantRequest) -> Bool do
  Bytes.length(value.object_id) == 32 && value.part_count >= 1 && value.part_count <= 257 && Bytes.length(value.upload_capability) == 32 && Bytes.length(value.download_capability) == 32 && !Bytes.secure_equals(value.upload_capability,
    value.download_capability)
end

fn work_hash(value :: ObjectGrantRequest, nonce :: Int) -> Bytes!String do
  Ok(Crypto.sha256(join([
      Bytes.from_utf8("mesh-msg/v1/object-grant-work"),
      value.object_id,
      write_u64(value.work_expires_at)?,
      write_u32(nonce)?,
      write_u32(value.part_count)?,
      write_u64(value.expires_at)?,
      Crypto.sha256(value.upload_capability),
      Crypto.sha256(value.download_capability)
    ],
    0,
    Bytes.empty())?))
end

fn power_of_two(exponent :: Int, value :: Int) -> Int do
  if exponent <= 0 do
    value
  else
    power_of_two(exponent - 1, value * 2)
  end
end

fn leading_zero_bits(hash :: Bytes, index :: Int, remaining :: Int) -> Bool do
  if remaining <= 0 do
    true
  else
    case Bytes.get(hash, index) do
      Err(_) -> false
      Ok(value) -> if remaining >= 8 do
        value == 0 && leading_zero_bits(hash, index + 1, remaining - 8)
      else
        value < power_of_two(8 - remaining, 1)
      end
    end
  end
end

fn mine(value :: ObjectGrantRequest, difficulty :: Int, nonce :: Int) -> ObjectGrantRequest!String do
  if nonce >= 2147483647 do
    Err("object work search exhausted")
  else if leading_zero_bits(work_hash(value, nonce)?, 0, difficulty) do
    Ok(ObjectGrantRequest {
      object_id: value.object_id,
      part_count: value.part_count,
      expires_at: value.expires_at,
      work_expires_at: value.work_expires_at,
      nonce: nonce,
      upload_capability: value.upload_capability,
      download_capability: value.download_capability
    })
  else
    mine(value, difficulty, nonce + 1)
  end
end

pub fn mint_grant(object_id :: Bytes,
  part_count :: Int,
  expires_at :: U64,
  work_expires_at :: U64,
  upload_capability :: Bytes,
  download_capability :: Bytes,
  difficulty :: Int) -> ObjectGrantRequest!String do
  let value = ObjectGrantRequest {
    object_id: object_id,
    part_count: part_count,
    expires_at: expires_at,
    work_expires_at: work_expires_at,
    nonce: 0,
    upload_capability: upload_capability,
    download_capability: download_capability
  }
  if !valid_shape(value) || difficulty < 1 || difficulty > 24 do
    Err("invalid object grant")
  else
    mine(value, difficulty, 0)
  end
end

pub fn encode_grant(value :: ObjectGrantRequest) -> Bytes!String do
  if !valid_shape(value) || value.nonce < 0 do
    Err("invalid object grant")
  else
    join([
        byte(1)?,
        Bytes.from_utf8("OGR"),
        value.object_id,
        write_u32(value.part_count)?,
        write_u64(value.expires_at)?,
        write_u64(value.work_expires_at)?,
        write_u32(value.nonce)?,
        value.upload_capability,
        value.download_capability
      ],
      0,
      Bytes.empty())
  end
end

pub fn decode_grant(input :: Bytes) -> ObjectGrantRequest!String do
  let object_id = take_fixed(start(input, 124, "OGR")?, 32)?
  let part_count = take_u32(object_id.state)?
  let expires_at = take_u64(part_count.state)?
  let work_expires_at = take_u64(expires_at.state)?
  let nonce = take_u32(work_expires_at.state)?
  let upload = take_fixed(nonce.state, 32)?
  let download = take_fixed(upload.state, 32)?
  done(download.state)?
  let value = ObjectGrantRequest {
    object_id: object_id.value,
    part_count: part_count.value,
    expires_at: expires_at.value,
    work_expires_at: work_expires_at.value,
    nonce: nonce.value,
    upload_capability: upload.value,
    download_capability: download.value
  }
  if valid_shape(value) do
    Ok(value)
  else
    Err("invalid object grant")
  end
end

pub fn verify_grant(input :: Bytes,
  now :: U64,
  maximum_work_future :: U64,
  maximum_object_future :: U64,
  difficulty :: Int) -> Bool!String do
  let value = decode_grant(input)?
  let latest_work = U64.add(now, maximum_work_future)?
  let latest_object = U64.add(now, maximum_object_future)?
  Ok(difficulty >= 1 && difficulty <= 24 && U64.compare(value.work_expires_at, now) >= 0 && U64.compare(value.work_expires_at,
    latest_work) <= 0 && U64.compare(value.expires_at, now) > 0 && U64.compare(value.expires_at,
    latest_object) <= 0 && leading_zero_bits(work_hash(value, value.nonce)?, 0, difficulty))
end

pub fn encode_grant_response(value :: ObjectGrantResponse) -> Bytes!String do
  if Bytes.length(value.object_id) != 32 do
    Err("invalid object grant response")
  else
    join([byte(1)?, Bytes.from_utf8("OGS"), value.object_id], 0, Bytes.empty())
  end
end

pub fn decode_grant_response(input :: Bytes) -> ObjectGrantResponse!String do
  let object_id = take_fixed(start(input, 36, "OGS")?, 32)?
  done(object_id.state)?
  Ok(ObjectGrantResponse { object_id: object_id.value })
end

fn encode_control(value :: ObjectControl, magic_value :: String) -> Bytes!String do
  if Bytes.length(value.object_id) != 32 || Bytes.length(value.capability) != 32 do
    Err("invalid object control")
  else
    join([byte(1)?, Bytes.from_utf8(magic_value), value.object_id, value.capability],
      0,
      Bytes.empty())
  end
end

fn decode_control(input :: Bytes, magic_value :: String) -> ObjectControl!String do
  let object_id = take_fixed(start(input, 68, magic_value)?, 32)?
  let capability = take_fixed(object_id.state, 32)?
  done(capability.state)?
  Ok(ObjectControl {
    object_id: object_id.value,
    capability: capability.value
  })
end

pub fn encode_complete(value :: ObjectControl) -> Bytes!String do
  encode_control(value, "OCP")
end

pub fn decode_complete(input :: Bytes) -> ObjectControl!String do
  decode_control(input, "OCP")
end

pub fn encode_delete(value :: ObjectControl) -> Bytes!String do
  encode_control(value, "ODL")
end

pub fn decode_delete(input :: Bytes) -> ObjectControl!String do
  decode_control(input, "ODL")
end
