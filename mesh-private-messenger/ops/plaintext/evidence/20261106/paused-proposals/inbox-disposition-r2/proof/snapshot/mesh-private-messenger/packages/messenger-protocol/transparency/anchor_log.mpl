from Transparency.Config import valid_witness_id

# Account bytes only. The native reader authenticates owner, address, log ID
# and service key through its pinned RPC quorum before using this record.
pub struct AnchorLog do
  version :: Int
  service_slashed :: Bool
  attendance_enabled :: Bool
  name :: String
  log_id :: Bytes
  service_public_key :: Bytes
  anchor_authority :: Bytes
  ring_address :: Bytes
  directory_bond_vault :: Bytes
  ready_at :: U64
  witness_generation :: Int
  origin :: String
end

fn short(bytes :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u16_le(bytes, offset) do
    Err(_) -> Err("invalid_anchor_log")
    Ok(value)
  end
end

fn wide(bytes :: Bytes, offset :: Int) -> U64!String do
  case Bytes.read_u64_le(bytes, offset) do
    Err(_) -> Err("invalid_anchor_log")
    Ok(value)
  end
end

fn zeroes(bytes :: Bytes, offset :: Int, length :: Int) -> Bool!String do
  Ok(Bytes.to_hex(Bytes.slice(bytes, offset, length)?) == String.repeat("00", length))
end

pub fn decode_anchor_log(bytes :: Bytes) -> AnchorLog!String do
  if Bytes.length(bytes) != 352 || Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "4d4c4701" do
    return Err("invalid_anchor_log")
  end
  let version = Bytes.get(bytes, 4)?
  let slashed = Bytes.get(bytes, 5)?
  let name_length = Bytes.get(bytes, 6)?
  let origin_length = short(bytes, 210)?
  if (version != 1 && version != 2)
    || slashed > 1
    || Bytes.get(bytes, 7)? > 1
    || name_length == 0
    || name_length > 32
    || origin_length > 128
    || (version == 1 && origin_length != 0)
    || (version == 2 && origin_length == 0) do
    return Err("invalid_anchor_log")
  end
  let name_bytes = Bytes.slice(bytes, 8, name_length)?
  let name = Bytes.to_utf8(name_bytes)?
  let origin_bytes = Bytes.slice(bytes, 212, origin_length)?
  let origin = Bytes.to_utf8(origin_bytes)?
  let ready = wide(bytes, 200)?
  if !valid_witness_id(name)
    || !Bytes.secure_equals(Crypto.sha256(name_bytes), Bytes.slice(bytes, 40, 32)?)
    || !zeroes(bytes, 8 + name_length, 32 - name_length)?
    || !zeroes(bytes, 212 + origin_length, 128 - origin_length)?
    || !zeroes(bytes, 340, 12)?
    || zeroes(bytes, 72, 32)?
    || zeroes(bytes, 104, 32)?
    || U64.compare(ready, U64.parse("9223372036854775807")?) > 0 do
    return Err("invalid_anchor_log")
  end
  for index in 0..origin_length do
    let byte = Bytes.get(origin_bytes, index)?
    if byte < 33 || byte > 126 || byte == 43 do
      return Err("invalid_anchor_log")
    end
  end
  Ok(AnchorLog {
    version: version,
    service_slashed: slashed == 1,
    attendance_enabled: Bytes.get(bytes, 7)? == 1,
    name: name,
    log_id: Bytes.slice(bytes, 40, 32)?,
    service_public_key: Bytes.slice(bytes, 72, 32)?,
    anchor_authority: Bytes.slice(bytes, 104, 32)?,
    ring_address: Bytes.slice(bytes, 136, 32)?,
    directory_bond_vault: Bytes.slice(bytes, 168, 32)?,
    ready_at: ready,
    witness_generation: short(bytes, 208)?,
    origin: origin
  })
end
