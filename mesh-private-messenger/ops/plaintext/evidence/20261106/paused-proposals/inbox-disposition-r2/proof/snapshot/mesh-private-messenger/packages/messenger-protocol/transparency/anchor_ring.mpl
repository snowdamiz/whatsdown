##! Judge account layout v1. These are decoded account bytes, not authenticated
##! anchors: callers must check native pins and RPC quorum before using them.
pub struct AnchorHeader do
  log_id :: Bytes
  head :: Int
  count :: Int
  last_sequence :: U64
  last_size :: U64
  last_slot :: U64
end

pub struct AnchorEntry do
  sequence :: U64
  tree_size :: U64
  tree_root :: Bytes
  checkpoint_hash :: Bytes
  timestamp :: U64
  slot :: U64
  cosign_bitmap :: Int
  log_version :: Int
  rollback :: Bool
  native_bitmap :: Int
  witness_generation :: Int
end

pub fn decode_anchor_header(bytes :: Bytes) -> AnchorHeader!String do
  if Bytes.length(bytes) != 64 || Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "4d524701" do
    return Err("invalid_anchor_header")
  end
  let value = AnchorHeader {
    log_id: Bytes.slice(bytes, 4, 32)?,
    head: read_short(bytes, 36)?,
    count: read_short(bytes, 38)?,
    last_sequence: read_wide(bytes, 40)?,
    last_size: read_wide(bytes, 48)?,
    last_slot: read_wide(bytes, 56)?
  }
  if value.head >= 4096
    || value.count > 4096
    || (value.count > 0 && value.count < 4096 && value.head != value.count - 1) do
    return Err("invalid_anchor_header")
  end
  if value.count == 0
    && (value.head != 0
      || U64.to_string(value.last_sequence) != "0"
      || U64.to_string(value.last_size) != "0"
      || U64.to_string(value.last_slot) != "0") do
    return Err("invalid_anchor_header")
  end
  Ok(value)
end

pub fn anchor_bitmap_contains(bitmap :: Int, index :: Int) -> Bool do
  if index < 0 || index >= 16 || bitmap < 0 || bitmap > 65535 do
    false
  else
    let divisor = List.get([
        1,
        2,
        4,
        8,
        16,
        32,
        64,
        128,
        256,
        512,
        1024,
        2048,
        4096,
        8192,
        16384,
        32768
      ],
      index)
    (bitmap / divisor) % 2 == 1
  end
end

pub fn decode_anchor_entry(bytes :: Bytes) -> AnchorEntry!String do
  if Bytes.length(bytes) != 104 do
    return Err("invalid_anchor_entry")
  end
  let flags = Bytes.get(bytes, 99)?
  let value = AnchorEntry {
    sequence: read_wide(bytes, 0)?,
    tree_size: read_wide(bytes, 8)?,
    tree_root: Bytes.slice(bytes, 16, 32)?,
    checkpoint_hash: Bytes.slice(bytes, 48, 32)?,
    timestamp: read_wide(bytes, 80)?,
    slot: read_wide(bytes, 88)?,
    cosign_bitmap: read_short(bytes, 96)?,
    log_version: Bytes.get(bytes, 98)?,
    rollback: flags == 1,
    native_bitmap: read_short(bytes, 100)?,
    witness_generation: read_short(bytes, 102)?
  }
  if (value.log_version != 1 && value.log_version != 2) || flags > 1
    || (value.witness_generation == 0 && value.cosign_bitmap != 0) do
    return Err("invalid_anchor_entry")
  end
  for index in 0..16 do
    if anchor_bitmap_contains(value.native_bitmap, index)
      && !anchor_bitmap_contains(value.cosign_bitmap, index) do
      return Err("invalid_anchor_entry")
    end
  end
  Ok(value)
end

# distance=0 is the most recently posted entry. Unfilled slots are inaccessible.
pub fn anchor_entry_offset(header :: AnchorHeader, distance :: Int) -> Int!String do
  if distance < 0
    || distance >= header.count
    || header.count > 4096
    || header.head < 0
    || header.head >= 4096 do
    Err("anchor_entry_not_found")
  else
    Ok(64 + ((header.head - distance + 4096) % 4096) * 104)
  end
end

pub fn anchor_entry_in_header(header :: AnchorHeader,
  entry :: AnchorEntry,
  distance :: Int) -> Bool do
  distance >= 0
    && distance < header.count
    && U64.compare(entry.slot, header.last_slot) <= 0
    && (distance != 0
      || (U64.compare(entry.sequence, header.last_sequence) == 0
        && U64.compare(entry.tree_size, header.last_size) == 0
        && U64.compare(entry.slot, header.last_slot) == 0))
end

fn read_short(bytes :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u16_le(bytes, offset) do
    Err(_) -> Err("invalid_anchor_account")
    Ok(value)
  end
end

fn read_wide(bytes :: Bytes, offset :: Int) -> U64!String do
  case Bytes.read_u64_le(bytes, offset) do
    Err(_) -> Err("invalid_anchor_account")
    Ok(value)
  end
end
