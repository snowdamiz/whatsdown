##! The judge accounts the monitor reads (protocol/morse-judge-v1.md §4.2,
##! §4.3): the Log account and the anchor ring. On-chain integers are
##! little-endian.

from Transparency.Fork import ForkLog, ForkRingEntry
from Transparency.Merkle import WitnessKey

pub struct ChainWitness do
  witness_id :: String
  public_key :: Bytes
  since_slot :: Int
end

pub struct ChainLog do
  log_id :: Bytes
  service_key :: Bytes
  ring :: String
  service_slashed :: Bool
  witnesses :: List<ChainWitness>
end

pub struct RingHeader do
  head :: Int
  count :: Int
  last_sequence :: Int
  last_size :: Int
  last_slot :: Int
end

# index is the physical ring slot the entry was read from.

pub struct RingEntry do
  index :: Int
  sequence :: Int
  tree_size :: Int
  root :: Bytes
  hash :: Bytes
  timestamp_ms :: Int
  slot :: Int
  bitmap :: Int
  evidence :: Int
  epoch :: Int
  bytes :: Bytes
end

pub fn monitor_ring_capacity() -> Int do
  4096
end

pub fn monitor_log_length() -> Int do
  2584
end

pub fn monitor_entry_offset(index :: Int) -> Int do
  64 + 104 * index
end

fn slice(data :: Bytes, offset :: Int, length :: Int) -> Bytes!String do
  case Bytes.slice(data, offset, length) do
    Err(_) -> Err("judge account too short")
    Ok(value)
  end
end

fn byte(data :: Bytes, offset :: Int) -> Int!String do
  case Bytes.get(data, offset) do
    Err(_) -> Err("judge account too short")
    Ok(value)
  end
end

fn wide(value :: U64) -> Int!String do
  case U64.to_int(value) do
    Err(_) -> Err("judge account integer out of range")
    Ok(parsed)
  end
end

fn u64_at(data :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u64_le(data, offset) do
    Err(_) -> Err("judge account too short")
    Ok(value) -> wide(value)
  end
end

fn u32_at(data :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u32_le(data, offset) do
    Err(_) -> Err("judge account too short")
    Ok(value) -> wide(value)
  end
end

fn u16_at(data :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u16_le(data, offset) do
    Err(_) -> Err("judge account too short")
    Ok(value)
  end
end

# The log ID convention: the log's ASCII name, zero-padded to 32 bytes.

pub fn monitor_log_id(name :: String) -> Bytes!String do
  let text = Bytes.from_utf8(name)
  let padding = case Bytes.repeat(0, 32 - Bytes.length(text)) do
    Err(_) -> Err("log name too long")
    Ok(value)
  end?
  case Bytes.concat(text, padding) do
    Err(_) -> Err("log name too long")
    Ok(value)
  end
end

fn list_entry(data :: Bytes, index :: Int) -> ChainWitness!String do
  let base = 280 + 144 * index
  let length = byte(data, base)?
  if length < 1 || length > 64 do
    Err("invalid witness list entry")
  else
    let id = case Bytes.to_utf8(slice(data, base + 1, length)?) do
      Err(_) -> Err("invalid witness list entry")
      Ok(value)
    end?
    Ok(ChainWitness {
      witness_id: id,
      public_key: slice(data, base + 72, 32)?,
      since_slot: u64_at(data, base + 136)?
    })
  end
end

pub fn monitor_decode_log(data :: Bytes) -> ChainLog!String do
  let count = byte(data, 4)?
  if Bytes.length(data) != monitor_log_length() || byte(data, 0)? != 2 || byte(data, 1)? != 1 do
    Err("not a judge Log account")
  else if count > 16 do
    Err("invalid witness count")
  else
    let witnesses = for index in 0..count do
      list_entry(data, index)?
    end
    Ok(ChainLog {
      log_id: slice(data, 16, 32)?,
      service_key: slice(data, 48, 32)?,
      ring: Bytes.to_base58(slice(data, 112, 32)?),
      service_slashed: byte(data, 3)? == 1,
      witnesses: witnesses
    })
  end
end

pub fn monitor_decode_header(data :: Bytes) -> RingHeader!String do
  let header = RingHeader {
    head: u32_at(data, 32)?,
    count: u32_at(data, 36)?,
    last_sequence: u64_at(data, 40)?,
    last_size: u64_at(data, 48)?,
    last_slot: u64_at(data, 56)?
  }
  if Bytes.length(data) != 64
    || header.head >= monitor_ring_capacity()
    || header.count > monitor_ring_capacity() do
    Err("invalid ring header")
  else
    Ok(header)
  end
end

pub fn monitor_decode_entry(index :: Int, data :: Bytes) -> RingEntry!String do
  if Bytes.length(data) != 104 do
    Err("invalid ring entry")
  else
    Ok(RingEntry {
      index: index,
      sequence: u64_at(data, 0)?,
      tree_size: u64_at(data, 8)?,
      root: slice(data, 16, 32)?,
      hash: slice(data, 48, 32)?,
      timestamp_ms: u64_at(data, 80)?,
      slot: u64_at(data, 88)?,
      bitmap: u16_at(data, 96)?,
      evidence: byte(data, 98)?,
      epoch: u32_at(data, 100)?,
      bytes: data
    })
  end
end

# Splits ring slice bytes into entries starting at physical index first.

pub fn monitor_decode_entries(first :: Int, data :: Bytes) -> List<RingEntry>!String do
  let count = Bytes.length(data) / 104
  if count * 104 != Bytes.length(data) do
    Err("invalid ring slice")
  else
    Ok(for offset in 0..count do
      monitor_decode_entry(first + offset, slice(data, offset * 104, 104)?)?
    end)
  end
end

pub fn monitor_bit(bitmap :: Int, index :: Int) -> Bool do
  if index <= 0 do
    bitmap % 2 == 1
  else
    monitor_bit(bitmap / 2, index - 1)
  end
end

# Bit i counts only when list entry i was filled at or before the slot the
# anchor was posted in (a reused slot must not inherit old bits).

pub fn monitor_cosigned(log :: ChainLog, entry :: RingEntry, index :: Int) -> Bool do
  index < List.length(log.witnesses)
    && monitor_bit(entry.bitmap, index)
    && List.get(log.witnesses, index).since_slot <= entry.slot
end

pub fn monitor_fork_log(log :: ChainLog) -> ForkLog do
  ForkLog {
    service_public_key: log.service_key,
    witnesses: List.map(log.witnesses,
      fn witness -> WitnessKey {
        witness_id: witness.witness_id,
        public_key: witness.public_key
      } end)
  }
end

fn wide_of(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

pub fn monitor_fork_ring_entry(entry :: RingEntry) -> ForkRingEntry!String do
  Ok(ForkRingEntry {
    sequence: wide_of(entry.sequence)?,
    tree_size: wide_of(entry.tree_size)?,
    root: entry.root,
    checkpoint_hash: entry.hash,
    cosign_bitmap: entry.bitmap
  })
end
