from Groups.GroupPayload import GroupPayload, encode_group_payload, decode_group_payload
from Groups.Mls import GroupError
from Groups.GroupCodec import (
  group_byte,
  group_join,
  group_write_u32,
  group_write_u64,
  group_wire_reader,
  group_wire_u8,
  group_wire_u32,
  group_wire_u64,
  group_wire_magic,
  group_wire_fixed,
  group_wire_end
)

## GMS6 authenticates this GAP2 frame inside its ciphertext. A duration is a
## per-message sender choice, not a global policy imposed on other senders.
pub struct TimedGroupPayload do
  timestamp :: U64
  disappearing_seconds :: Int
  payload :: GroupPayload
end

fn valid(value :: TimedGroupPayload) -> Bool do
  value.disappearing_seconds >= 1
    && value.disappearing_seconds <= 2592000
    && value.payload.kind == 1
    && Bytes.length(value.payload.body) <= 65225
end

fn encode(value :: TimedGroupPayload) -> Bytes!GroupError do
  if !valid(value) do
    return Err(InvalidGroup)
  end
  let legacy = case encode_group_payload(value.payload) do
    Err(_) -> return Err(InvalidGroup)
    Ok(value) -> value
  end
  let tail = case Bytes.slice(legacy, 4, Bytes.length(legacy) - 4) do
    Err(_) -> return Err(InvalidGroup)
    Ok(value) -> value
  end
  group_join([
      group_byte(2)?,
      Bytes.from_utf8("GAP"),
      group_write_u64(value.timestamp)?,
      group_write_u32(value.disappearing_seconds)?,
      tail
    ],
    0,
    Bytes.empty())
end

fn decode(input :: Bytes) -> TimedGroupPayload!GroupError do
  let version = group_wire_u8(group_wire_reader(input, 65290)?)?
  if version.value != 2 do
    return Err(InvalidGroup)
  end
  let state = group_wire_magic(version.state, "GAP")?
  let timestamp = group_wire_u64(state)?
  let duration = group_wire_u32(timestamp.state)?
  let tail = group_wire_fixed(duration.state, Bytes.length(input) - 16)?
  group_wire_end(tail.state)?
  let legacy = group_join([group_byte(1)?, Bytes.from_utf8("GAP"), tail.value], 0, Bytes.empty())?
  let payload = case decode_group_payload(legacy) do
    Err(_) -> return Err(InvalidGroup)
    Ok(value) -> value
  end
  let value = TimedGroupPayload {
    timestamp: timestamp.value,
    disappearing_seconds: duration.value,
    payload: payload
  }
  if valid(value) do
    Ok(value)
  else
    Err(InvalidGroup)
  end
end

pub fn encode_timed_group_payload(value :: TimedGroupPayload) -> Bytes!String do
  case encode(value) do
    Err(_) -> Err("invalid_timed_group_payload")
    Ok(value)
  end
end

pub fn decode_timed_group_payload(input :: Bytes) -> TimedGroupPayload!String do
  case decode(input) do
    Err(_) -> Err("invalid_timed_group_payload")
    Ok(value)
  end
end
