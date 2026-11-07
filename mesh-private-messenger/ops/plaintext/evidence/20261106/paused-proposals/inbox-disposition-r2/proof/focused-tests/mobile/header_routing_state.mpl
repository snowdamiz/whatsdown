from Mobile.Codec import (
  mobile_join,
  mobile_read_u32,
  mobile_read_u64,
  mobile_write_u32,
  mobile_write_u64
)

## Encrypted local work only: no delivery acknowledgement or failed-attempt counter.
pub struct HeaderCursor do
  envelope :: Bytes
  packet :: Bytes
  profile :: Bytes
  sessions :: Bytes
  count :: Int
  offset :: Int
  first_tick :: U64
  progress_tick :: U64
end

pub struct HeaderRoutingState do
  tick :: U64
  cursors :: List<HeaderCursor>
end

fn number(value :: String) -> U64!String do
  U64.parse(value)
end

fn slice(input :: Bytes, start :: Int, length :: Int) -> Bytes!String do
  case Bytes.slice(input, start, length) do
    Err(_) -> Err("invalid_header_routing_state")
    Ok(value)
  end
end

pub fn empty_header_routing() -> HeaderRoutingState!String do
  Ok(HeaderRoutingState { tick: number("0")?, cursors: [] })
end

fn valid_cursor(value :: HeaderCursor, tick :: U64) -> Bool do
  Bytes.length(value.envelope) == 16
    && Bytes.length(value.packet) == 32
    && Bytes.length(value.profile) == 32
    && Bytes.length(value.sessions) == 32
    && value.count > 0
    && value.offset >= 0
    && value.offset < value.count
    && U64.compare(value.first_tick, value.progress_tick) <= 0
    && U64.compare(value.progress_tick, tick) <= 0
end

pub fn encode_header_routing(state :: HeaderRoutingState) -> Bytes!String do
  if List.length(state.cursors) > 256 do
    return Err("invalid_header_routing_state")
  end
  let chunks = for index in 0..List.length(state.cursors) do
    let value = List.get(state.cursors, index)
    if !valid_cursor(value, state.tick)
      || List.any(List.take(state.cursors, index),
        fn(previous) -> Bytes.secure_equals(previous.envelope, value.envelope) end) do
      return Err("invalid_header_routing_state")
    end
    case Bytes.concat_many([
        value.envelope,
        value.packet,
        value.profile,
        value.sessions,
        mobile_write_u32(value.count)?,
        mobile_write_u32(value.offset)?,
        mobile_write_u64(value.first_tick)?,
        mobile_write_u64(value.progress_tick)?
      ],
      136) do
      Err(_) -> return Err("invalid_header_routing_state")
      Ok(value) -> value
    end
  end
  let parts = [mobile_write_u64(state.tick)?] ++ chunks
  case Bytes.concat_many(parts, 34824) do
    Err(_) -> Err("invalid_header_routing_state")
    Ok(value)
  end
end

pub fn decode_header_routing(input :: Bytes) -> HeaderRoutingState!String do
  if Bytes.length(input) < 8
    || Bytes.length(input) > 34824
    || (Bytes.length(input) - 8) % 136 != 0 do
    return Err("invalid_header_routing_state")
  end
  let tick = mobile_read_u64(slice(input, 0, 8)?)?
  let values = for index in 0..((Bytes.length(input) - 8) / 136) do
    let start = 8 + index * 136
    HeaderCursor {
      envelope: slice(input, start, 16)?,
      packet: slice(input, start + 16, 32)?,
      profile: slice(input, start + 48, 32)?,
      sessions: slice(input, start + 80, 32)?,
      count: mobile_read_u32(slice(input, start + 112, 4)?)?,
      offset: mobile_read_u32(slice(input, start + 116, 4)?)?,
      first_tick: mobile_read_u64(slice(input, start + 120, 8)?)?,
      progress_tick: mobile_read_u64(slice(input, start + 128, 8)?)?
    }
  end
  let state = HeaderRoutingState { tick: tick, cursors: values }
  let canonical = encode_header_routing(state)?
  if !Bytes.secure_equals(canonical, input) do
    Err("invalid_header_routing_state")
  else
    Ok(state)
  end
end

fn expired(value :: HeaderCursor, tick :: U64) -> Bool!String do
  let idle = U64.subtract(tick, value.progress_tick)?
  let lifetime = U64.subtract(tick, value.first_tick)?
  Ok(U64.compare(idle, number("65536")?) >= 0 || U64.compare(lifetime, number("1048576")?) >= 0)
end

## Same envelope ID cannot extend its original lease by changing packet/profile/index.
## At capacity only expired work is reclaimed; active work is never displaced by arrivals.
pub fn reserve_header_cursor(state :: HeaderRoutingState,
  envelope :: Bytes,
  packet :: Bytes,
  profile :: Bytes,
  sessions :: Bytes,
  count :: Int) -> Result<(HeaderRoutingState, Option<HeaderCursor>), String> do
  let tick = U64.add(state.tick, number("1")?)?
  let (remaining, existing) = retained(state.cursors, tick, envelope, 0, [], None)?
  if count <= 0 do
    return Ok((HeaderRoutingState { tick: tick, cursors: remaining }, None))
  end
  let next = case existing do
    None -> HeaderCursor {
      envelope: envelope,
      packet: packet,
      profile: profile,
      sessions: sessions,
      count: count,
      offset: 0,
      first_tick: tick,
      progress_tick: tick
    }
    Some(previous) -> if Bytes.secure_equals(previous.packet, packet)
      && Bytes.secure_equals(previous.profile, profile)
      && Bytes.secure_equals(previous.sessions, sessions)
      && previous.count == count do
      previous
    else
      HeaderCursor {
        envelope: envelope,
        packet: packet,
        profile: profile,
        sessions: sessions,
        count: count,
        offset: 0,
        first_tick: previous.first_tick,
        progress_tick: previous.progress_tick
      }
    end
  end
  if List.length(remaining) >= 256 do
    return Ok((HeaderRoutingState { tick: tick, cursors: remaining }, None))
  end
  let updated = HeaderRoutingState { tick: tick, cursors: List.append(remaining, next) }
  encode_header_routing(updated)?
  Ok((updated, Some(next)))
end

fn retained(values :: List<HeaderCursor>,
  tick :: U64,
  envelope :: Bytes,
  index :: Int,
  output :: List<HeaderCursor>,
  existing :: Option<HeaderCursor>) -> Result<(List<HeaderCursor>, Option<HeaderCursor>), String> do
  if index >= List.length(values) do
    return Ok((output, existing))
  end
  let value = List.get(values, index)
  if expired(value, tick)? do
    retained(values, tick, envelope, index + 1, output, existing)
  else if Bytes.secure_equals(value.envelope, envelope) do
    retained(values, tick, envelope, index + 1, output, Some(value))
  else
    retained(values, tick, envelope, index + 1, List.append(output, value), existing)
  end
end

fn advancing(state :: HeaderRoutingState,
  envelope :: Bytes,
  offset :: Int,
  finished :: Bool,
  index :: Int,
  output :: List<HeaderCursor>) -> List<HeaderCursor>!String do
  if index >= List.length(state.cursors) do
    return Ok(output)
  end
  let value = List.get(state.cursors, index)
  if !Bytes.secure_equals(value.envelope, envelope) do
    advancing(state, envelope, offset, finished, index + 1, List.append(output, value))
  else if finished do
    advancing(state, envelope, offset, finished, index + 1, output)
  else
    if offset <= value.offset || offset >= value.count do
      return Err("invalid_header_routing_progress")
    end
    advancing(state,
      envelope,
      offset,
      finished,
      index + 1,
      List.append(output, %{value | offset: offset, progress_tick: state.tick}))
  end
end

pub fn advance_header_cursor(state :: HeaderRoutingState,
  envelope :: Bytes,
  offset :: Int,
  finished :: Bool) -> HeaderRoutingState!String do
  let next = HeaderRoutingState {
    tick: state.tick,
    cursors: advancing(state, envelope, offset, finished, 0, [])?
  }
  encode_header_routing(next)?
  Ok(next)
end
