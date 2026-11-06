from Mobile.HeaderRoutingState import (
  HeaderCursor,
  HeaderRoutingState,
  empty_header_routing,
  encode_header_routing,
  decode_header_routing,
  reserve_header_cursor,
  advance_header_cursor
)
from Mobile.HeaderCapabilities import require_new_header_capacity

fn bytes(value :: Int, length :: Int) -> Bytes!String do
  case Bytes.repeat(value, length) do
    Err(_) -> Err("fixture bytes")
    Ok(value)
  end
end

fn envelope(index :: Int) -> Bytes!String do
  let encoded = Bytes.from_utf8(Int.to_string(index))
  Bytes.slice(Crypto.sha256(encoded), 0, 16)
end

fn begin(state :: HeaderRoutingState,
  index :: Int) -> Result<(HeaderRoutingState, Option<HeaderCursor>), String> do
  reserve_header_cursor(state, envelope(index)?, bytes(1, 32)?, bytes(2, 32)?, bytes(3, 32)?, 8193)
end

fn fill(state :: HeaderRoutingState, index :: Int) -> HeaderRoutingState!String do
  if index >= 256 do
    return Ok(state)
  end
  let (next, admitted) = begin(state, index)?
  fixture_check(case admitted do
    None -> false
    Some(_) -> true
  end)?
  fill(next, index + 1)
end

fn required(value :: Option<HeaderCursor>) -> HeaderCursor!String do
  case value do
    None -> Err("not admitted")
    Some(value) -> Ok(value)
  end
end

pub fn capacity_and_progress() -> Bool!String do
  let full = fill(empty_header_routing()?, 0)?
  fixture_check(List.length(full.cursors) == 256)?
  fixture_check(Bytes.length(encode_header_routing(full)?) == 34824)?
  let cold = decode_header_routing(encode_header_routing(full)?)?
  let (blocked, refused) = begin(cold, 999)?
  fixture_check(case refused do
    None -> true
    Some(_) -> false
  end)?
  fixture_check(List.length(blocked.cursors) == 256)?
  let (resumed, cursor) = begin(blocked, 0)?
  let cursor = required(cursor)?
  fixture_check(cursor.offset == 0 && cursor.count == 8193)?
  let progressed = advance_header_cursor(resumed, envelope(0)?, 16, false)?
  let (blocked_again, refused) = begin(progressed, 1000)?
  fixture_check(case refused do
    None -> true
    Some(_) -> false
  end)?
  let (resumed, cursor) = begin(decode_header_routing(encode_header_routing(blocked_again)?)?, 0)?
  fixture_check(required(cursor)?.offset == 16)?
  let finished = advance_header_cursor(resumed, envelope(0)?, 32, true)?
  fixture_check(List.length(finished.cursors) == 255)?
  let (admitted, cursor) = begin(finished, 1000)?
  fixture_check(case cursor do
    Some(_) -> true
    None -> false
  end)?
  fixture_check(List.length(admitted.cursors) == 256)?
  Ok(true)
end

pub fn expiry_and_churn() -> Bool!String do
  let full = fill(empty_header_routing()?, 0)?
  let before = List.get(full.cursors, 0).first_tick
  let (changed, cursor) = reserve_header_cursor(full,
    envelope(0)?,
    bytes(9, 32)?,
    bytes(8, 32)?,
    bytes(7, 32)?,
    9000)?
  let value = required(cursor)?
  fixture_check(value.offset == 0 && U64.compare(value.first_tick, before) == 0)?
  let advanced = advance_header_cursor(changed, envelope(0)?, 16, false)?
  let (reset, cursor) = reserve_header_cursor(advanced,
    envelope(0)?,
    bytes(9, 32)?,
    bytes(8, 32)?,
    bytes(6, 32)?,
    9000)?
  fixture_check(required(cursor)?.offset == 0)?
  let late = HeaderRoutingState { tick: U64.parse("65800")?, cursors: reset.cursors }
  let (fresh, cursor) = begin(decode_header_routing(encode_header_routing(late)?)?, 999)?
  fixture_check(case cursor do
    Some(_) -> true
    None -> false
  end)?
  fixture_check(List.length(fresh.cursors) == 1)?
  let absolute = HeaderRoutingState {
    tick: U64.parse("1048576")?,
    cursors: [
      HeaderCursor {
        envelope: envelope(1)?,
        packet: bytes(1, 32)?,
        profile: bytes(2, 32)?,
        sessions: bytes(3, 32)?,
        count: 9000,
        offset: 16,
        first_tick: U64.parse("1")?,
        progress_tick: U64.parse("1048576")?
      }
    ]
  }
  let (fresh, cursor) = begin(absolute, 2)?
  fixture_check(List.length(fresh.cursors) == 1)?
  fixture_check(case cursor do
    Some(_) -> true
    None -> false
  end)?
  Ok(true)
end

pub fn malformed() -> Bool!String do
  let state = fill(empty_header_routing()?, 0)?
  let bytes = encode_header_routing(state)?
  fixture_check(case decode_header_routing(Bytes.concat(bytes, Bytes.from_utf8("x"))?) do
    Err(_) -> true
    Ok(_) -> false
  end)?
  let first = List.get(state.cursors, 0)
  fixture_check(case encode_header_routing(%{state | cursors: [first, first]}) do
    Err(_) -> true
    Ok(_) -> false
  end)?
  fixture_check(case encode_header_routing(%{state | cursors: [%{first | offset: first.count}]}) do
    Err(_) -> true
    Ok(_) -> false
  end)?
  fixture_check(case encode_header_routing(%{state |
    cursors: [%{first | progress_tick: U64.parse("9999")?}]
  }) do
    Err(_) -> true
    Ok(_) -> false
  end)?
  fixture_check(case require_new_header_capacity(4096, 1) do
    Err(_) -> true
    Ok(_) -> false
  end)?
  fixture_check(case require_new_header_capacity(8193, 0) do
    Err(_) -> false
    Ok(_) -> true
  end)?
  Ok(true)
end

fn fixture_check(value :: Bool) -> Unit!String do
  if value do
    Ok(nil)
  else
    Err("header routing fixture invariant failed")
  end
end
