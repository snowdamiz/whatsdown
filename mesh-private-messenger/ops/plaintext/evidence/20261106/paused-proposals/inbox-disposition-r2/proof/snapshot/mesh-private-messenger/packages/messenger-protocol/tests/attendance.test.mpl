from Transparency.Attendance import (
  AttendanceClock,
  AttendanceEpoch,
  AttendanceRow,
  AttendanceAddresses,
  decode_attendance_clock,
  decode_attendance_epoch,
  attendance_posting_epoch,
  attendance_addresses
)
from Solana.Read import pubkey

fn join(parts :: List<Bytes>, output :: Bytes) -> Bytes!String do
  if List.length(parts) == 0 do
    Ok(output)
  else
    join(List.tail(parts), Bytes.concat(output, List.head(parts))?)
  end
end

fn wide(value :: String) -> Bytes!String do
  case Bytes.write_uint_le(value, 8) do
    Err(_) -> Err("fixture_integer")
    Ok(bytes)
  end
end

fn replace(bytes :: Bytes, offset :: Int, replacement :: Bytes) -> Bytes!String do
  join([
      Bytes.slice(bytes, 0, offset)?,
      replacement,
      Bytes.slice(bytes,
        offset + Bytes.length(replacement),
        Bytes.length(bytes) - offset - Bytes.length(replacement))?
    ],
    Bytes.empty())
end

fn invalid_epoch(bytes :: Bytes) do
  case decode_attendance_epoch(bytes) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
end

fn proof() -> Bool!String do
  let clock_bytes = join([
      Bytes.from_hex("4d414301" <> String.repeat("09", 32))?,
      wide("6048010")?,
      wide("100")?,
      wide("11")?,
      wide("10")?,
      Bytes.from_hex(String.repeat("00", 12))?
    ],
    Bytes.empty())?
  let clock = decode_attendance_clock(clock_bytes)?
  assert(U64.to_string(clock.first_full_epoch) == "11")
  assert(U64.to_string(clock.activated_slot) == "100")
  let slot = join([wide("11")?, wide("101")?], Bytes.empty())?
  assert(attendance_posting_epoch(clock, slot, U64.parse("101")?)? == Some(U64.parse("10")?))
  assert(attendance_posting_epoch(clock,
    Bytes.from_hex(String.repeat("00", 16))?,
    U64.parse("100")?)? == None)
  case attendance_posting_epoch(clock, slot, U64.parse("102")?) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  for offset in [0, 43, 52, 68, 79] do
    case decode_attendance_clock(replace(clock_bytes, offset, Bytes.from_hex("ff")?)?) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  let wire = join([
      Bytes.from_hex("4d414501" <> String.repeat("09", 32))?,
      wide("10")?,
      wide("4100")?,
      wide("4200")?,
      Bytes.from_hex("020001" <> String.repeat("00", 17))?,
      Bytes.from_hex(String.repeat("07", 32))?,
      wide("4100")?,
      Bytes.from_hex(String.repeat("08", 32))?,
      wide("1")?,
      Bytes.from_hex(String.repeat("00", 62 * 40))?
    ],
    Bytes.empty())?
  let week = decode_attendance_epoch(wire)?
  assert(week.sealed && U64.to_string(week.posts) == "4100" && List.length(week.rows) == 2)
  assert(U64.to_string(List.get(week.rows, 0).signed) == "4100")
  for offset in [0, 61, 62, 63, 79, 160, 2639] do
    invalid_epoch(replace(wire, offset, Bytes.from_hex("ff")?)?)
  end
  invalid_epoch(replace(wire, 112, wide("4101")?)?)
  invalid_epoch(replace(wire, 152, wide("0")?)?)
  invalid_epoch(replace(wire, 120, Bytes.from_hex(String.repeat("07", 32))?)?)
  invalid_epoch(replace(wire, 80, Bytes.from_hex(String.repeat("00", 32))?)?)
  invalid_epoch(replace(wire, 44, wide("0")?)?)
  invalid_epoch(Bytes.slice(wire, 0, 2639)?)
  invalid_epoch(Bytes.concat(wire, Bytes.from_hex("00")?)?)
  let program = pubkey("11111111111111111111111111111111")?
  let first = attendance_addresses(program, clock.log_id, U64.parse("10")?)?
  let next = attendance_addresses(program, clock.log_id, U64.parse("11")?)?
  assert(first.clock == next.clock && first.epoch != next.epoch)
  Ok(true)
end

test("weekly attendance preserves u64 counters and rejects malformed or misattributed records") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
