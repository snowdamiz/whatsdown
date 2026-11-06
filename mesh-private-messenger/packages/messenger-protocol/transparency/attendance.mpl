from Solana.Read import Pubkey
from Solana.Address import ProgramDerivedAddress, find_program_address

# Decode only. Callers must authenticate the owner, canonical PDA, log ID and
# finalized RPC context. A registered witness is not automatically rewardable.
pub struct AttendanceClock do
  log_id :: Bytes
  activated_at :: U64
  activated_slot :: U64
  first_full_epoch :: U64
  latest_post_epoch :: U64
end

pub struct AttendanceRow do
  witness :: Bytes
  signed :: U64
end

pub struct AttendanceEpoch do
  log_id :: Bytes
  epoch :: U64
  posts :: U64
  max_post_slot :: U64
  sealed :: Bool
  rows :: List<AttendanceRow>
end

pub struct AttendanceAddresses do
  clock :: Pubkey
  epoch :: Pubkey
end

fn wide(bytes :: Bytes, offset :: Int) -> U64!String do
  case Bytes.read_u64_le(bytes, offset) do
    Err(_) -> Err("invalid_attendance")
    Ok(value)
  end
end

fn zeroes(bytes :: Bytes, offset :: Int, length :: Int) -> Bool!String do
  Ok(Bytes.to_hex(Bytes.slice(bytes, offset, length)?) == String.repeat("00", length))
end

pub fn attendance_addresses(program :: Pubkey,
  log_id :: Bytes,
  epoch :: U64) -> AttendanceAddresses!String do
  if Bytes.length(log_id) != 32 do
    return Err("invalid_attendance")
  end
  let encoded = case Bytes.write_uint_le(U64.to_string(epoch), 8) do
    Err(_) -> return Err("invalid_attendance")
    Ok(value) -> value
  end
  Ok(AttendanceAddresses {
    clock: find_program_address(program, [Bytes.from_utf8("attendance"), log_id])?.address,
    epoch: find_program_address(program,
      [Bytes.from_utf8("attendance-epoch"), log_id, encoded])?.address
  })
end

# Accept the 80-byte header slice; the RPC reader separately checks full space
# 65616 and fetches only the needed 16-byte slot at 80 + ring_index * 16.
pub fn decode_attendance_clock(bytes :: Bytes) -> AttendanceClock!String do
  if Bytes.length(bytes) != 80
    || Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "4d414301"
    || !zeroes(bytes, 68, 12)? do
    return Err("invalid_attendance")
  end
  let value = AttendanceClock {
    log_id: Bytes.slice(bytes, 4, 32)?,
    activated_at: wide(bytes, 36)?,
    activated_slot: wide(bytes, 44)?,
    first_full_epoch: wide(bytes, 52)?,
    latest_post_epoch: wide(bytes, 60)?
  }
  let zero = U64.parse("0")?
  if U64.compare(value.activated_at, U64.parse("9223372036854775807")?) > 0 do
    return Err("invalid_attendance")
  end
  if value.activated_at == zero do
    if value.activated_slot != zero
      || value.first_full_epoch != zero
      || value.latest_post_epoch != zero do
      return Err("invalid_attendance")
    end
  else
    let epoch = U64.divide(value.activated_at, U64.parse("604800")?)?
    if value.first_full_epoch != U64.add(epoch, U64.parse("1")?)?
      || U64.compare(value.latest_post_epoch, epoch) < 0 do
      return Err("invalid_attendance")
    end
  end
  Ok(value)
end

pub fn attendance_posting_epoch(clock :: AttendanceClock,
  slot_bytes :: Bytes,
  posted_slot :: U64) -> Option<U64>!String do
  if Bytes.length(slot_bytes) != 16 || clock.activated_at == U64.parse("0")? do
    return Err("invalid_attendance")
  end
  let marker = wide(slot_bytes, 0)?
  let slot = wide(slot_bytes, 8)?
  let zero = U64.parse("0")?
  if marker == zero && slot == zero && U64.compare(posted_slot, clock.activated_slot) <= 0 do
    return Ok(None)
  end
  if marker == zero || slot != posted_slot || U64.compare(slot, clock.activated_slot) < 0 do
    return Err("invalid_attendance")
  end
  Ok(Some(U64.subtract(marker, U64.parse("1")?)?))
end

pub fn decode_attendance_epoch(bytes :: Bytes) -> AttendanceEpoch!String do
  if Bytes.length(bytes) != 2640
    || Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "4d414501"
    || Bytes.get(bytes, 62)? > 1
    || !zeroes(bytes, 63, 17)? do
    return Err("invalid_attendance")
  end
  let count = case Bytes.read_u16_le(bytes, 60) do
    Err(_) -> return Err("invalid_attendance")
    Ok(value) -> value
  end
  let posts = wide(bytes, 44)?
  let slot = wide(bytes, 52)?
  let zero = U64.parse("0")?
  if count > 64
    || (posts == zero && (slot != zero || count != 0))
    || !zeroes(bytes, 80 + count * 40, (64 - count) * 40)? do
    return Err("invalid_attendance")
  end
  let rows = for index in 0..count do
    let witness = Bytes.slice(bytes, 80 + index * 40, 32)?
    let signed = wide(bytes, 112 + index * 40)?
    if zeroes(witness, 0, 32)? || signed == zero || U64.compare(signed, posts) > 0 do
      return Err("invalid_attendance")
    end
    if index > 0
      && Bytes.to_hex(Bytes.slice(bytes, 80 + (index - 1) * 40, 32)?) >= Bytes.to_hex(witness) do
      return Err("invalid_attendance")
    end
    AttendanceRow { witness: witness, signed: signed }
  end
  Ok(AttendanceEpoch {
    log_id: Bytes.slice(bytes, 4, 32)?,
    epoch: wide(bytes, 36)?,
    posts: posts,
    max_post_slot: slot,
    sealed: Bytes.get(bytes, 62)? == 1,
    rows: rows
  })
end
