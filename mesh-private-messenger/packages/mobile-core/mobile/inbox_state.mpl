from Mobile.Codec import mobile_append, mobile_byte, mobile_read_u64, mobile_wide, mobile_write_u64
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local, seal_local

##! What a device remembers about envelopes it could not open yet.
##!
##! The delivery service hands over the oldest unacknowledged envelopes first,
##! and an envelope that cannot be opened yet is not acknowledged. Left alone,
##! a handful of those at the head of a mailbox would be handed over again and
##! again and nothing behind them would ever arrive. So a pass asks past the
##! envelopes it has set aside, and an envelope is not set aside for ever.
# An envelope is acknowledged unopened once it has been tried this many times
# and the first of those tries is a day old. Both, because what stops it being
# opened may be the device's own trouble, a full disk or a directory it cannot
# reach, and sixteen tries can go by in a minute: a message must not be lost to
# that. Nothing is held up meanwhile, and the mailbox drops it within 31 days.

pub fn delivery_attempt_limit() -> Int do
  16
end

pub fn delivery_attempt_span() -> U64 ! String do
  mobile_wide("86400000")
end

fn load_state(database_path :: String, wrapping_key :: borrow StorageKey, label :: String) -> Bytes ! String do
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
    Ok(blob) -> open_local(blob, wrapping_key, local_context(label) ?)
  end
end

# Where the next fetch starts: zero, or past what this pass has set aside.

pub fn load_fetch_cursor(database_path :: String, wrapping_key :: borrow StorageKey) -> U64 ! String do
  let stored = load_state(database_path, wrapping_key, "inbox-cursor/v1") ?
  if Bytes.length(stored) != 8 do
    mobile_wide("0")
  else
    mobile_read_u64(stored)
  end
end

# Twenty-five bytes an envelope: its identifier, how often it was set aside,
# and when it first was.

pub fn load_delivery_attempts(database_path :: String, wrapping_key :: borrow StorageKey) -> Bytes ! String do
  let stored = load_state(database_path, wrapping_key, "delivery-retries/v1") ?
  if Bytes.length(stored) % 25 != 0 do
    Ok(Bytes.empty())
  else
    Ok(stored)
  end
end

fn position(records :: Bytes, envelope_id :: Bytes, offset :: Int) -> Int ! String do
  if offset >= Bytes.length(records) do
    Ok(0 - 1)
  else if Bytes.secure_equals(Bytes.slice(records, offset, 16) ?, envelope_id) do
    Ok(offset)
  else
    position(records, envelope_id, offset + 25)
  end
end

fn attempts_at(records :: Bytes, found :: Int) -> Int ! String do
  case Bytes.get(records, found + 16) do
    Err(_) -> Err("invalid_delivery_attempts")
    Ok(value) -> Ok(value)
  end
end

pub fn without_delivery_attempts(records :: Bytes, envelope_id :: Bytes) -> Bytes ! String do
  let found = position(records, envelope_id, 0) ?
  if found < 0 do
    Ok(records)
  else
    mobile_append(Bytes.slice(records, 0, found) ?,
    Bytes.slice(records, found + 25, Bytes.length(records) - found - 25) ?)
  end
end

# Whether this try, which has just failed, is the last one.

pub fn delivery_given_up(records :: Bytes, envelope_id :: Bytes, now :: U64) -> Bool ! String do
  let found = position(records, envelope_id, 0) ?
  if found < 0 do
    Ok(false)
  else
    let tried = attempts_at(records, found) ? + 1
    let first = mobile_read_u64(Bytes.slice(records, found + 17, 8) ?) ?
    let old_enough = U64.compare(now, U64.add(first, delivery_attempt_span() ?) ?) >= 0
    Ok(tried >= delivery_attempt_limit() && old_enough)
  end
end

pub fn with_delivery_attempt(records :: Bytes, envelope_id :: Bytes, now :: U64) -> Bytes ! String do
  let found = position(records, envelope_id, 0) ?
  let tried = if found < 0 do
    1
  else
    attempts_at(records, found) ? + 1
  end
  let first = if found < 0 do
    mobile_write_u64(now) ?
  else
    Bytes.slice(records, found + 17, 8) ?
  end
  let others = without_delivery_attempts(records, envelope_id) ?
  # ponytail: remembers 256 envelopes; past that the oldest is forgotten and
  # starts again from its next try, which only means it is tried for longer.
  let bounded = if Bytes.length(others) >= 6400 do
    Bytes.slice(others, 25, Bytes.length(others) - 25) ?
  else
    others
  end
  let counted = if tried > 255 do
    255
  else
    tried
  end
  mobile_append(mobile_append(mobile_append(bounded, envelope_id) ?, mobile_byte(counted) ?) ?,
  first)
end

pub fn inbox_state_writes(wrapping_key :: borrow StorageKey, attempts :: Bytes, cursor :: U64) -> Result <(List < String >, List < Bytes >), String > do
  Ok((["delivery-retries/v1", "inbox-cursor/v1"],
  [seal_local(attempts, wrapping_key, local_context("delivery-retries/v1") ?) ?, seal_local(mobile_write_u64(cursor) ?,
  wrapping_key,
  local_context("inbox-cursor/v1") ?) ?]))
end
