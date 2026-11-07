## Expiry is inclusive and uses elapsed time, avoiding overflow for a future
## timestamp near U64's maximum. A backwards clock never expires future data.
pub fn message_unexpired(timestamp :: U64, seconds :: Int, now :: U64) -> Bool!String do
  if seconds < 0 do
    return Err("invalid_message_expiry")
  end
  if seconds == 0 || U64.compare(now, timestamp) < 0 do
    return Ok(true)
  end
  let lifetime = U64.parse(Int.to_string(seconds * 1000))?
  let elapsed = U64.subtract(now, timestamp)?
  Ok(U64.compare(elapsed, lifetime) < 0)
end
