from Api.Binary import Admission, admit_request
from Privacy.Edge import RequestStamp, encode_stamped_request, mint_request_stamp
from Storage.RateLimit import purge_rate_limits

fn wide(value :: String) -> U64 ! String do
  U64.parse(value)
end

fn repeated(value :: Int, length :: Int) -> Bytes ! String do
  case Bytes.repeat(value, length) do
    Err( _) -> Err("test allocation failed")
    Ok( output) -> Ok(output)
  end
end

fn stamped(label :: String, payload :: Bytes, expires_at :: U64, difficulty :: Int) -> Bytes ! String do
  encode_stamped_request(mint_request_stamp(label, payload, expires_at, difficulty) ?, payload)
end

# 0 admitted with the exact payload, 1 malformed, 2 refused.

fn outcome(pool :: PoolHandle,
label :: String,
body :: Bytes,
payload :: Bytes,
now :: U64,
difficulty :: Int) -> Int ! String do
  case admit_request(pool, label, body, 200, now, difficulty) ? do
    Admitted( admitted) -> if Bytes.secure_equals(admitted, payload) do
      Ok(0)
    else
      Err("admitted a different payload")
    end
    AdmissionMalformed -> Ok(1)
    AdmissionRefused -> Ok(2)
  end
end

fn count(pool :: PoolHandle) -> Int ! String do
  let rows = Pool.query_values(pool,
  "SELECT count(*)::text AS total FROM messenger_rate_limits",
  []) ?
  if List.length(rows) != 1 do
    Err("count failed")
  else
    case Map.get(List.head(rows), "total") do
      Text( value) -> case String.to_int(value) do
        None -> Err("count failed")
        Some( output) -> Ok(output)
      end
      _ -> Err("count failed")
    end
  end
end

fn proof() -> Bool ! String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
  "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000) ?
  let _ = Pool.execute(pool, "TRUNCATE messenger_rate_limits", []) ?
  let now = wide("1700000000000") ?
  let soon = wide("1700000060000") ?
  let payload = repeated(9, 120) ?
  let resolve = "mesh-msg/v1/work/resolve"
  let body = stamped(resolve, payload, soon, 8) ?
  # Paid work admits the exact request once. Replaying it buys nothing.
  assert(outcome(pool, resolve, body, payload, now, 8) ? == 0)
  assert(outcome(pool, resolve, body, payload, now, 8) ? == 2)
  # Work for another endpoint, too little work, and stale work are all refused.
  assert(outcome(pool,
  "mesh-msg/v1/work/register",
  stamped(resolve, payload, soon, 8) ?,
  payload,
  now,
  8) ? == 2)
  assert(outcome(pool,
  resolve,
  stamped(resolve, repeated(3, 120) ?, soon, 1) ?,
  repeated(3, 120) ?,
  now,
  20) ? == 2)
  assert(outcome(pool,
  resolve,
  stamped(resolve, payload, soon, 8) ?,
  payload,
  wide("1700000060001") ?,
  8) ? == 2)
  # An unstamped or oversized body never reaches the directory.
  assert(outcome(pool, resolve, payload, payload, now, 8) ? == 1)
  assert(outcome(pool, resolve, stamped(resolve, repeated(1, 201) ?, soon, 8) ?, payload, now, 8) ? == 1)
  # Spent stamps are forgotten once they can no longer be replayed, so the
  # table cannot grow without bound.
  assert(count(pool) ? == 1)
  let _ = Pool.execute(pool,
  "UPDATE messenger_rate_limits SET window_started_at = clock_timestamp() - interval '25 hours'",
  []) ?
  let fresh = stamped(resolve, repeated(4, 120) ?, soon, 8) ?
  assert(outcome(pool, resolve, fresh, repeated(4, 120) ?, now, 8) ? == 0)
  assert(count(pool) ? == 2)
  assert(purge_rate_limits(pool, 128) ? == 1)
  assert(count(pool) ? == 1)
  assert(outcome(pool, resolve, fresh, repeated(4, 120) ?, now, 8) ? == 2)
  Ok(true)
end

test("anonymous directory requests are admitted once, for paid work, and spent stamps are purged") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
