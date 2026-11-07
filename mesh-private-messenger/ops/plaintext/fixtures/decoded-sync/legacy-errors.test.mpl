from Mobile.Codec import mobile_join, mobile_vector
from Mobile.Sessions import parse_sync_payload

fn fixture_only(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "test-only exact self-sync parsing outcomes for fixed synthetic fixtures; no application disclosure")
end

fn frame(username :: Bytes, timestamp :: Bytes, body :: Bytes) -> Bytes!String do
  mobile_join([
      mobile_vector(username)?,
      mobile_vector(Bytes.from_hex(String.repeat("01", 32))?)?,
      mobile_vector(Bytes.from_hex(String.repeat("02", 16))?)?,
      mobile_vector(Bytes.from_hex(String.repeat("03", 16))?)?,
      mobile_vector(timestamp)?,
      mobile_vector(body)?,
      mobile_vector(Bytes.from_hex("00000000")?)?
    ],
    0,
    Bytes.empty())
end

fn outcome(input :: Bytes, expected :: String) -> Bool do
  let legacy = case parse_sync_payload(input) do
    Err(error) -> error == expected
    Ok(_) -> expected == "ok"
  end
  legacy
end

fn exercise() -> Bool!String do
  let username = Bytes.from_utf8("public-peer")
  let timestamp = Bytes.from_hex("0000000000000001")?
  let body = Bytes.from_utf8("synthetic private body")
  let legacy = frame(username, timestamp, body)?
  let empty_tail = Bytes.concat(legacy, mobile_vector(Bytes.empty())?)?
  let safety = Bytes.from_hex(String.repeat("04", 64))?
  let full_tail = Bytes.concat(legacy, mobile_vector(safety)?)?
  let short_tail = Bytes.concat(legacy, mobile_vector(Bytes.from_hex("04")?)?)?
  let long_tail = Bytes.concat(legacy, mobile_vector(Bytes.from_hex(String.repeat("04", 65))?)?)?
  let truncated_tail = Bytes.concat(legacy, Bytes.from_hex("00")?)?
  let trailing = Bytes.concat(empty_tail, Bytes.from_hex("00")?)?
  let invalid_username = frame(Bytes.from_hex("ff")?, timestamp, body)?
  let short_timestamp = frame(username, Bytes.from_hex("00000000000001")?, body)?
  let oversized_body = frame(username, timestamp, Bytes.from_hex(String.repeat("05", 32001))?)?
  let invalid_username_short_safety = Bytes.concat(invalid_username,
    mobile_vector(Bytes.from_hex("04")?)?)?
  let invalid_username_truncated_safety = Bytes.concat(invalid_username, Bytes.from_hex("00")?)?
  let short_timestamp_short_safety = Bytes.concat(short_timestamp,
    mobile_vector(Bytes.from_hex("04")?)?)?
  Ok(outcome(legacy, "ok")
    && outcome(empty_tail, "ok")
    && outcome(full_tail, "ok")
    && outcome(short_tail, "invalid_safety_number")
    && outcome(long_tail, "invalid_store_request")
    && outcome(truncated_tail, "invalid_store_request")
    && outcome(trailing, "invalid_sync_payload")
    && outcome(invalid_username, "invalid_sync_payload")
    && outcome(short_timestamp, "invalid_sync_payload")
    && outcome(oversized_body, "invalid_sync_payload")
    && outcome(invalid_username_short_safety, "invalid_safety_number")
    && outcome(invalid_username_truncated_safety, "invalid_store_request")
    && outcome(short_timestamp_short_safety, "invalid_safety_number"))
end

test("self-sync parsing preserves the three exact error identities and legacy optional safety tails") do
  assert(fixture_only(Result.unwrap_or(exercise(), false)))
end
