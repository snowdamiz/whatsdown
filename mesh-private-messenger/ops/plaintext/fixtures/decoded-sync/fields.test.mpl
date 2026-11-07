from Mobile.Codec import mobile_join, mobile_vector
from Mobile.Sessions import parse_sync_payload
from Mobile.Types import MobileSyncPayload

fn fixture_only(value :: Plaintext<Bool>) -> Bool do
  declassify(value, "test-only Boolean equality for fixed synthetic sync fields and body; no application disclosure")
end

fn fields(value :: MobileSyncPayload, safety :: Bytes) -> Bool do
  value.peer_username == "synthetic-peer"
    && Bytes.to_hex(value.peer_account_id) == String.repeat("11", 32)
    && Bytes.to_hex(value.conversation_id) == String.repeat("22", 16)
    && Bytes.to_hex(value.client_message_id) == String.repeat("33", 16)
    && U64.to_string(value.client_timestamp) == "72623859790382856"
    && Bytes.secure_equals(value.body, Bytes.from_utf8("synthetic body \u{03bb}"))
    && value.disappearing_seconds == 3600
    && Bytes.secure_equals(value.safety_number, safety)
end

fn parses_fields(input :: Bytes, safety :: Bytes) -> Bool do
  case parse_sync_payload(input) do
    Err(_) -> false
    Ok(value) -> fields(value, safety)
  end
end

fn exercise_fields() -> Bool!String do
  let input = mobile_join([
      mobile_vector(Bytes.from_utf8("synthetic-peer"))?,
      mobile_vector(Bytes.from_hex(String.repeat("11", 32))?)?,
      mobile_vector(Bytes.from_hex(String.repeat("22", 16))?)?,
      mobile_vector(Bytes.from_hex(String.repeat("33", 16))?)?,
      mobile_vector(Bytes.from_hex("0102030405060708")?)?,
      mobile_vector(Bytes.from_utf8("synthetic body \u{03bb}"))?,
      mobile_vector(Bytes.from_hex("00000e10")?)?
    ], 0, Bytes.empty())?
  let empty = Bytes.empty()
  let safety = Bytes.from_hex(String.repeat("44", 64))?
  Ok(parses_fields(input, empty)
    && parses_fields(Bytes.concat(input, mobile_vector(empty)?)?, empty)
    && parses_fields(Bytes.concat(input, mobile_vector(safety)?)?, safety))
end

test("all synthetic successful sync fields survive legacy, empty, and 64-byte tails") do
  assert(fixture_only(Result.unwrap_or(exercise_fields(), false)))
end
