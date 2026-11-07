from Groups.Expiry import TimedGroupPayload, encode_timed_group_payload, decode_timed_group_payload
from Groups.GroupPayload import GroupPayload, encode_group_payload, decode_group_payload

fn fixture_only(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "synthetic public timed group payload fixture comparisons only; no application disclosure")
end

fn check_fixture(value :: Plaintext<Bool>) -> Bool!String do
  if value do
    Ok(true)
  else
    Err("fixture comparison failed")
  end
end

fn bytes(count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat("41", count))
end

fn proof() -> Bool!String do
  let payload = GroupPayload {
    kind: 1,
    body: bytes(65225)?,
    hint: bytes(40)?,
    recipient_account: Bytes.empty(),
    recipient_device: Bytes.empty()
  }
  let value = TimedGroupPayload {
    timestamp: U64.parse("18446744073709551615")?,
    disappearing_seconds: 2592000,
    payload: payload
  }
  let wire = encode_timed_group_payload(value)?
  check_fixture(Bytes.length(wire) == 65290)?
  let opened = decode_timed_group_payload(wire)?
  check_fixture(U64.compare(opened.timestamp, value.timestamp) == 0)?
  check_fixture(opened.disappearing_seconds == 2592000)?
  check_fixture(Bytes.secure_equals(opened.payload.body, payload.body))?
  check_fixture(Bytes.secure_equals(opened.payload.hint, payload.hint))?
  check_fixture(Bytes.secure_equals(encode_timed_group_payload(opened)?, wire))?
  check_fixture(Result.is_err(decode_group_payload(wire)))?
  check_fixture(Result.is_err(decode_timed_group_payload(encode_group_payload(payload)?)))?
  for seconds in [0, -1, 2592001] do
    check_fixture(Result.is_err(encode_timed_group_payload(%{value |
      disappearing_seconds: seconds
    })))?
  end
  check_fixture(Result.is_err(encode_timed_group_payload(%{value |
    payload: %{payload | body: bytes(65226)?}
  })))?
  let control = %{payload |
    kind: 5,
    body: bytes(1)?,
    hint: Bytes.empty(),
    recipient_account: bytes(32)?,
    recipient_device: bytes(16)?
  }
  check_fixture(Result.is_err(encode_timed_group_payload(%{value | payload: control})))?
  let small = encode_timed_group_payload(%{value |
    payload: %{payload | body: Bytes.empty(), hint: Bytes.empty()}
  })?
  check_fixture(Bytes.length(small) == 25)?
  check_fixture(Result.is_err(decode_timed_group_payload(Bytes.slice(small,
    0,
    Bytes.length(small) - 1)?)))?
  check_fixture(Result.is_err(decode_timed_group_payload(Bytes.concat(small, bytes(1)?)?)))?
  let unknown_version = Bytes.concat(Bytes.from_hex("03")?,
    Bytes.slice(small, 1, Bytes.length(small) - 1)?)?
  check_fixture(Result.is_err(decode_timed_group_payload(unknown_version)))?
  let zero_duration = Bytes.concat(Bytes.slice(small, 0, 12)?, Bytes.from_hex("00000000")?)?
  let zero_duration = Bytes.concat(zero_duration,
    Bytes.slice(small, 16, Bytes.length(small) - 16)?)?
  check_fixture(Result.is_err(decode_timed_group_payload(zero_duration)))?
  Ok(true)
end

test("GAP2 preserves encrypted timestamp/duration and exact bounds without legacy confusion") do
  assert(fixture_only(Result.unwrap_or(proof(), false)))
end

fn oversized_empty_hint_proof() -> Bool!String do
  let legacy = encode_group_payload(GroupPayload {
    kind: 1,
    body: bytes(65226)?,
    hint: Bytes.empty(),
    recipient_account: Bytes.empty(),
    recipient_device: Bytes.empty()
  })?
  let decoded_legacy = decode_group_payload(legacy)?
  check_fixture(Bytes.length(decoded_legacy.body) == 65226)?
  check_fixture(Bytes.length(decoded_legacy.hint) == 0)?
  # The GAP1 body fits its 65237 limit; GAP2 must enforce 65225 even when an
  # empty hint leaves the total frame below the shared 65290 wire limit.
  let header = Bytes.from_hex("02474150ffffffffffffffff00278d00")?
  let wire = Bytes.concat(header, Bytes.slice(legacy, 4, Bytes.length(legacy) - 4)?)?
  check_fixture(Bytes.length(wire) == 65251)?
  Ok(case decode_timed_group_payload(wire) do
    Err(error) -> error == "invalid_timed_group_payload"
    Ok(_) -> false
  end)
end

test("GAP2 rejects a 65226-byte body with an empty hint below the total wire limit") do
  assert(fixture_only(Result.unwrap_or(oversized_empty_hint_proof(), false)))
end
