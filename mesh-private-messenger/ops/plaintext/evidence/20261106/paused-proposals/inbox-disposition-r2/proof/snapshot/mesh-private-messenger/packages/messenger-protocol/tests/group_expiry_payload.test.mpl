from Groups.Expiry import TimedGroupPayload, encode_timed_group_payload, decode_timed_group_payload
from Groups.GroupPayload import GroupPayload, encode_group_payload, decode_group_payload

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
  assert(Bytes.length(wire) == 65290)
  let opened = decode_timed_group_payload(wire)?
  assert(U64.compare(opened.timestamp, value.timestamp) == 0)
  assert(opened.disappearing_seconds == 2592000)
  assert(Bytes.secure_equals(opened.payload.body, payload.body))
  assert(Bytes.secure_equals(opened.payload.hint, payload.hint))
  assert(Bytes.secure_equals(encode_timed_group_payload(opened)?, wire))
  assert(Result.is_err(decode_group_payload(wire)))
  assert(Result.is_err(decode_timed_group_payload(encode_group_payload(payload)?)))
  for seconds in [0, -1, 2592001] do
    assert(Result.is_err(encode_timed_group_payload(%{value | disappearing_seconds: seconds})))
  end
  assert(Result.is_err(encode_timed_group_payload(%{value |
    payload: %{payload | body: bytes(65226)?}
  })))
  let control = %{payload |
    kind: 5,
    body: bytes(1)?,
    hint: Bytes.empty(),
    recipient_account: bytes(32)?,
    recipient_device: bytes(16)?
  }
  assert(Result.is_err(encode_timed_group_payload(%{value | payload: control})))
  let small = encode_timed_group_payload(%{value |
    payload: %{payload | body: Bytes.empty(), hint: Bytes.empty()}
  })?
  assert(Bytes.length(small) == 25)
  assert(Result.is_err(decode_timed_group_payload(Bytes.slice(small, 0, Bytes.length(small) - 1)?)))
  assert(Result.is_err(decode_timed_group_payload(Bytes.concat(small, bytes(1)?)?)))
  let unknown_version = Bytes.concat(Bytes.from_hex("03")?,
    Bytes.slice(small, 1, Bytes.length(small) - 1)?)?
  assert(Result.is_err(decode_timed_group_payload(unknown_version)))
  let zero_duration = Bytes.concat(Bytes.slice(small, 0, 12)?, Bytes.from_hex("00000000")?)?
  let zero_duration = Bytes.concat(zero_duration,
    Bytes.slice(small, 16, Bytes.length(small) - 16)?)?
  assert(Result.is_err(decode_timed_group_payload(zero_duration)))
  Ok(true)
end

test("GAP2 preserves encrypted timestamp/duration and exact bounds without legacy confusion") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
