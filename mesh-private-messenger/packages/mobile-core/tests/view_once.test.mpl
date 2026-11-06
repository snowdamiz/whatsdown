from Attachments.ViewOnce import encode_view_once_reference, decode_view_once_reference
from Mobile.ViewOnce import prepare_view_once, consume_prepared_view_once, consume_view_once
from Storage.ViewOnce import (
  ViewOnceAvailable,
  ViewOnceRecord,
  encode_view_once_record,
  decode_view_once_record
)
from Tests.ViewOnceFixture import (
  view_once_fixture,
  view_once_fixture_selection,
  view_once_fixture_clear,
  view_once_fixture_match,
  view_once_fixture_refused,
  view_once_fixture_reference_opens,
  view_once_fixture_generic_opens,
  view_once_fixture_trigger,
  view_once_fixture_row,
  view_once_fixture_repair_cache
)
from Tests.Support import append, repeated

fn observe(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "TEST ONLY finite assertions over authored synthetic view-once ciphertext and local SQLite fixtures; no real image metadata keys references errors or prior caller control")
end

fn observed(value :: Result<Plaintext<Bool>, String>) -> Bool do
  case value do
    Err(_) -> false
    Ok(valid) -> observe(valid)
  end
end

fn canonical_case() -> Plaintext<Bool>!String do
  let fixture = view_once_fixture(0)?
  let encoded = encode_view_once_reference(fixture.reference)
  let decoded = decode_view_once_reference(fixture.wire)
  let short = case Bytes.slice(fixture.wire, 0, Bytes.length(fixture.wire) - 1) do
    Err(_) -> return Err("view_once_test_slice")
    Ok(bytes) -> bytes
  end
  let truncated = decode_view_once_reference(short)
  let trailing = decode_view_once_reference(append(fixture.wire, Bytes.from_utf8("x"))?)
  let original_binding = fixture.binding
  let original_reference = fixture.reference
  let invalid_binding = %{original_binding | receiver_device_id: Bytes.empty()}
  let invalid = encode_view_once_reference(%{original_reference | binding: invalid_binding})
  let opened = view_once_fixture_reference_opens(fixture)
  let state_encoded = encode_view_once_record(Available(ViewOnceAvailable {
    reference: fixture.wire,
    chunk_hashes: [Crypto.sha256(fixture.chunk)],
    message_expiry: None
  }))
  let state_decoded = decode_view_once_record(fixture.record_wire)
  view_once_fixture_clear(fixture)?
  let encoded_ok = case encoded do
    Err(_) -> false
    Ok(bytes) -> Bytes.secure_equals(bytes, fixture.wire)
  end
  let decoded_ok = case decoded do
    Err(_) -> false
    Ok(value) -> Bytes.secure_equals(value.wrapped_key, fixture.reference.wrapped_key)
  end
  let truncated_refused = case truncated do
    Err(_) -> true
    Ok(_) -> false
  end
  let trailing_refused = case trailing do
    Err(_) -> true
    Ok(_) -> false
  end
  let invalid_refused = case invalid do
    Err(_) -> true
    Ok(_) -> false
  end
  let state_encode_ok = case state_encoded do
    Err(_) -> false
    Ok(bytes) -> Bytes.secure_equals(bytes, fixture.record_wire)
  end
  let state_decode_ok = case state_decoded do
    Err(_) -> false
    Ok(Consumed(_)) -> false
    Ok(Available(value)) -> Bytes.secure_equals(value.reference, fixture.wire)
      && List.length(value.chunk_hashes) == 1
  end
  Ok(encoded_ok
    && decoded_ok
    && truncated_refused
    && trailing_refused
    && invalid_refused
    && state_encode_ok
    && state_decode_ok
    && Result.unwrap_or(opened, false))
end

fn domain_case() -> Plaintext<Bool>!String do
  let fixture = view_once_fixture(0)?
  let positive = view_once_fixture_reference_opens(fixture)
  let generic = view_once_fixture_generic_opens(fixture, false)
  let ordinary = view_once_fixture_generic_opens(fixture, true)
  let original_binding = fixture.binding
  let wrong_binding = %{original_binding | message_id: repeated(45, 16)?}
  let wrong = view_once_fixture_reference_opens(%{fixture | binding: wrong_binding})
  view_once_fixture_clear(fixture)?
  Ok(Result.unwrap_or(positive, false)
    && !Result.unwrap_or(generic, true)
    && Result.unwrap_or(ordinary, false)
    && !Result.unwrap_or(wrong, true))
end

fn consume_case() -> Plaintext<Bool>!String do
  let fixture = view_once_fixture(0)?
  let first = consume_view_once(view_once_fixture_selection(fixture))
  let second = consume_view_once(view_once_fixture_selection(fixture))
  view_once_fixture_clear(fixture)?
  Ok(view_once_fixture_match(first, fixture.png) && view_once_fixture_refused(second))
end

fn contender_case() -> Plaintext<Bool>!String do
  let fixture = view_once_fixture(0)?
  let first = prepare_view_once(view_once_fixture_selection(fixture))?
  let second = prepare_view_once(view_once_fixture_selection(fixture))?
  let winner = consume_prepared_view_once(first)
  let loser = consume_prepared_view_once(second)
  view_once_fixture_clear(fixture)?
  Ok(view_once_fixture_match(winner, fixture.png) && view_once_fixture_refused(loser))
end

fn rollback_case() -> Plaintext<Bool>!String do
  let fixture = view_once_fixture(0)?
  let prepared = prepare_view_once(view_once_fixture_selection(fixture))?
  view_once_fixture_trigger(fixture, true)?
  let aborted = consume_prepared_view_once(prepared)
  view_once_fixture_trigger(fixture, false)?
  let retry = consume_view_once(view_once_fixture_selection(fixture))
  view_once_fixture_clear(fixture)?
  Ok(view_once_fixture_refused(aborted) && view_once_fixture_match(retry, fixture.png))
end

fn expired_case(mode :: Int) -> Plaintext<Bool>!String do
  let positive = view_once_fixture(0)?
  let good = consume_view_once(view_once_fixture_selection(positive))
  view_once_fixture_clear(positive)?
  let expired = view_once_fixture(mode)?
  let bad = consume_view_once(view_once_fixture_selection(expired))
  view_once_fixture_clear(expired)?
  Ok(view_once_fixture_match(good, positive.png) && view_once_fixture_refused(bad))
end

fn ordinary_case() -> Plaintext<Bool>!String do
  let fixture = view_once_fixture(0)?
  let ordinary = view_once_fixture_generic_opens(fixture, true)
  view_once_fixture_clear(fixture)?
  ordinary
end

fn cache_auth_case() -> Plaintext<Bool>!String do
  let fixture = view_once_fixture(3)?
  let invalid = consume_view_once(view_once_fixture_selection(fixture))
  let retained = view_once_fixture_row(fixture)
  view_once_fixture_repair_cache(fixture)?
  let retry = consume_view_once(view_once_fixture_selection(fixture))
  view_once_fixture_clear(fixture)?
  Ok(view_once_fixture_refused(invalid)
    && Bytes.secure_equals(Result.unwrap_or(retained, Bytes.empty()), fixture.row_blob)
    && view_once_fixture_match(retry, fixture.png))
end

test("view-once canonical reference authenticates and rejects truncated or trailing bytes") do
  assert(observed(canonical_case()))
end

test("view-once HPKE domain cannot be normalized into an ordinary ATR") do
  assert(observed(domain_case()))
end

test("cached view-once consume returns one image and fresh custody reopening refuses") do
  assert(observed(consume_case()))
end

test("two prepared view-once consumers have exactly one durable winner") do
  assert(observed(contender_case()))
end

test("failed cache deletion rolls back consumed state and preserves a valid retry") do
  assert(observed(rollback_case()))
end

test("view-once object expiry refuses while a valid cached image opens offline") do
  assert(observed(expired_case(1)))
end

test("view-once message expiry refuses while a valid cached image opens offline") do
  assert(observed(expired_case(2)))
end

test("authenticated damaged cache does not consume and repaired ciphertext remains usable") do
  assert(observed(cache_auth_case()))
end

test("ordinary encrypted attachment reads retain their existing format") do
  assert(observed(ordinary_case()))
end
