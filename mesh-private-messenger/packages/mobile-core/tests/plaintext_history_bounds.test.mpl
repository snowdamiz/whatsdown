from Storage.HistoryBlobs import seal_history_blob, open_history_blob
from Storage.Keys import platform_key

# Only finite observations of the fixed synthetic fixtures cross into the test runner.
# Private payloads and derived Result control never select a later storage operation.
fn known_fixture(value :: Bool) -> Bool do
  declassify(value,
    "test-only Boolean comparison or outcome of known synthetic fixtures; no application disclosure")
end

fn exercise_storage() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let fixture = case Bytes.repeat(42, 130001) do
    Err(_) -> return Err("fixture allocation failed")
    Ok(value) -> value
  end
  let value :: Plaintext<Bytes> = fixture
  let label = "history/v1/fixture"
  let sealed = seal_history_blob(fixture, key, label)?
  assert(known_fixture(case seal_history_blob(value, key, label) do
    Ok(blob) -> Bytes.length(blob) > 65536
    Err(_) -> false
  end))
  assert(Bytes.length(sealed) > 65536)
  let opened :: Plaintext<Bytes> = open_history_blob(sealed, key, label)?
  if !declassify(Bytes.secure_equals(value, opened),
    "test fixture compares only its known chunked storage roundtrip bytes") do
    return Err("chunked storage mismatch")
  end
  let small_fixture = Bytes.from_utf8("small history fixture")
  let small :: Plaintext<Bytes> = small_fixture
  let legacy = seal_history_blob(small_fixture, key, label)?
  assert(known_fixture(Result.is_ok(seal_history_blob(small, key, label))))
  let small_opened :: Plaintext<Bytes> = open_history_blob(legacy, key, label)?
  if !declassify(Bytes.secure_equals(small, small_opened),
    "test fixture compares only its known legacy storage roundtrip bytes") do
    return Err("legacy storage mismatch")
  end
  let too_short :: Plaintext<Bytes> = Bytes.from_utf8("short")
  assert(known_fixture(case seal_history_blob(too_short, key, label) do
    Err("history_capacity") -> true
    _ -> false
  end))
  let at_limit = case Bytes.repeat(99, 16794632) do
    Err(_) -> return Err("limit allocation failed")
    Ok(value) -> value
  end
  let private_limit :: Plaintext<Bytes> = at_limit
  let limit_sealed = seal_history_blob(at_limit, key, label)?
  assert(known_fixture(Result.is_ok(seal_history_blob(private_limit, key, label))))
  let limit_opened :: Plaintext<Bytes> = open_history_blob(limit_sealed, key, label)?
  if !declassify(Bytes.secure_equals(private_limit, limit_opened),
    "test fixture compares only its known exact-capacity private storage roundtrip") do
    return Err("limit roundtrip mismatch")
  end
  let excessive :: Plaintext<Bytes> = case Bytes.repeat(99, 16794633) do
    Err(_) -> return Err("excess allocation failed")
    Ok(value) -> value
  end
  assert(known_fixture(case seal_history_blob(excessive, key, label) do
    Err("history_capacity") -> true
    _ -> false
  end))
  assert(known_fixture(Result.is_err(open_history_blob(sealed, key, "history/v1/other"))))
  Ok(true)
end

test("labeled history uses real platform seals for packed and legacy storage") do
  assert(known_fixture(case exercise_storage() do
    Ok(value) -> value
    Err(_) -> false
  end))
end
