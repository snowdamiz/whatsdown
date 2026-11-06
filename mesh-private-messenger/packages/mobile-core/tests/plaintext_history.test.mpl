import File
from Mobile.HistoryWire import encode_history, decode_history
from Mobile.Types import MobileHistoryEntry
from Protocol.V1 import InnerEnvelope
from Storage.HistoryBlobs import seal_history_blob, open_history_blob
from Storage.Keys import platform_key
from Storage.Blobs import ensure_schema, load_blob
from Storage.Records import store_updated_blobs
from Tests.Support import repeated, database_path

# Only finite observations of the fixed synthetic fixtures cross into the test runner.
# Private payloads and derived Result control never select a later storage operation.
fn known_fixture(value :: Bool) -> Bool do
  declassify(value,
    "test-only Boolean comparison or outcome of known synthetic fixtures; no application disclosure")
end

fn exercise_full() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let path = database_path("labeled_history")?
  ensure_schema(path)?
  let body = repeated(120, 32768)?
  let inner = InnerEnvelope {
    version: 1,
    sender_account_id: repeated(1, 32)?,
    sender_device_id: repeated(2, 16)?,
    recipient_device_id: repeated(3, 16)?,
    conversation_id: repeated(4, 16)?,
    client_message_id: repeated(5, 16)?,
    client_timestamp: U64.parse("1")?,
    message_type: 1,
    body: body,
    reply_reference: Bytes.empty(),
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: []
  }
  let fixture_values = for index in 0..256 do
    MobileHistoryEntry { direction: 1, inner: %{inner | client_message_id: repeated(index, 16)?} }
  end
  let values :: Plaintext<List<MobileHistoryEntry>> = fixture_values
  let encoded = encode_history(fixture_values)?
  let private_encoded = encode_history(values)
  assert(known_fixture(case private_encoded do
    Ok(value) -> Bytes.secure_equals(value, encoded)
    Err(_) -> false
  end))
  # The public bytes are the same fixed fixture, not a declassified private result.
  let sealed = seal_history_blob(encoded, wrapping, "history/v1/fixture")?
  let private_sealed = seal_history_blob(Result.unwrap_or(private_encoded, Bytes.empty()),
    wrapping,
    "history/v1/fixture")
  assert(known_fixture(case private_sealed do
    Ok(value) -> Bytes.length(value) > 8388608
    Err(_) -> false
  end))
  assert(Bytes.length(sealed) > 8388608)
  store_updated_blobs(path, ["history/v1/fixture"], [sealed])?
  let opened = open_history_blob(load_blob(path, "history/v1/fixture")?,
    wrapping,
    "history/v1/fixture")?
  let private_opened :: Plaintext<Bytes> = opened
  let restored = decode_history(private_opened)
  let exact = Bytes.secure_equals(encoded, private_opened)
    && case restored do
      Ok(rows) -> List.length(rows) == 256
        && Bytes.secure_equals(List.get(rows, 255).inner.body, body)
      Err(_) -> false
    end
  if !declassify(exact,
    "test fixture compares only its known full private history and256-entry roundtrip") do
    return Err("full history mismatch")
  end
  File.delete(path)?
  Ok(true)
end

test("private 256-entry history survives more than eight MiB through platform seals and SQLite") do
  assert(known_fixture(case exercise_full() do
    Ok(value) -> value
    Err(_) -> false
  end))
end
