from Storage.OutboxGuard import OutboxBasis, PreparedOutboxIndex
import File
from Binary.Reader import BinaryReader
from Mobile.Codec import (
  mobile_byte,
  mobile_finish,
  mobile_join,
  mobile_reader,
  mobile_vector,
  mobile_write_u16,
  mobile_write_u32,
  take_fixed,
  take_vector
)
from Mobile.History import updated_history
from Mobile.HistoryWire import encode_history, decode_history
from Mobile.Types import MobileHistoryEntry
from Protocol.V1 import InnerEnvelope
from Storage.Blobs import ensure_schema, load_blob, load_blob_with_key
from Storage.Keys import platform_key, local_context, seal_local, open_local
from Storage.HistoryBlobs import seal_history_blob, open_history_blob
from Storage.Records import store_updated_blobs, store_outbound
from Tests.Support import database_path, repeated

fn entry(body :: Bytes, id :: Int) -> InnerEnvelope!String do
  Ok(InnerEnvelope {
    version: 1,
    sender_account_id: repeated(1, 32)?,
    sender_device_id: repeated(2, 16)?,
    recipient_device_id: repeated(3, 16)?,
    conversation_id: repeated(4, 16)?,
    client_message_id: repeated(id, 16)?,
    client_timestamp: U64.parse("1700000000000")?,
    message_type: 1,
    body: body,
    reply_reference: Bytes.empty(),
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: []
  })
end

fn full_history() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("history_full")?
  ensure_schema(path)?
  let body = repeated(120, 32768)?
  let values = for index in 0..256 do
    MobileHistoryEntry { direction: 1, inner: entry(body, index)? }
  end
  let encoded = encode_history(values)?
  assert(Bytes.length(encoded) > 8388608)
  let label = "history/v1/#{Bytes.to_hex(List.head(values).inner.conversation_id)}"
  let sealed = seal_history_blob(encoded, key, label)?
  store_updated_blobs(path, ["sessions/v1", label], [Bytes.from_utf8("before"), sealed])?
  let restored = decode_history(open_history_blob(load_blob(path, label)?, key, label)?)?
  assert(List.length(restored) == 256)
  assert(Bytes.secure_equals(List.head(restored).inner.client_message_id, repeated(0, 16)?))
  assert(Bytes.secure_equals(List.get(restored, 255).inner.body, body))
  assert(Bytes.secure_equals(encode_history(restored)?, encoded))
  # A failed later outbox write rolls back both the index and whole new history.
  let other = seal_history_blob(encoded, key, label)?
  let custody = Bytes.from_utf8("opaque fixture custody")
  store_updated_blobs(path, ["profile/v1"], [custody])?
  assert(Result.is_err(store_outbound(path,
    [],
    [],
    Bytes.from_utf8("after"),
    [label],
    [other],
    ["outbox/rejected"],
    [Bytes.empty()],
    PreparedOutboxIndex {
      value: Bytes.from_utf8("after"),
      before: OutboxBasis {
        profile: custody,
        index: Bytes.empty(),
        postage: Bytes.empty(),
        delivery: Bytes.empty()
      }
    })))
  assert(Bytes.secure_equals(load_blob(path, label)?, sealed))
  assert(Bytes.secure_equals(load_blob(path, "sessions/v1")?, Bytes.from_utf8("before")))
  assert(Result.is_err(load_blob(path, "outbox/rejected")))
  let tail = %{entry(Bytes.from_utf8("tail"), 5)? |
    client_message_id: Bytes.from_utf8("additional-entry")
  }
  let (labels, blobs) = updated_history(path, key, tail, 1)?
  store_updated_blobs(path, labels, blobs)?
  let retained = decode_history(open_history_blob(load_blob(path, label)?, key, label)?)?
  assert(List.length(retained) == 256)
  assert(Bytes.secure_equals(List.head(retained).inner.client_message_id, repeated(1, 16)?))
  assert(Bytes.secure_equals(List.get(retained, 255).inner.body, Bytes.from_utf8("tail")))
  File.delete(path)?
  Ok(true)
end

fn read_test_parts(state :: BinaryReader, count :: Int) -> List<Bytes>!String do
  if count == 0 do
    mobile_finish(state, "unexpected_part_tail")?
    Ok([])
  else
    let part = take_vector(state, 66000)?
    Ok([part.value] ++ read_test_parts(part.state, count - 1)?)
  end
end

fn test_parts(blob :: Bytes) -> List<Bytes>!String do
  let header = take_fixed(mobile_reader(blob, 200000, "unexpected_blob_size")?, 38)?
  let count = case Bytes.read_u16_be(header.value, 36) do
    Err(_) -> Err("unexpected_part_count")
    Ok(value)
  end?
  read_test_parts(header.state, count)
end

fn pack_test_parts(header :: Bytes, parts :: List<Bytes>) -> Bytes!String do
  mobile_join([header]
      ++ for part in parts do
        mobile_vector(part)?
      end,
    0,
    Bytes.empty())
end

fn damage_last(value :: Bytes) -> Bytes!String do
  let length = Bytes.length(value)
  let last = List.head(Bytes.to_list(Bytes.slice(value, length - 1, 1)?))
  Bytes.concat(Bytes.slice(value, 0, length - 1)?, mobile_byte((last + 1) % 256)?)
end

fn malformed_parts() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let label = "history/v1/adversarial"
  let input = repeated(42, 130001)?
  let sealed = seal_history_blob(input, key, label)?
  let header = Bytes.slice(sealed, 0, 38)?
  let parts = test_parts(sealed)?
  assert(List.length(parts) == 4)
  assert(Bytes.secure_equals(open_history_blob(sealed, key, label)?, input))
  assert(Result.is_err(open_history_blob(sealed, key, "history/v1/other")))
  assert(Result.is_err(open_history_blob(damage_last(sealed)?, key, label)))
  assert(Result.is_err(open_history_blob(Bytes.slice(sealed, 0, Bytes.length(sealed) - 1)?,
    key,
    label)))
  assert(Result.is_err(open_history_blob(Bytes.concat(sealed, mobile_byte(0)?)?, key, label)))
  # Ciphertexts must authenticate their position as well as their generation.
  let swapped = pack_test_parts(header,
    [List.get(parts, 0), List.get(parts, 2), List.get(parts, 1), List.get(parts, 3)])?
  assert(Result.is_err(open_history_blob(swapped, key, label)))
  let truncated = pack_test_parts(header, List.take(parts, 3))?
  assert(Result.is_err(open_history_blob(truncated, key, label)))
  let smaller_header = Bytes.concat(Bytes.slice(header, 0, 36)?, mobile_write_u16(3)?)?
  assert(Result.is_err(open_history_blob(pack_test_parts(smaller_header, List.take(parts, 3))?,
    key,
    label)))
  let root_damaged = pack_test_parts(header,
    [damage_last(List.get(parts, 0))?, List.get(parts, 1), List.get(parts, 2), List.get(parts, 3)])?
  assert(Result.is_err(open_history_blob(root_damaged, key, label)))
  let another = test_parts(seal_history_blob(input, key, label)?)?
  let mixed = pack_test_parts(header,
    [List.get(parts, 0), List.get(another, 1), List.get(parts, 2), List.get(parts, 3)])?
  assert(Result.is_err(open_history_blob(mixed, key, label)))
  let wrong_generation = Bytes.concat(Bytes.from_utf8("HCB2"),
    Bytes.concat(repeated(0, 32)?, mobile_write_u16(4)?)?)?
  assert(Result.is_err(open_history_blob(pack_test_parts(wrong_generation, parts)?, key, label)))
  for count in [0, 1, 282, 65535] do
    let invalid_header = Bytes.concat(Bytes.slice(header, 0, 36)?, mobile_write_u16(count)?)?
    assert(Result.is_err(open_history_blob(pack_test_parts(invalid_header, parts)?, key, label)))
  end
  # Even an authenticated root must agree with the actual container. These
  # fixtures distinguish manifest validation from merely rejecting a bad tag.
  let generation = Bytes.slice(header, 4, 32)?
  let root_context = local_context("#{label}/chunks/v2/#{Bytes.to_hex(generation)}/manifest")?
  let manifest = open_local(List.head(parts), key, root_context)?
  let wrong_count = mobile_join([
      Bytes.slice(manifest, 0, 8)?,
      mobile_write_u16(2)?,
      Bytes.slice(manifest, 10, 96)?
    ],
    0,
    Bytes.empty())?
  let wrong_size = mobile_join([
      Bytes.slice(manifest, 0, 4)?,
      mobile_write_u32(130000)?,
      Bytes.slice(manifest, 8, 98)?
    ],
    0,
    Bytes.empty())?
  let too_small = mobile_join([
      Bytes.slice(manifest, 0, 4)?,
      mobile_write_u32(65536)?,
      Bytes.slice(manifest, 8, 98)?
    ],
    0,
    Bytes.empty())?
  let wrong_label = mobile_join([
      Bytes.slice(manifest, 0, 42)?,
      repeated(0, 32)?,
      Bytes.slice(manifest, 74, 32)?
    ],
    0,
    Bytes.empty())?
  let wrong_manifest_generation = mobile_join([
      Bytes.slice(manifest, 0, 10)?,
      repeated(0, 32)?,
      Bytes.slice(manifest, 42, 64)?
    ],
    0,
    Bytes.empty())?
  for inconsistent in [
    wrong_count,
    wrong_size,
    too_small,
    wrong_label,
    wrong_manifest_generation,
    damage_last(manifest)?,
    Bytes.slice(manifest, 0, 105)?
  ] do
    let root = seal_local(inconsistent, key, root_context)?
    let inconsistent_blob = pack_test_parts(header,
      [root, List.get(parts, 1), List.get(parts, 2), List.get(parts, 3)])?
    assert(Result.is_err(open_history_blob(inconsistent_blob, key, label)))
  end
  Ok(true)
end

fn legacy_migration_and_seal_failure() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("history_legacy")?
  ensure_schema(path)?
  let first = entry(repeated(120, 32768)?, 8)?
  let label = "history/v1/#{Bytes.to_hex(first.conversation_id)}"
  let wire = encode_history([MobileHistoryEntry { direction: 2, inner: first }])?
  # Write the exact pre-chunking platform format, independently of the new writer.
  let legacy = seal_local(wire, key, local_context(label)?)?
  store_updated_blobs(path, [label], [legacy])?
  assert(Bytes.secure_equals(open_history_blob(legacy, key, label)?, wire))
  let second = entry(repeated(121, 32768)?, 9)?
  let (labels, blobs) = updated_history(path, key, second, 1)?
  store_updated_blobs(path, labels, blobs)?
  let packed = load_blob(path, label)?
  assert(Bytes.secure_equals(Bytes.slice(packed, 0, 4)?, Bytes.from_utf8("HCB2")))
  let restored = decode_history(open_history_blob(packed, key, label)?)?
  assert(List.length(restored) == 2)
  assert(List.head(restored).direction == 2)
  assert(Bytes.secure_equals(List.head(restored).inner.body, first.body))
  assert(Bytes.secure_equals(List.get(restored, 1).inner.body, second.body))
  # Losing the secure-store counter must fail a rewrite before any DB mutation.
  # Existing key material can still authenticate the old saved generation.
  assert(Test.install_in_memory_secure_store())
  assert(Bytes.secure_equals(open_history_blob(packed, key, label)?, encode_history(restored)?))
  assert(Result.is_err(updated_history(path, key, entry(Bytes.from_utf8("not committed"), 10)?, 1)))
  # D1 also authenticates catalog reads. A new platform key must not bind or
  # report this database empty; the retained original capability proves that
  # its exact previous generation is still present.
  assert(Result.is_err(load_blob(path, label)))
  assert(Bytes.secure_equals(load_blob_with_key(path, label, key)?, packed))
  File.delete(path)?
  Ok(true)
end

fn two_large_messages() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("history_large")?
  ensure_schema(path)?
  let first = entry(repeated(120, 32768)?, 5)?
  let (labels, blobs) = updated_history(path, key, first, 1)?
  store_updated_blobs(path, labels, blobs)?
  let second = entry(repeated(121, 32768)?, 6)?
  let (next_labels, next_blobs) = updated_history(path, key, second, 1)?
  store_updated_blobs(path, next_labels, next_blobs)?
  let label = "history/v1/#{Bytes.to_hex(first.conversation_id)}"
  assert(Bytes.length(load_blob(path, label)?) > 65536)
  # Loading the same saved history must also be possible on the next update.
  let (last_labels, last_blobs) = updated_history(path,
    key,
    entry(Bytes.from_utf8("third"), 7)?,
    1)?
  store_updated_blobs(path, last_labels, last_blobs)?
  File.delete(path)?
  Ok(true)
end

test("two valid large messages survive the platform's per-seal limit") do
  case two_large_messages() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

test("more than eight MiB restores all 256 entries and keeps atomic commits") do
  case full_history() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

test("history parts reject tampering, truncation, reordering and mixed generations") do
  case malformed_parts() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

test("legacy history migrates and failed secure storage leaves its last commit intact") do
  case legacy_migration_and_seal_failure() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
