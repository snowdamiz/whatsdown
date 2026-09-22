import File
from Mobile.Codec import current_time, mobile_join, mobile_byte
from Mobile.Attachments import validate_attachment
from MobileCore import (
  attachment_open_chunk_export,
  attachment_prepare_export,
  attachment_seal_chunk_export,
  create_account_export,
  group_history_export,
  group_receive_export,
  group_send_export,
  load_history_export,
  receive_initial_export,
  start_conversation_export
)
from Objects.Grant import ObjectGrantRequest, decode_grant, verify_grant
from Protocol.V1 import DirectoryEntry
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleSupport import GroupAccountFixture, group_account_fixture
from Tests.GroupLifecycleWire import acknowledge, envelope_for, group_vectors, output_list, read_u32_at
from Tests.Support import database_path, read_u32, repeated, write_u32

struct PreparedAttachment do
  reference :: Bytes
  object_id :: Bytes
  upload_capability :: Bytes
  grant :: Bytes
  complete :: Bytes
  delete :: Bytes
  encrypted_manifest :: Bytes
end

fn ensure(value :: Bool, error :: String) -> Result <(), String > do
  if value do
    Ok(nil)
  else
    Err(error)
  end
end

fn slice(input :: Bytes, offset :: Int, length :: Int) -> Bytes ! String do
  case Bytes.slice(input, offset, length) do
    Err(_) -> Err("slice failed")
    Ok(value) -> Ok(value)
  end
end

fn vector_items(input :: Bytes, offset :: Int, items :: List < Bytes >) -> List < Bytes > ! String do
  if offset == Bytes.length(input) do
    Ok(items)
  else
    if offset + 4 > Bytes.length(input) do
      Err("vector list decode failed")
    else
      let length = read_u32_at(input, offset) ?
      let item = slice(input, offset + 4, length) ?
      vector_items(input, offset + 4 + length, List.append(items, item))
    end
  end
end

fn wide(value :: String) -> U64 ! String do
  case U64.parse(value) do
    Err(_) -> Err("test integer conversion failed")
    Ok(parsed) -> Ok(parsed)
  end
end

fn prepare(path :: String, filename :: String, mime_type :: String, size :: Int) -> PreparedAttachment ! String do
  let output = attachment_prepare_export(group_vectors([Bytes.from_utf8(path), Bytes.from_utf8(filename), Bytes.from_utf8(mime_type), write_u32(size) ?, write_u32(1) ?]) ?) ?
  let items = output_list(output) ?
  ensure(List.length(items) == 7, "prepare output count mismatch") ?
  Ok(PreparedAttachment {
    reference : List.get(items, 0),
    object_id : List.get(items, 1),
    upload_capability : List.get(items, 2),
    grant : List.get(items, 3),
    complete : List.get(items, 4),
    delete : List.get(items, 5),
    encrypted_manifest : List.get(items, 6)
  })
end

fn seal(path :: String, reference :: Bytes, index :: Int, payload :: Bytes) -> Bytes ! String do
  attachment_seal_chunk_export(group_vectors([Bytes.from_utf8(path), reference, write_u32(index) ?, payload]) ?)
end

fn open(path :: String, reference :: Bytes, index :: Int, payload :: Bytes) -> Bytes ! String do
  attachment_open_chunk_export(group_vectors([Bytes.from_utf8(path), reference, write_u32(index) ?, payload]) ?)
end

# The summary is what the host renders: opaque reference first, then the opened manifest.

fn assert_summary(summary :: Bytes,
prepared :: PreparedAttachment,
filename :: String,
size :: Int,
chunk_count :: Int) -> Bytes ! String do
  let items = output_list(summary) ?
  ensure(List.length(items) == 9, "attachment summary count mismatch") ?
  ensure(Bytes.secure_equals(List.get(items, 1), prepared.object_id), "summary object id mismatch") ?
  ensure(Bytes.length(List.get(items, 2)) == 32, "summary download capability mismatch") ?
  ensure(Bytes.secure_equals(List.get(items, 3), Bytes.from_utf8(filename)),
  "summary filename mismatch") ?
  ensure(Bytes.secure_equals(List.get(items, 4), Bytes.from_utf8("image/jpeg")),
  "summary mime type mismatch") ?
  ensure(read_u32(List.get(items, 5)) ? == size, "summary size mismatch") ?
  ensure(read_u32(List.get(items, 6)) ? == chunk_count, "summary chunk count mismatch") ?
  ensure(read_u32(List.get(items, 7)) ? == 65536, "summary chunk size mismatch") ?
  ensure(Bytes.length(List.get(items, 8)) == 8, "summary expiry mismatch") ?
  Ok(List.get(items, 0))
end

fn exercise_preparation(path :: String) -> PreparedAttachment ! String do
  case attachment_prepare_export(group_vectors([Bytes.from_utf8(path), Bytes.from_utf8("huge.bin"), Bytes.from_utf8("application/octet-stream"), write_u32(256 * 65536 + 1) ?, write_u32(1) ?]) ?) do
    Ok(_) -> Err("oversized attachment was accepted") ?
    Err(error) -> ensure(error == "attachment_too_large",
    "wrong oversized attachment error" <> ": " <> error) ?
  end
  case attachment_prepare_export(group_vectors([Bytes.from_utf8(path), Bytes.from_utf8("empty.bin"), Bytes.from_utf8("application/octet-stream"), write_u32(0) ?, write_u32(1) ?]) ?) do
    Ok(_) -> Err("empty attachment was accepted") ?
    Err(error) -> ensure(error == "attachment_too_large",
    "wrong empty attachment error" <> ": " <> error) ?
  end
  let prepared = prepare(path, "photo.jpg", "image/jpeg", 70000) ?
  ensure(Bytes.length(prepared.object_id) == 32, "object id length mismatch") ?
  ensure(Bytes.length(prepared.upload_capability) == 32, "upload capability length mismatch") ?
  let grant = decode_grant(prepared.grant) ?
  ensure(Bytes.secure_equals(grant.object_id, prepared.object_id), "grant object id mismatch") ?
  ensure(grant.part_count == 3, "grant part count mismatch") ?
  ensure(Bytes.secure_equals(grant.upload_capability, prepared.upload_capability),
  "grant upload capability mismatch") ?
  ensure(verify_grant(prepared.grant, current_time() ?, wide("150000") ?, wide("518400000") ?, 1) ?,
  "grant proof of work did not verify") ?
  ensure(Bytes.length(prepared.complete) == 68 && Bytes.length(prepared.delete) == 68,
  "object control length mismatch") ?
  ensure(Bytes.length(prepared.encrypted_manifest) > 48, "encrypted manifest too small") ?
  Ok(prepared)
end

fn exercise_chunks(path :: String, prepared :: PreparedAttachment) -> Bool ! String do
  let first = repeated(7, 65536) ?
  let last = repeated(9, 4464) ?
  let sealed_first = seal(path, prepared.reference, 0, first) ?
  let sealed_last = seal(path, prepared.reference, 1, last) ?
  ensure(Bytes.length(sealed_first) == 65576, "sealed chunk length mismatch") ?
  ensure(Bytes.length(sealed_last) == 4504, "sealed final chunk length mismatch") ?
  ensure(Bytes.secure_equals(open(path, prepared.reference, 0, sealed_first) ?, first),
  "first chunk round trip mismatch") ?
  ensure(Bytes.secure_equals(open(path, prepared.reference, 1, sealed_last) ?, last),
  "last chunk round trip mismatch") ?
  case seal(path, prepared.reference, 2, last) do
    Ok(_) -> Err("out of range chunk was sealed") ?
    Err(error) -> ensure(error == "invalid_attachment_chunk_index",
    "wrong chunk index error" <> ": " <> error) ?
  end
  case seal(path, prepared.reference, 1, first) do
    Ok(_) -> Err("wrong sized chunk was sealed") ?
    Err(error) -> ensure(error == "invalid_attachment_chunk_size",
    "wrong chunk size error" <> ": " <> error) ?
  end
  case open(path, prepared.reference, 1, sealed_first) do
    Ok(_) -> Err("chunk opened under the wrong index") ?
    Err(error) -> ensure(error == "invalid_attachment_chunk_index",
    "wrong reordered chunk error" <> ": " <> error) ?
  end
  Ok(true)
end

fn exercise_direct_message(carol_path :: String, dave_path :: String) -> Bool ! String do
  let carol_profile = create_account_export(group_vectors([Bytes.from_utf8(carol_path), Bytes.from_utf8("carol")]) ?) ?
  let dave_profile = create_account_export(group_vectors([Bytes.from_utf8(dave_path), Bytes.from_utf8("dave")]) ?) ?
  let prepared = exercise_preparation(carol_path) ?
  ensure(exercise_chunks(carol_path, prepared) ?, "chunk checks failed") ?
  case start_conversation_export(group_vectors([Bytes.from_utf8(carol_path), dave_profile, Bytes.empty()]) ?) do
    Ok(_) -> Err("empty message without attachment was accepted") ?
    Err(error) -> ensure(error == "invalid_start_request",
    "wrong empty start error" <> ": " <> error) ?
  end
  case start_conversation_export(group_vectors([Bytes.from_utf8(carol_path), dave_profile, Bytes.empty(), repeated(1,
  40) ?]) ?) do
    Ok(_) -> Err("malformed attachment reference was accepted") ?
    Err(error) -> ensure(error == "invalid_attachment_reference",
    "wrong malformed reference error: " <> error) ?
  end
  let photos = for index in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9] do
    prepare(carol_path, "photo#{index}.jpg", "image/jpeg", 1000) ?
  end
  let references = for photo in photos do
    photo.reference
  end
  let album = mobile_join([mobile_byte(1) ?, Bytes.from_utf8("ATB"), write_u32(10) ?, group_vectors(references) ?],
  0,
  Bytes.empty()) ?
  let too_many = mobile_join([mobile_byte(1) ?, Bytes.from_utf8("ATB"), write_u32(11) ?, group_vectors(List.append(references,
  prepared.reference)) ?],
  0,
  Bytes.empty()) ?
  let nested = mobile_join([mobile_byte(1) ?, Bytes.from_utf8("ATB"), write_u32(2) ?, group_vectors([album, prepared.reference]) ?],
  0,
  Bytes.empty()) ?
  let trailing = mobile_join([album, mobile_byte(0) ?], 0, Bytes.empty()) ?
  let truncated = slice(album, 0, Bytes.length(album) - 1) ?
  let _ = for invalid in [too_many, nested, trailing, truncated] do
    case validate_attachment(invalid) do
      Ok(_) -> Err("invalid attachment batch was accepted") ?
      Err(_) -> Ok(nil) ?
    end
  end
  let initial = start_conversation_export(group_vectors([Bytes.from_utf8(carol_path), dave_profile, Bytes.empty(), album]) ?) ?
  acknowledge(carol_path, [initial], 0) ?
  ensure(Bytes.length(receive_initial_export(group_vectors([Bytes.from_utf8(dave_path), initial]) ?) ?) == 0,
  "attachment-only message body mismatch") ?
  let dave_history = output_list(load_history_export(group_vectors([Bytes.from_utf8(dave_path), carol_profile]) ?) ?) ?
  ensure(List.length(dave_history) == 1, "dave history count mismatch") ?
  let dave_entry = vector_items(List.head(dave_history), 0, List.new()) ?
  ensure(List.length(dave_entry) == 7, "dave history entry shape mismatch") ?
  # The last field is what became of a sent message; a received one has nothing to say.
  ensure(Bytes.secure_equals(List.get(dave_entry, 6), mobile_byte(0) ?),
  "received message carries a delivery state") ?
  ensure(Bytes.length(List.get(dave_entry, 3)) == 0, "dave history body mismatch") ?
  let dave_summaries = vector_items(List.get(dave_entry, 5), 8, []) ?
  ensure(List.length(dave_summaries) == 10, "receiver lost album photos") ?
  let carol_history = output_list(load_history_export(group_vectors([Bytes.from_utf8(carol_path), dave_profile]) ?) ?) ?
  ensure(List.length(carol_history) == 1, "album created multiple messages") ?
  let carol_entry = vector_items(List.head(carol_history), 0, []) ?
  let carol_summaries = vector_items(List.get(carol_entry, 5), 8, []) ?
  let _ = for index in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9] do
    let photo = List.get(photos, index)
    let reference = assert_summary(List.get(dave_summaries, index),
    photo,
    "photo#{index}.jpg",
    1000,
    1) ?
    let chunk = seal(carol_path, photo.reference, 0, repeated(index, 1000) ?) ?
    ensure(Bytes.secure_equals(open(dave_path, reference, 0, chunk) ?, repeated(index, 1000) ?),
    "album chunk did not decrypt") ?
    let own = assert_summary(List.get(carol_summaries, index), photo, "photo#{index}.jpg", 1000, 1) ?
    ensure(Bytes.secure_equals(own, photo.reference), "sender lost album reference") ?
    case open(dave_path, photo.reference, 0, chunk) do
      Ok(_) -> Err("peer opened sender reference") ?
      Err(error) -> ensure(error == "attachment_key_unwrap_failed", "wrong foreign reference error") ?
    end
  end
  Ok(true)
end

fn exercise_group_message(accounts :: GroupAccountFixture, group_id :: Bytes) -> Bool ! String do
  let prepared = prepare(accounts.alice_path, "trail.jpg", "image/jpeg", 1000) ?
  let payload = repeated(3, 1000) ?
  let sealed = seal(accounts.alice_path, prepared.reference, 0, payload) ?
  let body = Bytes.from_utf8("team photo")
  let deliveries = output_list(group_send_export(group_vectors([Bytes.from_utf8(accounts.alice_path), group_id, body, prepared.reference]) ?) ?) ?
  ensure(List.length(deliveries) == 1, "group attachment delivery count mismatch") ?
  let bob_envelope = envelope_for(deliveries, accounts.bob_entry.mailbox_token, 0) ?
  ensure(Bytes.secure_equals(group_receive_export(group_vectors([Bytes.from_utf8(accounts.bob_path), bob_envelope]) ?) ?,
  body),
  "group attachment body mismatch") ?
  acknowledge(accounts.alice_path, deliveries, 0) ?
  let bob_history = output_list(group_history_export(group_vectors([Bytes.from_utf8(accounts.bob_path), group_id]) ?) ?) ?
  ensure(List.length(bob_history) == 1, "bob group history count mismatch") ?
  let bob_record = output_list(List.head(bob_history)) ?
  ensure(List.length(bob_record) == 10, "bob group history record shape mismatch") ?
  # The last field is what became of a sent message; a received one has nothing to say.
  ensure(Bytes.secure_equals(List.get(bob_record, 9), mobile_byte(0) ?),
  "received group message carries a delivery state") ?
  ensure(Bytes.secure_equals(List.get(bob_record, 6), body), "bob group history body mismatch") ?
  let bob_reference = assert_summary(List.get(bob_record, 7), prepared, "trail.jpg", 1000, 1) ?
  ensure(!Bytes.secure_equals(bob_reference, prepared.reference),
  "group attachment key was not rewrapped for bob") ?
  ensure(Bytes.secure_equals(open(accounts.bob_path, bob_reference, 0, sealed) ?, payload),
  "bob could not open the group attachment") ?
  let alice_history = output_list(group_history_export(group_vectors([Bytes.from_utf8(accounts.alice_path), group_id]) ?) ?) ?
  ensure(List.length(alice_history) == 1, "alice group history count mismatch") ?
  let alice_record = output_list(List.head(alice_history)) ?
  let alice_reference = assert_summary(List.get(alice_record, 7), prepared, "trail.jpg", 1000, 1) ?
  ensure(Bytes.secure_equals(alice_reference, prepared.reference),
  "alice group history lost her own reference") ?
  let silent = output_list(group_send_export(group_vectors([Bytes.from_utf8(accounts.alice_path), group_id, Bytes.empty(), prepared.reference]) ?) ?) ?
  let silent_envelope = envelope_for(silent, accounts.bob_entry.mailbox_token, 0) ?
  let silent_body = group_receive_export(group_vectors([Bytes.from_utf8(accounts.bob_path), silent_envelope]) ?) ?
  ensure(Bytes.length(silent_body) == 0, "attachment-only group body mismatch") ?
  acknowledge(accounts.alice_path, silent, 0) ?
  let bob_after = output_list(group_history_export(group_vectors([Bytes.from_utf8(accounts.bob_path), group_id]) ?) ?) ?
  ensure(List.length(bob_after) == 2, "attachment-only group message was dropped from history") ?
  let silent_record = output_list(List.get(bob_after, 1)) ?
  ensure(Bytes.length(List.get(silent_record, 6)) == 0, "attachment-only group body was not empty") ?
  let _ = assert_summary(List.get(silent_record, 7), prepared, "trail.jpg", 1000, 1) ?
  let photos = for index in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9] do
    prepare(accounts.alice_path, "trail#{index}.jpg", "image/jpeg", 1000) ?
  end
  let references = for photo in photos do
    photo.reference
  end
  let album = mobile_join([mobile_byte(1) ?, Bytes.from_utf8("ATB"), write_u32(10) ?, group_vectors(references) ?],
  0,
  Bytes.empty()) ?
  let album_deliveries = output_list(group_send_export(group_vectors([Bytes.from_utf8(accounts.alice_path), group_id, body, album]) ?) ?) ?
  let album_envelope = envelope_for(album_deliveries, accounts.bob_entry.mailbox_token, 0) ?
  let _ = group_receive_export(group_vectors([Bytes.from_utf8(accounts.bob_path), album_envelope]) ?) ?
  acknowledge(accounts.alice_path, album_deliveries, 0) ?
  let album_history = output_list(group_history_export(group_vectors([Bytes.from_utf8(accounts.bob_path), group_id]) ?) ?) ?
  ensure(List.length(album_history) == 3, "group album did not remain one message") ?
  let album_record = output_list(List.get(album_history, 2)) ?
  let summaries = vector_items(List.get(album_record, 7), 8, []) ?
  ensure(List.length(summaries) == 10, "group album lost photos") ?
  let _ = for index in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9] do
    let photo = List.get(photos, index)
    let reference = assert_summary(List.get(summaries, index), photo, "trail#{index}.jpg", 1000, 1) ?
    let chunk = seal(accounts.alice_path, photo.reference, 0, repeated(index, 1000) ?) ?
    ensure(Bytes.secure_equals(open(accounts.bob_path, reference, 0, chunk) ?,
    repeated(index, 1000) ?),
    "group album chunk did not decrypt") ?
  end
  Ok(true)
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let carol_path = database_path("attachments-carol") ?
  let dave_path = database_path("attachments-dave") ?
  assert(exercise_direct_message(carol_path, dave_path) ?)
  let accounts = group_account_fixture() ?
  let group_id = create_group_with_bob(accounts) ?
  assert(exercise_group_message(accounts, group_id) ?)
  File.delete(carol_path) ?
  File.delete(dave_path) ?
  File.delete(accounts.alice_path) ?
  File.delete(accounts.linked_path) ?
  File.delete(accounts.bob_path) ?
  Ok(true)
end

test("attachments travel as rewrapped references through direct and group messages") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
