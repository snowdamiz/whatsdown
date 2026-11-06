from MobileCore import create_account_export
from Mobile.Codec import current_time, mobile_join, mobile_vector
from Mobile.Inbox import process_delivery_batch
from Mobile.HistoryWire import encode_history, decode_history
from Mobile.HistoryExpiry import prepare_direct_history_expiry, commit_history_expiry
from Mobile.Expiry import message_unexpired
from Mobile.MailboxSync import synchronize_mailbox
from Mobile.Sessions import updated_session_record, seal_session_ids
from Mobile.Types import MobileBatchRequest, MobileHistoryEntry, MobileSessionRecord
from Protocol.MailboxWire import encode_delivery_batch
from Protocol.V1 import InnerEnvelope
from Storage.Blobs import load_blob
from Storage.HistoryBlobs import seal_history_blob, open_history_blob
from Storage.Keys import platform_key, seal_local, local_context
from Storage.Records import store_updated_blobs
from Tests.Support import database_path, repeated
from Transport.Packet import decode_client_profile

fn request(values :: List<Bytes>) -> Bytes!String do
  mobile_join(for value in values do mobile_vector(value)? end, 0, Bytes.empty())
end

fn rejected_stale(result :: Result<(), String>) -> Bool do
  case result do
    Err("account_state_changed") -> true
    _ -> false
  end
end

fn entry(conversation :: Bytes,
  number :: Int,
  timestamp :: U64,
  seconds :: Int) -> MobileHistoryEntry!String do
  Ok(MobileHistoryEntry {
    direction: 2,
    inner: InnerEnvelope {
      version: 1,
      sender_account_id: repeated(11, 32)?,
      sender_device_id: repeated(12, 16)?,
      recipient_device_id: repeated(13, 16)?,
      conversation_id: conversation,
      client_message_id: repeated(number, 16)?,
      client_timestamp: timestamp,
      message_type: 1,
      body: Bytes.from_utf8("synthetic expiry fixture #{number}"),
      reply_reference: Bytes.empty(),
      attachment_manifest: Bytes.empty(),
      receipt_policy: 0,
      disappearing_seconds: seconds,
      extensions: []
    }
  })
end

fn empty_sync_deletes_unopened_history() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("expiry-sync")?
  let profile = decode_client_profile(create_account_export(request([
    Bytes.from_utf8(path), Bytes.from_utf8("expiryfixture")
  ])?)?)?
  let key = platform_key()?
  let session = repeated(21, 32)?
  let conversation = repeated(22, 16)?
  let session_label = "session/v1/#{Bytes.to_hex(session)}"
  let history_label = "history/v1/#{Bytes.to_hex(conversation)}"
  let record = MobileSessionRecord {
    snapshot: Bytes.empty(),
    local_account_id: profile.account_id,
    local_device_id: profile.device_id,
    peer_account_id: repeated(11, 32)?,
    peer_device_id: repeated(12, 16)?,
    peer_username: "fixturepeer",
    peer_mailbox: repeated(14, 32)?,
    conversation_id: conversation,
    request_state: 1,
    blocked: false,
    verified: false,
    key_changed: false,
    disappearing_seconds: 0,
    strongest_suite: 2,
    safety_number: Bytes.empty(),
    peer_transport_key: Bytes.empty()
  }
  let now = current_time()?
  let entries = [
    entry(conversation, 1, U64.parse("1000")?, 1)?,
    entry(conversation, 2, U64.parse("1000")?, 0)?,
    entry(conversation, 3, now, 86400)?
  ]
  let original = seal_history_blob(encode_history(entries)?, key, history_label)?
  store_updated_blobs(path,
    ["sessions/v1", session_label, history_label],
    [
      seal_session_ids([session], key)?,
      seal_local(updated_session_record(Bytes.empty(), record)?, key, local_context(session_label)?)?,
      original
    ])?
  let batch = case encode_delivery_batch([]) do
    Err(_) -> Err("fixture batch encoding failed")
    Ok(value)
  end?
  let ack = process_delivery_batch(MobileBatchRequest { database_path: path, batch: batch })?
  assert(Bytes.length(ack) == 0)
  # Observe the sealed row directly. No history display/export may trigger cleanup.
  let stored = load_blob(path, history_label)?
  let remaining = decode_history(open_history_blob(stored, key, history_label)?)?
  assert(List.length(remaining) == 2)
  assert(Bytes.secure_equals(List.get(remaining, 0).inner.client_message_id, repeated(2, 16)?))
  assert(Bytes.secure_equals(List.get(remaining, 1).inner.client_message_id, repeated(3, 16)?))
  let second = process_delivery_batch(MobileBatchRequest { database_path: path, batch: batch })?
  assert(Bytes.length(second) == 0)
  assert(Bytes.secure_equals(load_blob(path, history_label)?, stored))

  # A concurrent incoming message must survive a stale cleanup plan unchanged.
  store_updated_blobs(path, [history_label], [original])?
  let stale_history = prepare_direct_history_expiry(path, key, session, now)?
  let incoming = seal_history_blob(encode_history(List.append(entries,
    entry(conversation, 4, now, 0)?))?, key, history_label)?
  store_updated_blobs(path, [history_label], [incoming])?
  assert(rejected_stale(commit_history_expiry(path, stale_history)))
  assert(Bytes.secure_equals(load_blob(path, history_label)?, incoming))
  commit_history_expiry(path, prepare_direct_history_expiry(path, key, session, now)?)?
  let after_incoming = decode_history(open_history_blob(load_blob(path, history_label)?, key, history_label)?)?
  assert(List.length(after_incoming) == 3)
  assert(Bytes.secure_equals(List.get(after_incoming, 2).inner.client_message_id, repeated(4, 16)?))

  store_updated_blobs(path, [history_label], [original])?
  let stale_index = prepare_direct_history_expiry(path, key, session, now)?
  store_updated_blobs(path, ["sessions/v1"], [seal_session_ids([], key)?])?
  assert(rejected_stale(commit_history_expiry(path, stale_index)))
  assert(Bytes.secure_equals(load_blob(path, history_label)?, original))
  store_updated_blobs(path, ["sessions/v1"], [seal_session_ids([session], key)?])?

  let stale_record = prepare_direct_history_expiry(path, key, session, now)?
  let changed_record = %{record | blocked: true}
  store_updated_blobs(path, [session_label], [seal_local(updated_session_record(Bytes.empty(), changed_record)?,
    key, local_context(session_label)?)?])?
  assert(rejected_stale(commit_history_expiry(path, stale_record)))
  assert(Bytes.secure_equals(load_blob(path, history_label)?, original))

  # Use another real account's valid sealed custody, not malformed ciphertext.
  let other_path = database_path("expiry-other")?
  create_account_export(request([Bytes.from_utf8(other_path), Bytes.from_utf8("expiryother")])?)?
  let original_profile = load_blob(path, "profile/v1")?
  let stale_account = prepare_direct_history_expiry(path, key, session, now)?
  store_updated_blobs(path, ["profile/v1"], [load_blob(other_path, "profile/v1")?])?
  assert(rejected_stale(commit_history_expiry(path, stale_account)))
  assert(Bytes.secure_equals(load_blob(path, history_label)?, original))
  store_updated_blobs(path, ["profile/v1"], [original_profile])?
  File.delete(other_path)?

  # Cleanup runs before transport setup, even when no network can be attempted.
  assert(Test.set_push_token(Bytes.from_utf8("messenger/network/v1"), Bytes.empty()))
  assert(case synchronize_mailbox(path) do
    Err("invalid_network_configuration") -> true
    _ -> false
  end)
  let offline = decode_history(open_history_blob(load_blob(path, history_label)?, key, history_label)?)?
  assert(List.length(offline) == 2)

  # An entirely expired history removes the row; a repeat empty sync stays empty.
  let expired = seal_history_blob(encode_history([entry(conversation, 5, U64.parse("1000")?, 1)?])?,
    key, history_label)?
  store_updated_blobs(path, [history_label], [expired])?
  process_delivery_batch(MobileBatchRequest { database_path: path, batch: batch })?
  assert(case load_blob(path, history_label) do
    Err("local_state_not_found") -> true
    _ -> false
  end)
  process_delivery_batch(MobileBatchRequest { database_path: path, batch: batch })?
  assert(case load_blob(path, history_label) do
    Err("local_state_not_found") -> true
    _ -> false
  end)
  File.delete(path)?
  Ok(true)
end

fn expiry_boundaries() -> Bool!String do
  let timestamp = U64.parse("1000")?
  assert(message_unexpired(timestamp, 1, U64.parse("1999")?)?)
  assert(!message_unexpired(timestamp, 1, U64.parse("2000")?)?)
  assert(!message_unexpired(timestamp, 1, U64.parse("2001")?)?)
  assert(message_unexpired(timestamp, 0, U64.parse("18446744073709551615")?)?)
  assert(message_unexpired(timestamp, 1, U64.parse("999")?)?)
  let future = U64.parse("18446744073709551000")?
  assert(message_unexpired(future, 2592000, U64.parse("18446744073709551615")?)?)
  Ok(true)
end

test("expiry is inclusive, preserves untimed and future messages, and cannot overflow") do
  case expiry_boundaries() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("an empty sync deletes expired stored direct messages without opening their chat and preserves live history") do
  case empty_sync_deletes_unopened_history() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
