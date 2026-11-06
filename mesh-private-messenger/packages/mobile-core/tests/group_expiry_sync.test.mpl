from Mobile.Codec import current_time, mobile_wide
from Mobile.GroupState import decode_group_history, encode_group_history, group_history_label
from Mobile.Inbox import process_delivery_batch
from Mobile.MailboxSync import synchronize_mailbox
from Mobile.Types import MobileBatchRequest, MobileGroupHistoryEntry
from Protocol.MailboxWire import encode_delivery_batch
from Storage.Blobs import load_blob
from Storage.Keys import platform_key, local_context, seal_local, open_local
from Storage.Records import store_updated_blobs
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleSupport import group_account_fixture
from Tests.Support import repeated

fn entry(seconds :: Int, timestamp :: U64, marker :: Int) -> MobileGroupHistoryEntry!String do
  Ok(MobileGroupHistoryEntry {
    disappearing_seconds: seconds,
    message_id: repeated(marker, 32)?,
    direction: 2,
    epoch: mobile_wide("1")?,
    sender_account_id: repeated(1, 32)?,
    sender_device_id: repeated(2, 16)?,
    timestamp: timestamp,
    body: Bytes.from_utf8("synthetic unopened group content"),
    attachment: Bytes.empty()
  })
end

fn cleanup_through_sync() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let accounts = group_account_fixture()?
  let group = create_group_with_bob(accounts)?
  let path = accounts.alice_path
  let key = platform_key()?
  let label = group_history_label(group)
  let original = seal_local(encode_group_history([
    entry(1, mobile_wide("1")?, 71)?,
    entry(0, mobile_wide("1")?, 72)?,
    entry(86400, current_time()?, 73)?
  ])?, key, local_context(label)?)?
  let batch = case encode_delivery_batch([]) do
    Err(_) -> Err("fixture batch encoding")
    Ok(value) -> Ok(value)
  end?
  store_updated_blobs(path, [label], [original])?
  let ack = process_delivery_batch(MobileBatchRequest { database_path: path, batch: batch })?
  assert(Bytes.length(ack) == 0)
  # Inspect the encrypted row before any group history display/export can clean it.
  let partial = load_blob(path, label)?
  let visible = decode_group_history(open_local(partial, key, local_context(label)?)?)?
  assert(List.length(visible) == 2)
  assert(Bytes.secure_equals(List.head(visible).message_id, repeated(72, 32)?))
  assert(Bytes.secure_equals(List.last(visible).message_id, repeated(73, 32)?))
  process_delivery_batch(MobileBatchRequest { database_path: path, batch: batch })?
  assert(Bytes.secure_equals(load_blob(path, label)?, partial))

  store_updated_blobs(path, [label], [original])?
  assert(Test.set_push_token(Bytes.from_utf8("messenger/network/v1"), Bytes.empty()))
  assert(case synchronize_mailbox(path) do
    Err("invalid_network_configuration") -> true
    _ -> false
  end)
  let offline = decode_group_history(open_local(load_blob(path, label)?, key, local_context(label)?)?)?
  assert(List.length(offline) == 2)
  store_updated_blobs(path, [label], [seal_local(encode_group_history([
    entry(1, mobile_wide("1")?, 74)?
  ])?, key, local_context(label)?)?])?
  process_delivery_batch(MobileBatchRequest { database_path: path, batch: batch })?
  assert(load_blob(path, label) == Err("local_state_not_found"))
  process_delivery_batch(MobileBatchRequest { database_path: path, batch: batch })?
  assert(load_blob(path, label) == Err("local_state_not_found"))
  Ok(nil)
end

test("empty and offline sync durably expire unopened group history before display") do
  case cleanup_through_sync() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
