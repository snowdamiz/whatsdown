from Mobile.Types import MobileHistoryAttachment
from MobileCore import create_account_export
from Mobile.Codec import mobile_join, mobile_vector
from Mobile.Inbox import process_delivery_batch
from Mobile.HistoryWire import encode_history, decode_history
from Mobile.Sessions import updated_session_record, seal_session_ids
from Mobile.Types import MobileBatchRequest, MobileHistoryEntry, MobileSessionRecord
from Protocol.MailboxWire import encode_delivery_batch
from Protocol.V1 import InnerEnvelope
from Storage.Blobs import load_blob
from Storage.HistoryBlobs import seal_history_blob, open_history_blob
from Storage.Keys import platform_key, seal_local, local_context
from Storage.Records import store_updated_blobs
from Tests.Support import database_path, repeated
from Transport.Packet import ClientProfile, decode_client_profile

fn request(values :: List<Bytes>) -> Bytes!String do
  mobile_join(for value in values do
      mobile_vector(value)?
    end,
    0,
    Bytes.empty())
end

fn entry(conversation :: Bytes,
  body :: Bytes,
  id :: Int,
  seconds :: Int) -> MobileHistoryEntry!String do
  Ok(MobileHistoryEntry {
    attachment_kind: HistoryOrdinary,
    direction: 2,
    inner: InnerEnvelope {
      version: 1,
      sender_account_id: repeated(11, 32)?,
      sender_device_id: repeated(12, 16)?,
      recipient_device_id: repeated(13, 16)?,
      conversation_id: conversation,
      client_message_id: repeated(id, 16)?,
      client_timestamp: U64.parse("1000")?,
      message_type: 1,
      body: body,
      reply_reference: Bytes.empty(),
      attachment_manifest: Bytes.empty(),
      receipt_policy: 0,
      disappearing_seconds: seconds,
      extensions: []
    }
  })
end

fn record(profile :: ClientProfile,
  conversation :: Bytes,
  device :: Int) -> MobileSessionRecord!String do
  Ok(MobileSessionRecord {
    snapshot: Bytes.empty(),
    local_account_id: profile.account_id,
    local_device_id: profile.device_id,
    peer_account_id: repeated(11, 32)?,
    peer_device_id: repeated(device, 16)?,
    peer_username: "capacitypeer",
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
  })
end

fn synchronize(path :: String, batch :: Bytes, name :: String) -> Bool!String do
  let started = Monotonic.now_nanos()
  let ack = process_delivery_batch(MobileBatchRequest { database_path: path, batch: batch })?
  let nanos = Monotonic.elapsed(started, Monotonic.now_nanos())?
  assert(Bytes.length(ack) == 0)
  println("expiry_capacity #{name} nanos=#{nanos}")
  Ok(true)
end

fn full_text_history_cleanup() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("expiry-capacity")?
  let profile = decode_client_profile(create_account_export(request([
    Bytes.from_utf8(path),
    Bytes.from_utf8("expirycapacity")
  ])?)?)?
  let key = platform_key()?
  let conversation = repeated(31, 16)?
  let other_conversation = repeated(32, 16)?
  let label = "history/v1/#{Bytes.to_hex(conversation)}"
  let other_label = "history/v1/#{Bytes.to_hex(other_conversation)}"
  let body = repeated(120, 32768)?
  let entries = for id in 0..256 do
    entry(conversation,
      body,
      id,
      if id < 128 do
        1
      else
        0
      end)?
  end
  let wire = encode_history(entries)?
  assert(Bytes.length(wire) > 8388608)
  let original = seal_history_blob(wire, key, label)?
  assert(Bytes.secure_equals(Bytes.slice(original, 0, 4)?, Bytes.from_utf8("HCB2")))
  let other = seal_history_blob(encode_history([
      entry(other_conversation, Bytes.from_utf8("unrelated untimed history"), 9, 0)?
    ])?,
    key,
    other_label)?
  # Four linked-device aliases point at one large conversation. A fifth points
  # elsewhere; cleanup must preserve that unrelated history byte-for-byte.
  let ids = for index in 0..5 do
    repeated(21 + index, 32)?
  end
  let labels = for id in ids do
    "session/v1/#{Bytes.to_hex(id)}"
  end
  let blobs = for index in 0..5 do
    let conversation_id = if index == 4 do
      other_conversation
    else
      conversation
    end
    let value = record(profile, conversation_id, 100 + index)?
    seal_local(updated_session_record(Bytes.empty(), value)?,
      key,
      local_context(List.get(labels, index))?)?
  end
  store_updated_blobs(path,
    ["sessions/v1", label, other_label] ++ labels,
    [seal_session_ids(ids, key)?, original, other] ++ blobs)?
  let batch = case encode_delivery_batch([]) do
    Err(_) -> Err("fixture batch encoding failed")
    Ok(value)
  end?
  assert(synchronize(path, batch, "partial_expiry")?)
  let compacted = load_blob(path, label)?
  assert(!Bytes.secure_equals(compacted, original))
  assert(Bytes.secure_equals(Bytes.slice(compacted, 0, 4)?, Bytes.from_utf8("HCB2")))
  let retained = decode_history(open_history_blob(compacted, key, label)?)?
  assert(List.length(retained) == 128)
  for index in 0..128 do
    let value = List.get(retained, index)
    assert(Bytes.secure_equals(value.inner.client_message_id, repeated(128 + index, 16)?))
    assert(Bytes.secure_equals(value.inner.body, body))
    assert(value.inner.disappearing_seconds == 0)
  end
  assert(Bytes.secure_equals(load_blob(path, other_label)?, other))
  assert(synchronize(path, batch, "untimed_repeat")?)
  assert(Bytes.secure_equals(load_blob(path, label)?, compacted))
  assert(Bytes.secure_equals(load_blob(path, other_label)?, other))
  let expired = for value in retained do
    MobileHistoryEntry {
      attachment_kind: HistoryOrdinary,
      direction: value.direction,
      inner: %{value.inner | disappearing_seconds: 1}
    }
  end
  store_updated_blobs(path, [label], [seal_history_blob(encode_history(expired)?, key, label)?])?
  assert(synchronize(path, batch, "complete_expiry")?)
  assert(case load_blob(path, label) do
    Err("local_state_not_found") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(load_blob(path, other_label)?, other))
  File.delete(path)?
  Ok(true)
end

test("256 full-size text messages expire through chunked storage with linked aliases and no-op stability") do
  case full_text_history_cleanup() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
