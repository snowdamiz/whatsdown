import File
from Mobile.GroupState import group_history_entries
from Mobile.History import decode_conversation_summary, history_entries_for
from Mobile.Types import ConversationSummary, MobileGroupHistoryEntry, MobileHistoryEntry
from MobileCore import (
  attachment_prepare_export,
  create_account_export,
  expiry_purge_export,
  group_add_export,
  group_history_export,
  group_key_package_export,
  group_receive_export,
  group_send_export,
  group_timer_export,
  group_timer_state_export,
  list_conversations_export,
  load_history_export,
  outbox_ack_export,
  process_delivery_batch_export,
  receive_initial_export,
  receive_message_export,
  send_message_export,
  start_conversation_export,
  update_conversation_export
)
from Protocol.MailboxWire import encode_delivery_batch
from Protocol.V1 import DeliveredEnvelope, InnerEnvelope
from Storage.Keys import platform_key
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleSupport import GroupAccountFixture, group_account_fixture
from Tests.GroupLifecycleWire import (
  acknowledge,
  envelope_for,
  group_vectors,
  outer,
  output_list,
  read_u32_at
)
from Tests.Support import database_path, read_u32, write_u32

fn ensure(value :: Bool, error :: String) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err(error)
  end
end

fn byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("test byte allocation failed")
    Ok(output)
  end
end

fn text(value :: String) -> Bytes do
  Bytes.from_utf8(value)
end

# What a mailbox fetch returns when nothing is waiting, which ends every sync.

fn sync(path :: String) -> Result<(), String> do
  let empty = case encode_delivery_batch([]) do
    Err(_) -> Err("delivery batch encode failed")
    Ok(value)
  end?
  process_delivery_batch_export(group_vectors([text(path), empty])?)?
  Ok(nil)
end

fn stored_bodies(path :: String, conversation_id :: Bytes) -> List<Bytes>!String do
  let key = platform_key()?
  let entries = history_entries_for(path, key, conversation_id)?
  Ok(for entry in entries do
    entry.inner.body
  end)
end

fn stored_group_bodies(path :: String, group_id :: Bytes) -> List<Bytes>!String do
  let key = platform_key()?
  let entries = group_history_entries(path, key, group_id)?
  Ok(for entry in entries do
    entry.body
  end)
end

fn holds(values :: List<Bytes>, wanted :: String) -> Bool do
  List.any(values, fn(value) do Bytes.secure_equals(value, text(wanted)) end)
end

fn prepared_photo(path :: String) -> Result<(Bytes, Bytes), String> do
  let items = output_list(attachment_prepare_export(group_vectors([
    text(path),
    text("photo.jpg"),
    text("image/jpeg"),
    write_u32(1000)?,
    write_u32(1)?
  ])?)?)?
  Ok((List.get(items, 0), List.get(items, 1)))
end

fn direct_proof() -> Bool!String do
  let alice_path = database_path("disappearing-alice")?
  let bob_path = database_path("disappearing-bob")?
  let alice_profile = create_account_export(group_vectors([text(alice_path), text("alice")])?)?
  let bob_profile = create_account_export(group_vectors([text(bob_path), text("bob")])?)?
  let initial = start_conversation_export(group_vectors([
    text(alice_path),
    bob_profile,
    text("hello bob")
  ])?)?
  acknowledge(alice_path, [initial], 0)?
  receive_initial_export(group_vectors([text(bob_path), initial])?)?
  update_conversation_export(group_vectors([
    text(bob_path),
    alice_profile,
    byte(1)?,
    write_u32(0)?
  ])?)?
  # Alice's chat with Bob now keeps messages for one second.
  update_conversation_export(group_vectors([
    text(alice_path),
    bob_profile,
    byte(5)?,
    write_u32(1)?
  ])?)?
  let (reference, object_id) = prepared_photo(alice_path)?
  let short = send_message_export(group_vectors([
    text(alice_path),
    bob_profile,
    text("gone soon"),
    reference
  ])?)?
  acknowledge(alice_path, [short], 0)?
  receive_message_export(group_vectors([text(bob_path), short])?)?
  let bob_chat = decode_conversation_summary(list_conversations_export(text(bob_path))?)?
  let alice_chat = decode_conversation_summary(list_conversations_export(text(alice_path))?)?
  ensure(holds(stored_bodies(bob_path, bob_chat.conversation_id)?, "gone soon"),
    "the message never reached storage")?
  Timer.sleep(1300)
  sync(bob_path)?
  let kept = stored_bodies(bob_path, bob_chat.conversation_id)?
  ensure(!holds(kept, "gone soon"), "an expired message stayed in storage after a sync")?
  ensure(holds(kept, "hello bob"), "a message without a timer left with it")?
  # Alice's copy goes as her chat opens; the app is handed the object it named, once.
  load_history_export(group_vectors([text(alice_path), bob_profile])?)?
  let purged = output_list(expiry_purge_export(text(alice_path))?)?
  ensure(!holds(stored_bodies(alice_path, alice_chat.conversation_id)?, "gone soon"),
    "the sender's expired copy stayed in storage")?
  ensure(List.length(purged) == 2 && Bytes.secure_equals(List.get(purged, 1), object_id),
    "the purged attachment's object was not handed over")?
  ensure(List.length(output_list(expiry_purge_export(text(alice_path))?)?) == 1,
    "a purged object was handed over twice")?
  File.delete(alice_path)?
  File.delete(bob_path)?
  Ok(true)
end

fn group_rows(path :: String, group_id :: Bytes) -> List<List<Bytes>>!String do
  let rows = output_list(group_history_export(group_vectors([text(path), group_id])?)?)?
  Ok(for row in rows do
    output_list(row)?
  end)
end

fn last_row(path :: String, group_id :: Bytes) -> List<Bytes>!String do
  let rows = group_rows(path, group_id)?
  ensure(List.length(rows) > 0, "group history is empty")?
  Ok(List.get(rows, List.length(rows) - 1))
end

fn timer_of(path :: String, group_id :: Bytes) -> Int!String do
  read_u32(group_timer_state_export(group_vectors([text(path), group_id])?)?)
end

fn set_timer(path :: String, group_id :: Bytes, seconds :: Int) -> List<Bytes>!String do
  let sent = output_list(group_timer_export(group_vectors([
    text(path),
    group_id,
    write_u32(seconds)?
  ])?)?)?
  acknowledge(path, sent, 0)?
  Ok(sent)
end

fn post(path :: String, group_id :: Bytes, body :: String) -> List<Bytes>!String do
  let sent = output_list(group_send_export(group_vectors([text(path), group_id, text(body)])?)?)?
  acknowledge(path, sent, 0)?
  Ok(sent)
end

fn take(path :: String, envelopes :: List<Bytes>, mailbox :: Bytes) -> Result<(), String> do
  group_receive_export(group_vectors([text(path), envelope_for(envelopes, mailbox, 0)?])?)?
  Ok(nil)
end

fn nonzero(value :: Bytes) -> Bool do
  List.any(for index in 0..Bytes.length(value) do
      case Bytes.get(value, index) do
        Err(_) -> 0
        Ok(octet) -> octet
      end
    end,
    fn(octet) do octet != 0 end)
end

# Alice sets a timer; Bob applies it and sees a notice; his messages then carry
# it. Alice's linked device joins later and learns the timer from the next
# message, and a message whose time is up leaves storage at the next sync.

fn group_proof() -> Bool!String do
  let accounts = group_account_fixture()?
  let group_id = create_group_with_bob(accounts)?
  let bob_mailbox = accounts.bob_entry.mailbox_token
  let alice_mailbox = accounts.alice_entry.mailbox_token
  let linked_mailbox = accounts.linked_entry.mailbox_token
  let change = set_timer(accounts.alice_path, group_id, 3600)?
  take(accounts.bob_path, change, bob_mailbox)?
  ensure(timer_of(accounts.bob_path, group_id)? == 3600, "bob did not apply the group timer")?
  let notice = last_row(accounts.bob_path, group_id)?
  ensure(List.length(notice) == 12, "group history summaries have twelve fields")?
  ensure(Bytes.secure_equals(List.get(notice, 11), byte(3)?)
      && Bytes.secure_equals(List.get(notice, 6), text("3600")),
    "bob was not shown the timer change")?
  let rows_before = List.length(group_rows(accounts.alice_path, group_id)?)
  set_timer(accounts.alice_path, group_id, 3600)?
  ensure(List.length(group_rows(accounts.alice_path, group_id)?) == rows_before,
    "setting the same timer again showed a change")?
  let greeting = post(accounts.bob_path, group_id, "short-lived")?
  take(accounts.alice_path, greeting, alice_mailbox)?
  let received = last_row(accounts.alice_path, group_id)?
  ensure(Bytes.secure_equals(List.get(received, 6), text("short-lived"))
      && nonzero(List.get(received, 10)),
    "a message under the timer carries no expiry")?
  # The linked device joins after the change.
  let package = group_key_package_export(text(accounts.linked_path))?
  let added = output_list(group_add_export(group_vectors([
    text(accounts.alice_path),
    group_id,
    accounts.alice_set,
    package
  ])?)?)?
  acknowledge(accounts.alice_path, added, 0)?
  take(accounts.bob_path, added, bob_mailbox)?
  take(accounts.linked_path, added, linked_mailbox)?
  ensure(timer_of(accounts.linked_path, group_id)? == 0, "the new device knew the timer early")?
  let after_join = post(accounts.bob_path, group_id, "welcome aboard")?
  take(accounts.linked_path, after_join, linked_mailbox)?
  take(accounts.alice_path, after_join, alice_mailbox)?
  ensure(timer_of(accounts.linked_path, group_id)? == 3600,
    "the late joiner never learned the timer")?
  # A one-second timer, then a message that outlives it.
  let shorter = set_timer(accounts.alice_path, group_id, 1)?
  take(accounts.bob_path, shorter, bob_mailbox)?
  take(accounts.linked_path, shorter, linked_mailbox)?
  ensure(timer_of(accounts.linked_path, group_id)? == 1, "the linked device missed the change")?
  let brief = post(accounts.bob_path, group_id, "gone soon")?
  take(accounts.alice_path, brief, alice_mailbox)?
  ensure(holds(stored_group_bodies(accounts.alice_path, group_id)?, "gone soon"),
    "the group message never reached storage")?
  Timer.sleep(1300)
  sync(accounts.alice_path)?
  let kept = stored_group_bodies(accounts.alice_path, group_id)?
  ensure(!holds(kept, "gone soon"), "an expired group message stayed in storage after a sync")?
  ensure(holds(kept, "1"), "the timer notice left with the messages")?
  File.delete(accounts.alice_path)?
  File.delete(accounts.linked_path)?
  File.delete(accounts.bob_path)?
  Ok(true)
end

test("an expired direct message leaves storage at the next sync, with its objects handed to the app") do
  assert(Test.install_in_memory_secure_store())
  case direct_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("a group timer change reaches every member, late joiners included, and expired messages leave storage") do
  assert(Test.install_in_memory_secure_store())
  case group_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
