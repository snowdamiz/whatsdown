import File
from MobileCore import (
  create_account_export,
  load_history_export,
  outbox_ack_export,
  outbox_fail_export,
  outbox_list_export,
  outbox_page_export,
  send_message_export,
  start_conversation_export
)
from Tests.GroupLifecycleWire import output_list
from Tests.Support import append, database_path, vector, write_u32

fn request(values :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(values) do
    Ok(output)
  else
    request(values, index + 1, append(output, vector(List.get(values, index))?)?)
  end
end

# What the conversation shows for each message, oldest first: the last field of
# a history summary is one byte, 0 sent, 1 waiting to leave, 2 not delivered.

fn states(path :: String, peer :: Bytes) -> List<Int>!String do
  let summaries = output_list(load_history_export(request([Bytes.from_utf8(path), peer],
    0,
    Bytes.empty())?)?)?
  Ok(List.map(summaries,
    fn (summary) do
      case Bytes.get(summary, Bytes.length(summary) - 1) do
        Err(_) -> 255
        Ok(value) -> value
      end
    end))
end

fn queued(path :: String, offset :: Int) -> Int!String do
  Ok(List.length(output_list(outbox_page_export(request([Bytes.from_utf8(path), write_u32(offset)?],
    0,
    Bytes.empty())?)?)?))
end

fn send_many(path :: String, peer :: Bytes, remaining :: Int) -> Result<(), String> do
  if remaining <= 0 do
    Ok(nil)
  else
    send_message_export(request([Bytes.from_utf8(path), peer, Bytes.from_utf8("again")],
      0,
      Bytes.empty())?)?
    send_many(path, peer, remaining - 1)
  end
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let alice = database_path("delivery-state-alice")?
  let bob = database_path("delivery-state-bob")?
  create_account_export(request([Bytes.from_utf8(alice), Bytes.from_utf8("alice")],
    0,
    Bytes.empty())?)?
  let bob_profile = create_account_export(request([Bytes.from_utf8(bob), Bytes.from_utf8("bob")],
    0,
    Bytes.empty())?)?
  # A queued message is waiting, not sent.
  let first = start_conversation_export(request([
      Bytes.from_utf8(alice),
      bob_profile,
      Bytes.from_utf8("hello")
    ],
    0,
    Bytes.empty())?)?
  assert(states(alice, bob_profile)? == [1])
  # The service refuses it for good: it leaves the outbox and the conversation
  # says so, instead of reading as sent.
  assert(Bytes.length(outbox_fail_export(request([Bytes.from_utf8(alice), first], 0, Bytes.empty())?)?) == 0)
  assert(queued(alice, 0)? == 0)
  assert(states(alice, bob_profile)? == [2])
  # An accepted one reads as sent, and the earlier failure stays a failure.
  let second = send_message_export(request([
      Bytes.from_utf8(alice),
      bob_profile,
      Bytes.from_utf8("still there?")
    ],
    0,
    Bytes.empty())?)?
  assert(states(alice, bob_profile)? == [2, 1])
  assert(Bytes.length(outbox_ack_export(request([Bytes.from_utf8(alice), second], 0, Bytes.empty())?)?) == 0)
  assert(states(alice, bob_profile)? == [2, 0])
  # Refusing something that is not queued changes nothing.
  assert(Bytes.length(outbox_fail_export(request([Bytes.from_utf8(alice), second], 0, Bytes.empty())?)?) == 0)
  assert(states(alice, bob_profile)? == [2, 0])
  # The outbox holds more than the first page shows, and an offset reaches the
  # rest, so envelopes that must wait cannot hide the ones behind them.
  send_many(alice, bob_profile, 10)?
  assert(List.length(output_list(outbox_list_export(Bytes.from_utf8(alice))?)?) == 8)
  assert(queued(alice, 0)? == 8)
  assert(queued(alice, 8)? == 2)
  assert(queued(alice, 10)? == 0)
  File.delete(alice)?
  File.delete(bob)?
  Ok(true)
end

test("the conversation tells a sent message from a waiting one and from one that was refused") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
