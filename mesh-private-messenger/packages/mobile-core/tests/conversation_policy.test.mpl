import File
from MobileCore import ConversationSummary, create_account_export, decode_conversation_summary, list_conversations_export, load_history_export, outbox_ack_export, receive_initial_export, receive_message_export, safety_number_export, send_message_export, start_conversation_export, update_conversation_export
from Tests.Support import append, database_path, vector, write_u32

fn encode_vectors(values :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_vectors(values, index + 1, append(output, vector(List.get(values, index)) ?) ?)
  end
end

fn request(values :: List < Bytes >) -> Bytes ! String do
  encode_vectors(values, 0, Bytes.empty())
end

fn byte(value :: Int) -> Bytes ! String do
  case Bytes.from_list([value]) do
    Err( _) -> Err("test byte allocation failed")
    Ok( output) -> Ok(output)
  end
end

fn acknowledge(path :: String, envelope :: Bytes) -> Bool ! String do
  assert(Bytes.length(outbox_ack_export(request([Bytes.from_utf8(path), envelope]) ?) ?) == 0)
  Ok(true)
end

fn policy(path :: String, profile :: Bytes, action :: Int, value :: Int) -> Bytes ! String do
  update_conversation_export(request([Bytes.from_utf8(path), profile, byte(action) ?, write_u32(value) ?]) ?)
end

fn assert_summary(value :: ConversationSummary,
username :: String,
safety_number :: Bytes,
request_state :: Int,
blocked :: Bool,
disappearing_seconds :: Int) -> Bool do
  assert(Bytes.length(value.conversation_id) == 16)
  assert(value.username == username)
  assert(Bytes.length(value.peer_account_id) == 32)
  assert(Bytes.length(value.peer_device_id) == 16)
  assert(Bytes.length(value.safety_number) == 64)
  assert(Bytes.secure_equals(value.safety_number, safety_number))
  assert(value.request_state == request_state)
  assert(value.blocked == blocked)
  assert(!value.verified)
  assert(!value.key_changed)
  assert(value.disappearing_seconds == disappearing_seconds)
  true
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let alice_path = database_path("conversation-policy-alice") ?
  let bob_path = database_path("conversation-policy-bob") ?
  let alice_profile = create_account_export(request([Bytes.from_utf8(alice_path), Bytes.from_utf8("alice")]) ?) ?
  let bob_profile = create_account_export(request([Bytes.from_utf8(bob_path), Bytes.from_utf8("bob")]) ?) ?
  let greeting = Bytes.from_utf8("hello bob")
  let initial = start_conversation_export(request([Bytes.from_utf8(alice_path), bob_profile, greeting]) ?) ?
  assert(acknowledge(alice_path, initial) ?)
  assert(Bytes.secure_equals(receive_initial_export(request([Bytes.from_utf8(bob_path), initial]) ?) ?,
  greeting))
  let alice_safety = safety_number_export(request([Bytes.from_utf8(alice_path), bob_profile]) ?) ?
  let bob_safety = safety_number_export(request([Bytes.from_utf8(bob_path), alice_profile]) ?) ?
  assert(Bytes.secure_equals(alice_safety, bob_safety))
  assert(assert_summary(decode_conversation_summary(list_conversations_export(Bytes.from_utf8(bob_path)) ?) ?,
  "alice",
  bob_safety,
  0,
  false,
  0))
  let reply = Bytes.from_utf8("hello alice")
  let reply_request = request([Bytes.from_utf8(bob_path), alice_profile, reply]) ?
  case send_message_export(reply_request) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "message_request_pending")
  end
  assert(Bytes.secure_equals(policy(bob_path, alice_profile, 1, 0) ?, Bytes.from_utf8("ok")))
  assert(assert_summary(decode_conversation_summary(list_conversations_export(Bytes.from_utf8(bob_path)) ?) ?,
  "alice",
  bob_safety,
  1,
  false,
  0))
  let reply_outer = send_message_export(reply_request) ?
  assert(acknowledge(bob_path, reply_outer) ?)
  assert(Bytes.secure_equals(receive_message_export(request([Bytes.from_utf8(alice_path), reply_outer]) ?) ?,
  reply))
  assert(Bytes.secure_equals(policy(bob_path, alice_profile, 2, 0) ?, Bytes.from_utf8("ok")))
  assert(assert_summary(decode_conversation_summary(list_conversations_export(Bytes.from_utf8(bob_path)) ?) ?,
  "alice",
  bob_safety,
  1,
  true,
  0))
  let blocked_outer = send_message_export(request([Bytes.from_utf8(alice_path), bob_profile, Bytes.from_utf8("blocked")]) ?) ?
  assert(acknowledge(alice_path, blocked_outer) ?)
  case receive_message_export(request([Bytes.from_utf8(bob_path), blocked_outer]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "blocked_message")
  end
  assert(Bytes.secure_equals(policy(bob_path, alice_profile, 3, 0) ?, Bytes.from_utf8("ok")))
  let history_request = request([Bytes.from_utf8(bob_path), alice_profile]) ?
  let history_before = load_history_export(history_request) ?
  assert(Bytes.secure_equals(policy(alice_path, bob_profile, 5, 1) ?, Bytes.from_utf8("ok")))
  let disappearing = Bytes.from_utf8("gone soon")
  let disappearing_outer = send_message_export(request([Bytes.from_utf8(alice_path), bob_profile, disappearing]) ?) ?
  assert(acknowledge(alice_path, disappearing_outer) ?)
  assert(Bytes.secure_equals(receive_message_export(request([Bytes.from_utf8(bob_path), disappearing_outer]) ?) ?,
  disappearing))
  assert(!Bytes.secure_equals(load_history_export(history_request) ?, history_before))
  Timer.sleep(2000)
  assert(Bytes.secure_equals(load_history_export(history_request) ?, history_before))
  case decode_conversation_summary(Bytes.empty()) do
    Ok( _) -> assert(false)
    Err( _) -> assert(true)
  end
  File.delete(alice_path) ?
  File.delete(bob_path) ?
  Ok(true)
end

test("mobile conversation policy and disappearing history are proven in Mesh") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
