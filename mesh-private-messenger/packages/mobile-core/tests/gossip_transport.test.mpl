from MobileCore import (
  create_account_export,
  start_conversation_export,
  send_message_export,
  receive_initial_export,
  receive_message_export,
  update_conversation_export,
  outbox_list_export,
  outbox_ack_export,
  install_group_checkpoint_for_test,
  group_create_export,
  transparency_fork_export
)
from Mobile.Codec import current_time
from Mobile.TransparencySafety import retained_fork
from Storage.Keys import platform_key
from Tests.GroupLifecycleWire import output_list
from Tests.Support import (
  append,
  vector,
  write_u32,
  repeated,
  database_path,
  install_security_config
)
from Transparency.Merkle import sign_tree_checkpoint_for
from Transparency.Wire import encode_checkpoint

fn request(parts :: List<Bytes>, index :: Int, bytes :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(bytes)
  else
    request(parts, index + 1, append(bytes, vector(List.get(parts, index))?)?)
  end
end

fn call_input(path :: String, payload :: Bytes) -> Bytes!String do
  request([Bytes.from_utf8(path), payload], 0, Bytes.empty())
end

fn say(path :: String, peer :: Bytes, body :: String) -> Bytes!String do
  send_message_export(request([Bytes.from_utf8(path), peer, Bytes.from_utf8(body)],
    0,
    Bytes.empty())?)
end

fn take_control(path :: String) -> Bytes!String do
  let controls = output_list(outbox_list_export(Bytes.from_utf8(path))?)?
  assert(List.length(controls) == 1)
  let control = List.head(controls)
  # Reading twice must not advance the send ratchet twice or duplicate the queue.
  let again = output_list(outbox_list_export(Bytes.from_utf8(path))?)?
  assert(List.length(again) == 1 && Bytes.secure_equals(List.head(again), control))
  outbox_ack_export(call_input(path, control)?)?
  Ok(control)
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let signer = case Crypto.signing_generate() do
    Err(_) -> return Err("fixture signer failed")
    Ok(value) -> value
  end
  assert(install_security_config(signer.public_key.bytes,
    repeated(31, 32)?,
    repeated(32, 32)?,
    repeated(33, 32)?,
    8))
  let alice = database_path("gossip-transport-alice")?
  let bob = database_path("gossip-transport-bob")?
  let a = create_account_export(call_input(alice, Bytes.from_utf8("alice"))?)?
  let b = create_account_export(call_input(bob, Bytes.from_utf8("bob"))?)?
  let hello = start_conversation_export(request([
      Bytes.from_utf8(alice),
      b,
      Bytes.from_utf8("hello")
    ],
    0,
    Bytes.empty())?)?
  outbox_ack_export(call_input(alice, hello)?)?
  receive_initial_export(call_input(bob, hello)?)?
  update_conversation_export(request([Bytes.from_utf8(bob), a, repeated(1, 1)?, write_u32(0)?],
    0,
    Bytes.empty())?)?
  let now = current_time()?
  for (path, root) in [(alice, repeated(4, 32)?), (bob, repeated(5, 32)?)] do
    let checkpoint = sign_tree_checkpoint_for(1,
      signer.private_key,
      signer.public_key.bytes,
      U64.parse("4")?,
      U64.parse("8")?,
      root,
      repeated(0, 32)?,
      now)?
    install_group_checkpoint_for_test(path, encode_checkpoint(checkpoint)?)?
  end
  let message = say(alice, b, "compare logs")?
  outbox_ack_export(call_input(alice, message)?)?
  assert(Bytes.to_utf8(receive_message_export(call_input(bob, message)?)?)? == "compare logs")
  let ask = take_control(bob)?
  assert(Bytes.length(receive_message_export(call_input(alice, ask)?)?) == 0)
  let answer = take_control(alice)?
  assert(Bytes.length(receive_message_export(call_input(bob, answer)?)?) == 0)
  let reciprocal = take_control(bob)?
  assert(Bytes.length(receive_message_export(call_input(alice, reciprocal)?)?) == 0)
  let key = platform_key()?
  assert(Bytes.length(retained_fork(alice, key)?) > 0 && Bytes.length(retained_fork(bob, key)?) > 0)
  assert(Bytes.secure_equals(transparency_fork_export(Bytes.from_utf8(alice))?,
    retained_fork(alice, key)?))
  assert(List.length(output_list(outbox_list_export(Bytes.from_utf8(alice))?)?) == 0)
  assert(List.length(output_list(outbox_list_export(Bytes.from_utf8(bob))?)?) == 0)
  # Existing conversations keep working; starting or replacing a session pauses.
  let continued = say(alice, b, "still here")?
  assert(Bytes.to_utf8(receive_message_export(call_input(bob, continued)?)?)? == "still here")
  case start_conversation_export(request([Bytes.from_utf8(alice), b, Bytes.from_utf8("replace")],
    0,
    Bytes.empty())?) do
    Err(error) -> assert(error == "transparency_fork_detected")
    Ok(_) -> assert(false)
  end
  case group_create_export(Bytes.from_utf8(alice)) do
    Err(error) -> assert(error == "transparency_fork_detected")
    Ok(_) -> assert(false)
  end
  File.delete(alice)?
  File.delete(bob)?
  Ok(true)
end

test("encrypted gossip controls survive outbox retries and both phones pause only new sessions") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
