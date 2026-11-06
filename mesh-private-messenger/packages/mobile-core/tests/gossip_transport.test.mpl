from MobileCore import (
  start_conversation_export,
  send_message_export,
  receive_initial_export,
  receive_message_export,
  update_conversation_export,
  outbox_list_export,
  outbox_ack_export,
  install_group_transparency_for_test,
  group_create_export,
  transparency_fork_export
)
from Mobile.Codec import current_time
from Mobile.Profile import load_profile
from Mobile.TransparencySafety import retained_fork
from Storage.Keys import platform_key
from Tests.GroupLifecycleWire import output_list
from Tests.GroupConsistencySupport import account_fixture, evidence_bytes, signing_pair, verify_for
from Tests.Support import (
  append,
  vector,
  write_u32,
  repeated
)
from Transparency.Merkle import sign_checkpoint, leaf_hash, consistency_proof
from Transparency.Wire import encode_checkpoint, encode_consistency_proof

fn assert_owned_fixture(value :: Bool) do
  assert(declassify(value,
    "test-only Boolean assertion of controlled synthetic encrypted gossip transport fixture result; no application disclosure"))
end

fn assert_received_body(value :: Bool) do
  assert(declassify(value,
    "test-only Boolean assertion of controlled synthetic gossip message bodies; no application disclosure"))
end

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
  let signer = signing_pair()?
  let witness_a = signing_pair()?
  let witness_b = signing_pair()?
  let accounts = [
    account_fixture("gossip-transport-alice", "alice")?,
    account_fixture("gossip-transport-bob", "bob")?
  ]
  let alice = List.get(accounts, 0).path
  let bob = List.get(accounts, 1).path
  let a = load_profile(alice)?
  let b = load_profile(bob)?
  let leaves = for account in accounts do
    leaf_hash(account.device_set)?
  end
  let initial_checkpoint = sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    U64.parse("1")?,
    leaves,
    repeated(0, 32)?,
    current_time()?)?
  for owner in accounts do
    for index in 0..List.length(accounts) do
      let subject = List.get(accounts, index)
      let evidence = evidence_bytes(subject.device_set,
        leaves,
        index,
        if index == 0 do
          []
        else
          leaves
        end,
        initial_checkpoint,
        witness_a.private_key,
        witness_b.private_key)?
      verify_for(owner,
        subject.username,
        evidence,
        signer.public_key.bytes,
        witness_a.public_key.bytes,
        witness_b.public_key.bytes)?
    end
  end
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
  for (path, marker) in [(alice, 4), (bob, 5)] do
    let fork_leaves = leaves
      ++ for index in 0..6 do
        repeated(marker + index, 32)?
      end
    let checkpoint = sign_checkpoint(signer.private_key,
      signer.public_key.bytes,
      U64.parse("4")?,
      fork_leaves,
      repeated(0, 32)?,
      now)?
    for account in accounts do
      assert(install_group_transparency_for_test(path,
        encode_checkpoint(checkpoint)?,
        encode_consistency_proof(consistency_proof([], fork_leaves)?)?,
        signer.public_key.bytes,
        witness_a.public_key.bytes,
        witness_b.public_key.bytes,
        account.device_set)?)
    end
  end
  let message = say(alice, b, "compare logs")?
  outbox_ack_export(call_input(alice, message)?)?
  assert_received_body(Bytes.secure_equals(receive_message_export(call_input(bob, message)?)?,
    Bytes.from_utf8("compare logs")))
  let ask = take_control(bob)?
  assert_received_body(Bytes.length(receive_message_export(call_input(alice, ask)?)?) == 0)
  let answer = take_control(alice)?
  assert_received_body(Bytes.length(receive_message_export(call_input(bob, answer)?)?) == 0)
  let reciprocal = take_control(bob)?
  assert_received_body(Bytes.length(receive_message_export(call_input(alice, reciprocal)?)?) == 0)
  let key = platform_key()?
  assert(Bytes.length(retained_fork(alice, key)?) > 0 && Bytes.length(retained_fork(bob, key)?) > 0)
  assert(Bytes.secure_equals(transparency_fork_export(Bytes.from_utf8(alice))?,
    retained_fork(alice, key)?))
  assert(List.length(output_list(outbox_list_export(Bytes.from_utf8(alice))?)?) == 0)
  assert(List.length(output_list(outbox_list_export(Bytes.from_utf8(bob))?)?) == 0)
  # Existing conversations keep working; starting or replacing a session pauses.
  let continued = say(alice, b, "still here")?
  assert_received_body(Bytes.secure_equals(receive_message_export(call_input(bob, continued)?)?,
    Bytes.from_utf8("still here")))
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
  assert_owned_fixture(Result.unwrap_or(proof(), false))
end
