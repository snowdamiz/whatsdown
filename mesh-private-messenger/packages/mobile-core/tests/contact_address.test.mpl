import File
from MobileCore import (
  create_account_export,
  outbox_ack_export,
  outbox_fail_export,
  receive_initial_export,
  receive_message_export,
  reconcile_prekeys_export,
  replenish_prekeys_export,
  send_message_export,
  start_conversation_export,
  update_conversation_export
)
from Prekeys.Pool import PrekeyPublishRequest, PrekeyPublishResponse, decode_prekey_publish, encode_prekey_publish_response
from Protocol.EnvelopeWire import decode_outer_envelope
from Protocol.V1 import DirectoryEntry, OuterEnvelope
from Tests.Support import append, database_path, vector, write_u32
from Transport.Packet import ClientProfile, decode_client_profile

fn request(values :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(values) do
    Ok(output)
  else
    request(values, index + 1, append(output, vector(List.get(values, index)) ?) ?)
  end
end

fn byte(value :: Int) -> Bytes ! String do
  case Bytes.from_list([value]) do
    Err( _) -> Err("test allocation failed")
    Ok( output) -> Ok(output)
  end
end

fn publication(path :: String) -> PrekeyPublishRequest ! String do
  decode_prekey_publish(replenish_prekeys_export(request([Bytes.from_utf8(path), write_u32(0) ?],
  0,
  Bytes.empty()) ?) ?)
end

fn published_hash(path :: String) -> Bytes ! String do
  case publication(path) ?.contact_address_hash do
    None -> Err("publication names no contact address")
    Some( value) -> Ok(value)
  end
end

# What the directory answers to any publication it accepted.

fn answered(path :: String) -> Result <(), String > do
  let sent = publication(path) ?
  let answer = encode_prekey_publish_response(PrekeyPublishResponse {
    account_id : sent.account_id,
    device_id : sent.device_id,
    active_ids : List.new()
  }) ?
  let _ = reconcile_prekeys_export(request([Bytes.from_utf8(path), answer], 0, Bytes.empty()) ?) ?
  Ok(nil)
end

fn addressed_to(envelope :: Bytes) -> Bytes ! String do
  case decode_outer_envelope(envelope) do
    Err( _) -> Err("envelope did not decode")
    Ok( outer) -> Ok(outer.mailbox_token)
  end
end

fn say(path :: String, peer :: Bytes, body :: String) -> Bytes ! String do
  send_message_export(request([Bytes.from_utf8(path), peer, Bytes.from_utf8(body)],
  0,
  Bytes.empty()) ?)
end

fn settle(path :: String, envelope :: Bytes, accepted :: Bool) -> Result <(), String > do
  let payload = request([Bytes.from_utf8(path), envelope], 0, Bytes.empty()) ?
  let _ = if accepted do
    outbox_ack_export(payload)
  else
    outbox_fail_export(payload)
  end ?
  Ok(nil)
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let alice = database_path("contact-address-alice") ?
  let bob = database_path("contact-address-bob") ?
  let carol = database_path("contact-address-carol") ?
  let alice_profile = create_account_export(request([Bytes.from_utf8(alice), Bytes.from_utf8("alice")],
  0,
  Bytes.empty()) ?) ?
  let bob_profile = create_account_export(request([Bytes.from_utf8(bob), Bytes.from_utf8("bob")],
  0,
  Bytes.empty()) ?) ?
  let carol_profile = create_account_export(request([Bytes.from_utf8(carol), Bytes.from_utf8("carol")],
  0,
  Bytes.empty()) ?) ?
  let alice_public = decode_client_profile(alice_profile) ?.entry.mailbox_token
  # Alice's publication names the hash of a contact address, the same one until
  # the directory has answered; only then is it handed to anyone.
  let named = published_hash(alice) ?
  assert(Bytes.length(named) == 32)
  assert(Bytes.secure_equals(published_hash(alice) ?, named))
  # Until then the directory could not route it, so Carol, written to too early,
  # is handed nothing and replies to the public address.
  let early = start_conversation_export(request([Bytes.from_utf8(alice), carol_profile, Bytes.from_utf8("hello carol")],
  0,
  Bytes.empty()) ?) ?
  settle(alice, early, true) ?
  let _ = receive_initial_export(request([Bytes.from_utf8(carol), early], 0, Bytes.empty()) ?) ?
  let _ = update_conversation_export(request([Bytes.from_utf8(carol), alice_profile, byte(1) ?, write_u32(0) ?],
  0,
  Bytes.empty()) ?) ?
  assert(Bytes.secure_equals(addressed_to(say(carol, alice_profile, "hello alice") ?) ?,
  alice_public))
  answered(alice) ?
  assert(Bytes.secure_equals(published_hash(alice) ?, named))
  # Alice writes to Bob, who accepts and replies. His reply goes to the address
  # she handed him inside the message, not to the public one in the directory.
  let hello = start_conversation_export(request([Bytes.from_utf8(alice), bob_profile, Bytes.from_utf8("hello bob")],
  0,
  Bytes.empty()) ?) ?
  settle(alice, hello, true) ?
  let _ = receive_initial_export(request([Bytes.from_utf8(bob), hello], 0, Bytes.empty()) ?) ?
  let _ = update_conversation_export(request([Bytes.from_utf8(bob), alice_profile, byte(1) ?, write_u32(0) ?],
  0,
  Bytes.empty()) ?) ?
  let reply = say(bob, alice_profile, "hello alice") ?
  let reply_address = addressed_to(reply) ?
  assert(!Bytes.secure_equals(reply_address, alice_public))
  assert(Bytes.secure_equals(Crypto.sha256(reply_address), named))
  # The directory refuses that address for good: Bob stops using it, so the
  # worst a bad address can do is lose the one message that tried it.
  settle(bob, reply, false) ?
  let retry = say(bob, alice_profile, "are you there?") ?
  assert(Bytes.secure_equals(addressed_to(retry) ?, alice_public))
  settle(bob, retry, true) ?
  # Alice blocks Bob. She gets a new address to publish, so what Bob holds
  # stops counting as a contact's once the directory hears of it.
  let _ = update_conversation_export(request([Bytes.from_utf8(alice), bob_profile, byte(2) ?, write_u32(0) ?],
  0,
  Bytes.empty()) ?) ?
  let rotated = published_hash(alice) ?
  assert(!Bytes.secure_equals(rotated, named))
  assert(Bytes.secure_equals(published_hash(alice) ?, rotated))
  File.delete(alice) ?
  File.delete(bob) ?
  File.delete(carol) ?
  Ok(true)
end

test("a contact is handed a private deposit address, and a bad one is forgotten") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
