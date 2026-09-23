import File
from Mobile.History import decode_conversation_summary
from Mobile.Types import ConversationSummary
from MobileCore import (
  authorize_device_link_export,
  complete_device_link_export,
  create_account_export,
  create_link_request_export,
  directory_entry_export,
  install_group_transparency_for_test,
  list_conversations_export,
  load_history_export,
  receive_initial_export,
  receive_message_export,
  replenish_prekeys_export,
  reserve_fanout_prekey_export,
  send_fanout_export,
  start_conversation_export,
  update_conversation_export
)
from Prekeys.Bundle import normalize_prekey_bundle
from Prekeys.Pool import decode_prekey_publish
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set
from Protocol.EnvelopeWire import decode_outer_envelope
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import DeviceSet, DirectoryEntry, OuterEnvelope, PrekeyBundle
from Tests.GroupConsistencySupport import (
  SignedTransparencyViewFixture,
  request,
  signed_transparency_view,
  signing_pair,
  wide
)
from Tests.Support import database_path, install_security_config, write_u32
from Transparency.Merkle import leaf_hash

fn byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("test byte encoding failed")
    Ok(encoded)
  end
end

fn entry(input :: Bytes) -> DirectoryEntry!String do
  case decode_directory_entry(input) do
    Err(_) -> Err("directory entry decode failed")
    Ok(value)
  end
end

fn bundle(input :: Bytes) -> PrekeyBundle!String do
  case decode_prekey_bundle(input) do
    Err(_) -> Err("prekey bundle decode failed")
    Ok(value)
  end
end

fn outer(input :: Bytes) -> OuterEnvelope!String do
  case decode_outer_envelope(input) do
    Err(_) -> Err("outer envelope decode failed")
    Ok(value)
  end
end

fn bundle_wire(value :: PrekeyBundle) -> Bytes!String do
  case encode_prekey_bundle(value) do
    Err(_) -> Err("prekey bundle encode failed")
    Ok(encoded)
  end
end

# A device set carries base bundles; the claimed one-time prekeys travel separately.

fn base_entry(claimed :: DirectoryEntry) -> DirectoryEntry!String do
  case normalize_prekey_bundle(bundle(claimed.prekey_bundle)?) do
    Err(_) -> Err("prekey bundle normalization failed")
    Ok(normalized) -> Ok(% { claimed | prekey_bundle: bundle_wire(normalized)? })
  end
end

fn device_set_wire(value :: DeviceSet) -> Bytes!String do
  case encode_device_set(value) do
    Err(_) -> Err("device set encode failed")
    Ok(encoded)
  end
end

fn read_u32_at(input :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u32_be(input, offset) do
    Err(_) -> Err("output list decode failed")
    Ok(value) -> case U64.to_int(value) do
      Err(_) -> Err("output list decode failed")
      Ok(parsed)
    end
  end
end

fn slice(input :: Bytes, offset :: Int, length :: Int) -> Bytes!String do
  case Bytes.slice(input, offset, length) do
    Err(_) -> Err("output list decode failed")
    Ok(value)
  end
end

fn output_items(input :: Bytes, count :: Int, index :: Int, offset :: Int, items :: List<Bytes>) -> List<Bytes>!String do
  if index >= count do
    if offset == Bytes.length(input) do
      Ok(items)
    else
      Err("output list decode failed")
    end
  else
    let length = read_u32_at(input, offset)?
    if length <= 0 do
      Err("output list decode failed")
    else
      let item = slice(input, offset + 4, length)?
      output_items(input, count, index + 1, offset + 4 + length, List.append(items, item))
    end
  end
end

fn output_list(input :: Bytes) -> List<Bytes>!String do
  if Bytes.length(input) < 8 || read_u32_at(input, 0)? != 4 do
    Err("output list decode failed")
  else
    let count = read_u32_at(input, 4)?
    if count < 0 || count > 64 do
      Err("output list decode failed")
    else
      output_items(input, count, 0, 8, List.new())
    end
  end
end

fn history_body(input :: Bytes) -> Bytes!String do
  if read_u32_at(input, 0)? != 1 do
    Err("history summary decode failed")
  else
    let client_offset = 5
    let client_length = read_u32_at(input, client_offset)?
    let timestamp_offset = client_offset + 4 + client_length
    let timestamp_length = read_u32_at(input, timestamp_offset)?
    let body_offset = timestamp_offset + 4 + timestamp_length
    if client_length != 16 || timestamp_length != 8 do
      Err("history summary decode failed")
    else
      slice(input, body_offset + 4, read_u32_at(input, body_offset)?)
    end
  end
end

fn bodies(summaries :: List<Bytes>, index :: Int, output :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(summaries) do
    Ok(output)
  else
    bodies(summaries, index + 1, List.append(output, history_body(List.get(summaries, index))?))
  end
end

# What one device shows for its conversation with a peer, oldest first.

fn history_bodies(path :: String, peer_profile :: Bytes) -> List<Bytes>!String do
  bodies(output_list(load_history_export(request([Bytes.from_utf8(path), peer_profile])?)?)?,
    0,
    List.new())
end

fn same_bodies(actual :: List<Bytes>, expected :: List<String>, index :: Int) -> Bool do
  if List.length(actual) != List.length(expected) do
    false
  else if index >= List.length(expected) do
    true
  else if !Bytes.secure_equals(List.get(actual, index), Bytes.from_utf8(List.get(expected, index))) do
    false
  else
    same_bodies(actual, expected, index + 1)
  end
end

# The one conversation on a device, as its list shows it.

fn request_state(path :: String) -> Int!String do
  let summary = decode_conversation_summary(list_conversations_export(Bytes.from_utf8(path))?)?
  Ok(summary.request_state)
end

# A fresh one-time prekey on a device, in the claimable bundle a sender reserves
# before starting a session with it.

fn fresh_bundle(path :: String, claimed :: PrekeyBundle) -> Bytes!String do
  let publication = decode_prekey_publish(replenish_prekeys_export(request([
    Bytes.from_utf8(path),
    write_u32(1)?
  ])?)?)?
  let prekey = List.head(publication.prekeys)
  bundle_wire(% { claimed | one_time_prekey_id: prekey.id, one_time_prekey: prekey.public_key })
end

fn reserve(path :: String, peer_set :: Bytes, local_set :: Bytes, claimed :: Bytes) -> Bool!String do
  assert(Bytes.length(reserve_fanout_prekey_export(request([
    Bytes.from_utf8(path),
    peer_set,
    local_set,
    claimed
  ])?)?) == 0)
  Ok(true)
end

fn install(path :: String, view :: SignedTransparencyViewFixture, device_set :: Bytes) -> Bool!String do
  install_group_transparency_for_test(path,
    view.checkpoint,
    view.consistency,
    view.service_public_key,
    view.witness_a_public_key,
    view.witness_b_public_key,
    device_set)
end

fn fanout(path :: String, peer_set :: Bytes, local_set :: Bytes, body :: String) -> List<Bytes>!String do
  output_list(send_fanout_export(request([
    Bytes.from_utf8(path),
    peer_set,
    local_set,
    Bytes.from_utf8(body)
  ])?)?)
end

fn addressed_to(envelopes :: List<Bytes>, mailbox :: Bytes, index :: Int) -> Bytes!String do
  if index >= List.length(envelopes) do
    Err("no envelope for that mailbox")
  else
    let candidate = List.get(envelopes, index)
    if Bytes.secure_equals(outer(candidate)?.mailbox_token, mailbox) do
      Ok(candidate)
    else
      addressed_to(envelopes, mailbox, index + 1)
    end
  end
end

fn received(path :: String, envelope :: Bytes, initial :: Bool, body :: String) -> Bool!String do
  let opened = if initial do
    receive_initial_export(request([Bytes.from_utf8(path), envelope])?)
  else
    receive_message_export(request([Bytes.from_utf8(path), envelope])?)
  end?
  assert(Bytes.secure_equals(opened, Bytes.from_utf8(body)))
  Ok(true)
end

fn accept(path :: String, peer_profile :: Bytes) -> Bool!String do
  assert(Bytes.secure_equals(update_conversation_export(request([
      Bytes.from_utf8(path),
      peer_profile,
      byte(1)?,
      write_u32(0)?
    ])?)?,
    Bytes.from_utf8("ok")))
  Ok(true)
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let service_pair = signing_pair()?
  let witness_a = signing_pair()?
  let witness_b = signing_pair()?
  let delivery_pair = case Crypto.x25519_generate() do
    Err(_) -> Err("test delivery key generation failed")
    Ok(value)
  end?
  assert(install_security_config(service_pair.public_key.bytes,
    witness_a.public_key.bytes,
    witness_b.public_key.bytes,
    delivery_pair.public_key.bytes,
    8))
  let root_path = database_path("linked-sync-root")?
  let linked_path = database_path("linked-sync-linked")?
  let bob_path = database_path("linked-sync-bob")?
  let carol_path = database_path("linked-sync-carol")?
  let root_profile = create_account_export(request([
    Bytes.from_utf8(root_path),
    Bytes.from_utf8("alice")
  ])?)?
  let bob_profile = create_account_export(request([
    Bytes.from_utf8(bob_path),
    Bytes.from_utf8("bob")
  ])?)?
  let carol_profile = create_account_export(request([
    Bytes.from_utf8(carol_path),
    Bytes.from_utf8("carol")
  ])?)?
  let link_request = create_link_request_export(Bytes.from_utf8(linked_path))?
  let authorization = authorize_device_link_export(request([
    Bytes.from_utf8(root_path),
    link_request
  ])?)?
  assert(Bytes.length(complete_device_link_export(request([
    Bytes.from_utf8(linked_path),
    authorization
  ])?)?) > 0)
  let root_claimed = entry(directory_entry_export(Bytes.from_utf8(root_path))?)?
  let linked_claimed = entry(directory_entry_export(Bytes.from_utf8(linked_path))?)?
  let bob_claimed = entry(directory_entry_export(Bytes.from_utf8(bob_path))?)?
  let carol_claimed = entry(directory_entry_export(Bytes.from_utf8(carol_path))?)?
  let root_entry = base_entry(root_claimed)?
  let linked_entry = base_entry(linked_claimed)?
  let bob_entry = base_entry(bob_claimed)?
  let carol_entry = base_entry(carol_claimed)?
  let alice_set = device_set_wire(DeviceSet {
    version: 1,
    username: "alice",
    account_identity: root_entry.account_identity,
    sequence: wide(2)?,
    devices: [root_entry, linked_entry],
    revoked_device_ids: List.new()
  })?
  let bob_set = device_set_wire(DeviceSet {
    version: 1,
    username: "bob",
    account_identity: bob_entry.account_identity,
    sequence: wide(1)?,
    devices: [bob_entry],
    revoked_device_ids: List.new()
  })?
  let carol_set = device_set_wire(DeviceSet {
    version: 1,
    username: "carol",
    account_identity: carol_entry.account_identity,
    sequence: wide(1)?,
    devices: [carol_entry],
    revoked_device_ids: List.new()
  })?
  let alice_view = signed_transparency_view([
    leaf_hash(alice_set)?,
    leaf_hash(bob_set)?,
    leaf_hash(carol_set)?
  ])?
  assert(install(root_path, alice_view, alice_set)?)
  assert(install(root_path, alice_view, bob_set)?)
  assert(install(root_path, alice_view, carol_set)?)
  assert(install(linked_path, alice_view, alice_set)?)
  assert(install(linked_path, alice_view, bob_set)?)
  assert(install(linked_path, alice_view, carol_set)?)
  let bob_view = signed_transparency_view([leaf_hash(alice_set)?, leaf_hash(bob_set)?])?
  assert(install(bob_path, bob_view, alice_set)?)
  assert(install(bob_path, bob_view, bob_set)?)
  let carol_view = signed_transparency_view([leaf_hash(alice_set)?, leaf_hash(carol_set)?])?
  assert(install(carol_path, carol_view, alice_set)?)
  assert(install(carol_path, carol_view, carol_set)?)
  # Bob writes first, to both of alice's devices: a request on each.
  assert(reserve(bob_path,
    alice_set,
    bob_set,
    fresh_bundle(root_path, bundle(root_claimed.prekey_bundle)?)?)?)
  assert(reserve(bob_path,
    alice_set,
    bob_set,
    fresh_bundle(linked_path, bundle(linked_claimed.prekey_bundle)?)?)?)
  let hello = "hello alice"
  let hellos = fanout(bob_path, alice_set, bob_set, hello)?
  assert(List.length(hellos) == 2)
  assert(received(root_path, addressed_to(hellos, root_entry.mailbox_token, 0)?, true, hello)?)
  assert(received(linked_path, addressed_to(hellos, linked_entry.mailbox_token, 0)?, true, hello)?)
  assert(request_state(root_path)? == 0)
  assert(request_state(linked_path)? == 0)
  # Alice accepts on the root device and replies from there.
  assert(accept(root_path, bob_profile)?)
  assert(reserve(root_path,
    bob_set,
    alice_set,
    fresh_bundle(linked_path, bundle(linked_claimed.prekey_bundle)?)?)?)
  let from_root = "hi from the root device"
  let root_replies = fanout(root_path, bob_set, alice_set, from_root)?
  assert(List.length(root_replies) == 2)
  assert(received(bob_path,
    addressed_to(root_replies, bob_entry.mailbox_token, 0)?,
    false,
    from_root)?)
  assert(received(linked_path,
    addressed_to(root_replies, linked_entry.mailbox_token, 0)?,
    true,
    from_root)?)
  # The linked device saw its own account reply, so the request is accepted
  # there too, and the conversation reads the same...
  assert(request_state(linked_path)? == 1)
  assert(same_bodies(history_bodies(linked_path, bob_profile)?, [hello, from_root], 0))
  # ...and it can carry the conversation on itself, with the root device following.
  let from_linked = "and from the linked device"
  let linked_replies = fanout(linked_path, bob_set, alice_set, from_linked)?
  assert(List.length(linked_replies) == 2)
  assert(received(bob_path,
    addressed_to(linked_replies, bob_entry.mailbox_token, 0)?,
    false,
    from_linked)?)
  assert(received(root_path,
    addressed_to(linked_replies, root_entry.mailbox_token, 0)?,
    false,
    from_linked)?)
  assert(same_bodies(history_bodies(root_path, bob_profile)?, [hello, from_root, from_linked], 0))
  assert(same_bodies(history_bodies(bob_path, root_profile)?, [hello, from_root, from_linked], 0))
  # A conversation the root device had before the link. The linked device
  # writes first, knowing nothing of it, and everyone still meets in one place.
  let hello_carol = "hello carol"
  let carol_initial = start_conversation_export(request([
    Bytes.from_utf8(root_path),
    carol_profile,
    Bytes.from_utf8(hello_carol)
  ])?)?
  assert(received(carol_path, carol_initial, true, hello_carol)?)
  assert(accept(carol_path, root_profile)?)
  assert(reserve(linked_path,
    carol_set,
    alice_set,
    fresh_bundle(carol_path, bundle(carol_claimed.prekey_bundle)?)?)?)
  let to_carol = "carol, from the linked device"
  let carol_fanout = fanout(linked_path, carol_set, alice_set, to_carol)?
  assert(List.length(carol_fanout) == 2)
  assert(received(carol_path,
    addressed_to(carol_fanout, carol_entry.mailbox_token, 0)?,
    true,
    to_carol)?)
  assert(received(root_path,
    addressed_to(carol_fanout, root_entry.mailbox_token, 0)?,
    false,
    to_carol)?)
  assert(same_bodies(history_bodies(carol_path, root_profile)?, [hello_carol, to_carol], 0))
  assert(same_bodies(history_bodies(root_path, carol_profile)?, [hello_carol, to_carol], 0))
  let from_carol = "back to both of you"
  let carol_replies = fanout(carol_path, alice_set, carol_set, from_carol)?
  assert(List.length(carol_replies) == 2)
  assert(received(root_path,
    addressed_to(carol_replies, root_entry.mailbox_token, 0)?,
    false,
    from_carol)?)
  assert(received(linked_path,
    addressed_to(carol_replies, linked_entry.mailbox_token, 0)?,
    false,
    from_carol)?)
  assert(same_bodies(history_bodies(root_path, carol_profile)?,
    [hello_carol, to_carol, from_carol],
    0))
  assert(same_bodies(history_bodies(linked_path, carol_profile)?, [to_carol, from_carol], 0))
  File.delete(root_path)?
  File.delete(linked_path)?
  File.delete(bob_path)?
  File.delete(carol_path)?
  Ok(true)
end

test("a linked device shares every direct conversation with its siblings") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
