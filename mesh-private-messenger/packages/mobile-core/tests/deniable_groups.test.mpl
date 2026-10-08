import File
from Groups.GroupCodec import delivery_targets
from Groups.GroupMessages import (
  encode_group_message,
  encrypt_group_message_deniable,
  encrypt_group_message_for_transport,
  group_message_signed_input
)
from Groups.Mls import GroupDeliveryTarget, GroupEncryptOutcome, GroupMessage, GroupState
from Mobile.Codec import canonical_outer, current_time
from Mobile.GroupSigning import group_signer_key
from Mobile.GroupState import (
  GroupSigningRecord,
  canonical_group_message,
  consume_group_state,
  decode_group_packet,
  encode_group_packet,
  group_history_entries,
  group_target_envelopes,
  load_group,
  load_group_signing
)
from Mobile.Groups import receive_mobile_group_classified
from Mobile.History import decode_conversation_summary, history_entries_for
from Mobile.Profile import load_profile, open_device
from Identity.Device import DeviceKeys
from Mobile.Transport import MobileOpenedPacket, open_outer_packet
from Mobile.Types import MobileGroupReceiveOutcome, MobileReceiveRequest
from MobileCore import (
  authorize_device_link_export,
  complete_device_link_export,
  create_account_export,
  create_link_request_export,
  directory_entry_export,
  group_add_export,
  group_create_export,
  group_inspect_export,
  group_key_package_export,
  group_receive_export,
  group_remove_export,
  group_send_export,
  install_group_transparency_for_test,
  list_conversations_export,
  receive_initial_export,
  receive_message_export,
  replenish_prekeys_export,
  reserve_fanout_prekey_export,
  send_fanout_export,
  update_conversation_export
)
from Prekeys.Bundle import normalize_prekey_bundle
from Prekeys.Pool import decode_prekey_publish
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set
from Protocol.EnvelopeWire import decode_outer_envelope
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import DeviceSet, DirectoryEntry, OuterEnvelope, PrekeyBundle
from Storage.Keys import context, open_signing, platform_key
from Tests.GroupConsistencySupport import (
  SignedTransparencyViewFixture,
  request,
  signed_transparency_view,
  wide
)
from Tests.GroupLifecycleWire import acknowledge, output_list
from Tests.Support import database_path, write_u32
from Transparency.Merkle import leaf_hash
from Transport.Packet import ClientProfile, decode_client_profile

# Alice's root device and her linked device, and Bob, as in the linked-device
# fixture: device sets hold base bundles, one-time prekeys are reserved apart.

struct Deniable do
  root_path :: String
  linked_path :: String
  bob_path :: String
  root_profile :: Bytes
  bob_profile :: Bytes
  root_claimed :: DirectoryEntry
  linked_claimed :: DirectoryEntry
  root_entry :: DirectoryEntry
  linked_entry :: DirectoryEntry
  bob_entry :: DirectoryEntry
  alice_set :: Bytes
  bob_set :: Bytes
end

fn ensure(value :: Bool, error :: String) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err(error)
  end
end

fn text(value :: String) -> Bytes do
  Bytes.from_utf8(value)
end

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

fn base_entry(claimed :: DirectoryEntry) -> DirectoryEntry!String do
  case normalize_prekey_bundle(bundle(claimed.prekey_bundle)?) do
    Err(_) -> Err("prekey bundle normalization failed")
    Ok(normalized) -> Ok(%{claimed | prekey_bundle: bundle_wire(normalized)?})
  end
end

fn device_set_wire(value :: DeviceSet) -> Bytes!String do
  case encode_device_set(value) do
    Err(_) -> Err("device set encode failed")
    Ok(encoded)
  end
end

fn install(path :: String,
  view :: SignedTransparencyViewFixture,
  device_set :: Bytes) -> Result<(), String> do
  ensure(install_group_transparency_for_test(path,
      view.checkpoint,
      view.service_public_key,
      view.witness_a_public_key,
      view.witness_b_public_key,
      device_set)?,
    "transparency install failed")
end

fn fixture() -> Deniable!String do
  let root_path = database_path("deniable-root")?
  let linked_path = database_path("deniable-linked")?
  let bob_path = database_path("deniable-bob")?
  let root_profile = create_account_export(request([text(root_path), text("alice")])?)?
  let bob_profile = create_account_export(request([text(bob_path), text("bob")])?)?
  let link_request = create_link_request_export(text(linked_path))?
  let authorization = authorize_device_link_export(request([text(root_path), link_request])?)?
  complete_device_link_export(request([text(linked_path), authorization])?)?
  let root_claimed = entry(directory_entry_export(text(root_path))?)?
  let linked_claimed = entry(directory_entry_export(text(linked_path))?)?
  let bob_claimed = entry(directory_entry_export(text(bob_path))?)?
  let root_entry = base_entry(root_claimed)?
  let linked_entry = base_entry(linked_claimed)?
  let bob_entry = base_entry(bob_claimed)?
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
  let view = signed_transparency_view([leaf_hash(alice_set)?, leaf_hash(bob_set)?])?
  for path in [root_path, linked_path, bob_path] do
    install(path, view, alice_set)?
    install(path, view, bob_set)?
  end
  Ok(Deniable {
    root_path: root_path,
    linked_path: linked_path,
    bob_path: bob_path,
    root_profile: root_profile,
    bob_profile: bob_profile,
    root_claimed: root_claimed,
    linked_claimed: linked_claimed,
    root_entry: root_entry,
    linked_entry: linked_entry,
    bob_entry: bob_entry,
    alice_set: alice_set,
    bob_set: bob_set
  })
end

# Direct messages, which carry each side's session features.

fn fresh_bundle(path :: String, claimed :: DirectoryEntry) -> Bytes!String do
  let publication = decode_prekey_publish(replenish_prekeys_export(request([
    text(path),
    write_u32(1)?
  ])?)?)?
  let prekey = List.head(publication.prekeys)
  bundle_wire(%{bundle(claimed.prekey_bundle)? |
    one_time_prekey_id: prekey.id,
    one_time_prekey: prekey.public_key
  })
end

fn reserve(path :: String,
  peer_set :: Bytes,
  local_set :: Bytes,
  claimed :: Bytes) -> Result<(), String> do
  ensure(Bytes.length(reserve_fanout_prekey_export(request([
      text(path),
      peer_set,
      local_set,
      claimed
    ])?)?) == 0,
    "prekey reservation failed")
end

fn fanout(path :: String,
  peer_set :: Bytes,
  local_set :: Bytes,
  body :: String) -> List<Bytes>!String do
  let sent = output_list(send_fanout_export(request([
    text(path),
    peer_set,
    local_set,
    text(body)
  ])?)?)?
  acknowledge(path, sent, 0)?
  Ok(sent)
end

fn to_mailbox(envelopes :: List<Bytes>, mailbox :: Bytes) -> List<Bytes>!String do
  let marked = for envelope in envelopes do
    (Bytes.secure_equals(outer(envelope)?.mailbox_token, mailbox), envelope)
  end
  Ok(for (wanted, envelope) in marked when wanted do
    envelope
  end)
end

fn first_to(envelopes :: List<Bytes>, mailbox :: Bytes) -> Bytes!String do
  let found = to_mailbox(envelopes, mailbox)?
  ensure(List.length(found) > 0, "no envelope for that mailbox")?
  Ok(List.head(found))
end

fn direct(path :: String, envelope :: Bytes, initial :: Bool) -> Bytes!String do
  if initial do
    receive_initial_export(request([text(path), envelope])?)
  else
    receive_message_export(request([text(path), envelope])?)
  end
end

fn accept(path :: String, peer_profile :: Bytes) -> Result<(), String> do
  ensure(Bytes.secure_equals(update_conversation_export(request([
        text(path),
        peer_profile,
        byte(1)?,
        write_u32(0)?
      ])?)?,
      text("ok")),
    "request not accepted")
end

# Bob writes to both of Alice's devices; the root device accepts and answers,
# and its sibling gets the copy. Root and Bob have each heard the other now.

fn root_and_bob_talk(value :: Deniable) -> Result<(), String> do
  reserve(value.bob_path,
    value.alice_set,
    value.bob_set,
    fresh_bundle(value.root_path, value.root_claimed)?)?
  reserve(value.bob_path,
    value.alice_set,
    value.bob_set,
    fresh_bundle(value.linked_path, value.linked_claimed)?)?
  let hellos = fanout(value.bob_path, value.alice_set, value.bob_set, "hello alice")?
  direct(value.root_path, first_to(hellos, value.root_entry.mailbox_token)?, true)?
  direct(value.linked_path, first_to(hellos, value.linked_entry.mailbox_token)?, true)?
  accept(value.root_path, value.bob_profile)?
  reserve(value.root_path,
    value.bob_set,
    value.alice_set,
    fresh_bundle(value.linked_path, value.linked_claimed)?)?
  let replies = fanout(value.root_path, value.bob_set, value.alice_set, "hi bob")?
  direct(value.bob_path, first_to(replies, value.bob_entry.mailbox_token)?, false)?
  direct(value.linked_path, first_to(replies, value.linked_entry.mailbox_token)?, true)?
  Ok(nil)
end

# Groups.

fn post(path :: String, group_id :: Bytes, body :: String) -> List<Bytes>!String do
  let sent = output_list(group_send_export(request([text(path), group_id, text(body)])?)?)?
  acknowledge(path, sent, 0)?
  Ok(sent)
end

fn take(path :: String, envelope :: Bytes) -> Bytes!String do
  group_receive_export(request([text(path), envelope])?)
end

fn refused_with(path :: String, envelope :: Bytes, expected :: String) -> Result<(), String> do
  case take(path, envelope) do
    Ok(_) -> Err("a group message that should wait or be refused opened")
    Err(error) -> ensure(error == expected, "wrong group refusal: " <> error)
  end
end

fn signing_mode(path :: String, group_id :: Bytes) -> Int!String do
  let fields = output_list(group_inspect_export(request([text(path), group_id])?)?)?
  ensure(List.length(fields) == 8, "group details have eight fields")?
  case Bytes.get(List.get(fields, 7), 0) do
    Err(_) -> Err("signing mode missing")
    Ok(mode)
  end
end

fn holds_body(path :: String, group_id :: Bytes, body :: String) -> Bool!String do
  let entries = group_history_entries(path, platform_key()?, group_id)?
  Ok(List.any(entries, fn(entry) do Bytes.secure_equals(entry.body, text(body)) end))
end

fn profile_of(path :: String) -> ClientProfile!String do
  decode_client_profile(load_profile(path)?)
end

# What a group envelope carries, opened as its recipient would.

fn message_in(path :: String, envelope :: Bytes) -> GroupMessage!String do
  let profile = profile_of(path)?
  let device = open_device(profile, platform_key()?, path)?
  let opened = open_outer_packet(canonical_outer(envelope)?, device.identity_private_key)?
  canonical_group_message(decode_group_packet(opened.packet)?.payload)
end

fn epoch_of(path :: String, group_id :: Bytes) -> U64!String do
  let state = load_group(path, profile_of(path)?, platform_key()?, group_id)?
  let epoch = state.epoch
  consume_group_state(state)
  Ok(epoch)
end

fn record_of(path :: String, group_id :: Bytes) -> GroupSigningRecord!String do
  load_group_signing(path, platform_key()?, group_id)
end

fn verifies(key :: Bytes, input :: Bytes, signature :: Signature) -> Bool do
  case Crypto.verify(SigningPublicKey { bytes: key }, input, signature) do
    Ok(value) -> value
    Err(_) -> false
  end
end

fn sealed_to(path :: String,
  targets :: List<GroupDeliveryTarget>,
  outcome :: GroupEncryptOutcome) -> Bytes!String do
  case outcome do
    GroupEncryptRejected(rejected, _) -> do
      consume_group_state(rejected)
      Err("test message encryption failed")
    end
    GroupMessageEncrypted(next, message) -> do
      consume_group_state(next)
      let wire = case encode_group_message(message) do
        Err(_) -> Err("test message encoding failed")
        Ok(value)
      end?
      let envelopes = group_target_envelopes(path,
        platform_key()?,
        targets,
        encode_group_packet(3, wire)?,
        current_time()?,
        0,
        [])?
      Ok(List.head(envelopes))
    end
  end
end

fn targets_for(state :: borrow GroupState,
  account_id :: Bytes) -> List<GroupDeliveryTarget>!String do
  let targets = case delivery_targets(state.tree, state.local_leaf) do
    Err(_) -> Err("group targets failed")
    Ok(value)
  end?
  Ok(List.filter(targets, fn(target) do Bytes.secure_equals(target.account_id, account_id) end))
end

# A message from `path`'s leaf, never stored there, signed with its long-term
# device key (a version 4 message).

fn long_term_message(path :: String,
  group_id :: Bytes,
  recipient :: Bytes,
  body :: String) -> Bytes!String do
  let key = platform_key()?
  let profile = profile_of(path)?
  let state = load_group(path, profile, key, group_id)?
  let targets = targets_for(state, recipient)?
  let device = open_device(profile, key, path)?
  sealed_to(path,
    targets,
    encrypt_group_message_for_transport(state,
      device.signing_private_key,
      text(body),
      text("mesh-mobile-group/v1")))
end

# A version 6 message from `path`'s leaf signed with the key `owner` keeps in
# `record` for `group_id`.

fn deniable_message(path :: String,
  owner :: String,
  record :: GroupSigningRecord,
  group_id :: Bytes,
  recipient :: Bytes,
  body :: String) -> Bytes!String do
  let key = platform_key()?
  let owner_profile = profile_of(owner)?
  let label = "group-signing/v1/#{Bytes.to_hex(group_id)}/#{U64.to_string(record.epoch)}"
  let signing = open_signing(record.sealed_key,
    key,
    context(owner_profile.account_id, owner_profile.device_id, label, 7)?)?
  let state = load_group(path, profile_of(path)?, key, group_id)?
  let targets = targets_for(state, recipient)?
  sealed_to(path,
    targets,
    encrypt_group_message_deniable(state,
      signing,
      SigningPublicKey { bytes: record.public_key },
      text(body),
      text("mesh-mobile-group/v1")))
end

fn permanent(path :: String, envelope :: Bytes) -> Bool do
  case current_time() do
    Err(_) -> false
    Ok(now) -> case receive_mobile_group_classified(MobileReceiveRequest {
      database_path: path,
      outer: envelope,
      now: now
    }) do
      GroupReceiveRejected(_) -> true
      GroupReceiveRetry(_) -> false
      GroupReceiveApplied(_) -> false
    end
  end
end

fn join(value :: Deniable, path :: String, group_id :: Bytes, set :: Bytes) -> List<Bytes>!String do
  let package = group_key_package_export(text(path))?
  let added = output_list(group_add_export(request([
    text(value.root_path),
    group_id,
    set,
    package
  ])?)?)?
  acknowledge(value.root_path, added, 0)?
  Ok(added)
end

# 1. A group of Alice's root device and Bob, who have never talked directly:
# Alice signs with her long-term key, and Bob reads it.

fn before_sessions(value :: Deniable) -> Bytes!String do
  let group_id = group_create_export(text(value.root_path))?
  let welcome = join(value, value.bob_path, group_id, value.bob_set)?
  ensure(Bytes.secure_equals(take(value.bob_path, List.head(welcome))?, group_id),
    "bob did not join")?
  ensure(signing_mode(value.root_path, group_id)? == 0, "a mode before any message")?
  let signed = post(value.root_path, group_id, "signed with my device key")?
  ensure(List.length(signed) == 1, "a long-term message announced something")?
  ensure(message_in(value.bob_path, List.head(signed))?.version == 4,
    "without a session the message must be version 4")?
  ensure(signing_mode(value.root_path, group_id)? == 1, "the fallback is not reported")?
  take(value.bob_path, List.head(signed))?
  ensure(holds_body(value.bob_path, group_id, "signed with my device key")?,
    "bob did not read the long-term message")?
  Ok(group_id)
end

# 2. Once both have heard the other over a session, Alice's next message
# starts a new epoch, tells Bob its key over the session, and is deniable.
# It waits for the announcement; the announcement shows nothing in Bob's chat.

fn deniable_round(value :: Deniable, group_id :: Bytes) -> Result<(), String> do
  let sent = post(value.root_path, group_id, "deniable now")?
  ensure(List.length(sent) == 3, "expected commit, announcement and message")?
  let commit = List.get(sent, 0)
  let announcement = List.get(sent, 1)
  let message = List.get(sent, 2)
  ensure(signing_mode(value.root_path, group_id)? == 2, "deniable signing is not reported")?
  let wire = message_in(value.bob_path, message)?
  ensure(wire.version == 6, "the message is not version 6")?
  refused_with(value.bob_path, message, "group_future_epoch")?
  take(value.bob_path, commit)?
  refused_with(value.bob_path, message, "group_sender_key_pending")?
  ensure(!permanent(value.bob_path, message), "a message waiting for its key was dropped")?
  let chat = decode_conversation_summary(list_conversations_export(text(value.bob_path))?)?
  let before = List.length(history_entries_for(value.bob_path,
    platform_key()?,
    chat.conversation_id)?)
  ensure(Bytes.length(direct(value.bob_path, announcement, false)?) == 0,
    "the announcement was shown")?
  ensure(List.length(history_entries_for(value.bob_path,
      platform_key()?,
      chat.conversation_id)?) == before,
    "the announcement reached the chat")?
  ensure(Bytes.secure_equals(take(value.bob_path, message)?, text("deniable now")),
    "the deniable message did not open")?
  # What Bob holds proves nothing about who wrote it: the signature verifies
  # under the announced key only, never under Alice's long-term key.
  let root = profile_of(value.root_path)?
  let announced = group_signer_key(value.bob_path,
    platform_key()?,
    group_id,
    wire.epoch,
    root.account_id,
    root.device_id)?
  let signed = case group_message_signed_input(wire, text("mesh-mobile-group/v1")) do
    Err(_) -> Err("signed input failed")
    Ok(input)
  end?
  ensure(verifies(announced, signed, wire.signature), "the announced key does not verify")?
  ensure(!verifies(root.credential.signing_public_key, signed, wire.signature),
    "the long-term key verifies a deniable message")?
  ensure(!verifies(profile_of(value.bob_path)?.credential.signing_public_key,
      signed,
      wire.signature),
    "another member's long-term key verifies it")?
  # Now that Alice signs deniably in this epoch, her long-term-signed message is a downgrade.
  let downgraded = long_term_message(value.root_path,
    group_id,
    profile_of(value.bob_path)?.account_id,
    "downgraded")?
  refused_with(value.bob_path, downgraded, "group_downgrade_rejected")?
  ensure(permanent(value.bob_path, downgraded), "a downgrade must be refused for good")?
  Ok(nil)
end

# 3. Bob answers: he has heard Alice's root device, so his first message in
# the epoch is deniable too, announced to her over the same session.

fn bob_answers(value :: Deniable, group_id :: Bytes) -> Result<(), String> do
  let sent = post(value.bob_path, group_id, "deniable back")?
  ensure(List.length(sent) == 2, "expected Bob's announcement and message")?
  ensure(message_in(value.root_path, List.get(sent, 1))?.version == 6,
    "Bob's reply is not deniable")?
  direct(value.root_path, List.get(sent, 0), false)?
  ensure(Bytes.secure_equals(take(value.root_path, List.get(sent, 1))?, text("deniable back")),
    "Alice did not read Bob's deniable reply")?
  Ok(nil)
end

# 4. Alice's linked device joins. Nobody has heard it over a session yet, so
# Alice falls back to her long-term key in the new epoch, and both read it.

fn linked_joins(value :: Deniable, group_id :: Bytes) -> Result<(), String> do
  let added = join(value, value.linked_path, group_id, value.alice_set)?
  take(value.bob_path, first_to(added, value.bob_entry.mailbox_token)?)?
  take(value.linked_path, first_to(added, value.linked_entry.mailbox_token)?)?
  let sent = post(value.root_path, group_id, "welcome, linked device")?
  ensure(List.length(sent) == 2, "a fallback message announced something")?
  ensure(signing_mode(value.root_path, group_id)? == 1, "the fallback is not reported")?
  let to_bob = first_to(sent, value.bob_entry.mailbox_token)?
  ensure(message_in(value.bob_path, to_bob)?.version == 4, "the fallback is not version 4")?
  take(value.bob_path, to_bob)?
  take(value.linked_path, first_to(sent, value.linked_entry.mailbox_token)?)?
  Ok(nil)
end

# 5. The linked device writes directly to Bob, with the copy to the root
# device: now both have heard it. Alice's next message starts a new epoch
# with a new key, announced to Bob and to the linked device over their
# sessions. The key of the earlier deniable epoch signs for nothing any more.

fn linked_talks(value :: Deniable,
  group_id :: Bytes,
  earlier :: GroupSigningRecord) -> Result<(), String> do
  let written = fanout(value.linked_path,
    value.bob_set,
    value.alice_set,
    "hello from the linked device")?
  direct(value.bob_path, first_to(written, value.bob_entry.mailbox_token)?, false)?
  direct(value.root_path, first_to(written, value.root_entry.mailbox_token)?, false)?
  let sent = post(value.root_path, group_id, "deniable again")?
  ensure(List.length(sent) == 6, "expected two commits, two announcements, two messages")?
  let for_bob = to_mailbox(sent, value.bob_entry.mailbox_token)?
  let for_linked = to_mailbox(sent, value.linked_entry.mailbox_token)?
  take(value.bob_path, List.get(for_bob, 0))?
  direct(value.bob_path, List.get(for_bob, 1), false)?
  ensure(Bytes.secure_equals(take(value.bob_path, List.get(for_bob, 2))?, text("deniable again")),
    "bob did not read the new epoch's message")?
  take(value.linked_path, List.get(for_linked, 0))?
  direct(value.linked_path, List.get(for_linked, 1), false)?
  ensure(Bytes.secure_equals(take(value.linked_path, List.get(for_linked, 2))?,
      text("deniable again")),
    "the linked device did not read it")?
  let current = record_of(value.root_path, group_id)?
  ensure(current.mode == 2 && U64.compare(current.epoch, earlier.epoch) > 0,
    "the new epoch is not deniable")?
  ensure(!Bytes.secure_equals(current.public_key, earlier.public_key), "the key did not rotate")?
  let root = profile_of(value.root_path)?
  ensure(Bytes.length(group_signer_key(value.bob_path,
      platform_key()?,
      group_id,
      earlier.epoch,
      root.account_id,
      root.device_id)?) == 0,
    "bob kept the key of an epoch he left")?
  let stale_key = deniable_message(value.root_path,
    value.root_path,
    earlier,
    group_id,
    profile_of(value.bob_path)?.account_id,
    "old key, new epoch")?
  refused_with(value.bob_path, stale_key, "group_message_rejected")?
  Ok(nil)
end

# 6. The linked device writes deniably too. Its key never signs for another
# member: a message from the root device's leaf under it is refused.

fn linked_posts(value :: Deniable, group_id :: Bytes) -> Result<(), String> do
  let sent = post(value.linked_path, group_id, "linked, deniably")?
  ensure(List.length(sent) == 4, "expected two announcements and two messages")?
  let for_bob = to_mailbox(sent, value.bob_entry.mailbox_token)?
  direct(value.bob_path, List.get(for_bob, 0), false)?
  ensure(message_in(value.bob_path, List.get(for_bob, 1))?.version == 6,
    "the linked device's message is not deniable")?
  take(value.bob_path, List.get(for_bob, 1))?
  let for_root = to_mailbox(sent, value.root_entry.mailbox_token)?
  direct(value.root_path, List.get(for_root, 0), false)?
  take(value.root_path, List.get(for_root, 1))?
  let bob_account = profile_of(value.bob_path)?.account_id
  let impersonated = deniable_message(value.root_path,
    value.linked_path,
    record_of(value.linked_path, group_id)?,
    group_id,
    bob_account,
    "not from the root device")?
  refused_with(value.bob_path, impersonated, "group_message_rejected")?
  Ok(nil)
end

# 7. Alice removes the linked device. Its key is for an epoch the group has
# left, so its next message is refused.

fn linked_removed(value :: Deniable, group_id :: Bytes) -> Result<(), String> do
  let linked = profile_of(value.linked_path)?
  let removal = output_list(group_remove_export(request([
    text(value.root_path),
    group_id,
    linked.account_id,
    linked.device_id
  ])?)?)?
  acknowledge(value.root_path, removal, 0)?
  take(value.bob_path, first_to(removal, value.bob_entry.mailbox_token)?)?
  let late = post(value.linked_path, group_id, "after my removal")?
  ensure(List.length(late) == 2, "an unchanged epoch announced again")?
  refused_with(value.bob_path, first_to(late, value.bob_entry.mailbox_token)?, "group_stale_epoch")?
  ensure(!holds_body(value.bob_path, group_id, "after my removal")?,
    "a removed device's message was kept")?
  Ok(nil)
end

fn proof() -> Bool!String do
  let value = fixture()?
  let group_id = before_sessions(value)?
  root_and_bob_talk(value)?
  deniable_round(value, group_id)?
  bob_answers(value, group_id)?
  let earlier = record_of(value.root_path, group_id)?
  linked_joins(value, group_id)?
  linked_talks(value, group_id, earlier)?
  linked_posts(value, group_id)?
  linked_removed(value, group_id)?
  File.delete(value.root_path)?
  File.delete(value.linked_path)?
  File.delete(value.bob_path)?
  Ok(true)
end

test("group messages are deniable once every member device reads them, with keys only from pairwise sessions") do
  assert(Test.install_in_memory_secure_store())
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
