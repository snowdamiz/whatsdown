##! Synthetic encrypted receives against clean-account admission epochs. No network.
from Attachments.ViewOnce import ViewOnceBinding
from Mobile.Codec import current_time, mobile_join, mobile_vector, mobile_byte
from Mobile.Gossip import outgoing_gossip_hint
from Mobile.Messages import receive_initial_message
from Mobile.Profile import load_profile, open_device
from Mobile.Types import MobileReceiveRequest
from Mobile.ViewOnceNative import native_view_once_consume
from Protocol.V1 import InnerEnvelope, ProtocolExtension
from Storage.AccountGuard import load_account_basis, same_account_basis
from Storage.Blobs import load_blob
from Storage.Keys import platform_key, open_local, seal_local, local_context, one_time_prekey_label
from Storage.Records import store_updated_blobs, store_record_changes
from Storage.ViewOnce import ViewOnceRecord, encode_view_once_record
from Tests.Support import repeated
from Tests.ViewOnceFixture import (
  view_once_receive_material,
  view_once_fixture,
  view_once_fixture_clear
)
from Tests.ViewOnceInitialSyncFixture import (
  InitialSyncFixture,
  initial_sync_fixture,
  clear_initial_sync_fixture,
  initial_carrier,
  pending_label,
  identity_label,
  history_label,
  pending_and_history
)
from Transport.Packet import ClientProfile, decode_client_profile, direct_conversation_id

fn epoch_label() -> String do
  "view-once/admission-epoch/v1"
end

fn epoch_check(value :: Plaintext<Bool>, message :: String) -> Unit!String do
  if declassify(value, "test-only observation of synthetic view-once epoch and receive state") do
    Ok(nil)
  else
    Err(message)
  end
end

# The magic is deliberately read from the sealed record: its literal is not
# specified by the design. Its fixed length and equality across accounts are
# checked, as are the exact account and device suffixes.
fn epoch_open(path :: String, profile :: ClientProfile) -> Bytes!String do
  let key = platform_key()?
  let blob = load_blob(path, epoch_label())?
  let raw = open_local(blob, key, local_context(epoch_label())?)?
  epoch_check(Bytes.length(raw) > 48, "epoch lacks a fixed magic and identity")?
  let magic_length = Bytes.length(raw) - 48
  epoch_check(Bytes.secure_equals(Bytes.slice(raw, magic_length, 32)?, profile.account_id)
      && Bytes.secure_equals(Bytes.slice(raw, magic_length + 32, 16)?, profile.device_id),
    "epoch is not bound to the local account and device")?
  epoch_check(!Bytes.secure_equals(blob, raw), "epoch was stored without sealing")?
  Ok(raw)
end

fn epoch_inner(sender :: ClientProfile,
  receiver :: ClientProfile,
  conversation :: Bytes,
  id :: Bytes,
  reference :: Bytes,
  offered :: Bytes,
  hint :: Bytes) -> InnerEnvelope!String do
  Ok(InnerEnvelope {
    version: 1,
    sender_account_id: sender.account_id,
    sender_device_id: sender.device_id,
    recipient_device_id: receiver.device_id,
    conversation_id: conversation,
    client_message_id: id,
    client_timestamp: current_time()?,
    message_type: 1,
    body: Bytes.from_utf8("synthetic epoch control"),
    reply_reference: Bytes.empty(),
    attachment_manifest: reference,
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: [
      ProtocolExtension { id: 1, mandatory: false, value: offered },
      ProtocolExtension { id: 2, mandatory: false, value: hint }
    ]
  })
end

fn epoch_receive(path :: String, wire :: Bytes) -> Bytes!String do
  receive_initial_message(MobileReceiveRequest { database_path: path, outer: wire })
end

fn epoch_good_receive(sender_path :: String, receiver_path :: String, id :: Bytes) -> Unit!String do
  let key = platform_key()?
  let sender = decode_client_profile(load_profile(sender_path)?)?
  let receiver = decode_client_profile(load_profile(receiver_path)?)?
  let conversation = direct_conversation_id(sender.account_id, receiver.account_id)?
  let binding = ViewOnceBinding {
    sender_account_id: sender.account_id,
    sender_device_id: sender.device_id,
    receiver_account_id: receiver.account_id,
    receiver_device_id: receiver.device_id,
    conversation_id: conversation,
    message_id: id
  }
  let device = open_device(receiver, key, receiver_path)?
  let (reference, _chunk, _png) = view_once_receive_material(device, binding)?
  let inner = epoch_inner(sender,
    receiver,
    conversation,
    id,
    reference,
    repeated(201, 32)?,
    outgoing_gossip_hint(sender_path, key)?)?
  let (_state, wire) = initial_carrier(sender_path, receiver_path, inner)?
  epoch_check(Bytes.secure_equals(epoch_receive(receiver_path, wire)?, inner.body),
    "valid epoch did not admit an authenticated view-once receive")?
  epoch_check(pending_and_history(receiver_path, conversation, id, reference, 1)?,
    "admitted receive did not create pending and sanitized history")
end

fn epoch_creation_body(fixture :: InitialSyncFixture) -> Unit!String do
  let alice = decode_client_profile(load_profile(fixture.alice_path)?)?
  let linked = decode_client_profile(load_profile(fixture.linked_path)?)?
  let bob = decode_client_profile(load_profile(fixture.bob_path)?)?
  let a = epoch_open(fixture.alice_path, alice)?
  let l = epoch_open(fixture.linked_path, linked)?
  let b = epoch_open(fixture.bob_path, bob)?
  let n = Bytes.length(a) - 48
  epoch_check(Bytes.length(l) == Bytes.length(a)
      && Bytes.length(b) == Bytes.length(a)
      && Bytes.secure_equals(Bytes.slice(a, 0, n)?, Bytes.slice(l, 0, n)?)
      && Bytes.secure_equals(Bytes.slice(a, 0, n)?, Bytes.slice(b, 0, n)?)
      && Bytes.secure_equals(alice.account_id, linked.account_id)
      && !Bytes.secure_equals(alice.device_id, linked.device_id),
    "account creation and link did not produce the same fixed magic for distinct devices")?
  epoch_good_receive(fixture.alice_path, fixture.bob_path, repeated(211, 16)?)?
  epoch_good_receive(fixture.bob_path, fixture.linked_path, repeated(212, 16)?)
end

# Cases: absent, unauthenticated bytes, authenticated wrong account, wrong
# device, and authenticated malformed magic. Each retains an unrelated orphan
# marker, so acceptance cannot depend only on looking up the incoming identity.
fn epoch_damage(path :: String, other_path :: String, kind :: Int) -> Unit!String do
  if kind == 0 do
    return store_record_changes(path, [], [], [epoch_label()])
  end
  if kind == 1 do
    return store_updated_blobs(path, [epoch_label()], [Bytes.from_utf8("damaged ciphertext")])
  end
  let key = platform_key()?
  let receiver = decode_client_profile(load_profile(path)?)?
  let other = decode_client_profile(load_profile(other_path)?)?
  let raw = epoch_open(path, receiver)?
  let n = Bytes.length(raw) - 48
  let magic = Bytes.slice(raw, 0, n)?
  let wrong_magic = repeated(0, n)?
  let invalid = mobile_join([
      if kind == 4 do
        wrong_magic
      else
        magic
      end,
      if kind == 2 do
        other.account_id
      else
        receiver.account_id
      end,
      if kind == 3 do
        other.device_id
      else
        receiver.device_id
      end
    ],
    0,
    Bytes.empty())?
  epoch_check(kind != 4 || !Bytes.secure_equals(magic, wrong_magic),
    "fixture must actually alter the magic")?
  let sealed = seal_local(invalid, key, local_context(epoch_label())?)?
  store_updated_blobs(path, [epoch_label()], [sealed])
end

fn epoch_refusal_body(fixture :: InitialSyncFixture, kind :: Int) -> Unit!String do
  let key = platform_key()?
  let sender = decode_client_profile(load_profile(fixture.alice_path)?)?
  let receiver = decode_client_profile(load_profile(fixture.bob_path)?)?
  let conversation = direct_conversation_id(sender.account_id, receiver.account_id)?
  let id = repeated(213, 16)?
  let binding = ViewOnceBinding {
    sender_account_id: sender.account_id,
    sender_device_id: sender.device_id,
    receiver_account_id: receiver.account_id,
    receiver_device_id: receiver.device_id,
    conversation_id: conversation,
    message_id: id
  }
  let device = open_device(receiver, key, fixture.bob_path)?
  let (reference, _chunk, _png) = view_once_receive_material(device, binding)?
  let offered = repeated(214, 32)?
  let inner = epoch_inner(sender,
    receiver,
    conversation,
    id,
    reference,
    offered,
    outgoing_gossip_hint(fixture.alice_path, key)?)?
  let (_state, wire) = initial_carrier(fixture.alice_path, fixture.bob_path, inner)?
  epoch_damage(fixture.bob_path, fixture.alice_path, kind)?
  let orphan = "view-once/v1/#{Bytes.to_hex(repeated(215, 16)?)}/#{Bytes.to_hex(repeated(216,
    16)?)}"
  let orphan_blob = seal_local(encode_view_once_record(Consumed(repeated(218, 32)?))?,
    key,
    local_context(orphan)?)?
  store_updated_blobs(fixture.bob_path, [orphan], [orphan_blob])?
  let contact = "peer-contact-address/v1/#{Bytes.to_hex(Crypto.sha256(sender.entry.mailbox_token))}"
  let owner = "peer-contact-owner/v1/#{Bytes.to_hex(Crypto.sha256(offered))}"
  let gossip = "checkpoint-gossip/v1/#{Bytes.to_hex(sender.account_id)}"
  let legacy = "view-once/v1/#{Bytes.to_hex(conversation)}/#{Bytes.to_hex(id)}"
  let labels = [
    epoch_label(),
    orphan,
    contact,
    owner,
    gossip,
    "sessions/v1",
    "one-time-prekeys/v1",
    "one-time-prekey-active/v1",
    one_time_prekey_label(receiver.bundle.one_time_prekey_id),
    legacy,
    pending_label(conversation, id),
    identity_label(binding)?,
    history_label(conversation)
  ]
  let before = load_account_basis(fixture.bob_path, labels)?
  let refused = epoch_receive(fixture.bob_path, wire)
  epoch_check(Result.is_err(refused),
    "invalid epoch admitted an authenticated view-once reference")?
  epoch_check(same_account_basis(before, load_account_basis(fixture.bob_path, labels)?),
    "refusal changed contact, gossip, session, prekey, identity, pending, history or epoch")?
  # The same account and prekey remain usable for an ordinary authenticated message.
  let ordinary = %{inner |
    client_message_id: repeated(217, 16)?,
    attachment_manifest: Bytes.empty()
  }
  let (_next, ordinary_wire) = initial_carrier(fixture.alice_path, fixture.bob_path, ordinary)?
  epoch_check(Bytes.secure_equals(epoch_receive(fixture.bob_path, ordinary_wire)?, ordinary.body),
    "invalid epoch blocked an ordinary message")
end

fn epoch_refusal_case(kind :: Int) -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let fixture = initial_sync_fixture()?
  let result = epoch_refusal_body(fixture, kind)
  clear_initial_sync_fixture(fixture)?
  result
end

fn epoch_creation_case() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let fixture = initial_sync_fixture()?
  let result = epoch_creation_body(fixture)
  clear_initial_sync_fixture(fixture)?
  result
end

fn epoch_legacy_native_case() -> Unit!String do
  let fixture = view_once_fixture(0)?
  store_record_changes(fixture.path, [], [], [epoch_label()])?
  let request = mobile_join([
      mobile_byte(1)?,
      mobile_vector(Bytes.from_utf8(fixture.path))?,
      mobile_vector(fixture.profile)?,
      fixture.binding.conversation_id,
      fixture.binding.message_id
    ],
    0,
    Bytes.empty())?
  let first = native_view_once_consume(request)
  let second = native_view_once_consume(request)
  let expected = mobile_join([Bytes.from_hex("01564f4901")?, mobile_vector(fixture.png)?],
    0,
    Bytes.empty())?
  let refusal = Bytes.from_hex("01564f4900")?
  let ok = case (first, second) do
    (Ok(image), Ok(consumed)) -> Bytes.secure_equals(image, expected)
      && Bytes.secure_equals(consumed, refusal)
    _ -> false
  end
  view_once_fixture_clear(fixture)?
  epoch_check(ok, "missing epoch changed legacy Available or Consumed native behavior")
end

fn epoch_assert(result :: Unit!String) do
  case result do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("new account and linked device have sealed identity epochs and admit encrypted view-once") do
  epoch_assert(epoch_creation_case())
end

test("missing epoch refuses unknown orphaned legacy state without blocking ordinary receive") do
  epoch_assert(epoch_refusal_case(0))
end

test("corrupt sealed epoch refuses view-once without changing receive state") do
  epoch_assert(epoch_refusal_case(1))
end

test("authenticated epoch for another account refuses view-once") do
  epoch_assert(epoch_refusal_case(2))
end

test("authenticated epoch for another device refuses view-once") do
  epoch_assert(epoch_refusal_case(3))
end

test("authenticated epoch with malformed magic refuses view-once") do
  epoch_assert(epoch_refusal_case(4))
end

test("legacy native Available and Consumed remain usable with no epoch") do
  epoch_assert(epoch_legacy_native_case())
end
