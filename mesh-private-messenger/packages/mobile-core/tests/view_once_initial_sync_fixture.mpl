##! Authenticated synthetic initial and sibling carriers for view-once admission tests.
import File
from Attachments.ViewOnce import ViewOnceBinding
from Mobile.Codec import current_time, mobile_join
from Mobile.Profile import load_profile, open_device, policy
from Mobile.Sessions import initial_bytes, inner_bytes, ratchet_bytes
from Mobile.Transport import sealed_outer_bytes
from Protocol.V1 import InnerEnvelope
from Session.Handshake import initiate_at_minimum_suite
from Session.Ratchet import encrypt_sealed
from Session.State import RatchetState
from Storage.Blobs import blob_record_hash, load_blob
from Storage.HistoryBlobs import open_history_blob
from Storage.Keys import platform_key, open_local, local_context
from Storage.ViewOnce import ViewOnceRecord, decode_view_once_record
from Mobile.HistoryWire import decode_history
from Mobile.Types import MobileHistoryAttachment
from Transport.Packet import (
  ClientProfile,
  TransportPacket,
  decode_client_profile,
  encode_initial_plaintext,
  encode_packet,
  session_aad
)
from Tests.GroupLifecycleSupport import install_signed_transparency
from Tests.GroupConsistencySupport import signed_transparency_view, request, wide
from Tests.Support import database_path
from MobileCore import (
  create_account_export,
  create_link_request_export,
  authorize_device_link_export,
  complete_device_link_export,
  directory_entry_export
)
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set
from Protocol.V1 import DeviceSet
from Transparency.Merkle import leaf_hash
from Storage.Records import erase_local_state

pub struct InitialSyncFixture do
  alice_path :: String
  linked_path :: String
  bob_path :: String
end

pub fn initial_sync_fixture() -> InitialSyncFixture!String do
  let fixture = InitialSyncFixture {
    alice_path: database_path("vo-initial-alice")?,
    linked_path: database_path("vo-initial-sibling")?,
    bob_path: database_path("vo-initial-bob")?
  }
  let result = install_initial_sync_transparency(fixture)
  case result do
    Err(error) -> do
      clear_initial_sync_fixture(fixture)?
      Err(error)
    end
    Ok(_) -> Ok(fixture)
  end
end

fn install_initial_sync_transparency(fixture :: InitialSyncFixture) -> Unit!String do
  let _alice = create_account_export(request([
    Bytes.from_utf8(fixture.alice_path),
    Bytes.from_utf8("alice")
  ])?)?
  let _bob = create_account_export(request([
    Bytes.from_utf8(fixture.bob_path),
    Bytes.from_utf8("bob")
  ])?)?
  let link_request = create_link_request_export(Bytes.from_utf8(fixture.linked_path))?
  let authorization = authorize_device_link_export(request([
    Bytes.from_utf8(fixture.alice_path),
    link_request
  ])?)?
  let _linked = complete_device_link_export(request([
    Bytes.from_utf8(fixture.linked_path),
    authorization
  ])?)?
  let alice = case decode_directory_entry(directory_entry_export(Bytes.from_utf8(fixture.alice_path))?) do
    Err(_) -> return Err("initial_sync_directory_entry")
    Ok(value) -> value
  end
  let sibling = case decode_directory_entry(directory_entry_export(Bytes.from_utf8(fixture.linked_path))?) do
    Err(_) -> return Err("initial_sync_directory_entry")
    Ok(value) -> value
  end
  let bob = case decode_directory_entry(directory_entry_export(Bytes.from_utf8(fixture.bob_path))?) do
    Err(_) -> return Err("initial_sync_directory_entry")
    Ok(value) -> value
  end
  let alice_set = case encode_device_set(DeviceSet {
    version: 1,
    username: "alice",
    account_identity: alice.account_identity,
    sequence: wide(2)?,
    devices: [alice, sibling],
    revoked_device_ids: List.new()
  }) do
    Err(_) -> return Err("initial_sync_device_set")
    Ok(value) -> value
  end
  let bob_set = case encode_device_set(DeviceSet {
    version: 1,
    username: "bob",
    account_identity: bob.account_identity,
    sequence: wide(1)?,
    devices: [bob],
    revoked_device_ids: List.new()
  }) do
    Err(_) -> return Err("initial_sync_device_set")
    Ok(value) -> value
  end
  let signed = signed_transparency_view([leaf_hash(alice_set)?, leaf_hash(bob_set)?])?
  for path in [fixture.alice_path, fixture.linked_path, fixture.bob_path] do
    if !install_signed_transparency(path, signed, alice_set)?
      || !install_signed_transparency(path, signed, bob_set)? do
      return Err("initial_sync_transparency_install_failed")
    end
  end
  Ok(nil)
end

pub fn clear_initial_sync_fixture(fixture :: InitialSyncFixture) -> Unit!String do
  for path in [fixture.alice_path, fixture.linked_path, fixture.bob_path] do
    erase_local_state(path)?
    File.delete(path)?
  end
  Ok(nil)
end

pub fn initial_carrier(sender_path :: String,
  recipient_path :: String,
  inner :: InnerEnvelope) -> Result<(RatchetState, Bytes), String> do
  let key = platform_key()?
  let sender_wire = load_profile(sender_path)?
  let sender = decode_client_profile(sender_wire)?
  let recipient = decode_client_profile(load_profile(recipient_path)?)?
  let device = open_device(sender, key, sender_path)?
  let now = current_time()?
  let plaintext = encode_initial_plaintext(sender_wire, inner_bytes(inner)?)?
  let (state, initial) = case initiate_at_minimum_suite(device,
    sender.credential,
    recipient.account,
    recipient.bundle,
    policy(recipient, now),
    0,
    1,
    plaintext) do
    Err(_) -> return Err("initial_sync_test_handshake")
    Ok(value) -> value
  end
  let packet = encode_packet(InitialPacket(sender.entry.account_identity, initial_bytes(initial)?))?
  let outer = sealed_outer_bytes(recipient.entry.mailbox_token,
    packet,
    recipient.credential.dh_public_key,
    now)?
  Ok((state, outer))
end

pub fn sibling_carrier(state :: consume RatchetState,
  recipient :: ClientProfile,
  inner :: InnerEnvelope) -> Result<(RatchetState, Bytes), String> do
  let aad = session_aad(state.session_id)?
  let (next, message) = case encrypt_sealed(state, inner_bytes(inner)?, aad) do
    Err(_) -> return Err("initial_sync_test_ratchet")
    Ok(value) -> value
  end
  let packet = encode_packet(RatchetPacket(ratchet_bytes(message)?))?
  let outer = sealed_outer_bytes(recipient.entry.mailbox_token,
    packet,
    recipient.credential.dh_public_key,
    current_time()?)?
  Ok((next, outer))
end

pub fn pending_label(conversation :: Bytes, message :: Bytes) -> String do
  "view-once/v2/#{Bytes.to_hex(conversation)}/#{Bytes.to_hex(message)}"
end

pub fn history_label(conversation :: Bytes) -> String do
  "history/v1/#{Bytes.to_hex(conversation)}"
end

pub fn identity_label(binding :: ViewOnceBinding) -> String!String do
  let tuple = mobile_join([
      Bytes.from_utf8("morse/view-once/key/v2\n"),
      binding.sender_account_id,
      binding.sender_device_id,
      binding.receiver_account_id,
      binding.receiver_device_id,
      binding.conversation_id,
      binding.message_id
    ],
    0,
    Bytes.empty())?
  Ok("view-once/id/v2/#{Bytes.to_hex(Crypto.sha256(tuple))}")
end

pub fn logical_label(account :: Bytes, peer :: Bytes, message :: Bytes) -> String!String do
  let tuple = mobile_join([Bytes.from_utf8("morse/view-once/message/v2\n"), account, peer, message],
    0,
    Bytes.empty())?
  Ok("view-once/message/v2/#{Bytes.to_hex(Crypto.sha256(tuple))}")
end

pub fn pending_and_history(path :: String,
  conversation :: Bytes,
  message :: Bytes,
  reference :: Bytes,
  expected_count :: Int) -> Plaintext<Bool>!String do
  let key = platform_key()?
  let row = pending_label(conversation, message)
  let raw = open_local(load_blob(path, row)?, key, local_context(row)?)?
  let pending = case decode_view_once_record(raw) do
    Ok(PendingFetch(value)) -> Bytes.secure_equals(value.reference, reference)
    _ -> false
  end
  let history_row = history_label(conversation)
  let history = decode_history(open_history_blob(load_blob(path, history_row)?, key, history_row)?)?
  if List.length(history) != expected_count do
    return Ok(false)
  end
  let entry = List.last(history)
  Ok(pending
    && Bytes.secure_equals(entry.inner.client_message_id, message)
    && entry.attachment_kind == HistoryViewOnce
    && Bytes.length(entry.inner.attachment_manifest) == 0)
end

## A transaction must roll back regardless of which of the two writes fails.
pub fn fail_write(path :: String, label :: String, enabled :: Bool) -> Unit!String do
  let database = Sqlite.open(path)?
  let statement = if enabled do
    "CREATE TRIGGER vo_initial_sync_fail BEFORE INSERT ON encrypted_blobs WHEN NEW.record_hash = '#{blob_record_hash(database,
      label)?}' BEGIN SELECT RAISE(ABORT, 'test write failure'); END"
  else
    "DROP TRIGGER vo_initial_sync_fail"
  end
  let result = Sqlite.execute(database, statement, [])
  Sqlite.close(database)
  case result do
    Err(_) -> Err("initial_sync_test_trigger")
    Ok(_) -> Ok(nil)
  end
end
