##! Synthetic two-account proof of the current direct ratchet receive policy.
import File
from Mobile.Codec import current_time
from Mobile.HistoryWire import decode_history
from Mobile.Messages import start_conversation, receive_initial_message, receive_message
from Mobile.Sessions import (
  find_peer_session,
  inner_bytes,
  load_session_ids,
  ratchet_bytes,
  restore_session,
  seal_updated_session,
  updated_session_record
)
from Mobile.Transport import sealed_outer_bytes
from Mobile.Types import MobileReceiveRequest, MobileStartRequest
from MobileCore import create_account_export
from Protocol.V1 import InnerEnvelope
from Session.Ratchet import encrypt_sealed
from Storage.AccountGuard import commit_account_changes, load_account_basis
from Storage.Blobs import load_blob
from Storage.HistoryBlobs import open_history_blob
from Storage.Keys import local_context, platform_key, seal_local
from Storage.Records import erase_local_state, store_updated_blobs
from Tests.GroupConsistencySupport import request
from Tests.Support import database_path, repeated
from Tests.WitnessedSessionFixture import install_witnessed_session_fixtures
from Transport.Packet import (
  TransportPacket,
  decode_client_profile,
  direct_conversation_id,
  encode_packet,
  session_aad
)

fn alias_check(value :: Plaintext<Bool>, message :: String) -> Unit!String do
  if declassify(value, "test-only observation of synthetic direct-message receive and history") do
    Ok(nil)
  else
    Err(message)
  end
end

# Use the established sender ratchet to authenticate the chosen wire ID, then
# persist its actual next state just as an ordinary send would.
fn alias_carrier(path :: String, peer_wire :: Bytes, inner :: InnerEnvelope) -> Bytes!String do
  let key = platform_key()?
  let peer = decode_client_profile(peer_wire)?
  let loaded = find_peer_session(path, key, peer.account_id, load_session_ids(path, key)?, 0)?
  let before = load_account_basis(path, ["sessions/v1", loaded.label])?
  let (next, message) = case encrypt_sealed(restore_session(loaded, key)?,
    inner_bytes(inner)?,
    session_aad(loaded.session_id)?) do
    Err(_) -> return Err("alias_test_encrypt_failed")
    Ok(value) -> value
  end
  let outer = sealed_outer_bytes(peer.entry.mailbox_token,
    encode_packet(RatchetPacket(ratchet_bytes(message)?))?,
    peer.credential.dh_public_key,
    current_time()?)?
  commit_account_changes(path,
    before,
    [loaded.label],
    [seal_updated_session(next, loaded, key)?],
    [])?
  Ok(outer)
end

fn alias_proof(alice_path :: String, bob_path :: String) -> Unit!String do
  let alice_wire = create_account_export(request([
    Bytes.from_utf8(alice_path),
    Bytes.from_utf8("alice")
  ])?)?
  let bob_wire = create_account_export(request([
    Bytes.from_utf8(bob_path),
    Bytes.from_utf8("bob")
  ])?)?
  install_witnessed_session_fixtures([alice_path, bob_path])?
  let alice = decode_client_profile(alice_wire)?
  let bob = decode_client_profile(bob_wire)?
  let hello = start_conversation(MobileStartRequest {
    database_path: alice_path,
    peer_profile: bob_wire,
    body: Bytes.from_utf8("initial handshake"),
    attachment: Bytes.empty()
  })?
  let initial = receive_initial_message(MobileReceiveRequest {
    database_path: bob_path,
    outer: hello
  })?
  alias_check(Bytes.secure_equals(initial, Bytes.from_utf8("initial handshake")),
    "initial receive failed")?
  let key = platform_key()?
  let selected = find_peer_session(bob_path,
    key,
    alice.account_id,
    load_session_ids(bob_path, key)?,
    0)?
  let canonical = direct_conversation_id(alice.account_id, bob.account_id)?
  let legacy = repeated(144, 16)?
  let unknown = repeated(145, 16)?
  alias_check(Bytes.secure_equals(selected.record.conversation_id, canonical)
      && !Bytes.secure_equals(legacy, canonical)
      && !Bytes.secure_equals(unknown, canonical)
      && !Bytes.secure_equals(unknown, legacy),
    "fixture IDs are not distinct")?
  let changed = %{selected.record | conversation_id: legacy}
  let sealed = seal_local(updated_session_record(changed.snapshot, changed)?,
    key,
    local_context(selected.label)?)?
  store_updated_blobs(bob_path, [selected.label], [sealed])?
  let reloaded = find_peer_session(bob_path,
    key,
    alice.account_id,
    load_session_ids(bob_path, key)?,
    0)?
  alias_check(Bytes.secure_equals(reloaded.session_id, selected.session_id)
      && Bytes.secure_equals(reloaded.record.conversation_id, legacy)
      && Bytes.secure_equals(reloaded.record.snapshot, selected.record.snapshot),
    "stored session selection changed")?
  let message_id = repeated(146, 16)?
  let body = Bytes.from_utf8("authenticated legacy conversation")
  let inner = InnerEnvelope {
    version: 1,
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    recipient_device_id: bob.device_id,
    conversation_id: legacy,
    client_message_id: message_id,
    client_timestamp: current_time()?,
    message_type: 1,
    body: body,
    reply_reference: Bytes.empty(),
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: List.new()
  }
  let legacy_outer = alias_carrier(alice_path, bob_wire, inner)?
  let received = receive_message(MobileReceiveRequest {
    database_path: bob_path,
    outer: legacy_outer
  })?
  alias_check(Bytes.secure_equals(received, body), "stored wire alias was not delivered")?
  let history_label = "history/v1/#{Bytes.to_hex(legacy)}"
  let history_blob = load_blob(bob_path, history_label)?
  let history = decode_history(open_history_blob(history_blob, key, history_label)?)?
  alias_check(List.length(history) == 1,
    "legacy history did not contain exactly the received message")?
  let entry = List.head(history)
  alias_check(entry.direction == 2
      && Bytes.secure_equals(entry.inner.conversation_id, legacy)
      && Bytes.secure_equals(entry.inner.client_message_id, message_id)
      && Bytes.secure_equals(entry.inner.body, body),
    "message was not filed under local legacy history")?
  let unknown_inner = %{inner |
    conversation_id: unknown,
    client_message_id: repeated(147, 16)?,
    body: Bytes.from_utf8("unrecognized authenticated alias")
  }
  let unknown_outer = alias_carrier(alice_path, bob_wire, unknown_inner)?
  let session_before = load_blob(bob_path, selected.label)?
  let rejected = receive_message(MobileReceiveRequest {
    database_path: bob_path,
    outer: unknown_outer
  })
  alias_check(case rejected do
      Err("message_rejected") -> true
      _ -> false
    end,
    "unrecognized authenticated alias was not rejected")?
  alias_check(Bytes.secure_equals(load_blob(bob_path, selected.label)?, session_before)
      && Bytes.secure_equals(load_blob(bob_path, history_label)?, history_blob)
      && Result.is_err(load_blob(bob_path, "history/v1/#{Bytes.to_hex(unknown)}")),
    "rejected alias changed the recipient session or history")
end

fn run_alias_proof() -> Unit!String do
  if !Test.install_in_memory_secure_store() do
    return Err("secure_store_fixture_failed")
  end
  let alice_path = database_path("direct-alias-alice")?
  let bob_path = database_path("direct-alias-bob")?
  let result = alias_proof(alice_path, bob_path)
  # Cleanup also runs when setup or either receive returns an error.
  let alice_erased = erase_local_state(alice_path)
  let bob_erased = erase_local_state(bob_path)
  let alice_deleted = File.delete(alice_path)
  let bob_deleted = File.delete(bob_path)
  alice_erased?
  bob_erased?
  alice_deleted?
  bob_deleted?
  result
end

test("direct ratchet accepts the selected stored legacy wire ID but rejects another alias") do
  case run_alias_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
