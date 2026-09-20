import File
from MobileCore import (
  create_account_export,
  direct_delivery_classification_for_test,
  outbox_ack_export,
  outbox_list_export,
  process_delivery_batch_export,
  receive_initial_export,
  receive_message_export,
  reconcile_prekeys_export,
  replenish_prekeys_export,
  start_conversation_export
)
from Prekeys.Pool import PrekeyPublishResponse, decode_prekey_publish, encode_prekey_publish_response
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.V1 import DirectoryEntry, MailboxAck, OuterEnvelope
from Tests.GroupLifecycleWire import ack, delivery_batch, outer
from Tests.Support import append, database_path, read_u32, repeated, vector, write_u32
from Transport.Packet import ClientProfile, decode_client_profile
from Transport.Recipient import is_recipient_packet, seal_recipient_packet

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

fn row_text(row :: Map < String, DbValue >, key :: String) -> String ! String do
  case Map.get(row, key) do
    Text( value) -> Ok(value)
    Binary( _) -> Err("expected text database value")
    Null -> Err("expected text database value")
  end
end

fn fingerprint_rows(rows :: List < Map < String, DbValue > >, index :: Int, output :: String) -> String ! String do
  if index >= List.length(rows) do
    Ok(output)
  else
    let row = List.get(rows, index)
    let separator = if index == 0 do
      ""
    else
      "|"
    end
    fingerprint_rows(rows,
    index + 1,
    output <> separator <> row_text(row, "record_hash") ? <> ":" <> row_text(row, "ciphertext_hex") ?)
  end
end

fn database_fingerprint(path :: String) -> String ! String do
  let database = Sqlite.open(path) ?
  case Sqlite.query_values(database,
  "SELECT record_hash, hex(ciphertext) AS ciphertext_hex FROM encrypted_blobs ORDER BY record_hash",
  []) do
    Err( error) -> do
      Sqlite.close(database)
      Err(error)
    end
    Ok( rows) -> do
      Sqlite.close(database)
      fingerprint_rows(rows, 0, "")
    end
  end
end

fn set_receive_failure(path :: String, enabled :: Bool) -> Result <(), String > do
  let database = Sqlite.open(path) ?
  let statement = if enabled do
    "CREATE TRIGGER mesh_test_fail_receive BEFORE UPDATE ON encrypted_blobs WHEN NEW.record_hash = '1157310c10370fde0a5d9bd24a1963b3d14362f1d666addd33e692f9bc246a63' BEGIN SELECT RAISE(ABORT, 'forced late receive write failure'); END"
  else
    "DROP TRIGGER mesh_test_fail_receive"
  end
  case Sqlite.execute(database, statement, []) do
    Err( error) -> do
      Sqlite.close(database)
      Err(error)
    end
    Ok( _) -> do
      Sqlite.close(database)
      Ok(nil)
    end
  end
end

fn assert_single_outbox(path :: String, envelope :: Bytes) -> Bool ! String do
  let expected = append(vector(write_u32(1) ?) ?, vector(envelope) ?) ?
  assert(Bytes.secure_equals(outbox_list_export(Bytes.from_utf8(path)) ?, expected))
  assert(Bytes.length(outbox_ack_export(request([Bytes.from_utf8(path), envelope]) ?) ?) == 0)
  assert(Bytes.secure_equals(outbox_list_export(Bytes.from_utf8(path)) ?, vector(write_u32(0) ?) ?))
  Ok(true)
end

fn malformed_ratchet_packet() -> Bytes ! String do
  append(vector(repeated(2, 1) ?) ?, write_u32(8) ?)
end

fn replace_ciphertext(envelope :: Bytes, ciphertext :: Bytes) -> Bytes ! String do
  case encode_outer_envelope(% { outer(envelope) ? | ciphertext : ciphertext }) do
    Err( _) -> Err("outer envelope encode failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  assert(direct_delivery_classification_for_test())
  let alice_path = database_path("initial-session-alice") ?
  let bob_path = database_path("initial-session-bob") ?
  let alice_profile = create_account_export(request([Bytes.from_utf8(alice_path), Bytes.from_utf8("alice")]) ?) ?
  let bob_profile_id2 = create_account_export(request([Bytes.from_utf8(bob_path), Bytes.from_utf8("bob")]) ?) ?
  assert(Bytes.length(alice_profile) > 0)
  assert(Bytes.length(bob_profile_id2) > 0)
  let publication = decode_prekey_publish(replenish_prekeys_export(request([Bytes.from_utf8(bob_path), write_u32(1) ?]) ?) ?) ?
  assert(List.length(publication.prekeys) == 1)
  let generated = List.head(publication.prekeys)
  assert(U64.compare(generated.id, U64.parse("3") ?) == 0)
  let greeting = Bytes.from_utf8("hello bob")
  let start_request = request([Bytes.from_utf8(alice_path), bob_profile_id2, greeting]) ?
  let initial_outer = start_conversation_export(start_request) ?
  assert(Bytes.length(initial_outer) > 0)
  let sender = decode_client_profile(alice_profile) ?
  assert(!String.contains(Bytes.to_hex(initial_outer), Bytes.to_hex(sender.account_id)))
  assert(!String.contains(Bytes.to_hex(initial_outer), Bytes.to_hex(sender.entry.account_identity)))
  let padded = outer(initial_outer) ?
  assert(Bytes.length(padded.ciphertext) == padded.padding_bucket)
  # Delivery sees the recipient-sealed transport only: no protocol suite and no
  # marker that this envelope starts a conversation.
  assert(padded.suite == 4)
  assert(is_recipient_packet(padded.ciphertext))
  assert(assert_single_outbox(alice_path, initial_outer) ?)
  # A sealed outer suite whose body is not a sealed packet is permanent poison...
  let malformed_outer = replace_ciphertext(initial_outer, malformed_ratchet_packet() ?) ?
  case receive_message_export(request([Bytes.from_utf8(bob_path), malformed_outer]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "invalid_recipient_packet")
  end
  let malformed_id = outer(malformed_outer) ?.envelope_id
  let malformed_ack = ack(process_delivery_batch_export(request([Bytes.from_utf8(bob_path), delivery_batch(malformed_outer) ?]) ?) ?) ?
  assert(List.length(malformed_ack.envelope_ids) == 1)
  assert(Bytes.secure_equals(List.head(malformed_ack.envelope_ids), malformed_id))
  # ...and so is a correctly sealed packet whose contents are malformed.
  let recipient = decode_client_profile(bob_profile_id2) ?
  let sealed_malformed = seal_recipient_packet(malformed_ratchet_packet() ?,
  X25519PublicKey { bytes : recipient.credential.dh_public_key }) ?
  let sealed_malformed_outer = replace_ciphertext(initial_outer, sealed_malformed) ?
  case receive_message_export(request([Bytes.from_utf8(bob_path), sealed_malformed_outer]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "invalid_ratchet_packet")
  end
  let sealed_malformed_ack = ack(process_delivery_batch_export(request([Bytes.from_utf8(bob_path), delivery_batch(sealed_malformed_outer) ?]) ?) ?) ?
  assert(List.length(sealed_malformed_ack.envelope_ids) == 1)
  let acknowledgement = encode_prekey_publish_response(PrekeyPublishResponse {
    account_id : publication.account_id,
    device_id : publication.device_id,
    active_ids : [generated.id]
  }) ?
  let reconciled = reconcile_prekeys_export(request([Bytes.from_utf8(bob_path), acknowledgement]) ?) ?
  assert(Bytes.length(reconciled) == 4)
  assert(read_u32(reconciled) ? == 1)
  let initial_batch = delivery_batch(initial_outer) ?
  let initial_id = outer(initial_outer) ?.envelope_id
  let before_failure = database_fingerprint(bob_path) ?
  set_receive_failure(bob_path, true) ?
  let failed_ack = process_delivery_batch_export(request([Bytes.from_utf8(bob_path), initial_batch]) ?) ?
  set_receive_failure(bob_path, false) ?
  assert(Bytes.length(failed_ack) == 0)
  assert(database_fingerprint(bob_path) ? == before_failure)
  let received_ack = ack(process_delivery_batch_export(request([Bytes.from_utf8(bob_path), initial_batch]) ?) ?) ?
  assert(List.length(received_ack.envelope_ids) == 1)
  assert(Bytes.secure_equals(List.head(received_ack.envelope_ids), initial_id))
  assert(database_fingerprint(bob_path) ? != before_failure)
  let replay_ack = ack(process_delivery_batch_export(request([Bytes.from_utf8(bob_path), initial_batch]) ?) ?) ?
  assert(List.length(replay_ack.envelope_ids) == 1)
  assert(Bytes.secure_equals(List.head(replay_ack.envelope_ids), initial_id))
  let stale_outer = start_conversation_export(start_request) ?
  assert(Bytes.length(stale_outer) > 0)
  assert(assert_single_outbox(alice_path, stale_outer) ?)
  case receive_initial_export(request([Bytes.from_utf8(bob_path), stale_outer]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "one_time_prekey_not_found")
  end
  File.delete(alice_path) ?
  File.delete(bob_path) ?
  Ok(true)
end

test("mobile initial sessions reconcile prekeys and commit atomically in Mesh") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
