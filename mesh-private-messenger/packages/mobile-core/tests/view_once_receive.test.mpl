##! Real encrypted direct receive; all accounts and image material are synthetic.
import File
from Attachments.ViewOnce import ViewOnceBinding, decode_view_once_reference
from Mobile.Messages import start_conversation, receive_initial_message, receive_message
from Mobile.Profile import load_profile, open_device
from Mobile.Sessions import (
  load_session_ids,
  find_peer_session,
  restore_session,
  seal_updated_session,
  ratchet_bytes,
  inner_bytes
)
from Mobile.Types import (
  MobileStartRequest,
  MobileReceiveRequest,
  MobileHistoryAttachment,
  MobileBatchRequest
)
from Mobile.Transport import sealed_outer_bytes
from Mobile.Codec import current_time
from Mobile.Codec import (
  take_vector,
  mobile_read_u32,
  mobile_read_byte,
  mobile_join,
  mobile_vector,
  mobile_write_u32,
  mobile_write_u64
)
from Mobile.HistoryWire import decode_history
from Mobile.Inbox import process_delivery_batch
from MobileCore import load_history_export
from Binary.Reader import reader, finish
from Storage.HistoryBlobs import open_history_blob
from Storage.Keys import platform_key, open_local, local_context, seal_local
from Storage.ViewOnce import ViewOnceRecord, decode_view_once_record, encode_view_once_record
from Storage.Blobs import load_blob
from Storage.AccountGuard import load_account_basis, commit_account_changes, same_account_basis
from Storage.Records import erase_local_state, store_updated_blobs
from Storage.Blobs import blob_record_hash
from Session.Ratchet import encrypt_sealed
from Transport.Packet import TransportPacket, decode_client_profile, encode_packet, session_aad
from Protocol.V1 import InnerEnvelope, DeliveredEnvelope, ProtocolExtension
from Protocol.MailboxWire import encode_delivery_batch, decode_mailbox_ack
from Mobile.Codec import canonical_outer
from Tests.GroupLifecycleSupport import group_account_fixture, install_signed_transparency
from Tests.GroupConsistencySupport import signed_transparency_view, request
from Tests.ViewOnceFixture import view_once_receive_material, view_once_receive_material_at
from Tests.ViewOnceInitialSyncFixture import identity_label, logical_label
from Mobile.History import updated_history_with_kind
from Tests.Support import repeated
from Transparency.Merkle import leaf_hash

fn encrypted_carrier(path :: String, peer_wire :: Bytes, inner :: InnerEnvelope) -> Bytes!String do
  let key = platform_key()?
  let peer = decode_client_profile(peer_wire)?
  let loaded = find_peer_session(path, key, peer.account_id, load_session_ids(path, key)?, 0)?
  let before = load_account_basis(path, ["sessions/v1", loaded.label])?
  let (next, message) = case encrypt_sealed(restore_session(loaded, key)?,
    inner_bytes(inner)?,
    session_aad(loaded.session_id)?) do
    Err(_) -> return Err("view_once_test_encrypt")
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

fn fail_pending_insert(path :: String, label :: String, enabled :: Bool) -> Unit!String do
  let database = Sqlite.open(path)?
  let statement = if enabled do
    "CREATE TRIGGER vo_fail_pending BEFORE INSERT ON encrypted_blobs WHEN NEW.record_hash = '#{blob_record_hash(database,
      label)?}' BEGIN SELECT RAISE(ABORT, 'test pending failure'); END"
  else
    "DROP TRIGGER vo_fail_pending"
  end
  let result = Sqlite.execute(database, statement, [])
  Sqlite.close(database)
  case result do
    Err(_) -> Err("view_once_test_trigger")
    Ok(_) -> Ok(nil)
  end
end

fn contains_bytes(input :: Bytes, needle :: Bytes, offset :: Int) -> Bool!String do
  if Bytes.length(needle) == 0 || offset + Bytes.length(needle) > Bytes.length(input) do
    Ok(false)
  else if Bytes.secure_equals(Bytes.slice(input, offset, Bytes.length(needle))?, needle) do
    Ok(true)
  else
    contains_bytes(input, needle, offset + 1)
  end
end

fn retain_synthetic_history(output :: Result<Plaintext<Bytes>, String>,
  message_id :: Bytes,
  reference :: Bytes,
  chunk :: Bytes,
  image :: Bytes) -> Unit!String do
  let directory = Env.get("MORSE_VIEW_ONCE_EVIDENCE_ROOT", "")
  if String.length(directory) == 0 do
    return Ok(nil)
  end
  let value = Result.unwrap_or(output, Bytes.empty())
  let decoded = decode_view_once_reference(reference)?
  let checked = pending_history_contract(value, message_id)
  let safe = Result.unwrap_or(checked, false)
    && !Result.unwrap_or(contains_bytes(value, reference, 0), true)
    && !Result.unwrap_or(contains_bytes(value, decoded.download_capability, 0), true)
    && !Result.unwrap_or(contains_bytes(value, decoded.wrapped_key, 0), true)
    && !Result.unwrap_or(contains_bytes(value, decoded.encrypted_manifest, 0), true)
    && !Result.unwrap_or(contains_bytes(value, chunk, 0), true)
    && !Result.unwrap_or(contains_bytes(value, image, 0), true)
  if !declassify(safe,
    "test-only synthetic history fixture validation: expected placeholder framing and absence of fixture reference capability wrapped key manifest ciphertext and image") do
    return Err("view_once_test_fixture_unsafe")
  end
  let bytes = declassify(value,
    "TEST ONLY retained synthetic account history after checking the expected placeholder and excluding the synthetic reference capability wrapped key manifest ciphertext and image")
  File.write_bytes(directory <> "/direct-pending-mixed.bin", 0, bytes, true)?
  Ok(nil)
end

fn pending_history_contract(output :: Bytes, message_id :: Bytes) -> Bool!String do
  if Bytes.length(output) < 4
    || !Bytes.secure_equals(Bytes.slice(output, 0, 4)?, Bytes.from_hex("02485354")?) do
    return Ok(false)
  end
  let list = case reader(Bytes.slice(output, 4, Bytes.length(output) - 4)?, 16794632) do
    Err(_) -> return Ok(false)
    Ok(value) -> value
  end
  let count = take_vector(list, 4)?
  if mobile_read_u32(count.value)? != 2 do
    return Ok(false)
  end
  let first = take_vector(count.state, 65536)?
  let second = take_vector(first.state, 65536)?
  case finish(second.state) do
    Err(_) -> return Ok(false)
    Ok(_) -> nil
  end
  let entry = case reader(second.value, 65536) do
    Err(_) -> return Ok(false)
    Ok(value) -> value
  end
  let direction = take_vector(entry, 1)?
  let message = take_vector(direction.state, 16)?
  let timestamp = take_vector(message.state, 8)?
  let body = take_vector(timestamp.state, 65536)?
  let expiry = take_vector(body.state, 4)?
  let attachment = take_vector(expiry.state, 16384)?
  let delivery = take_vector(attachment.state, 1)?
  let status = take_vector(delivery.state, 1)?
  case finish(status.state) do
    Err(_) -> Ok(false)
    Ok(_) -> Ok(Bytes.secure_equals(message.value, message_id)
      && Bytes.length(attachment.value) == 0
      && mobile_read_byte(status.value)? == 1)
  end
end

fn proof() -> Result<(Bool, Bool, Bool, Bool, Bool, Bool, Bool, Bool), String> do
  assert(Test.install_in_memory_secure_store())
  let fixture = group_account_fixture()?
  let signed = signed_transparency_view([
    leaf_hash(fixture.alice_set)?,
    leaf_hash(fixture.bob_set)?
  ])?
  for path in [fixture.alice_path, fixture.bob_path] do
    assert(install_signed_transparency(path, signed, fixture.alice_set)?)
    assert(install_signed_transparency(path, signed, fixture.bob_set)?)
  end
  let alice_wire = load_profile(fixture.alice_path)?
  let bob_wire = load_profile(fixture.bob_path)?
  let alice = decode_client_profile(alice_wire)?
  let bob = decode_client_profile(bob_wire)?
  let hello = start_conversation(MobileStartRequest {
    database_path: fixture.alice_path,
    peer_profile: bob_wire,
    body: Bytes.from_utf8("hello"),
    attachment: Bytes.empty()
  })?
  let _ = receive_initial_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: hello
  })?
  let ordinary_output = load_history_export(request([
    Bytes.from_utf8(fixture.bob_path),
    alice_wire
  ])?)
  let ordinary_framing = declassify(case ordinary_output do
      Err(_) -> false
      Ok(value) -> Bytes.secure_equals(Result.unwrap_or(Bytes.slice(value, 0, 8), Bytes.empty()),
        Result.unwrap_or(Bytes.from_hex("0000000400000001"), Bytes.empty()))
    end,
    "test-only observation of the unchanged synthetic ordinary history framing")
  let key = platform_key()?
  let loaded = find_peer_session(fixture.alice_path,
    key,
    bob.account_id,
    load_session_ids(fixture.alice_path, key)?,
    0)?
  let message_id = repeated(44, 16)?
  let binding = ViewOnceBinding {
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    receiver_account_id: bob.account_id,
    receiver_device_id: bob.device_id,
    conversation_id: loaded.record.conversation_id,
    message_id: message_id
  }
  let device = open_device(bob, key, fixture.bob_path)?
  let (reference, chunk, png) = view_once_receive_material(device, binding)?
  let now = current_time()?
  let inner = InnerEnvelope {
    version: 1,
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    recipient_device_id: bob.device_id,
    conversation_id: loaded.record.conversation_id,
    client_message_id: message_id,
    client_timestamp: now,
    message_type: 1,
    body: Bytes.from_utf8("one image"),
    reply_reference: Bytes.empty(),
    attachment_manifest: reference,
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: List.new()
  }
  let outer = encrypted_carrier(fixture.alice_path, bob_wire, inner)?
  let received = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: outer
  })?
  let row = "view-once/v2/#{Bytes.to_hex(binding.conversation_id)}/#{Bytes.to_hex(message_id)}"
  let pending_exists = case load_blob(fixture.bob_path, row) do
    Err(_) -> false
    Ok(blob) -> case open_local(blob, key, local_context(row)?) do
      Err(_) -> false
      Ok(raw) -> case decode_view_once_record(raw) do
        Ok(PendingFetch(value)) -> Bytes.secure_equals(value.reference, reference)
        _ -> false
      end
    end
  end
  let history_label = "history/v1/#{Bytes.to_hex(binding.conversation_id)}"
  let history = decode_history(open_history_blob(load_blob(fixture.bob_path, history_label)?,
    key,
    history_label)?)?
  let latest = List.last(history)
  let sanitized = Bytes.length(latest.inner.attachment_manifest) == 0
    && latest.attachment_kind == HistoryViewOnce
  let delivered = Bytes.secure_equals(received, Bytes.from_utf8("one image"))
  let output = load_history_export(request([Bytes.from_utf8(fixture.bob_path), alice_wire])?)
  let contract = case output do
    Err(_) -> false
    Ok(value) -> Result.unwrap_or(pending_history_contract(value, message_id), false)
  end
  let contract = declassify(contract,
    "test-only finite observation of synthetic history placeholder framing")
    && ordinary_framing
  retain_synthetic_history(output, message_id, reference, chunk, png)?
  let original_row = load_blob(fixture.bob_path, row)?
  let original_history = load_blob(fixture.bob_path, history_label)?
  let offered = repeated(80, 32)?
  let other_offered = repeated(81, 32)?
  let contact_label = "peer-contact-address/v1/#{Bytes.to_hex(Crypto.sha256(alice.entry.mailbox_token))}"
  let offered_label = "peer-contact-owner/v1/#{Bytes.to_hex(Crypto.sha256(offered))}"
  let other_offered_label = "peer-contact-owner/v1/#{Bytes.to_hex(Crypto.sha256(other_offered))}"
  let contact_labels = [contact_label, offered_label, other_offered_label]
  let before_contact = load_account_basis(fixture.bob_path, contact_labels)?
  let replay_wire = encrypted_carrier(fixture.alice_path,
    bob_wire,
    %{inner | extensions: [ProtocolExtension { id: 1, mandatory: false, value: offered }]})?
  let replay = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: replay_wire
  })
  let duplicate_delivered = declassify(case replay do
      Ok(value) -> Bytes.length(value) == 0
      Err(_) -> false
    end,
    "test-only delivery status for a synthetic duplicate")
  let duplicate = duplicate_delivered
    && Bytes.secure_equals(load_blob(fixture.bob_path, row)?, original_row)
    && Bytes.secure_equals(load_blob(fixture.bob_path, history_label)?, original_history)
  let contact_after_duplicate = load_account_basis(fixture.bob_path, contact_labels)?
  let duplicate_contact_safe = same_account_basis(before_contact, contact_after_duplicate)
  if !duplicate_contact_safe do
    println("TEST_SYNTHETIC_DUPLICATE_CONTACT_MUTATED")
  end
  let changed_body_wire = encrypted_carrier(fixture.alice_path,
    bob_wire,
    %{inner |
      body: Bytes.from_utf8("changed caption"),
      extensions: [ProtocolExtension { id: 1, mandatory: false, value: other_offered }]
    })?
  let changed_body_result = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: changed_body_wire
  })
  let changed_body_refused = declassify(case changed_body_result do
      Err("view_once_reference_refused") -> true
      _ -> false
    end,
    "test-only refusal of a changed synthetic body with the same view-once identity")
  let changed_body_returned = declassify(case changed_body_result do
      Ok(value) -> Bytes.secure_equals(value, Bytes.from_utf8("changed caption"))
      _ -> false
    end,
    "test-only observation of a changed synthetic body returned without a durable update")
  if changed_body_returned do
    println("TEST_SYNTHETIC_CHANGED_DUPLICATE_BODY_RETURNED")
  end
  let conflict_contact_safe = same_account_basis(contact_after_duplicate,
    load_account_basis(fixture.bob_path, contact_labels)?)
  if !conflict_contact_safe do
    println("TEST_SYNTHETIC_REFUSED_CONTACT_MUTATED")
  end
  let (replacement, _replacement_chunk, _replacement_png) = view_once_receive_material(device,
    binding)?
  let replacement_wire = encrypted_carrier(fixture.alice_path,
    bob_wire,
    %{inner | attachment_manifest: replacement})?
  let replacement_result = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: replacement_wire
  })
  let replacement_refused = declassify(case replacement_result do
      Err("view_once_reference_refused") -> true
      _ -> false
    end,
    "test-only refusal status for a conflicting synthetic reference")
  let conflict = replacement_refused
    && Bytes.secure_equals(load_blob(fixture.bob_path, row)?, original_row)
    && Bytes.secure_equals(load_blob(fixture.bob_path, history_label)?, original_history)
  let forged_id = repeated(46, 16)?
  let expected_binding = %{binding | message_id: forged_id}
  let forged_bindings = [
    %{expected_binding | sender_account_id: repeated(99, 32)?},
    %{expected_binding | sender_device_id: repeated(99, 16)?},
    %{expected_binding | receiver_account_id: repeated(98, 32)?},
    %{expected_binding | receiver_device_id: repeated(98, 16)?},
    %{expected_binding | conversation_id: repeated(97, 16)?},
    %{expected_binding | message_id: repeated(96, 16)?}
  ]
  let malformed_cases = for forged_binding in forged_bindings do
    let (forged, _forged_chunk, _forged_png) = view_once_receive_material(device, forged_binding)?
    let forged_wire = encrypted_carrier(fixture.alice_path,
      bob_wire,
      %{inner | client_message_id: forged_id, attachment_manifest: forged})?
    let forged_result = receive_message(MobileReceiveRequest {
      database_path: fixture.bob_path,
      outer: forged_wire
    })
    declassify(case forged_result do
        Err("view_once_reference_refused") -> true
        _ -> false
      end,
      "test-only refusal status for a forged synthetic sender recipient or context binding")
  end
  let malformed = List.all(malformed_cases, fn(value) -> value end)
  let batch = mobile_join([
      Bytes.from_hex("01415442")?,
      mobile_write_u32(2)?,
      mobile_vector(reference)?,
      mobile_vector(reference)?
    ],
    0,
    Bytes.empty())?
  let batch_wire = encrypted_carrier(fixture.alice_path,
    bob_wire,
    %{inner | attachment_manifest: batch})?
  let batch_result = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: batch_wire
  })
  let batch_refused = declassify(case batch_result do
      Err("view_once_reference_refused") -> true
      _ -> false
    end,
    "test-only refusal of a synthetic view-once reference inside an attachment batch")
  let ordinary_wire = encrypted_carrier(fixture.alice_path,
    bob_wire,
    %{inner | attachment_manifest: Bytes.empty()})?
  let ordinary_result = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: ordinary_wire
  })
  let ordinary_refused = declassify(case ordinary_result do
      Err("view_once_reference_refused") -> true
      _ -> false
    end,
    "test-only refusal of a synthetic ordinary message conflicting with a view-once identity")
  if !batch_refused do
    println("TEST_SYNTHETIC_BATCH_WRAPPER_ACCEPTED")
  end
  if !ordinary_refused do
    println("TEST_SYNTHETIC_ORDINARY_COLLISION_ACCEPTED")
  end
  # Reconstruct the durable terminal state of a prior admitted synthetic item;
  # the duplicate itself is sent through the genuine ratchet receive boundary.
  let expired_id = repeated(48, 16)?
  let expired_binding = %{binding | message_id: expired_id}
  let (expired_reference, _expired_chunk, _expired_png) = view_once_receive_material_at(device,
    expired_binding,
    U64.parse("946684800000")?)?
  let expired_row = "view-once/v2/#{Bytes.to_hex(binding.conversation_id)}/#{Bytes.to_hex(expired_id)}"
  let terminal = seal_local(encode_view_once_record(Expired(Crypto.sha256(expired_reference)))?,
    key,
    local_context(expired_row)?)?
  let expired_identity = identity_label(%{binding | message_id: expired_id})?
  let expired_logical = logical_label(bob.account_id, alice.account_id, expired_id)?
  let expired_identity_input = mobile_join([
      Bytes.from_utf8("morse/view-once/identity/v2\n"),
      bob.account_id,
      alice.account_id,
      binding.conversation_id,
      expired_id,
      Crypto.sha256(expired_reference)
    ],
    0,
    Bytes.empty())?
  let expired_inner = %{inner | client_message_id: expired_id, attachment_manifest: Bytes.empty()}
  let expired_content_input = mobile_join([
      Bytes.from_utf8("morse/view-once/content/v2\n"),
      Bytes.from_hex("02")?,
      expired_inner.sender_account_id,
      expired_inner.sender_device_id,
      expired_inner.recipient_device_id,
      expired_inner.client_message_id,
      mobile_write_u64(expired_inner.client_timestamp)?,
      mobile_write_u32(expired_inner.message_type)?,
      mobile_write_u32(expired_inner.receipt_policy)?,
      mobile_write_u32(expired_inner.disappearing_seconds)?,
      Crypto.sha256(expired_inner.body),
      Crypto.sha256(expired_inner.reply_reference)
    ],
    0,
    Bytes.empty())?
  let expired_identity_plain = mobile_join([
      Bytes.from_hex("02564f49")?,
      Crypto.sha256(expired_identity_input),
      Crypto.sha256(expired_reference),
      Crypto.sha256(expired_content_input),
      binding.conversation_id,
      alice.account_id
    ],
    0,
    Bytes.empty())?
  let expired_identity_blob = seal_local(expired_identity_plain,
    key,
    local_context(expired_identity)?)?
  let expired_logical_blob = seal_local(expired_identity_plain,
    key,
    local_context(expired_logical)?)?
  let (expired_history_labels, expired_history_blobs) = updated_history_with_kind(fixture.bob_path,
    key,
    expired_inner,
    2,
    HistoryViewOnce)?
  store_updated_blobs(fixture.bob_path,
    expired_history_labels ++ [expired_row, expired_identity, expired_logical],
    expired_history_blobs ++ [terminal, expired_identity_blob, expired_logical_blob])?
  let prior_expired_history = load_blob(fixture.bob_path, history_label)?
  let expired_wire = encrypted_carrier(fixture.alice_path,
    bob_wire,
    %{inner | client_message_id: expired_id, attachment_manifest: expired_reference})?
  let expired_result = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: expired_wire
  })
  let expired_accepted = declassify(case expired_result do
      Ok(value) -> Bytes.length(value) == 0
      _ -> false
    end,
    "test-only outcome for an identical synthetic duplicate after expiry")
  let expired_changed_wire = encrypted_carrier(fixture.alice_path,
    bob_wire,
    %{inner |
      client_message_id: expired_id,
      attachment_manifest: expired_reference,
      body: Bytes.from_utf8("changed expired caption"),
      disappearing_seconds: 60
    })?
  let expired_changed_result = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: expired_changed_wire
  })
  let expired_changed_refused = declassify(case expired_changed_result do
      Err("view_once_reference_refused") -> true
      _ -> false
    end,
    "test-only refusal of changed synthetic content and expiry for a terminal item")
  let expired_duplicate = expired_accepted
    && expired_changed_refused
    && Bytes.secure_equals(load_blob(fixture.bob_path, expired_row)?, terminal)
    && Bytes.secure_equals(load_blob(fixture.bob_path, expired_identity)?, expired_identity_blob)
    && Bytes.secure_equals(load_blob(fixture.bob_path, expired_logical)?, expired_logical_blob)
    && Bytes.secure_equals(load_blob(fixture.bob_path, history_label)?, prior_expired_history)
  if !expired_duplicate do
    println("TEST_SYNTHETIC_EXPIRED_DUPLICATE_REFUSED")
  end
  let ordinary_first_id = repeated(49, 16)?
  let ordinary_first = encrypted_carrier(fixture.alice_path,
    bob_wire,
    %{inner | client_message_id: ordinary_first_id, attachment_manifest: Bytes.empty()})?
  let ordinary_first_result = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: ordinary_first
  })
  let ordinary_first_delivered = declassify(case ordinary_first_result do
      Ok(value) -> Bytes.secure_equals(value, Bytes.from_utf8("one image"))
      _ -> false
    end,
    "test-only successful delivery of an ordinary synthetic message")
  let ordinary_first_history = load_blob(fixture.bob_path, history_label)?
  let ordinary_first_binding = %{binding | message_id: ordinary_first_id}
  let (after_ordinary, _after_ordinary_chunk, _after_ordinary_png) = view_once_receive_material(device,
    ordinary_first_binding)?
  let after_ordinary_wire = encrypted_carrier(fixture.alice_path,
    bob_wire,
    %{inner | client_message_id: ordinary_first_id, attachment_manifest: after_ordinary})?
  let after_ordinary_result = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: after_ordinary_wire
  })
  let after_ordinary_refused = declassify(case after_ordinary_result do
      Err("view_once_reference_refused") -> true
      _ -> false
    end,
    "test-only refusal of a synthetic view-once identity already used by an ordinary message")
  let ordinary_first_row = "view-once/v2/#{Bytes.to_hex(binding.conversation_id)}/#{Bytes.to_hex(ordinary_first_id)}"
  let ordinary_first_safe = ordinary_first_delivered
    && after_ordinary_refused
    && Result.is_err(load_blob(fixture.bob_path, ordinary_first_row))
    && Bytes.secure_equals(load_blob(fixture.bob_path, history_label)?, ordinary_first_history)
  if !ordinary_first_safe do
    println("TEST_SYNTHETIC_PRIOR_ORDINARY_COLLISION_ACCEPTED")
  end
  let rollback_id = repeated(47, 16)?
  let rollback_binding = %{binding | message_id: rollback_id}
  let (rollback_reference, _rollback_chunk, _rollback_png) = view_once_receive_material(device,
    rollback_binding)?
  let rollback_wire = encrypted_carrier(fixture.alice_path,
    bob_wire,
    %{inner | client_message_id: rollback_id, attachment_manifest: rollback_reference})?
  let rollback_row = "view-once/v2/#{Bytes.to_hex(binding.conversation_id)}/#{Bytes.to_hex(rollback_id)}"
  let rollback_identity = identity_label(rollback_binding)?
  let rollback_logical = logical_label(bob.account_id, alice.account_id, rollback_id)?
  let recipient_session = find_peer_session(fixture.bob_path,
    key,
    alice.account_id,
    load_session_ids(fixture.bob_path, key)?,
    0)?
  let recipient_before = load_account_basis(fixture.bob_path,
    [
      "sessions/v1",
      recipient_session.label,
      history_label,
      rollback_row,
      rollback_identity,
      rollback_logical
    ])?
  fail_pending_insert(fixture.bob_path, rollback_row, true)?
  let rejected = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: rollback_wire
  })
  let rolled_back = declassify(case rejected do
      Err("database_write_failed") -> true
      _ -> false
    end,
    "test-only synthetic transaction failure status")
  fail_pending_insert(fixture.bob_path, rollback_row, false)?
  let unchanged = same_account_basis(recipient_before,
    load_account_basis(fixture.bob_path,
      [
        "sessions/v1",
        recipient_session.label,
        history_label,
        rollback_row,
        rollback_identity,
        rollback_logical
      ])?)
  let retry = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: rollback_wire
  })
  let retry_succeeded = declassify(case retry do
      Ok(value) -> Bytes.secure_equals(value, Bytes.from_utf8("one image"))
      Err(_) -> false
    end,
    "test-only successful retry of a synthetic message after rollback")
  let rollback = rolled_back
    && unchanged
    && retry_succeeded
    && Result.is_ok(load_blob(fixture.bob_path, rollback_row))
    && Result.is_ok(load_blob(fixture.bob_path, rollback_identity))
    && Result.is_ok(load_blob(fixture.bob_path, rollback_logical))
  let mailbox_id = repeated(50, 16)?
  let mailbox_binding = %{binding | message_id: mailbox_id}
  let (mailbox_reference, _mailbox_chunk, _mailbox_png) = view_once_receive_material(device,
    mailbox_binding)?
  let mailbox_first = encrypted_carrier(fixture.alice_path,
    bob_wire,
    %{inner | client_message_id: mailbox_id, attachment_manifest: mailbox_reference})?
  let later_id = repeated(51, 16)?
  let mailbox_later = encrypted_carrier(fixture.alice_path,
    bob_wire,
    %{inner |
      client_message_id: later_id,
      body: Bytes.from_utf8("later message"),
      attachment_manifest: Bytes.empty()
    })?
  let mailbox_batch = case encode_delivery_batch([
    DeliveredEnvelope { sequence: U64.parse("1")?, envelope: mailbox_first },
    DeliveredEnvelope { sequence: U64.parse("2")?, envelope: mailbox_later }
  ]) do
    Err(_) -> return Err("view_once_test_batch")
    Ok(value) -> value
  end
  let answer = process_delivery_batch(MobileBatchRequest {
    database_path: fixture.bob_path,
    batch: mailbox_batch
  })?
  let receipt = case decode_mailbox_ack(answer) do
    Err(_) -> return Err("view_once_test_ack")
    Ok(value) -> value
  end
  let first_id = canonical_outer(mailbox_first)?.envelope_id
  let later_id_outer = canonical_outer(mailbox_later)?.envelope_id
  let mailbox_row = "view-once/v2/#{Bytes.to_hex(binding.conversation_id)}/#{Bytes.to_hex(mailbox_id)}"
  let latest_history = decode_history(open_history_blob(load_blob(fixture.bob_path, history_label)?,
    key,
    history_label)?)?
  let mailbox = List.length(receipt.envelope_ids) == 2
    && Bytes.secure_equals(List.get(receipt.envelope_ids, 0), first_id)
    && Bytes.secure_equals(List.get(receipt.envelope_ids, 1), later_id_outer)
    && Result.is_ok(load_blob(fixture.bob_path, mailbox_row))
    && Bytes.secure_equals(List.last(latest_history).inner.body, Bytes.from_utf8("later message"))
  if declassify(delivered, "test-only observation of synthetic message delivery") do
    println("TEST_SYNTHETIC_RECEIVE_DELIVERED")
  end
  if declassify(!pending_exists, "test-only observation of synthetic pending-row absence") do
    println("TEST_SYNTHETIC_PENDING_ABSENT")
  end
  if declassify(!sanitized, "test-only observation that synthetic history retains its reference") do
    println("TEST_SYNTHETIC_HISTORY_RETAINS_REFERENCE")
  end
  erase_local_state(fixture.alice_path)?
  erase_local_state(fixture.bob_path)?
  erase_local_state(fixture.linked_path)?
  File.delete(fixture.alice_path)?
  File.delete(fixture.bob_path)?
  File.delete(fixture.linked_path)?
  Ok((delivered,
    pending_exists,
    sanitized,
    contract,
    duplicate,
    conflict
      && malformed
      && batch_refused
      && ordinary_refused
      && expired_duplicate
      && ordinary_first_safe
      && changed_body_refused
      && duplicate_contact_safe
      && conflict_contact_safe,
    rollback,
    mailbox))
end

test("real ratchet receive admits view-once without object retrieval or history reference") do
  let result = case proof() do
    Err(_) -> do
      assert(false)
      (false, false, false, false, false, false, false, false)
    end
    Ok(value) -> value
  end
  let (delivered, pending, sanitized, contract, duplicate, refused, rollback, mailbox) = result
  assert(declassify(delivered,
    "test-only assertion for delivery of a synthetic authenticated message"))
  assert(declassify(pending, "test-only assertion that the synthetic message has a pending row"))
  assert(declassify(sanitized, "test-only assertion that synthetic history omits its reference"))
  assert(contract)
  assert(declassify(duplicate, "test-only synthetic duplicate remains idempotent"))
  assert(declassify(refused, "test-only synthetic conflicting and forged references are refused"))
  assert(declassify(rollback, "test-only synthetic failed transaction rolls back and can retry"))
  assert(declassify(mailbox,
    "test-only synthetic mailbox acknowledges a pending image and delivers the later message"))
end
