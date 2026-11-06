from Mobile.Attachments import encode_group_attachment
from Mobile.Presentation import present_message_with_attachment
from Mobile.Types import MobileAttachmentRecipient
from Tests.PresentationFixture import fixture_save_presentation
from Tests.Support import write_u32
from Groups.Mls import GroupState, GroupEncryptOutcome
from Groups.GroupCodec import delivery_targets
from Groups.GroupMessages import encrypt_timed_group_payload_for_transport, encode_group_message
from Groups.GroupPayload import GroupPayload
from Groups.Expiry import TimedGroupPayload
from Mobile.Codec import current_time, mobile_wide
from Mobile.GroupState import (
  load_group,
  consume_group_state,
  group_state_label,
  group_history_label,
  group_target_envelopes,
  encode_group_packet
)
from Mobile.Profile import load_profile, open_device
from MobileCore import (
  attachment_prepare_export,
  group_receive_export,
  process_delivery_batch_export
)
from Storage.Blobs import load_blob
from Storage.Keys import platform_key
from Identity.Device import DeviceKeys
from Transport.Packet import decode_client_profile
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleSupport import group_account_fixture
from Tests.GroupLifecycleWire import (
  group_vectors,
  output_list,
  envelope_for,
  outer,
  delivery_batch,
  ack
)
from Tests.HistoryFixture import fixture_group_history

fn packet(path :: String,
  key :: borrow StorageKey,
  device :: borrow DeviceKeys,
  state :: consume GroupState,
  timestamp :: U64,
  seconds :: Int,
  body :: Bytes) -> Result<(GroupState, List<Bytes>), String> do
  let targets = case delivery_targets(state.tree, state.local_leaf) do
    Err(_) -> return Err("fixture delivery targets")
    Ok(value) -> value
  end
  case encrypt_timed_group_payload_for_transport(state,
    device.signing_private_key,
    TimedGroupPayload {
      timestamp: timestamp,
      disappearing_seconds: seconds,
      payload: GroupPayload {
        kind: 1,
        body: body,
        hint: Bytes.empty(),
        recipient_account: Bytes.empty(),
        recipient_device: Bytes.empty()
      }
    },
    Bytes.from_utf8("mesh-mobile-group/v1")) do
    GroupEncryptRejected(rejected, _) -> do
      consume_group_state(rejected)
      Err("fixture group encryption")
    end
    GroupMessageEncrypted(next, message) -> do
      let wire = case encode_group_message(message) do
        Err(_) -> return Err("fixture group wire")
        Ok(value) -> value
      end
      let envelopes = group_target_envelopes(path,
        key,
        targets,
        encode_group_packet(3, wire)?,
        current_time()?,
        0,
        [])?
      Ok((next, envelopes))
    end
  end
end

fn expired_receive_advances() -> Bool!String do
  if !Test.install_in_memory_secure_store() do
    return Err("fixture secure store")
  end
  let accounts = group_account_fixture()?
  let group = create_group_with_bob(accounts)?
  let key = platform_key()?
  let profile = decode_client_profile(load_profile(accounts.alice_path)?)?
  let device = open_device(profile, key, accounts.alice_path)?
  let user_key = Bytes.from_utf8("user/#{Bytes.to_hex(accounts.alice_account.account_id)}")
  let group_key = Bytes.from_utf8("group/#{Bytes.to_hex(group)}")
  let _ = fixture_save_presentation(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    user_key,
    group_vectors([Bytes.from_utf8("Synthetic Alice"), Bytes.empty()])?
  ])?)?
  let _ = fixture_save_presentation(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    group_key,
    group_vectors([Bytes.from_utf8("Synthetic timed group"), Bytes.empty()])?
  ])?)?
  let prepared = output_list(attachment_prepare_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    Bytes.from_utf8("expired.png"),
    Bytes.from_utf8("image/png"),
    write_u32(1)?,
    write_u32(1)?
  ])?)?)?
  let bob = decode_client_profile(load_profile(accounts.bob_path)?)?
  let attachment = encode_group_attachment(device,
    List.head(prepared),
    [
      MobileAttachmentRecipient {
        account_id: bob.account_id,
        device_id: bob.device_id,
        public_key: bob.credential.dh_public_key
      }
    ])?
  let expired_body = present_message_with_attachment(accounts.alice_path,
    group,
    Bytes.from_utf8("expired hidden body"),
    attachment)?
  let protected_rows = [
    group_history_label(group),
    "presentation/v1/user/#{Bytes.to_hex(accounts.alice_account.account_id)}",
    "presentation/v1/group/#{Bytes.to_hex(group)}"
  ]
  for label in protected_rows do
    if load_blob(accounts.bob_path, label) != Err("local_state_not_found") do
      return Err("fixture already contains protected row")
    end
  end
  let state = load_group(accounts.alice_path, profile, key, group)?
  let (state, expired) = packet(accounts.alice_path,
    key,
    device,
    state,
    mobile_wide("1")?,
    1,
    expired_body)?
  let (state, visible) = packet(accounts.alice_path,
    key,
    device,
    state,
    current_time()?,
    60,
    Bytes.from_utf8("visible successor"))?
  consume_group_state(state)
  let expired_envelope = envelope_for(expired, accounts.bob_entry.mailbox_token, 0)?
  let visible_envelope = envelope_for(visible, accounts.bob_entry.mailbox_token, 0)?
  let state_before = load_blob(accounts.bob_path, group_state_label(group)?)?
  let response = ack(process_delivery_batch_export(group_vectors([
    Bytes.from_utf8(accounts.bob_path),
    delivery_batch(expired_envelope)?
  ])?)?)?
  if List.length(response.envelope_ids) != 1
    || !Bytes.secure_equals(List.head(response.envelope_ids),
      outer(expired_envelope)?.envelope_id) do
    return Err("expired delivery not acknowledged")
  end
  if Bytes.secure_equals(state_before, load_blob(accounts.bob_path, group_state_label(group)?)?) do
    return Err("expired ratchet not advanced")
  end
  # Inspect the raw authenticated storage BEFORE calling a history getter:
  # the getter's cleanup must not be allowed to hide an inbound-retention bug.
  for label in protected_rows do
    if load_blob(accounts.bob_path, label) != Err("local_state_not_found") do
      return Err("expired attachment or presentation body was durably retained")
    end
  end
  let history = output_list(fixture_group_history(group_vectors([
    Bytes.from_utf8(accounts.bob_path),
    group
  ])?)?)?
  if List.length(history) != 0 do
    return Err("expired body was retained")
  end
  let opened = group_receive_export(group_vectors([
    Bytes.from_utf8(accounts.bob_path),
    visible_envelope
  ])?)?
  if !declassify(Bytes.secure_equals(opened, Bytes.from_utf8("visible successor")),
    "test-only Boolean assertion of controlled synthetic group expiry delivery; no application disclosure") do
    return Err("successor ratchet failed")
  end
  let following = output_list(fixture_group_history(group_vectors([
    Bytes.from_utf8(accounts.bob_path),
    group
  ])?)?)?
  if List.length(following) != 1 do
    return Err("unexpected group history")
  end
  if declassify(Result.is_ok(group_receive_export(group_vectors([
      Bytes.from_utf8(accounts.bob_path),
      expired_envelope
    ])?)),
    "test-only Boolean observation of whether a controlled synthetic expired group replay is accepted; no application disclosure") do
    return Err("expired replay accepted")
  end
  Ok(true)
end

test("expired authenticated group ciphertext advances replay and ACK without retaining body") do
  case expired_receive_advances() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

from MobileCore import group_send_export
from Storage.Records import store_record_changes, store_updated_blobs

fn orphan_group_is_not_receivable() -> Bool!String do
  if !Test.install_in_memory_secure_store() do
    return Err("fixture secure store")
  end
  let accounts = group_account_fixture()?
  let group = create_group_with_bob(accounts)?
  let envelopes = output_list(group_send_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    group,
    Bytes.from_utf8("indexed legacy-compatible body")
  ])?)?)?
  let envelope = envelope_for(List.reverse(envelopes), accounts.bob_entry.mailbox_token, 0)?
  let index = load_blob(accounts.bob_path, "groups/v1")?
  let label = group_state_label(group)?
  let state = load_blob(accounts.bob_path, label)?
  # Model an orphan left by an old stale membership writer after local forget.
  # The real encrypted ratchet remains valid, but it is no longer indexed.
  store_record_changes(accounts.bob_path, [], [], ["groups/v1"])?
  let request = group_vectors([Bytes.from_utf8(accounts.bob_path), envelope])?
  if !declassify(group_receive_export(request) == Err("group_message_rejected"),
    "test-only Boolean assertion of controlled synthetic orphan-group refusal; no application disclosure")
    || !Bytes.secure_equals(load_blob(accounts.bob_path, label)?, state)
    || load_blob(accounts.bob_path, group_history_label(group)) != Err("local_state_not_found") do
    return Err("orphan group accepted or mutated stored state")
  end
  # Restoring only the exact authenticated index makes the identical ordinary
  # GMS5 message receivable. The rejected attempt must not consume its ratchet.
  store_updated_blobs(accounts.bob_path, ["groups/v1"], [index])?
  let opened = group_receive_export(request)?
  let valid = declassify(Bytes.secure_equals(opened,
      Bytes.from_utf8("indexed legacy-compatible body")),
    "test-only Boolean assertion of controlled synthetic orphan-group delivery; no application disclosure")
    && !Bytes.secure_equals(load_blob(accounts.bob_path, label)?, state)
  File.delete(accounts.alice_path)?
  File.delete(accounts.bob_path)?
  File.delete(accounts.linked_path)?
  Ok(valid)
end

test("orphan group state refuses receive while restoring its exact index permits the same legacy-compatible message") do
  case orphan_group_is_not_receivable() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
