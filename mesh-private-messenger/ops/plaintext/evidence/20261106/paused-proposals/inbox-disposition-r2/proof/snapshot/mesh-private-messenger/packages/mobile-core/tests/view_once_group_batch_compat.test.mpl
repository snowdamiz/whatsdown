from Groups.Mls import GroupState, GroupEncryptOutcome
from Groups.GroupCodec import delivery_targets
from Groups.GroupMessages import encrypt_timed_group_payload_for_transport, encode_group_message
from Groups.GroupPayload import GroupPayload
from Groups.Expiry import TimedGroupPayload
from Identity.Device import DeviceKeys
from Mobile.Attachments import encode_group_attachment
from Mobile.Codec import current_time, mobile_join, mobile_vector, mobile_write_u32
from Mobile.GroupState import (
  load_group,
  consume_group_state,
  group_target_envelopes,
  encode_group_packet
)
from Mobile.Presentation import present_message_with_attachment
from Mobile.Profile import load_profile, open_device
from Mobile.Types import MobileAttachmentRecipient
from MobileCore import attachment_prepare_export, group_receive_export
from Storage.Keys import platform_key
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleSupport import group_account_fixture
from Tests.GroupLifecycleWire import group_vectors, output_list, envelope_for, read_u32_at
from Tests.HistoryFixture import fixture_group_history
from Tests.PresentationFixture import fixture_save_presentation
from Tests.Support import write_u32
from Transport.Packet import decode_client_profile

fn compat_group_packet(path :: String,
  key :: borrow StorageKey,
  device :: borrow DeviceKeys,
  state :: consume GroupState,
  body :: Bytes) -> Result<(GroupState, List<Bytes>), String> do
  let targets = case delivery_targets(state.tree, state.local_leaf) do
    Err(_) -> return Err("fixture delivery targets")
    Ok(value) -> value
  end
  case encrypt_timed_group_payload_for_transport(state,
    device.signing_private_key,
    TimedGroupPayload {
      timestamp: current_time()?,
      disappearing_seconds: 3600,
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

# The history export returns an ATB of opened summaries for a multi-photo message.
fn compat_summary_parts(input :: Bytes,
  offset :: Int,
  items :: List<Bytes>) -> List<Bytes>!String do
  if offset == Bytes.length(input) do
    Ok(items)
  else if offset + 4 > Bytes.length(input) do
    Err("truncated summary batch")
  else
    let length = read_u32_at(input, offset)?
    let item = Bytes.slice(input, offset + 4, length)?
    compat_summary_parts(input, offset + 4 + length, List.append(items, item))
  end
end

fn compat_group_batch_receive() -> Bool!String do
  if !Test.install_in_memory_secure_store() do
    return Err("fixture secure store")
  end
  let accounts = group_account_fixture()?
  let group = create_group_with_bob(accounts)?
  let key = platform_key()?
  let profile = decode_client_profile(load_profile(accounts.alice_path)?)?
  let device = open_device(profile, key, accounts.alice_path)?
  let bob = decode_client_profile(load_profile(accounts.bob_path)?)?
  let _ = fixture_save_presentation(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    Bytes.from_utf8("user/#{Bytes.to_hex(accounts.alice_account.account_id)}"),
    group_vectors([Bytes.from_utf8("Synthetic Alice"), Bytes.empty()])?
  ])?)?
  let _ = fixture_save_presentation(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    Bytes.from_utf8("group/#{Bytes.to_hex(group)}"),
    group_vectors([Bytes.from_utf8("Synthetic group"), Bytes.empty()])?
  ])?)?
  let names = ["first.png", "second.png"]
  let prepared = for name in names do
    output_list(attachment_prepare_export(group_vectors([
      Bytes.from_utf8(accounts.alice_path),
      Bytes.from_utf8(name),
      Bytes.from_utf8("image/png"),
      write_u32(1)?,
      write_u32(1)?
    ])?)?)?
  end
  # Duplicate real synthetic Bob entries are currently accepted. They make each
  # independently valid ATG larger than 1024 bytes without making a large frame.
  let recipients = for _ in 0..12 do
    MobileAttachmentRecipient {
      account_id: bob.account_id,
      device_id: bob.device_id,
      public_key: bob.credential.dh_public_key
    }
  end
  let parts = for item in prepared do
    encode_group_attachment(device, List.head(item), recipients)?
  end
  if declassify(List.length(parts) != 2
      || List.any(parts, fn(part) do Bytes.length(part) <= 1024 || Bytes.length(part) > 65536 end),
    "test-only observation of synthetic group batch part sizes") do
    return Err("fixture ATG parts do not exercise the group size limit")
  end
  let attachment = mobile_join([
      Bytes.from_hex("01415442")?,
      mobile_write_u32(2)?,
      mobile_vector(List.get(parts, 0))?,
      mobile_vector(List.get(parts, 1))?
    ],
    0,
    Bytes.empty())?
  let body = Bytes.from_utf8("ordinary group album")
  let presented = present_message_with_attachment(accounts.alice_path, group, body, attachment)?
  if declassify(Bytes.length(attachment) > 65536 || Bytes.length(presented) > 65342,
    "test-only observation of synthetic group batch frame sizes") do
    return Err("fixture exceeds group frame limits")
  end
  let state = load_group(accounts.alice_path, profile, key, group)?
  let (state, envelopes) = compat_group_packet(accounts.alice_path, key, device, state, presented)?
  consume_group_state(state)
  let envelope = envelope_for(envelopes, accounts.bob_entry.mailbox_token, 0)?
  let opened = group_receive_export(group_vectors([Bytes.from_utf8(accounts.bob_path), envelope])?)?
  if !declassify(Bytes.secure_equals(opened, body),
    "test-only assertion of controlled synthetic group album text; no application disclosure") do
    return Err("ordinary group album text did not land")
  end
  let history = output_list(fixture_group_history(group_vectors([
    Bytes.from_utf8(accounts.bob_path),
    group
  ])?)?)?
  if List.length(history) != 1 do
    return Err("ordinary group album history missing")
  end
  let record = output_list(List.head(history))?
  if List.length(record) != 11 || !Bytes.secure_equals(List.get(record, 6), body) do
    return Err("ordinary group album history body missing")
  end
  let album = List.get(record, 7)
  if Bytes.length(album) < 8
    || !Bytes.secure_equals(Bytes.slice(album, 0, 4)?, Bytes.from_hex("01415442")?)
    || read_u32_at(album, 4)? != 2 do
    return Err("ordinary group album summary missing")
  end
  let summaries = compat_summary_parts(album, 8, [])?
  if List.length(summaries) != 2 do
    return Err("ordinary group album lost attachment summaries")
  end
  for index in 0..2 do
    let summary = output_list(List.get(summaries, index))?
    if List.length(summary) != 9
      || !Bytes.secure_equals(List.get(summary, 1), List.get(List.get(prepared, index), 1))
      || !Bytes.secure_equals(List.get(summary, 3), Bytes.from_utf8(List.get(names, index)))
      || !Bytes.secure_equals(List.get(summary, 4), Bytes.from_utf8("image/png")) do
      return Err("ordinary group attachment summary mismatch")
    end
  end
  File.delete(accounts.alice_path)?
  File.delete(accounts.bob_path)?
  File.delete(accounts.linked_path)?
  Ok(true)
end

test("ordinary group batch accepts ATG references larger than 1024 bytes") do
  case compat_group_batch_receive() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
