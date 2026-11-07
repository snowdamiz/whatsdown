from Attachments.ViewOnce import decode_view_once_reference
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
  group_state_label,
  group_history_label,
  group_target_envelopes,
  encode_group_packet
)
from Mobile.Presentation import present_message_with_attachment
from Mobile.Profile import load_profile, open_device
from Mobile.Types import MobileAttachmentRecipient
from MobileCore import attachment_prepare_export, group_receive_export
from Storage.Blobs import load_blob
from Storage.Keys import platform_key
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleSupport import group_account_fixture
from Tests.GroupLifecycleWire import group_vectors, output_list, envelope_for
from Tests.HistoryFixture import fixture_group_history
from Tests.PresentationFixture import fixture_save_presentation
from Tests.Support import repeated, write_u32
from Transport.Packet import decode_client_profile

# This is syntactically complete VOR1 framing, but its key and manifest bytes
# are synthetic and deliberately not usable cryptographic material. Group
# admission must reject the unsupported carrier before treating its body as an
# ordinary message, regardless of whether a direct recipient could open it.
fn group_refusal_vor() -> Bytes!String do
  mobile_join([
      Bytes.from_hex("01564f52")?,
      repeated(7, 192)?,
      mobile_vector(Bytes.from_utf8("synthetic manifest"))?,
      mobile_vector(Bytes.from_utf8("synthetic wrapped key"))?
    ],
    0,
    Bytes.empty())
end

fn group_refusal_packet(path :: String,
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

fn group_refusal_case(mode :: Int) -> Bool!String do
  if !Test.install_in_memory_secure_store() do
    return Err("fixture secure store")
  end
  let accounts = group_account_fixture()?
  let group = create_group_with_bob(accounts)?
  let key = platform_key()?
  let profile = decode_client_profile(load_profile(accounts.alice_path)?)?
  let device = open_device(profile, key, accounts.alice_path)?
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
  let vor = group_refusal_vor()?
  if !declassify(Result.is_ok(decode_view_once_reference(vor)),
    "test-only assertion that the authored synthetic VOR framing decodes; no application disclosure") do
    return Err("fixture VOR framing")
  end
  let attachment = if mode == 1 do
    # A real ordinary group attachment precedes the unsupported VOR in an ATB.
    let prepared = output_list(attachment_prepare_export(group_vectors([
      Bytes.from_utf8(accounts.alice_path),
      Bytes.from_utf8("synthetic.png"),
      Bytes.from_utf8("image/png"),
      write_u32(1)?,
      write_u32(1)?
    ])?)?)?
    let bob = decode_client_profile(load_profile(accounts.bob_path)?)?
    let ordinary = encode_group_attachment(device,
      List.head(prepared),
      [
        MobileAttachmentRecipient {
          account_id: bob.account_id,
          device_id: bob.device_id,
          public_key: bob.credential.dh_public_key
        }
      ])?
    mobile_join([
        Bytes.from_hex("01415442")?,
        mobile_write_u32(2)?,
        mobile_vector(ordinary)?,
        mobile_vector(vor)?
      ],
      0,
      Bytes.empty())?
  else if mode == 2 do
    # Versioned VOR header with truncated content.
    Bytes.from_hex("01564f52")?
  else
    vor
  end
  let presented = present_message_with_attachment(accounts.alice_path,
    group,
    Bytes.from_utf8("unsupported synthetic attachment"),
    attachment)?
  let protected_rows = [
    group_history_label(group),
    "presentation/v1/user/#{Bytes.to_hex(accounts.alice_account.account_id)}",
    "presentation/v1/group/#{Bytes.to_hex(group)}"
  ]
  for label in protected_rows do
    if load_blob(accounts.bob_path, label) != Err("local_state_not_found") do
      return Err("fixture protected row already exists")
    end
  end
  let state = load_group(accounts.alice_path, profile, key, group)?
  let (state, unsupported) = group_refusal_packet(accounts.alice_path,
    key,
    device,
    state,
    presented)?
  let (state, ordinary) = group_refusal_packet(accounts.alice_path,
    key,
    device,
    state,
    Bytes.from_utf8("ordinary successor"))?
  consume_group_state(state)
  let unsupported_envelope = envelope_for(unsupported, accounts.bob_entry.mailbox_token, 0)?
  let ordinary_envelope = envelope_for(ordinary, accounts.bob_entry.mailbox_token, 0)?
  let label = group_state_label(group)?
  let before = load_blob(accounts.bob_path, label)?
  let result = group_receive_export(group_vectors([
    Bytes.from_utf8(accounts.bob_path),
    unsupported_envelope
  ])?)
  if !declassify(Result.is_err(result),
    "test-only assertion that a synthetic unsupported group carrier is rejected; no application disclosure") do
    return Err("unsupported group carrier accepted")
  end
  if !Bytes.secure_equals(before, load_blob(accounts.bob_path, label)?) do
    return Err("rejected group carrier advanced state")
  end
  for row in protected_rows do
    if load_blob(accounts.bob_path, row) != Err("local_state_not_found") do
      return Err("rejected group carrier retained history or presentation")
    end
  end
  let opened = group_receive_export(group_vectors([
    Bytes.from_utf8(accounts.bob_path),
    ordinary_envelope
  ])?)?
  if !declassify(Bytes.secure_equals(opened, Bytes.from_utf8("ordinary successor")),
    "test-only assertion of controlled synthetic group successor delivery; no application disclosure") do
    return Err("ordinary successor failed")
  end
  let history = output_list(fixture_group_history(group_vectors([
    Bytes.from_utf8(accounts.bob_path),
    group
  ])?)?)?
  if List.length(history) != 1 do
    return Err("unexpected group history after successor")
  end
  File.delete(accounts.alice_path)?
  File.delete(accounts.bob_path)?
  File.delete(accounts.linked_path)?
  Ok(true)
end

test("group receive rejects standalone VOR without state or history changes") do
  case group_refusal_case(0) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("group receive rejects VOR enclosed in an attachment batch") do
  case group_refusal_case(1) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("group receive rejects truncated versioned VOR") do
  case group_refusal_case(2) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
