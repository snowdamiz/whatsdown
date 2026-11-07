##! Authenticated synthetic control carriers. No network or object fetches.
import File
from Attachments.ViewOnce import ViewOnceBinding, decode_view_once_reference
from Groups.GroupCodec import delivery_targets
from Groups.GroupMessages import encrypt_group_payload_for_transport, encode_group_message
from Groups.GroupPayload import GroupPayload
from Groups.Mls import GroupState, GroupEncryptOutcome
from Identity.Device import DeviceKeys
from Mobile.Attachments import rewrap_reference
from Mobile.ContactAddress import deposit_address, contact_address_extension
from Mobile.Codec import (
  current_time,
  mobile_join,
  mobile_vector,
  mobile_write_u32,
  mobile_write_u64,
  encode_output_list
)
from Mobile.GroupState import (
  load_group,
  consume_group_state,
  group_target_envelopes,
  encode_group_packet
)
from Mobile.Messages import start_conversation, receive_initial_message, receive_message
from Mobile.Presentation import (
  present_message_with_attachment,
  group_presentation_carrier_supported
)
from Mobile.Profile import load_profile, open_device
from Mobile.Sessions import (
  load_session_ids,
  find_peer_session,
  restore_session,
  seal_updated_session,
  inner_bytes,
  ratchet_bytes
)
from Mobile.Transport import sealed_outer_bytes
from Mobile.Types import MobileStartRequest, MobileReceiveRequest
from MobileCore import (
  attachment_prepare_export,
  group_key_package_export,
  group_invitations_export,
  group_receive_export
)
from Protocol.V1 import InnerEnvelope, ProtocolExtension
from Session.Ratchet import encrypt_sealed
from Storage.AccountGuard import load_account_basis, commit_account_changes
from Storage.Keys import platform_key
from Tests.GroupConsistencySupport import signed_transparency_view
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleSupport import group_account_fixture, install_signed_transparency
from Tests.GroupLifecycleWire import group_vectors, output_list, envelope_for
from Tests.HistoryFixture import fixture_group_history
from Tests.Support import repeated, write_u32
from Tests.ViewOnceFixture import view_once_receive_material
from Tests.ViewOnceInitialSyncFixture import initial_carrier
from Transparency.Gossip import CheckpointHint, GossipControl, encode_gossip, encode_hint
from Transparency.Merkle import leaf_hash
from Transport.Packet import (
  TransportPacket,
  decode_client_profile,
  direct_conversation_id,
  encode_packet,
  session_aad
)

fn control_check(value :: Plaintext<Bool>, error :: String) -> Unit!String do
  if declassify(value,
    "test-only observation of synthetic authenticated control delivery and storage") do
    Ok(nil)
  else
    Err(error)
  end
end

# Compare all encrypted records, including separately committed contact and
# gossip rows, before any history getter can clean up evidence.
fn control_row_text(row :: Map<String, DbValue>, name :: String) -> String!String do
  case Map.get(row, name) do
    Text(value) -> Ok(value)
    _ -> Err("control fixture database column")
  end
end

fn control_fingerprint_rows(rows :: List<Map<String, DbValue>>,
  index :: Int,
  output :: String) -> String!String do
  if index >= List.length(rows) do
    Ok(output)
  else
    let row = List.get(rows, index)
    control_fingerprint_rows(rows,
      index + 1,
      output
        <> "|"
        <> control_row_text(row, "record_hash")?
        <> ":"
        <> control_row_text(row, "ciphertext_hex")?)
  end
end

fn control_fingerprint(path :: String) -> String!String do
  let database = Sqlite.open(path)?
  let result = Sqlite.query_values(database,
    "SELECT record_hash, hex(ciphertext) AS ciphertext_hex FROM encrypted_blobs ORDER BY record_hash",
    [])
  Sqlite.close(database)
  control_fingerprint_rows(result?, 0, "")
end

fn control_ratchet(path :: String, peer_wire :: Bytes, inner :: InnerEnvelope) -> Bytes!String do
  let key = platform_key()?
  let peer = decode_client_profile(peer_wire)?
  let loaded = find_peer_session(path, key, peer.account_id, load_session_ids(path, key)?, 0)?
  let before = load_account_basis(path, ["sessions/v1", loaded.label])?
  let (next, message) = case encrypt_sealed(restore_session(loaded, key)?,
    inner_bytes(inner)?,
    session_aad(loaded.session_id)?) do
    Err(_) -> return Err("control fixture encryption")
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

fn control_attachment(vor :: Bytes, ordinary :: Bytes, batch :: Bool) -> Bytes!String do
  if batch do
    # A structurally valid ATB, with the VOR in a non-first position.
    mobile_join([
        Bytes.from_hex("01415442")?,
        mobile_write_u32(2)?,
        mobile_vector(ordinary)?,
        mobile_vector(vor)?
      ],
      0,
      Bytes.empty())
  else
    Ok(vor)
  end
end

fn control_body(kind :: Int, sender_path :: String) -> Bytes!String do
  if kind == 3 do
    let expires = U64.add(current_time()?, U64.parse("60000")?)?
    encode_output_list([
      repeated(31, 16)?,
      repeated(32, 32)?,
      mobile_write_u64(expires)?,
      repeated(33, 188)?
    ])
  else if kind == 4 do
    encode_output_list([
      repeated(31, 16)?,
      repeated(32, 32)?,
      group_key_package_export(Bytes.from_utf8(sender_path))?
    ])
  else
    encode_gossip(CheckpointRequest(repeated(34, 16)?,
      CheckpointHint { tree_size: U64.parse("1")?, tree_root: repeated(35, 32)? }))
  end
end

fn direct_control_case(kind :: Int, batch :: Bool, initial :: Bool) -> Bool!String do
  if !Test.install_in_memory_secure_store() do
    return Err("control fixture secure store")
  end
  let accounts = group_account_fixture()?
  let signed = signed_transparency_view([
    leaf_hash(accounts.alice_set)?,
    leaf_hash(accounts.bob_set)?
  ])?
  for path in [accounts.alice_path, accounts.bob_path] do
    if !install_signed_transparency(path, signed, accounts.alice_set)?
      || !install_signed_transparency(path, signed, accounts.bob_set)? do
      return Err("control fixture transparency")
    end
  end
  let alice_wire = load_profile(accounts.alice_path)?
  let bob_wire = load_profile(accounts.bob_path)?
  let alice = decode_client_profile(alice_wire)?
  let bob = decode_client_profile(bob_wire)?
  if !initial do
    let hello = start_conversation(MobileStartRequest {
      database_path: accounts.alice_path,
      peer_profile: bob_wire,
      body: Bytes.from_utf8("establish synthetic session"),
      attachment: Bytes.empty()
    })?
    let delivered = receive_initial_message(MobileReceiveRequest {
      database_path: accounts.bob_path,
      outer: hello
    })?
    control_check(Bytes.secure_equals(delivered, Bytes.from_utf8("establish synthetic session")),
      "control fixture initial session")?
  end
  let key = platform_key()?
  let device = open_device(bob, key, accounts.bob_path)?
  let sender_device = open_device(alice, key, accounts.alice_path)?
  let prepared = output_list(attachment_prepare_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    Bytes.from_utf8("ordinary.png"),
    Bytes.from_utf8("image/png"),
    write_u32(1)?,
    write_u32(1)?
  ])?)?)?
  let ordinary_attachment = rewrap_reference(sender_device,
    List.head(prepared),
    bob.credential.dh_public_key)?
  let conversation = direct_conversation_id(alice.account_id, bob.account_id)?
  let message = repeated(41, 16)?
  let binding = ViewOnceBinding {
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    receiver_account_id: bob.account_id,
    receiver_device_id: bob.device_id,
    conversation_id: conversation,
    message_id: message
  }
  let (vor, _chunk, _image) = view_once_receive_material(device, binding)?
  let inner = InnerEnvelope {
    version: 1,
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    recipient_device_id: bob.device_id,
    conversation_id: conversation,
    client_message_id: message,
    client_timestamp: current_time()?,
    message_type: kind,
    body: control_body(kind, accounts.alice_path)?,
    reply_reference: Bytes.empty(),
    attachment_manifest: control_attachment(vor, ordinary_attachment, batch)?,
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: [
      ProtocolExtension {
        id: contact_address_extension(),
        mandatory: false,
        value: repeated(61, 32)?
      },
      ProtocolExtension {
        id: 2,
        mandatory: false,
        value: encode_hint(CheckpointHint {
          tree_size: U64.parse("1")?,
          tree_root: repeated(62, 32)?
        })?
      }
    ]
  }
  let wire = if initial do
    let (_state, outer) = initial_carrier(accounts.alice_path, accounts.bob_path, inner)?
    outer
  else
    control_ratchet(accounts.alice_path, bob_wire, inner)?
  end
  let before = control_fingerprint(accounts.bob_path)?
  let result = if initial do
    receive_initial_message(MobileReceiveRequest { database_path: accounts.bob_path, outer: wire })
  else
    receive_message(MobileReceiveRequest { database_path: accounts.bob_path, outer: wire })
  end
  control_check(Result.is_err(result), "control with view-once carrier was accepted")?
  control_check(before == control_fingerprint(accounts.bob_path)?,
    "rejected direct control changed encrypted recipient state")?
  # An otherwise identical ordinary control must remain deliverable. Its
  # success also proves the rejected message did not consume recipient state.
  let clean = %{inner |
    client_message_id: repeated(42, 16)?,
    attachment_manifest: ordinary_attachment
  }
  let clean_wire = if initial do
    let (_state, outer) = initial_carrier(accounts.alice_path, accounts.bob_path, clean)?
    outer
  else
    control_ratchet(accounts.alice_path, bob_wire, clean)?
  end
  let delivered = if initial do
    receive_initial_message(MobileReceiveRequest {
      database_path: accounts.bob_path,
      outer: clean_wire
    })?
  else
    receive_message(MobileReceiveRequest { database_path: accounts.bob_path, outer: clean_wire })?
  end
  control_check(Bytes.length(delivered) == 0, "ordinary control did not succeed")?
  control_check(Bytes.secure_equals(deposit_address(accounts.bob_path,
        key,
        alice.entry.mailbox_token)?,
      repeated(61, 32)?),
    "ordinary control did not learn the synthetic contact address")?
  if kind == 3 do
    let invitations = output_list(group_invitations_export(Bytes.from_utf8(accounts.bob_path))?)?
    if List.length(invitations) != 1 do
      return Err("ordinary invitation was not recorded")
    end
  end
  File.delete(accounts.alice_path)?
  File.delete(accounts.bob_path)?
  File.delete(accounts.linked_path)?
  Ok(true)
end

fn control_group_packet(path :: String,
  key :: borrow StorageKey,
  device :: borrow DeviceKeys,
  state :: consume GroupState,
  payload :: GroupPayload) -> Result<(GroupState, List<Bytes>), String> do
  let targets = case delivery_targets(state.tree, state.local_leaf) do
    Err(_) -> return Err("control group targets")
    Ok(value) -> value
  end
  case encrypt_group_payload_for_transport(state,
    device.signing_private_key,
    payload,
    Bytes.from_utf8("mesh-mobile-group/v1")) do
    GroupEncryptRejected(rejected, _) -> do
      consume_group_state(rejected)
      Err("control group encryption")
    end
    GroupMessageEncrypted(next, message) -> do
      let wire = case encode_group_message(message) do
        Err(_) -> return Err("control group encoding")
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

fn group_control_case() -> Bool!String do
  if !Test.install_in_memory_secure_store() do
    return Err("control group secure store")
  end
  let accounts = group_account_fixture()?
  let group = create_group_with_bob(accounts)?
  let key = platform_key()?
  let alice = decode_client_profile(load_profile(accounts.alice_path)?)?
  let bob = decode_client_profile(load_profile(accounts.bob_path)?)?
  let device = open_device(alice, key, accounts.alice_path)?
  let vor = mobile_join([
      Bytes.from_hex("01564f52")?,
      repeated(7, 192)?,
      mobile_vector(Bytes.from_utf8("synthetic manifest"))?,
      mobile_vector(Bytes.from_utf8("synthetic wrapped key"))?
    ],
    0,
    Bytes.empty())?
  control_check(Result.is_ok(decode_view_once_reference(vor)), "control group VOR fixture framing")?
  let presented = present_message_with_attachment(accounts.alice_path,
    group,
    Bytes.from_utf8("synthetic control"),
    vor)?
  control_check(!group_presentation_carrier_supported(presented),
    "control group presentation did not contain recognized VOR")?
  let control = GroupPayload {
    kind: 5,
    body: presented,
    hint: Bytes.empty(),
    recipient_account: bob.account_id,
    recipient_device: bob.device_id
  }
  let ordinary = GroupPayload {
    kind: 1,
    body: Bytes.from_utf8("ordinary successor"),
    hint: Bytes.empty(),
    recipient_account: Bytes.empty(),
    recipient_device: Bytes.empty()
  }
  let state = load_group(accounts.alice_path, alice, key, group)?
  let (state, rejected) = control_group_packet(accounts.alice_path, key, device, state, control)?
  let (state, successor) = control_group_packet(accounts.alice_path, key, device, state, ordinary)?
  consume_group_state(state)
  let rejected_wire = envelope_for(rejected, accounts.bob_entry.mailbox_token, 0)?
  let next_wire = envelope_for(successor, accounts.bob_entry.mailbox_token, 0)?
  let before = control_fingerprint(accounts.bob_path)?
  let result = group_receive_export(group_vectors([
    Bytes.from_utf8(accounts.bob_path),
    rejected_wire
  ])?)
  control_check(Result.is_err(result),
    "addressed group control with view-once presentation accepted")?
  control_check(before == control_fingerprint(accounts.bob_path)?,
    "rejected group control changed encrypted group or gossip state")?
  let delivered = group_receive_export(group_vectors([
    Bytes.from_utf8(accounts.bob_path),
    next_wire
  ])?)?
  control_check(Bytes.secure_equals(delivered, ordinary.body), "ordinary group successor failed")?
  let history = output_list(fixture_group_history(group_vectors([
    Bytes.from_utf8(accounts.bob_path),
    group
  ])?)?)?
  if List.length(history) != 1 do
    return Err("group control entered history or successor missing")
  end
  File.delete(accounts.alice_path)?
  File.delete(accounts.bob_path)?
  File.delete(accounts.linked_path)?
  Ok(true)
end

fn assert_control_case(result :: Bool!String) do
  case result do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("ratchet invitation type 3 rejects standalone VOR") do
  assert_control_case(direct_control_case(3, false, false))
end

test("ratchet invitation type 3 rejects VOR in ATB") do
  assert_control_case(direct_control_case(3, true, false))
end

test("ratchet invitation type 4 rejects standalone VOR") do
  assert_control_case(direct_control_case(4, false, false))
end

test("ratchet invitation type 4 rejects VOR in ATB") do
  assert_control_case(direct_control_case(4, true, false))
end

test("ratchet gossip type 5 rejects standalone VOR") do
  assert_control_case(direct_control_case(5, false, false))
end

test("ratchet gossip type 5 rejects VOR in ATB") do
  assert_control_case(direct_control_case(5, true, false))
end

test("initial invitation type 3 rejects standalone VOR") do
  assert_control_case(direct_control_case(3, false, true))
end

test("initial invitation type 3 rejects VOR in ATB") do
  assert_control_case(direct_control_case(3, true, true))
end

test("initial invitation type 4 rejects standalone VOR") do
  assert_control_case(direct_control_case(4, false, true))
end

test("initial invitation type 4 rejects VOR in ATB") do
  assert_control_case(direct_control_case(4, true, true))
end

test("addressed signed encrypted group kind 5 rejects presentation-framed VOR") do
  assert_control_case(group_control_case())
end
