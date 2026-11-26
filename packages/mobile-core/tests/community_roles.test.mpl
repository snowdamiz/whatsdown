import File
from Groups.CommitWire import encode_group_commit
from Groups.Membership import commit_remove
from Groups.Mls import GroupRemoveOutcome
from Groups.Tree import find_member_index
from Identity.Device import DeviceKeys
from Protocol.V1 import AccountIdentity, DeviceCredential, DirectoryEntry, OuterEnvelope
from Mobile.Codec import current_time, mobile_wide, mobile_write_u64
from Mobile.GroupState import consume_group_state, encode_group_packet, load_group
from Mobile.Profile import load_profile, open_device
from Mobile.Transport import sealed_outer_bytes
from MobileCore import (
  group_add_export,
  group_forget_export,
  group_history_export,
  group_key_package_export,
  group_list_export,
  group_receive_export,
  group_remove_export,
  group_send_export,
  presentation_load_export,
  presentation_save_export
)
from Storage.Keys import platform_key
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleSupport import GroupAccountFixture, group_account_fixture
from Tests.GroupLifecycleWire import acknowledge, envelope_for, group_vectors, output_list
from Transport.Packet import decode_client_profile

fn ensure(value :: Bool, error :: String) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err(error)
  end
end

fn record(revision :: Int, details :: String, roles :: List<Bytes>) -> Bytes!String do
  group_vectors([
    Bytes.from_utf8("Solana builders"),
    Bytes.empty(),
    mobile_write_u64(mobile_wide("#{revision}")?)?,
    Bytes.from_utf8(details),
    List.reduce(roles,
      Bytes.empty(),
      fn(joined, id) do
        case Bytes.concat(joined, id) do
          Ok(value) -> value
          Err(_) -> Bytes.empty()
        end
      end)
  ])
end

fn save(path :: String, group_id :: Bytes, value :: Bytes) -> Bytes!String do
  presentation_save_export(group_vectors([
    Bytes.from_utf8(path),
    Bytes.from_utf8("group/" <> Bytes.to_hex(group_id)),
    value
  ])?)
end

fn stored(path :: String, group_id :: Bytes) -> Bytes!String do
  presentation_load_export(group_vectors([
    Bytes.from_utf8(path),
    Bytes.from_utf8("group/" <> Bytes.to_hex(group_id))
  ])?)
end

fn refused(result :: Bytes!String, expected :: String) -> Result<(), String> do
  case result do
    Ok(_) -> Err("#{expected} was not enforced")
    Err(error) -> ensure(error == expected, "expected #{expected}, got #{error}")
  end
end

# Sends from one device and delivers the envelope addressed to each listed mailbox.
fn post(from :: String,
  group_id :: Bytes,
  body :: String,
  targets :: List<(String, Bytes)>) -> Result<(), String> do
  let output = group_send_export(group_vectors([
    Bytes.from_utf8(from),
    group_id,
    Bytes.from_utf8(body)
  ])?)?
  deliver(from, output_list(output)?, targets, 0)
end

fn deliver(from :: String,
  envelopes :: List<Bytes>,
  targets :: List<(String, Bytes)>,
  index :: Int) -> Result<(), String> do
  if index >= List.length(targets) do
    acknowledge(from, envelopes, 0)
  else
    let (path, mailbox) = List.get(targets, index)
    group_receive_export(group_vectors([
      Bytes.from_utf8(path),
      envelope_for(envelopes, mailbox, 0)?
    ])?)?
    deliver(from, envelopes, targets, index + 1)
  end
end

# A commit made outside the core's own checks, as a modified client could send it.
fn forged_removal(accounts :: GroupAccountFixture,
  group_id :: Bytes,
  leaf :: Int) -> Bytes!String do
  let local = decode_client_profile(load_profile(accounts.bob_path)?)?
  let key = platform_key()?
  let state = load_group(accounts.bob_path, local, key, group_id)?
  let device = open_device(local, key, accounts.bob_path)?
  case commit_remove(state, device.signing_private_key, leaf) do
    GroupRemoveRejected(rejected, _) -> do
      consume_group_state(rejected)
      Err("forged removal failed")
    end
    GroupMemberRemoved(next, commit) -> do
      consume_group_state(next)
      let wire = case encode_group_commit(commit) do
        Ok(value)
        Err(_) -> Err("forged commit encoding failed")
      end?
      sealed_outer_bytes(accounts.alice_entry.mailbox_token,
        encode_group_packet(2, wire)?,
        decode_client_profile(load_profile(accounts.alice_path)?)?.credential.dh_public_key,
        current_time()?)
    end
  end
end

fn linked_leaf(accounts :: GroupAccountFixture, group_id :: Bytes) -> Int!String do
  let local = decode_client_profile(load_profile(accounts.alice_path)?)?
  let state = load_group(accounts.alice_path, local, platform_key()?, group_id)?
  let leaf = find_member_index(state.tree,
    accounts.alice_account.account_id,
    accounts.linked_credential.device_id)
  consume_group_state(state)
  Ok(leaf)
end

fn exercise() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let accounts = group_account_fixture()?
  let group_id = create_group_with_bob(accounts)?
  let alice = accounts.alice_account.account_id
  let bob = decode_client_profile(load_profile(accounts.bob_path)?)?.account_id
  let bob_box = (accounts.bob_path, accounts.bob_entry.mailbox_token)
  let linked_box = (accounts.linked_path, accounts.linked_entry.mailbox_token)
  let linked_package = group_key_package_export(Bytes.from_utf8(accounts.linked_path))?
  let added = output_list(group_add_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    group_id,
    accounts.alice_set,
    linked_package
  ])?)?)?
  deliver(accounts.alice_path, added, [bob_box, linked_box], 0)?
  # The creator makes the group a community it owns.
  let owned = record(1, "[]", [alice])?
  save(accounts.alice_path, group_id, owned)?
  let leaf = linked_leaf(accounts, group_id)?
  refused(group_receive_export(group_vectors([
      Bytes.from_utf8(accounts.alice_path),
      forged_removal(accounts, group_id, leaf)?
    ])?),
    "group_commit_rejected")?
  post(accounts.alice_path, group_id, "welcome", [bob_box, linked_box])?
  ensure(Bytes.secure_equals(stored(accounts.bob_path, group_id)?, owned),
    "members learn the community")?
  ensure(Bytes.secure_equals(stored(accounts.linked_path, group_id)?, owned),
    "the owner's other device learns the community")?
  # A member neither changes who is in it nor what it says.
  refused(group_remove_export(group_vectors([
      Bytes.from_utf8(accounts.bob_path),
      group_id,
      alice,
      accounts.linked_credential.device_id
    ])?),
    "community_admin_required")?
  refused(save(accounts.bob_path, group_id, record(2, "[1]", [alice])?),
    "community_admin_required")?
  # An admin edits it but cannot change the roles.
  let promoted = record(2, "[]", [alice, bob])?
  save(accounts.alice_path, group_id, promoted)?
  post(accounts.alice_path, group_id, "bob helps now", [bob_box, linked_box])?
  ensure(Bytes.secure_equals(stored(accounts.bob_path, group_id)?, promoted),
    "promotion reaches the admin")?
  let edited = record(3, "[1]", [alice, bob])?
  save(accounts.bob_path, group_id, edited)?
  refused(save(accounts.bob_path, group_id, record(4, "[1]", [alice])?),
    "community_admin_required")?
  refused(save(accounts.bob_path, group_id, record(4, "[1]", [bob, alice])?),
    "community_admin_required")?
  post(accounts.bob_path,
    group_id,
    "edited",
    [(accounts.alice_path, accounts.alice_entry.mailbox_token), linked_box])?
  ensure(Bytes.secure_equals(stored(accounts.alice_path, group_id)?, edited),
    "the owner accepts an admin's edit")?
  # No admin removes the owner, even one of the owner's devices; the owner may.
  refused(group_remove_export(group_vectors([
      Bytes.from_utf8(accounts.bob_path),
      group_id,
      alice,
      accounts.linked_credential.device_id
    ])?),
    "community_admin_required")?
  let removal = output_list(group_remove_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    group_id,
    alice,
    accounts.linked_credential.device_id
  ])?)?)?
  deliver(accounts.alice_path, removal, [bob_box], 0)?
  # The owner hands the community over and keeps only what an admin may do.
  let handed = record(5, "[1]", [bob, alice])?
  save(accounts.alice_path, group_id, handed)?
  post(accounts.alice_path, group_id, "bob owns it now", [bob_box])?
  ensure(Bytes.secure_equals(stored(accounts.bob_path, group_id)?, handed),
    "the handover reaches the new owner")?
  refused(save(accounts.alice_path, group_id, record(6, "[1]", [alice, bob])?),
    "community_admin_required")?
  save(accounts.bob_path, group_id, record(6, "[1]", [bob])?)?
  # The creator is protected only while they own it; now the owner may remove them.
  let alice_device = decode_client_profile(load_profile(accounts.alice_path)?)?.device_id
  ensure(List.length(output_list(group_remove_export(group_vectors([
      Bytes.from_utf8(accounts.bob_path),
      group_id,
      alice,
      alice_device
    ])?)?)?) == 0,
    "removing the last other member leaves no one to tell")?
  # Leaving forgets the group on this device: its state, history and record go at once.
  group_forget_export(group_vectors([Bytes.from_utf8(accounts.alice_path), group_id])?)?
  ensure(List.length(output_list(group_list_export(Bytes.from_utf8(accounts.alice_path))?)?) == 0,
    "a forgotten group leaves the list")?
  ensure(Bytes.length(stored(accounts.alice_path, group_id)?) == 0,
    "a forgotten group's record is gone")?
  refused(group_history_export(group_vectors([Bytes.from_utf8(accounts.alice_path), group_id])?),
    "local_state_not_found")?
  File.delete(accounts.alice_path)?
  File.delete(accounts.linked_path)?
  File.delete(accounts.bob_path)?
  Ok(true)
end

test("community owners and admins alone change its members and record, and ownership can move") do
  case exercise() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
