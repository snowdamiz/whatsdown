import File
from Attachments.Protocol import attachment_padded_size
from Mobile.Backup import backup_restore_begin_at
from Mobile.Codec import mobile_wide, mobile_write_u64
from Mobile.GroupState import group_history_entries
from Mobile.History import decode_conversation_summary
from Mobile.Types import MobileGroupHistoryEntry
from Identity.Device import verify_device_revocation
from MobileCore import (
  account_deletion_export,
  backup_restore_account_export,
  backup_restore_identity_export,
  create_account_export,
  create_device_revocation_export,
  directory_entry_export,
  install_group_transparency_for_test,
  backup_begin_export,
  backup_confirm_export,
  backup_disable_export,
  backup_finish_export,
  backup_part_export,
  backup_prepare_export,
  backup_restore_begin_export,
  backup_restore_chunk_export,
  backup_restore_finish_export,
  backup_restore_slots_export,
  backup_status_export,
  group_send_export,
  list_conversations_export,
  load_history_export,
  load_profile_export,
  outbox_ack_export,
  presentation_load_export,
  presentation_save_export,
  receive_initial_export,
  receive_message_export,
  send_message_export,
  start_conversation_export,
  update_conversation_export
)
from Objects.Grant import decode_grant
from Protocol.DirectoryWire import (
  decode_device_revocation,
  decode_directory_entry,
  encode_device_set
)
from Protocol.IdentityWire import decode_account_identity, decode_device_credential
from Protocol.PrekeyWire import decode_prekey_bundle
from Protocol.V1 import DeviceSet, DirectoryEntry
from Tests.GroupConsistencySupport import signed_transparency_view
from Transparency.Merkle import leaf_hash
from Transport.Packet import decode_client_profile
from Storage.Keys import platform_key
from Tests.GroupConsistencySupport import request, wide
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleSupport import GroupAccountFixture, group_account_fixture
from Tests.GroupLifecycleWire import acknowledge, group_vectors, output_list
from Tests.Support import append, database_path, read_u32, write_u32

fn byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("test byte allocation failed")
    Ok(output)
  end
end

fn path_bytes(path :: String) -> Bytes do
  Bytes.from_utf8(path)
end

fn ack(path :: String, envelope :: Bytes) -> Result<(), String> do
  outbox_ack_export(request([path_bytes(path), envelope])?)?
  Ok(nil)
end

fn backup_state(path :: String) -> Int!String do
  let status = backup_status_export(request([path_bytes(path)])?)?
  Bytes.get(field(status, 0, 0)?, 0)
end

# The `index`th u32-length vector of a record, from `offset`.

fn field(input :: Bytes, index :: Int, offset :: Int) -> Bytes!String do
  let length = read_u32(Bytes.slice(input, offset, 4)?)?
  if index == 0 do
    Bytes.slice(input, offset + 4, length)
  else
    field(input, index - 1, offset + 4 + length)
  end
end

fn history_bodies(path :: String, peer_profile :: Bytes) -> List<String>!String do
  let entries = output_list(load_history_export(request([path_bytes(path), peer_profile])?)?)?
  let bodies = for entry in entries do
    Bytes.to_utf8(field(entry, 3, 0)?)?
  end
  Ok(bodies)
end

fn group_bodies(values :: List<MobileGroupHistoryEntry>) -> List<String>!String do
  let bodies = for value in values do
    Bytes.to_utf8(value.body)?
  end
  Ok(bodies)
end

fn same_strings(left :: List<String>, right :: List<String>) -> Bool do
  List.length(left) == List.length(right)
    && List.all(List.zip(left, right),
      fn(pair) do
        let (first, second) = pair
        first == second
      end)
end

# What the database file holds, as hex, to look for a value in it.

fn database_hex(path :: String) -> String!String do
  let main = File.read_bytes(path, 0, File.size(path)?)?
  let wal = path <> "-wal"
  if File.exists(wal) do
    Ok(Bytes.to_hex(main) <> Bytes.to_hex(File.read_bytes(wal, 0, File.size(wal)?)?))
  else
    Ok(Bytes.to_hex(main))
  end
end

# A direct conversation with bob: one message each way, then one with a timer,
# which a backup leaves out.

fn converse(accounts :: GroupAccountFixture) -> Bytes!String do
  let bob_profile = load_profile_export(path_bytes(accounts.bob_path))?
  let alice_profile = load_profile_export(path_bytes(accounts.alice_path))?
  let initial = start_conversation_export(request([
    path_bytes(accounts.alice_path),
    bob_profile,
    Bytes.from_utf8("hello bob")
  ])?)?
  ack(accounts.alice_path, initial)?
  receive_initial_export(request([path_bytes(accounts.bob_path), initial])?)?
  update_conversation_export(request([
    path_bytes(accounts.bob_path),
    alice_profile,
    byte(1)?,
    write_u32(0)?
  ])?)?
  let reply = send_message_export(request([
    path_bytes(accounts.bob_path),
    alice_profile,
    Bytes.from_utf8("hello alice")
  ])?)?
  ack(accounts.bob_path, reply)?
  receive_message_export(request([path_bytes(accounts.alice_path), reply])?)?
  update_conversation_export(request([
    path_bytes(accounts.alice_path),
    bob_profile,
    byte(5)?,
    write_u32(60)?
  ])?)?
  let timed = send_message_export(request([
    path_bytes(accounts.alice_path),
    bob_profile,
    Bytes.from_utf8("gone in a minute")
  ])?)?
  ack(accounts.alice_path, timed)?
  assert(same_strings(history_bodies(accounts.alice_path, bob_profile)?,
    ["hello bob", "hello alice", "gone in a minute"]))
  Ok(bob_profile)
end

fn upload_parts(path :: String,
  count :: Int,
  index :: Int,
  parts :: List<Bytes>) -> List<Bytes>!String do
  if index >= count do
    Ok(parts)
  else
    let part = backup_part_export(request([path_bytes(path), write_u32(index)?])?)?
    upload_parts(path, count, index + 1, List.append(parts, part))
  end
end

fn restore_parts(path :: String, parts :: List<Bytes>, index :: Int) -> Result<(), String> do
  if index >= List.length(parts) do
    Ok(nil)
  else
    backup_restore_chunk_export(request([
      path_bytes(path),
      write_u32(index - 1)?,
      List.get(parts, index)
    ])?)?
    restore_parts(path, parts, index + 1)
  end
end

# The store sees what an attachment of the same padded size shows it: part 0 of
# 514 bytes, whole chunks of 65,576, and the last chunk's share of the bucket.

fn assert_attachment_shape(parts :: List<Bytes>, plaintext_size :: Int) -> Bool!String do
  let padded = attachment_padded_size(plaintext_size)
  let chunks = (padded + 65535) / 65536
  assert(List.length(parts) == chunks + 1)
  assert(Bytes.length(List.head(parts)) == 514)
  assert(Bytes.secure_equals(Bytes.slice(List.head(parts), 0, 4)?,
    append(byte(1)?, Bytes.from_utf8("EAM"))?))
  let sizes = for index in 1..List.length(parts) do
    Bytes.length(List.get(parts, index))
  end
  assert(List.all(List.take(sizes, chunks - 1), fn(size) do size == 65576 end))
  assert(List.get(sizes, chunks - 1) == padded - (chunks - 1) * 65536 + 40)
  assert(Bytes.secure_equals(Bytes.slice(List.get(parts, 1), 0, 4)?,
    append(byte(1)?, Bytes.from_utf8("ACH"))?))
  Ok(true)
end

fn tampered(part :: Bytes) -> Bytes!String do
  let last = Bytes.length(part) - 1
  let flipped = if Bytes.get(part, last)? == 0 do
    1
  else
    0
  end
  append(Bytes.slice(part, 0, last)?, byte(flipped)?)
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let accounts = group_account_fixture()?
  let group_id = create_group_with_bob(accounts)?
  let greeting = output_list(group_send_export(group_vectors([
    path_bytes(accounts.alice_path),
    group_id,
    Bytes.from_utf8("hello group")
  ])?)?)?
  acknowledge(accounts.alice_path, greeting, 0)?
  let bob_profile = converse(accounts)?
  let nickname_key = Bytes.from_utf8("nickname/"
    <> Bytes.to_hex(decode_conversation_summary(list_conversations_export(path_bytes(accounts.alice_path))?)?.peer_account_id))
  let nickname = request([
    Bytes.from_utf8("Bobby"),
    Bytes.empty(),
    mobile_write_u64(mobile_wide("2")?)?
  ])?
  presentation_save_export(request([path_bytes(accounts.alice_path), nickname_key, nickname])?)?
  # Off until the code is confirmed; a wrong code confirms nothing.
  assert(backup_state(accounts.alice_path)? == 0)
  let code = backup_begin_export(request([path_bytes(accounts.alice_path)])?)?
  assert(Bytes.length(code) == 32)
  case backup_confirm_export(request([path_bytes(accounts.alice_path), tampered(code)?])?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "backup_code_mismatch")
  end
  backup_confirm_export(request([path_bytes(accounts.alice_path), code])?)?
  assert(backup_state(accounts.alice_path)? == 2)
  # The code itself is kept nowhere on the device.
  assert(!String.contains(database_hex(accounts.alice_path)?, Bytes.to_hex(code)))
  # A backup is an object the store cannot tell from an attachment.
  let app_state = Bytes.from_utf8("{\"theme\":\"dark\"}")
  let prepared = output_list(backup_prepare_export(request([
    path_bytes(accounts.alice_path),
    app_state,
    write_u32(1)?
  ])?)?)?
  let object_id = List.get(prepared, 0)
  let part_count = read_u32(List.get(prepared, 5))?
  let grant = decode_grant(List.get(prepared, 2))?
  assert(Bytes.secure_equals(grant.object_id, object_id))
  assert(grant.part_count == part_count)
  let parts = upload_parts(accounts.alice_path, part_count, 0, List.new())?
  let slots = output_list(backup_restore_slots_export(request([
    path_bytes(accounts.linked_path),
    code
  ])?)?)?
  let slot_ids = for slot in slots do
    Bytes.slice(slot, 0, 32)?
  end
  assert(List.any(slot_ids, fn(slot) do Bytes.secure_equals(slot, object_id) end))
  backup_finish_export(request([path_bytes(accounts.alice_path), byte(1)?])?)?
  # Restore on the linked device, which has none of this yet.
  case backup_restore_begin_export(request([
    path_bytes(accounts.linked_path),
    tampered(code)?,
    List.head(parts)
  ])?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "backup_code_mismatch")
  end
  case backup_restore_begin_at(accounts.linked_path, code, List.head(parts), grant.expires_at) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "backup_expired")
  end
  let chunk_count = read_u32(backup_restore_begin_export(request([
    path_bytes(accounts.linked_path),
    code,
    List.head(parts)
  ])?)?)?
  assert(chunk_count == part_count - 1)
  case backup_restore_chunk_export(request([
    path_bytes(accounts.linked_path),
    write_u32(0)?,
    tampered(List.get(parts, 1))?
  ])?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "backup_damaged")
  end
  restore_parts(accounts.linked_path, parts, 1)?
  let summary = backup_restore_finish_export(request([path_bytes(accounts.linked_path)])?)?
  assert(read_u32(field(summary, 0, 0)?)? == 1)
  assert(read_u32(field(summary, 1, 0)?)? == 1)
  assert(Bytes.secure_equals(field(summary, 3, 0)?, app_state))
  assert(assert_attachment_shape(parts, read_u32(field(summary, 4, 0)?)?)?)
  let restored = decode_conversation_summary(list_conversations_export(path_bytes(accounts.linked_path))?)?
  assert(restored.username == "bob")
  assert(same_strings(history_bodies(accounts.linked_path, bob_profile)?,
    ["hello bob", "hello alice"]))
  let wrapping_key = platform_key()?
  assert(same_strings(group_bodies(group_history_entries(accounts.linked_path,
      wrapping_key,
      group_id)?)?,
    group_bodies(group_history_entries(accounts.alice_path, wrapping_key, group_id)?)?))
  assert(List.length(group_history_entries(accounts.linked_path, wrapping_key, group_id)?) == 1)
  assert(Bytes.secure_equals(presentation_load_export(request([
      path_bytes(accounts.linked_path),
      nickname_key
    ])?)?,
    nickname))
  # Restoring twice adds nothing twice.
  backup_restore_begin_export(request([path_bytes(accounts.linked_path), code, List.head(parts)])?)?
  restore_parts(accounts.linked_path, parts, 1)?
  backup_restore_finish_export(request([path_bytes(accounts.linked_path)])?)?
  assert(same_strings(history_bodies(accounts.linked_path, bob_profile)?,
    ["hello bob", "hello alice"]))
  # Another account's device cannot take it.
  backup_restore_begin_export(request([path_bytes(accounts.bob_path), code, List.head(parts)])?)?
  restore_parts(accounts.bob_path, parts, 1)?
  case backup_restore_finish_export(request([path_bytes(accounts.bob_path)])?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "backup_account_mismatch")
  end
  # Turning backups off hands back the deletion of every object it made.
  let deletions = output_list(backup_disable_export(request([path_bytes(accounts.alice_path)])?)?)?
  assert(List.length(deletions) == 1)
  assert(Bytes.secure_equals(Bytes.slice(List.head(deletions), 4, 32)?, object_id))
  assert(backup_state(accounts.alice_path)? == 0)
  File.delete(accounts.alice_path)?
  File.delete(accounts.linked_path)?
  File.delete(accounts.bob_path)?
  Ok(true)
end

test("a backup restores conversations, history and groups on a linked device") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn entry_of(path :: String) -> DirectoryEntry!String do
  case decode_directory_entry(directory_entry_export(path_bytes(path))?) do
    Err(_) -> Err("directory entry decode failed")
    Ok(value)
  end
end

fn device_set(entries :: List<DirectoryEntry>, sequence :: Int) -> Bytes!String do
  case encode_device_set(DeviceSet {
    version: 1,
    username: "alice",
    account_identity: List.head(entries).account_identity,
    sequence: wide(sequence)?,
    devices: entries,
    revoked_device_ids: List.new()
  }) do
    Err(_) -> Err("device set encode failed")
    Ok(encoded)
  end
end

fn witnessed(path :: String, set :: Bytes) -> Result<(), String> do
  let view = signed_transparency_view([leaf_hash(set)?])?
  assert(install_group_transparency_for_test(path,
    view.checkpoint,
    view.service_public_key,
    view.witness_a_public_key,
    view.witness_b_public_key,
    set)?)
  Ok(nil)
end

fn backed_up(path :: String) -> Result<(Bytes, List<Bytes>), String> do
  let code = backup_begin_export(request([path_bytes(path)])?)?
  backup_confirm_export(request([path_bytes(path), code])?)?
  let prepared = output_list(backup_prepare_export(request([
    path_bytes(path),
    Bytes.from_utf8("{}"),
    write_u32(1)?
  ])?)?)?
  let parts = upload_parts(path, read_u32(List.get(prepared, 5))?, 0, List.new())?
  backup_finish_export(request([path_bytes(path), byte(1)?])?)?
  Ok((code, parts))
end

# Every device of the account is gone. A fresh install with nothing on it but
# the recovery code gets the account back: the backup's account key authorizes
# a new device at the next sequence of the set the key log shows, and the old
# devices can be taken out of the account from it.

fn account_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let alice_path = database_path("backup-account-alice")?
  let bob_path = database_path("backup-account-bob")?
  let restored_path = database_path("backup-account-restored")?
  create_account_export(request([path_bytes(alice_path), Bytes.from_utf8("alice")])?)?
  let bob_profile = create_account_export(request([path_bytes(bob_path), Bytes.from_utf8("bob")])?)?
  let alice_profile = load_profile_export(path_bytes(alice_path))?
  let initial = start_conversation_export(request([
    path_bytes(alice_path),
    bob_profile,
    Bytes.from_utf8("hello bob")
  ])?)?
  ack(alice_path, initial)?
  receive_initial_export(request([path_bytes(bob_path), initial])?)?
  update_conversation_export(request([
    path_bytes(bob_path),
    alice_profile,
    byte(1)?,
    write_u32(0)?
  ])?)?
  let reply = send_message_export(request([
    path_bytes(bob_path),
    alice_profile,
    Bytes.from_utf8("hello alice")
  ])?)?
  ack(bob_path, reply)?
  receive_message_export(request([path_bytes(alice_path), reply])?)?
  let alice_entry = entry_of(alice_path)?
  let old_set = device_set([alice_entry], 1)?
  let (code, parts) = backed_up(alice_path)?
  # The old phone is gone. Nothing of it is on the new install.
  backup_restore_begin_export(request([path_bytes(restored_path), code, List.head(parts)])?)?
  restore_parts(restored_path, parts, 1)?
  let identity = backup_restore_identity_export(request([path_bytes(restored_path)])?)?
  assert(Bytes.to_utf8(field(identity, 0, 0)?)? == "alice")
  assert(Bytes.secure_equals(field(identity, 1, 0)?,
    decode_client_profile(alice_profile)?.account_id))
  assert(Bytes.secure_equals(field(identity, 2, 0)?, byte(1)?))
  # Only a set the key log shows can be extended.
  case backup_restore_account_export(request([path_bytes(restored_path), old_set])?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "device_set_transparency_unverified")
  end
  witnessed(restored_path, old_set)?
  let summary = backup_restore_account_export(request([path_bytes(restored_path), old_set])?)?
  assert(read_u32(field(summary, 0, 0)?)? == 1)
  let restored_profile = load_profile_export(path_bytes(restored_path))?
  let restored = decode_client_profile(restored_profile)?
  let old = decode_client_profile(alice_profile)?
  assert(Bytes.secure_equals(restored.account_id, old.account_id))
  assert(!Bytes.secure_equals(restored.device_id, old.device_id))
  assert(U64.compare(restored.credential.directory_sequence, wide(2)?) == 0)
  # It holds the account key again, so it can delete the account or remove devices.
  assert(Bytes.length(account_deletion_export(path_bytes(restored_path))?) > 0)
  assert(!String.contains(database_hex(restored_path)?, Bytes.to_hex(code)))
  assert(same_strings(history_bodies(restored_path, bob_profile)?, ["hello bob", "hello alice"]))
  # Contacts reach the new device, and it answers.
  let welcome = start_conversation_export(request([
    path_bytes(bob_path),
    restored_profile,
    Bytes.from_utf8("welcome back")
  ])?)?
  ack(bob_path, welcome)?
  assert(Bytes.secure_equals(receive_initial_export(request([
      path_bytes(restored_path),
      welcome
    ])?)?,
    Bytes.from_utf8("welcome back")))
  let thanks = send_message_export(request([
    path_bytes(restored_path),
    bob_profile,
    Bytes.from_utf8("thanks")
  ])?)?
  ack(restored_path, thanks)?
  assert(Bytes.secure_equals(receive_message_export(request([path_bytes(bob_path), thanks])?)?,
    Bytes.from_utf8("thanks")))
  assert(same_strings(history_bodies(restored_path, bob_profile)?,
    ["hello bob", "hello alice", "welcome back", "thanks"]))
  # The lost phone can be taken out of the account from the restored device.
  let new_set = device_set([alice_entry, entry_of(restored_path)?], 2)?
  witnessed(restored_path, new_set)?
  let revocation_wire = create_device_revocation_export(request([
    path_bytes(restored_path),
    new_set,
    old.device_id
  ])?)?
  let revocation = case decode_device_revocation(revocation_wire) do
    Err(_) -> Err("revocation decode failed")
    Ok(value)
  end?
  assert(Bytes.secure_equals(revocation.device_id, old.device_id))
  let valid = case verify_device_revocation(old.account, revocation) do
    Err(_) -> Err("revocation verification failed")
    Ok(value)
  end?
  assert(valid)
  # A device that already has an account restores onto it instead.
  case backup_restore_account_export(request([path_bytes(bob_path), old_set])?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "account_already_exists")
  end
  File.delete(alice_path)?
  File.delete(bob_path)?
  File.delete(restored_path)?
  Ok(true)
end

test("an account whose every device is lost comes back from its backup") do
  case account_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
