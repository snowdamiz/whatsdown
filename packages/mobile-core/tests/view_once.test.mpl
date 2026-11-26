import File
from Mobile.GroupState import group_history_entries
from Mobile.History import decode_conversation_summary, history_entries_for
from Mobile.Types import ConversationSummary, MobileGroupHistoryEntry, MobileHistoryEntry
from MobileCore import (
  create_account_export,
  directory_entry_export,
  group_history_export,
  group_open_view_once_export,
  group_receive_export,
  group_send_view_once_export,
  list_conversations_export,
  load_history_export,
  open_view_once_export,
  receive_initial_export,
  receive_message_export,
  send_view_once_export,
  start_conversation_export,
  update_conversation_export
)
from Prekeys.Bundle import normalize_prekey_bundle
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set
from Protocol.IdentityWire import decode_account_identity
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import AccountIdentity, DeviceSet, DirectoryEntry, InnerEnvelope, PrekeyBundle
from Storage.Keys import platform_key
from Tests.GroupConsistencySupport import signed_transparency_view
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleSupport import group_account_fixture, install_signed_transparency
from Tests.GroupLifecycleWire import acknowledge, envelope_for, group_vectors, output_list
from Tests.Support import database_path, write_u32
from Transparency.Merkle import leaf_hash

fn ensure(value :: Bool, error :: String) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err(error)
  end
end

fn byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("test byte allocation failed")
    Ok(output)
  end
end

fn text(value :: String) -> Bytes do
  Bytes.from_utf8(value)
end

# A direct history summary is a run of vectors: direction, message ID, time,
# body, timer, attachments, delivery state, kind.

fn fields(input :: Bytes, offset :: Int, output :: List<Bytes>) -> List<Bytes>!String do
  if offset >= Bytes.length(input) do
    Ok(output)
  else
    let length = case Bytes.read_u32_be(input, offset) do
      Err(_) -> Err("summary decode failed")
      Ok(value) -> case U64.to_int(value) do
        Err(_) -> Err("summary decode failed")
        Ok(number)
      end
    end?
    fields(input, offset + 4 + length, List.append(output, Bytes.slice(input, offset + 4, length)?))
  end
end

fn direct_rows(path :: String, peer :: Bytes) -> List<List<Bytes>>!String do
  let rows = output_list(load_history_export(group_vectors([text(path), peer])?)?)?
  Ok(for row in rows do
    fields(row, 0, [])?
  end)
end

fn last(values :: List<List<Bytes>>) -> List<Bytes>!String do
  ensure(List.length(values) > 0, "history is empty")?
  Ok(List.get(values, List.length(values) - 1))
end

fn directory_set(username :: String, entry :: DirectoryEntry) -> Bytes!String do
  let account = case decode_account_identity(entry.account_identity) do
    Err(_) -> Err("account identity decode failed")
    Ok(value)
  end?
  case encode_device_set(DeviceSet {
    version: 1,
    username: username,
    account_identity: entry.account_identity,
    sequence: account.directory_sequence,
    devices: [entry],
    revoked_device_ids: []
  }) do
    Err(_) -> Err("device set encode failed")
    Ok(value)
  end
end

# Device sets list each device with its base bundle, without a one-time prekey.

fn entry_of(path :: String) -> DirectoryEntry!String do
  let entry = case decode_directory_entry(directory_entry_export(text(path))?) do
    Err(_) -> Err("directory entry decode failed")
    Ok(value)
  end?
  let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
    Err(_) -> Err("prekey bundle decode failed")
    Ok(value)
  end?
  let base = case normalize_prekey_bundle(bundle) do
    Err(_) -> Err("prekey bundle normalization failed")
    Ok(value)
  end?
  case encode_prekey_bundle(base) do
    Err(_) -> Err("prekey bundle encode failed")
    Ok(encoded) -> Ok(%{entry | prekey_bundle: encoded})
  end
end

fn direct_proof() -> Bool!String do
  let alice_path = database_path("view-once-alice")?
  let bob_path = database_path("view-once-bob")?
  let alice_profile = create_account_export(group_vectors([text(alice_path), text("alice")])?)?
  let bob_profile = create_account_export(group_vectors([text(bob_path), text("bob")])?)?
  let initial = start_conversation_export(group_vectors([
    text(alice_path),
    bob_profile,
    text("hello bob")
  ])?)?
  acknowledge(alice_path, [initial], 0)?
  receive_initial_export(group_vectors([text(bob_path), initial])?)?
  update_conversation_export(group_vectors([
    text(bob_path),
    alice_profile,
    byte(1)?,
    write_u32(0)?
  ])?)?
  let alice_set = directory_set("alice", entry_of(alice_path)?)?
  let bob_set = directory_set("bob", entry_of(bob_path)?)?
  let view = signed_transparency_view([leaf_hash(alice_set)?, leaf_hash(bob_set)?])?
  install_signed_transparency(alice_path, view, bob_set)?
  install_signed_transparency(alice_path, view, alice_set)?
  let sent = output_list(send_view_once_export(group_vectors([
    text(alice_path),
    bob_set,
    alice_set,
    text("look once")
  ])?)?)?
  ensure(List.length(sent) == 1, "a view-once message went to more than the peer")?
  acknowledge(alice_path, sent, 0)?
  # The sender keeps a stub: kind 2, no content.
  let stub = last(direct_rows(alice_path, bob_profile)?)?
  ensure(List.length(stub) == 8
      && Bytes.secure_equals(List.get(stub, 7), byte(2)?)
      && Bytes.length(List.get(stub, 3)) == 0,
    "the sender kept a view-once message's content")?
  receive_message_export(group_vectors([text(bob_path), List.head(sent)])?)?
  let listed = last(direct_rows(bob_path, alice_profile)?)?
  ensure(Bytes.secure_equals(List.get(listed, 7), byte(1)?)
      && Bytes.length(List.get(listed, 3)) == 0,
    "an unopened view-once message was listed with its content")?
  let message_id = List.get(listed, 1)
  let opened = fields(open_view_once_export(group_vectors([
      text(bob_path),
      alice_profile,
      message_id
    ])?)?,
    0,
    [])?
  ensure(Bytes.secure_equals(List.get(opened, 3), text("look once")),
    "opening showed the wrong content")?
  case open_view_once_export(group_vectors([text(bob_path), alice_profile, message_id])?) do
    Ok(_) -> Err("a view-once message opened twice")?
    Err(error) -> ensure(error == "view_once_unavailable", "wrong second-open error: " <> error)?
  end
  let reopened = last(direct_rows(bob_path, alice_profile)?)?
  ensure(Bytes.secure_equals(List.get(reopened, 7), byte(2)?),
    "an opened message still reads as unopened")?
  let chat = decode_conversation_summary(list_conversations_export(text(bob_path))?)?
  let key = platform_key()?
  let stored = history_entries_for(bob_path, key, chat.conversation_id)?
  ensure(!List.any(stored,
      fn(entry) do Bytes.secure_equals(entry.inner.body, text("look once")) end),
    "the opened content stayed in storage")?
  File.delete(alice_path)?
  File.delete(bob_path)?
  Ok(true)
end

fn group_rows(path :: String, group_id :: Bytes) -> List<List<Bytes>>!String do
  let rows = output_list(group_history_export(group_vectors([text(path), group_id])?)?)?
  Ok(for row in rows do
    output_list(row)?
  end)
end

fn group_proof() -> Bool!String do
  let accounts = group_account_fixture()?
  let group_id = create_group_with_bob(accounts)?
  let sent = output_list(group_send_view_once_export(group_vectors([
    text(accounts.alice_path),
    group_id,
    text("group secret")
  ])?)?)?
  acknowledge(accounts.alice_path, sent, 0)?
  let stub = last(group_rows(accounts.alice_path, group_id)?)?
  ensure(Bytes.secure_equals(List.get(stub, 11), byte(2)?) && Bytes.length(List.get(stub, 6)) == 0,
    "the group sender kept a view-once message's content")?
  let shown = group_receive_export(group_vectors([
    text(accounts.bob_path),
    envelope_for(sent, accounts.bob_entry.mailbox_token, 0)?
  ])?)?
  ensure(Bytes.length(shown) == 0, "receiving a view-once message returned its content")?
  let listed = last(group_rows(accounts.bob_path, group_id)?)?
  ensure(Bytes.secure_equals(List.get(listed, 11), byte(1)?)
      && Bytes.length(List.get(listed, 6)) == 0,
    "an unopened group view-once message was listed with its content")?
  let message_id = List.get(listed, 8)
  let opened = output_list(group_open_view_once_export(group_vectors([
    text(accounts.bob_path),
    group_id,
    message_id
  ])?)?)?
  ensure(Bytes.secure_equals(List.get(opened, 6), text("group secret")),
    "opening the group message showed the wrong content")?
  case group_open_view_once_export(group_vectors([
    text(accounts.bob_path),
    group_id,
    message_id
  ])?) do
    Ok(_) -> Err("a group view-once message opened twice")?
    Err(error) -> ensure(error == "view_once_unavailable", "wrong second-open error: " <> error)?
  end
  let key = platform_key()?
  let stored = group_history_entries(accounts.bob_path, key, group_id)?
  ensure(!List.any(stored, fn(entry) do Bytes.secure_equals(entry.body, text("group secret")) end),
    "the opened group content stayed in storage")?
  case group_send_view_once_export(group_vectors([
    text(accounts.alice_path),
    group_id,
    Bytes.empty()
  ])?) do
    Ok(_) -> Err("an empty view-once message was sent")?
    Err(error) -> ensure(error == "invalid_view_once", "wrong empty view-once error: " <> error)?
  end
  File.delete(accounts.alice_path)?
  File.delete(accounts.linked_path)?
  File.delete(accounts.bob_path)?
  Ok(true)
end

test("a direct view-once message opens once and leaves no copy behind") do
  assert(Test.install_in_memory_secure_store())
  case direct_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("a group view-once message opens once and the sender keeps only a stub") do
  assert(Test.install_in_memory_secure_store())
  case group_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
