from Protocol.V1 import DirectoryEntry, AccountIdentity
from Protocol.IdentityWire import decode_account_identity
from Mobile.Transparency import transparency_device_set_label
from Storage.Blobs import load_blob, put_blob
import File
from MobileCore import group_send_export, group_receive_export, outbox_list_export, process_delivery_batch_export
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleSupport import GroupAccountFixture, group_account_fixture
from Tests.GroupLifecycleWire import acknowledge, delivery_batch, group_vectors, output_list

fn send_until_refresh(accounts :: GroupAccountFixture, group_id :: Bytes, remaining :: Int) -> Result<(), String> do
  if remaining == 0 do
    Ok(nil)
  else
    let entries = output_list(group_send_export(group_vectors([
      Bytes.from_utf8(accounts.alice_path),
      group_id,
      Bytes.empty()
    ])?)?)?
    assert(List.length(entries) == 1)
    group_receive_export(group_vectors([Bytes.from_utf8(accounts.bob_path), List.head(entries)])?)?
    acknowledge(accounts.alice_path, entries, 0)?
    send_until_refresh(accounts, group_id, remaining - 1)
  end
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let accounts = group_account_fixture()?
  let group_id = create_group_with_bob(accounts)?
  let bob_identity = case decode_account_identity(accounts.bob_entry.account_identity) do
    Ok(value)
    Err(_) -> Err("test identity decode failed")
  end?
  let label = transparency_device_set_label(bob_identity.account_id)
  let saved = load_blob(accounts.alice_path, label)?
  let database = Sqlite.open(accounts.alice_path)?
  Sqlite.execute_values(database,
    "DELETE FROM encrypted_blobs WHERE record_hash = ?",
    [Text(Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(label))))])?
  Sqlite.close(database)
  case group_send_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    group_id,
    Bytes.from_utf8("must wait for authorization")
  ])?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "device_set_transparency_unverified")
  end
  assert(List.length(output_list(outbox_list_export(Bytes.from_utf8(accounts.alice_path))?)?) == 0)
  let restored = Sqlite.open(accounts.alice_path)?
  put_blob(restored, label, saved)?
  Sqlite.close(restored)
  send_until_refresh(accounts, group_id, 256)?
  let plaintext = Bytes.from_utf8("after bounded refresh")
  let entries = output_list(group_send_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    group_id,
    plaintext
  ])?)?)?
  assert(List.length(entries) == 2)
  let pending = output_list(outbox_list_export(Bytes.from_utf8(accounts.alice_path))?)?
  assert(List.length(pending) == 2)
  # Receiving the message first must not acknowledge it before the commit.
  let late = process_delivery_batch_export(group_vectors([
    Bytes.from_utf8(accounts.bob_path),
    delivery_batch(List.get(entries, 1))?
  ])?)?
  assert(Bytes.length(late) == 0)
  group_receive_export(group_vectors([Bytes.from_utf8(accounts.bob_path), List.head(entries)])?)?
  let opened = group_receive_export(group_vectors([
    Bytes.from_utf8(accounts.bob_path),
    List.get(entries, 1)
  ])?)?
  assert(Bytes.secure_equals(opened, plaintext))
  acknowledge(accounts.alice_path, entries, 0)?
  File.delete(accounts.alice_path)?
  File.delete(accounts.linked_path)?
  File.delete(accounts.bob_path)?
  Ok(true)
end

test("C3 C5 group refresh commits its epoch and message outbox together after 256 sends") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
