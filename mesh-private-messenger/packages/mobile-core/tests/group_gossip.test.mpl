from Tests.HistoryFixture import fixture_group_history
from MobileCore import (
  group_send_export,
  group_receive_export,
  group_add_export,
  group_key_package_export,
  outbox_list_export,
  install_group_transparency_for_test,
  transparency_fork_export
)
from Mobile.Codec import current_time
from Protocol.V1 import DirectoryEntry, AccountIdentity
from Mobile.Transparency import transparency_device_set_label
from Storage.Blobs import load_blob
from Storage.Records import with_record_transaction, delete_blob, store_updated_session
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleSupport import group_account_fixture
from Tests.GroupLifecycleWire import output_list, group_vectors, acknowledge, envelope_for
from Tests.Support import repeated
from Transparency.Merkle import sign_checkpoint, consistency_proof, leaf_hash
from Transparency.Wire import encode_checkpoint, encode_consistency_proof

fn control(path :: String,
  target :: Bytes,
  spectator_path :: String,
  spectator :: Bytes) -> Bytes!String do
  let encoded = outbox_list_export(Bytes.from_utf8(path))?
  let queued = output_list(encoded)?
  let expected = if spectator_path == "" do
    1
  else
    2
  end
  assert(List.length(queued) == expected)
  assert(Bytes.secure_equals(encoded, outbox_list_export(Bytes.from_utf8(path))?))
  if spectator_path != "" do
    assert(Bytes.length(deliver(spectator_path, envelope_for(queued, spectator, 0)?)?) == 0)
    assert(List.length(output_list(outbox_list_export(Bytes.from_utf8(spectator_path))?)?) == 0)
    assert(Bytes.length(transparency_fork_export(Bytes.from_utf8(spectator_path))?) == 0)
  end
  acknowledge(path, queued, 0)?
  envelope_for(queued, target, 0)
end

fn deliver(path :: String, envelope :: Bytes) -> Bytes!String do
  group_receive_export(group_vectors([Bytes.from_utf8(path), envelope])?)
end

fn proof(include_linked :: Bool) -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let accounts = group_account_fixture()?
  let group = create_group_with_bob(accounts)?
  if include_linked do
    let added = output_list(group_add_export(group_vectors([
      Bytes.from_utf8(accounts.alice_path),
      group,
      accounts.alice_set,
      group_key_package_export(Bytes.from_utf8(accounts.linked_path))?
    ])?)?)?
    deliver(accounts.bob_path, envelope_for(added, accounts.bob_entry.mailbox_token, 0)?)?
    deliver(accounts.linked_path, envelope_for(added, accounts.linked_entry.mailbox_token, 0)?)?
    acknowledge(accounts.alice_path, added, 0)?
  end
  let signer = case Crypto.signing_generate() do
    Err(_) -> return Err("fixture signer failed")
    Ok(value) -> value
  end
  let now = current_time()?
  for (path, marker) in [
    (accounts.alice_path, 7),
    (accounts.bob_path, 8),
    (accounts.linked_path, 7)
  ] do
    let leaves = [
      leaf_hash(accounts.alice_set)?,
      leaf_hash(accounts.bob_set)?,
      repeated(marker, 32)?
    ]
    let checkpoint = encode_checkpoint(sign_checkpoint(signer.private_key,
      signer.public_key.bytes,
      U64.parse("8")?,
      leaves,
      repeated(0, 32)?,
      now)?)?
    for devices in [accounts.alice_set, accounts.bob_set] do
      assert(install_group_transparency_for_test(path,
        checkpoint,
        encode_consistency_proof(consistency_proof([], leaves)?)?,
        signer.public_key.bytes,
        repeated(31, 32)?,
        repeated(32, 32)?,
        devices)?)
    end
  end
  let deliveries = output_list(group_send_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    group,
    Bytes.from_utf8("compare group views")
  ])?)?)?
  acknowledge(accounts.alice_path, deliveries, 0)?
  assert(Bytes.to_utf8(deliver(accounts.bob_path,
    envelope_for(deliveries, accounts.bob_entry.mailbox_token, 0)?)?)? == "compare group views")
  if include_linked do
    assert(Bytes.to_utf8(deliver(accounts.linked_path,
      envelope_for(deliveries,
        accounts.linked_entry.mailbox_token,
        0)?)?)? == "compare group views")
  end
  let spectator = if include_linked do
    accounts.linked_path
  else
    ""
  end
  # Missing cached delivery material must leave the encrypted control pending
  # without making the ordinary outbox unreadable. Refresh restores its route.
  let recipient_label = transparency_device_set_label(accounts.alice_account.account_id)
  let cached_recipient = load_blob(accounts.bob_path, recipient_label)?
  with_record_transaction(accounts.bob_path,
    fn(database) do delete_blob(database, recipient_label) end)?
  assert(List.length(output_list(outbox_list_export(Bytes.from_utf8(accounts.bob_path))?)?) == 0)
  store_updated_session(accounts.bob_path, recipient_label, cached_recipient)?
  assert(Bytes.length(deliver(accounts.alice_path,
    control(accounts.bob_path,
      accounts.alice_entry.mailbox_token,
      spectator,
      accounts.linked_entry.mailbox_token)?)?) == 0)
  assert(Bytes.length(deliver(accounts.bob_path,
    control(accounts.alice_path,
      accounts.bob_entry.mailbox_token,
      spectator,
      accounts.linked_entry.mailbox_token)?)?) == 0)
  assert(Bytes.length(deliver(accounts.alice_path,
    control(accounts.bob_path,
      accounts.alice_entry.mailbox_token,
      spectator,
      accounts.linked_entry.mailbox_token)?)?) == 0)
  for path in [accounts.alice_path, accounts.bob_path] do
    assert(Bytes.length(transparency_fork_export(Bytes.from_utf8(path))?) > 0)
    assert(List.length(output_list(fixture_group_history(group_vectors([
      Bytes.from_utf8(path),
      group
    ])?)?)?) == 1)
    assert(List.length(output_list(outbox_list_export(Bytes.from_utf8(path))?)?) == 0)
  end
  # Existing group encryption remains available after signed evidence pauses new trust.
  let continued = output_list(group_send_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    group,
    Bytes.from_utf8("still here")
  ])?)?)?
  assert(Bytes.to_utf8(deliver(accounts.bob_path,
    envelope_for(continued, accounts.bob_entry.mailbox_token, 0)?)?)? == "still here")
  if include_linked do
    assert(Bytes.to_utf8(deliver(accounts.linked_path,
      envelope_for(continued, accounts.linked_entry.mailbox_token, 0)?)?)? == "still here")
    assert(List.length(output_list(fixture_group_history(group_vectors([
      Bytes.from_utf8(accounts.linked_path),
      group
    ])?)?)?) == 2)
  end
  File.delete(accounts.alice_path)?
  File.delete(accounts.bob_path)?
  File.delete(accounts.linked_path)?
  Ok(true)
end

test("group members exchange signed fork evidence without a direct session or visible controls") do
  case proof(false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("other group devices advance their ratchets without answering controls addressed elsewhere") do
  case proof(true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
