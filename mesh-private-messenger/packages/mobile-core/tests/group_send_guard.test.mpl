from Storage.Blobs import ensure_schema, load_blob
from Storage.Records import store_updated_blobs, store_record_changes, erase_local_state
from Storage.GroupRecords import store_group_message_outbound_guarded
from Storage.FanoutCommit import capture_fanout_snapshot, FanoutSnapshot
from Storage.OutboxGuard import OutboxBasis, PreparedOutboxIndex
from Tests.Support import database_path

fn commit(path :: String, profile :: Bytes, before :: FanoutSnapshot) -> Unit!String do
  store_group_message_outbound_guarded(path,
    "group-state/v1/test",
    Bytes.from_utf8("prepared group ratchet"),
    ["group-history/v1/test"],
    [Bytes.from_utf8("prepared history")],
    ["outbox-envelope/v1/group-test"],
    [Bytes.from_utf8("prepared attachment envelope")],
    PreparedOutboxIndex {
      value: Bytes.from_utf8("prepared index"),
      before: OutboxBasis {
        profile: profile,
        index: Bytes.empty(),
        postage: Bytes.empty(),
        delivery: Bytes.empty()
      }
    },
    before)
end

fn changed_source(label :: String) -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("group_attachment_guard")?
  ensure_schema(path)?
  let profile = Bytes.from_utf8("sealed group sender profile")
  let old = Bytes.from_utf8("old sealed source")
  let next = Bytes.from_utf8("new sealed source")
  store_updated_blobs(path, ["profile/v1", label], [profile, old])?
  let before = capture_fanout_snapshot(path,
    profile,
    ["group-state/v1/test", "group-history/v1/test", label])?
  # A receive, roster refresh or presentation change need not touch the outbox.
  store_updated_blobs(path, [label], [next])?
  assert(Result.is_err(commit(path, profile, before)))
  assert(Bytes.secure_equals(load_blob(path, label)?, next))
  assert(Result.is_err(load_blob(path, "outbox-envelope/v1/group-test")))
  assert(Result.is_err(load_blob(path, "outbox/v1")))
  erase_local_state(path)?
  File.delete(path)?
  Ok(nil)
end

test("group attachment commit rejects changed recipient, history and presentation even with an unchanged outbox") do
  for label in [
    "transparency-device-set/v1/peer",
    "device-set/v1/peer",
    "presentation/v1/group/test",
    "presentation/v1/user/test",
    "transparency-checkpoint/v1",
    "transparency-witnesses/v2"
  ] do
    assert(changed_source(label) == Ok(nil))
  end
end

fn changed_group_and_absence() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("group_attachment_absence_guard")?
  ensure_schema(path)?
  let profile = Bytes.from_utf8("sealed group sender")
  let old = Bytes.from_utf8("old group state")
  let next = Bytes.from_utf8("received group state")
  store_updated_blobs(path, ["profile/v1", "group-state/v1/test"], [profile, old])?
  let labels = ["group-state/v1/test", "group-history/v1/test"]
    ++ for index in 0..75 do
      "transparency-device-set/v1/#{index}"
    end
  let before = capture_fanout_snapshot(path, profile, labels)?
  assert(List.length(before.bases) == 2)
  store_updated_blobs(path, [List.get(labels, 76)], [Bytes.from_utf8("linked device appeared")])?
  assert(Result.is_err(commit(path, profile, before)))
  assert(Bytes.secure_equals(load_blob(path, "group-state/v1/test")?, old))
  let current = capture_fanout_snapshot(path, profile, labels)?
  store_updated_blobs(path, ["group-state/v1/test"], [next])?
  assert(Result.is_err(commit(path, profile, current)))
  assert(Bytes.secure_equals(load_blob(path, "group-state/v1/test")?, next))
  assert(Result.is_err(load_blob(path, "group-history/v1/test")))
  assert(Result.is_err(load_blob(path, "outbox-envelope/v1/group-test")))
  let fresh = capture_fanout_snapshot(path, profile, labels)?
  commit(path, profile, fresh)?
  assert(Bytes.to_utf8(load_blob(path, "group-state/v1/test")?)? == "prepared group ratchet")
  assert(Bytes.to_utf8(load_blob(path,
    "outbox-envelope/v1/group-test")?)? == "prepared attachment envelope")
  erase_local_state(path)?
  File.delete(path)?
  Ok(nil)
end

test("group attachment guards preserve changed group state and absent sources beyond64 rows, then accept a fresh plan") do
  assert(changed_group_and_absence() == Ok(nil))
end

from Protocol.IdentityWire import decode_account_identity
from Mobile.Groups import capture_group_attachment_send
from MobileCore import attachment_prepare_export, group_send_export
from Tests.GroupLifecycleSupport import group_account_fixture
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleWire import group_vectors, output_list
from Tests.Support import write_u32

fn actual_group_sources() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let accounts = group_account_fixture()?
  let group = create_group_with_bob(accounts)?
  let before = capture_group_attachment_send(accounts.alice_path, group)?
  let labels = List.flatten(for basis in before.bases do
    basis.labels
  end)
  for label in [
    "group-state/v1/#{Bytes.to_hex(group)}",
    "group-history/v1/#{Bytes.to_hex(group)}",
    "group-baseline/v1/#{Bytes.to_hex(group)}",
    "presentation/v1/group/#{Bytes.to_hex(group)}",
    "presentation/v1/user/#{Bytes.to_hex(accounts.alice_account.account_id)}",
    "transparency-device-set/v1/#{Bytes.to_hex(accounts.alice_account.account_id)}"
  ] do
    assert(List.contains(labels, label))
  end
  # The remote account is discovered from the authenticated group tree,
  # never from a caller-provided recipient list or capability bit.
  let bob = case decode_account_identity(accounts.bob_entry.account_identity) do
    Err(_) -> return Err("invalid_fixture_bob")
    Ok(value) -> value
  end
  assert(List.contains(labels, "transparency-device-set/v1/#{Bytes.to_hex(bob.account_id)}"))
  let material = output_list(attachment_prepare_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    Bytes.from_utf8("guarded.txt"),
    Bytes.from_utf8("text/plain"),
    write_u32(1)?,
    write_u32(1)?
  ])?)?)?
  let envelopes = output_list(group_send_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    group,
    Bytes.from_utf8("guarded attachment"),
    List.head(material)
  ])?)?)?
  assert(List.length(envelopes) > 0)
  File.delete(accounts.alice_path)?
  File.delete(accounts.bob_path)?
  File.delete(accounts.linked_path)?
  Ok(nil)
end

test("actual capable group captures every authorization source and sends under the atomic guard") do
  assert(actual_group_sources() == Ok(nil))
end

from Mobile.GroupState import group_state_label, group_history_label

fn same_record(left :: Result<Bytes, String>, right :: Result<Bytes, String>) -> Bool do
  case left do
    Err(error) -> right == Err(error)
    Ok(first) -> case right do
      Err(_) -> false
      Ok(second) -> Bytes.secure_equals(first, second)
    end
  end
end

fn orphan_send_refuses() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let accounts = group_account_fixture()?
  let group = create_group_with_bob(accounts)?
  let path = accounts.alice_path
  let index = load_blob(path, "groups/v1")?
  # The ratchet is genuine and retained; only the original membership index
  # is absent, as after forget followed by an old stale membership writer.
  store_record_changes(path, [], [], ["groups/v1"])?
  let labels = [
    "profile/v1",
    "groups/v1",
    group_state_label(group)?,
    group_history_label(group),
    "group-disappearing/v1/#{Bytes.to_hex(group)}",
    "presentation/v1/group/#{Bytes.to_hex(group)}",
    "presentation/v1/user/#{Bytes.to_hex(accounts.alice_account.account_id)}",
    "outbox/v1",
    "delivery/v1",
    "postage-queue/v1"
  ]
  let before = for label in labels do
    load_blob(path, label)
  end
  let request = group_vectors([
    Bytes.from_utf8(path),
    group,
    Bytes.from_utf8("synthetic retained-state send")
  ])?
  if group_send_export(request) != Err("group_not_found") do
    return Err("orphan group send accepted")
  end
  for offset in 0..List.length(labels) do
    if !same_record(List.get(before, offset), load_blob(path, List.get(labels, offset))) do
      return Err("orphan group send changed a source or outbox row")
    end
  end
  # Restore exactly the original index; the same prepared native request now
  # succeeds, proving the refusal did not corrupt the group or spend a ratchet.
  store_updated_blobs(path, ["groups/v1"], [index])?
  let envelopes = output_list(group_send_export(request)?)?
  if List.length(envelopes) == 0 do
    return Err("indexed group send did not produce delivery")
  end
  File.delete(accounts.alice_path)?
  File.delete(accounts.bob_path)?
  File.delete(accounts.linked_path)?
  Ok(nil)
end

test("orphan group send refuses without writes and restoring its exact index permits the same request") do
  case orphan_send_refuses() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
