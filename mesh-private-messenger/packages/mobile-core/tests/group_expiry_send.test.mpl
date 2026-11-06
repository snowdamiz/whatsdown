from MobileCore import group_send_export
from Storage.Keys import platform_key, seal_local, local_context
from Storage.Records import store_updated_blobs
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleSupport import group_account_fixture
from Tests.GroupLifecycleWire import group_vectors, output_list
from Tests.HistoryFixture import fixture_group_history
from Tests.Support import append, repeated, write_u32

fn seeded_timer_is_authenticated() -> Bool!String do
  if !Test.install_in_memory_secure_store() do
    return Err("fixture secure store")
  end
  let accounts = group_account_fixture()?
  let group = create_group_with_bob(accounts)?
  let key = platform_key()?
  let label = "group-disappearing/v1/#{Bytes.to_hex(group)}"
  let policy = append(repeated(1, 1)?, write_u32(60)?)?
  store_updated_blobs(accounts.alice_path,
    [label],
    [seal_local(policy, key, local_context(label)?)?])?
  let _ = group_send_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    group,
    Bytes.from_utf8("timed group fixture")
  ])?)?
  let entries = output_list(fixture_group_history(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    group
  ])?)?)?
  let entry = output_list(List.head(entries))?
  Ok(List.length(entry) == 11
    && Bytes.secure_equals(List.head(entry), repeated(2, 1)?)
    && Bytes.secure_equals(List.get(entry, 10), write_u32(60)?))
end

test("sealed local group timer is authenticated inside the sent message") do
  case seeded_timer_is_authenticated() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
