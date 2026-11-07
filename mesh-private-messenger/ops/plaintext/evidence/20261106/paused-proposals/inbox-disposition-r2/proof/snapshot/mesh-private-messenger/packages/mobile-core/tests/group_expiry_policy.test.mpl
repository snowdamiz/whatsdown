from MobileCore import group_policy_export, group_forget_export
from Mobile.GroupPolicyWire import group_policy_label
from Storage.Keys import platform_key, seal_local, local_context
from Storage.Blobs import load_blob
from Storage.Records import store_updated_blobs
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleSupport import group_account_fixture
from Tests.GroupLifecycleWire import group_vectors, output_list
from Tests.Support import write_u32, repeated

fn policy_contract() -> Bool!String do
  if !Test.install_in_memory_secure_store() do
    return Err("fixture secure store")
  end
  let accounts = group_account_fixture()?
  let group = create_group_with_bob(accounts)?
  let input = group_vectors([Bytes.from_utf8(accounts.alice_path), group])?
  let read = output_list(group_policy_export(input)?)?
  if List.length(read) != 3 || !Bytes.secure_equals(List.get(read, 2), write_u32(0)?) do
    return Err("missing policy not permanent")
  end
  let set = group_vectors([Bytes.from_utf8(accounts.alice_path), group, write_u32(2592000)?])?
  let written = group_policy_export(set)?
  if !Bytes.secure_equals(group_policy_export(input)?, written) do
    return Err("group timer not durable")
  end
  # The local preference does not impose a policy on Bob's device.
  let other = output_list(group_policy_export(group_vectors([
    Bytes.from_utf8(accounts.bob_path),
    group
  ])?)?)?
  if !Bytes.secure_equals(List.get(other, 2), write_u32(0)?) do
    return Err("policy changed another device")
  end
  for bad in [write_u32(2592001)?, Bytes.empty(), repeated(1, 3)?] do
    if Result.is_ok(group_policy_export(group_vectors([
      Bytes.from_utf8(accounts.alice_path),
      group,
      bad
    ])?)) do
      return Err("invalid policy accepted")
    end
  end
  if !Bytes.secure_equals(group_policy_export(input)?, written) do
    return Err("invalid policy mutated state")
  end
  let key = platform_key()?
  let label = group_policy_label(group)?
  let corrupt = seal_local(Bytes.from_utf8("authenticated malformed policy"),
    key,
    local_context(label)?)?
  store_updated_blobs(accounts.alice_path, [label], [corrupt])?
  if Result.is_ok(group_policy_export(input))
    || !Bytes.secure_equals(load_blob(accounts.alice_path, label)?, corrupt) do
    return Err("corrupt policy not refused")
  end
  let _ = group_forget_export(input)?
  if load_blob(accounts.alice_path, label) != Err("local_state_not_found") do
    return Err("forgotten group retained timer")
  end
  if Result.is_ok(group_policy_export(input)) do
    return Err("forgotten group accepted policy")
  end
  Ok(true)
end

test("group timer is bounded device-local authenticated state and forgotten atomically") do
  case policy_contract() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
