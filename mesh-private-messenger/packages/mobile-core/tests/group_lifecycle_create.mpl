from MobileCore import (
  group_add_export,
  group_create_export,
  group_inspect_export,
  group_key_package_export,
  group_list_export,
  group_receive_export,
  outbox_list_export
)
from Protocol.V1 import AccountIdentity, OuterEnvelope
from Tests.GroupConsistencySupport import SignedTransparencyViewFixture
from Tests.GroupLifecycleSupport import GroupAccountFixture, install_group_lifecycle_transparency, install_signed_transparency
from Tests.GroupLifecycleWire import acknowledge, assert_group_transport, group_vectors, outer, output_list, read_u32_at
from Tests.Support import repeated

fn group_create_ensure(value :: Bool, error :: String) -> Result <(), String > do
  if value do
    Ok(nil)
  else
    Err(error)
  end
end

fn assert_group_summary(alice_path :: Bytes, group_id :: Bytes) -> Bool ! String do
  let listed_wire = group_list_export(alice_path) ?
  let listed = output_list(listed_wire) ?
  group_create_ensure(List.length(listed) == 1, "created group list mismatch") ?
  let created_summary = output_list(List.head(listed)) ?
  group_create_ensure(Bytes.secure_equals(List.get(created_summary, 1), group_id),
  "created group id mismatch") ?
  group_create_ensure(read_u32_at(List.get(created_summary, 3), 0) ? == 1,
  "created group member count mismatch") ?
  Ok(true)
end

fn assert_group_creator(alice_path :: Bytes, group_id :: Bytes) -> Bool ! String do
  case group_vectors([alice_path, group_id]) do
    Err( error) -> Err(error)
    Ok( inspect_request) -> case group_inspect_export(inspect_request) do
      Err( error) -> Err(error)
      Ok( inspect_wire) -> case output_list(inspect_wire) do
        Err( error) -> Err(error)
        Ok( created_inspect) -> do
          group_create_ensure(Bytes.secure_equals(List.get(created_inspect, 1), group_id),
          "inspected group id mismatch") ?
          case output_list(List.get(created_inspect, 6)) do
            Err( error) -> Err(error)
            Ok( created_members) -> do
              group_create_ensure(List.length(created_members) == 1, "created group tree mismatch") ?
              case output_list(List.head(created_members)) do
                Err( error) -> Err(error)
                Ok( first_member) -> case Bytes.from_list([1]) do
                  Err( _) -> Err("creator marker encoding failed")
                  Ok( creator_marker) -> do
                    group_create_ensure(Bytes.secure_equals(List.get(first_member, 2),
                    creator_marker),
                    "creator marker mismatch") ?
                    group_create_ensure(List.length(first_member) == 8,
                    "missing verified member username") ?
                    group_create_ensure(Bytes.secure_equals(List.get(first_member, 7),
                    Bytes.from_utf8("alice")),
                    "member username must come from the verified identity") ?
                    Ok(true)
                  end
                end
              end
            end
          end
        end
      end
    end
  end
end

fn assert_created_group(accounts :: GroupAccountFixture, group_id :: Bytes) -> Bool ! String do
  let alice_path = Bytes.from_utf8(accounts.alice_path)
  group_create_ensure(assert_group_summary(alice_path, group_id) ?, "group summary check failed") ?
  group_create_ensure(assert_group_creator(alice_path, group_id) ?, "group creator check failed") ?
  Ok(true)
end

fn bob_package_for_group(accounts :: GroupAccountFixture, group_id :: Bytes) -> Bytes ! String do
  let bob_package = group_key_package_export(Bytes.from_utf8(accounts.bob_path)) ?
  group_create_ensure(Bytes.length(bob_package) == 369, "group key package length mismatch") ?
  group_create_ensure(Bytes.secure_equals(bob_package,
  group_key_package_export(Bytes.from_utf8(accounts.bob_path)) ?),
  "group key package was not stable") ?
  case group_add_export(group_vectors([Bytes.from_utf8(accounts.alice_path), group_id, repeated(0,
  305260) ?, repeated(0, 369) ?]) ?) do
    Ok( _) -> Err("invalid device set was accepted") ?
    Err( error) -> group_create_ensure(error == "invalid_device_set",
    "wrong invalid device set error") ?
  end
  case group_add_export(group_vectors([Bytes.from_utf8(accounts.alice_path), group_id, repeated(0,
  305261) ?, repeated(0, 369) ?]) ?) do
    Ok( _) -> Err("oversized device set was accepted") ?
    Err( error) -> group_create_ensure(error == "invalid_group_request",
    "wrong oversized device set error") ?
  end
  case group_add_export(group_vectors([Bytes.from_utf8(accounts.alice_path), group_id, accounts.bob_set, bob_package]) ?) do
    Ok( _) -> Err("uncached group device set was accepted") ?
    Err( error) -> group_create_ensure(error == "group_transparency_unverified",
    "wrong uncached device set error") ?
  end
  Ok(bob_package)
end

fn add_bob_to_group(accounts :: GroupAccountFixture,
transparency :: SignedTransparencyViewFixture,
group_id :: Bytes,
bob_package :: Bytes) -> Bool ! String do
  let bob_cache = install_signed_transparency(accounts.alice_path, transparency, accounts.bob_set) ?
  group_create_ensure(bob_cache, "bob transparency cache failed") ?
  let bob_welcome_output = group_add_export(group_vectors([Bytes.from_utf8(accounts.alice_path), group_id, accounts.bob_set, bob_package]) ?) ?
  let bob_welcome = output_list(bob_welcome_output) ?
  group_create_ensure(List.length(bob_welcome) == 1, "bob welcome count mismatch") ?
  group_create_ensure(Bytes.secure_equals(outbox_list_export(Bytes.from_utf8(accounts.alice_path)) ?,
  bob_welcome_output),
  "bob welcome outbox mismatch") ?
  group_create_ensure(outer(List.head(bob_welcome)) ?.suite == 4, "bob welcome suite mismatch") ?
  assert_group_transport(List.head(bob_welcome), group_id, accounts.alice_account.account_id) ?
  acknowledge(accounts.alice_path, bob_welcome, 0) ?
  group_create_ensure(Bytes.secure_equals(group_receive_export(group_vectors([Bytes.from_utf8(accounts.bob_path), List.head(bob_welcome)]) ?) ?,
  group_id),
  "bob welcome receive mismatch") ?
  Ok(true)
end

pub fn create_group_with_bob(accounts :: GroupAccountFixture) -> Bytes ! String do
  let transparency = install_group_lifecycle_transparency(accounts.alice_path,
  accounts.linked_path,
  accounts.bob_path,
  accounts.alice_set,
  accounts.bob_set) ?
  let group_id = group_create_export(Bytes.from_utf8(accounts.alice_path)) ?
  group_create_ensure(Bytes.length(group_id) == 32, "group id length mismatch") ?
  group_create_ensure(assert_created_group(accounts, group_id) ?, "created group check failed") ?
  let bob_package = bob_package_for_group(accounts, group_id) ?
  group_create_ensure(add_bob_to_group(accounts, transparency, group_id, bob_package) ?,
  "add bob check failed") ?
  let _ = install_signed_transparency(accounts.bob_path, transparency, accounts.alice_set) ?
  let _ = install_signed_transparency(accounts.linked_path, transparency, accounts.bob_set) ?
  Ok(group_id)
end
