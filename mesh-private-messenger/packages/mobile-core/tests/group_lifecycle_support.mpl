from MobileCore import (
  authorize_device_link_export,
  complete_device_link_export,
  create_account_export,
  create_link_request_export,
  directory_entry_export,
  install_group_transparency_for_test
)
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set
from Protocol.IdentityWire import decode_account_identity, decode_device_credential
from Protocol.PrekeyWire import decode_prekey_bundle
from Protocol.V1 import AccountIdentity, DeviceCredential, DeviceSet, DirectoryEntry, PrekeyBundle
from Tests.GroupConsistencySupport import SignedTransparencyViewFixture, request, signed_transparency_view, wide
from Tests.Support import database_path
from Transparency.Merkle import leaf_hash

pub struct GroupAccountFixture do
  alice_path :: String
  linked_path :: String
  bob_path :: String
  alice_entry :: DirectoryEntry
  linked_entry :: DirectoryEntry
  bob_entry :: DirectoryEntry
  alice_account :: AccountIdentity
  linked_credential :: DeviceCredential
  alice_set :: Bytes
  bob_set :: Bytes
end

fn entry(input :: Bytes) -> DirectoryEntry ! String do
  case decode_directory_entry(input) do
    Err(_) -> Err("directory entry decode failed")
    Ok(value) -> Ok(value)
  end
end

fn bundle(input :: Bytes) -> PrekeyBundle ! String do
  case decode_prekey_bundle(input) do
    Err(_) -> Err("prekey bundle decode failed")
    Ok(value) -> Ok(value)
  end
end

fn credential(input :: Bytes) -> DeviceCredential ! String do
  case decode_device_credential(input) do
    Err(_) -> Err("device credential decode failed")
    Ok(value) -> Ok(value)
  end
end

fn account(input :: Bytes) -> AccountIdentity ! String do
  case decode_account_identity(input) do
    Err(_) -> Err("account identity decode failed")
    Ok(value) -> Ok(value)
  end
end

fn directory_set(username :: String,
account_identity :: Bytes,
sequence :: U64,
devices :: List < DirectoryEntry >) -> Bytes ! String do
  case encode_device_set(DeviceSet {
    version : 1,
    username : username,
    account_identity : account_identity,
    sequence : sequence,
    devices : devices,
    revoked_device_ids : List.new()
  }) do
    Err(_) -> Err("device set encode failed")
    Ok(encoded) -> Ok(encoded)
  end
end

pub fn group_account_fixture() -> GroupAccountFixture ! String do
  let alice_path = database_path("groups-alice") ?
  let linked_path = database_path("groups-linked") ?
  let bob_path = database_path("groups-bob") ?
  let _alice_profile = create_account_export(request([Bytes.from_utf8(alice_path), Bytes.from_utf8("alice")]) ?) ?
  let _bob_profile = create_account_export(request([Bytes.from_utf8(bob_path), Bytes.from_utf8("bob")]) ?) ?
  let link_request = create_link_request_export(Bytes.from_utf8(linked_path)) ?
  let authorization = authorize_device_link_export(request([Bytes.from_utf8(alice_path), link_request]) ?) ?
  let _linked_profile = complete_device_link_export(request([Bytes.from_utf8(linked_path), authorization]) ?) ?
  let alice_entry = entry(directory_entry_export(Bytes.from_utf8(alice_path)) ?) ?
  let linked_entry = entry(directory_entry_export(Bytes.from_utf8(linked_path)) ?) ?
  let bob_entry = entry(directory_entry_export(Bytes.from_utf8(bob_path)) ?) ?
  let alice_account = account(alice_entry.account_identity) ?
  let bob_account = account(bob_entry.account_identity) ?
  let linked_credential = credential(bundle(linked_entry.prekey_bundle) ?.device_credential) ?
  let alice_set = directory_set("alice",
  alice_entry.account_identity,
  wide(2) ?,
  [alice_entry, linked_entry]) ?
  let bob_set = directory_set("bob",
  bob_entry.account_identity,
  bob_account.directory_sequence,
  [bob_entry]) ?
  Ok(GroupAccountFixture {
    alice_path : alice_path,
    linked_path : linked_path,
    bob_path : bob_path,
    alice_entry : alice_entry,
    linked_entry : linked_entry,
    bob_entry : bob_entry,
    alice_account : alice_account,
    linked_credential : linked_credential,
    alice_set : alice_set,
    bob_set : bob_set
  })
end

pub fn install_signed_transparency(path :: String,
fixture :: SignedTransparencyViewFixture,
device_set :: Bytes) -> Bool ! String do
  install_group_transparency_for_test(path,
  fixture.checkpoint,
  fixture.consistency,
  fixture.service_public_key,
  fixture.witness_a_public_key,
  fixture.witness_b_public_key,
  device_set)
end

pub fn install_group_lifecycle_transparency(alice_path :: String,
linked_path :: String,
bob_path :: String,
alice_set :: Bytes,
bob_set :: Bytes) -> SignedTransparencyViewFixture ! String do
  let fixture = signed_transparency_view([leaf_hash(alice_set) ?, leaf_hash(bob_set) ?]) ?
  let alice_installed = install_signed_transparency(alice_path, fixture, alice_set) ?
  let linked_installed = install_signed_transparency(linked_path, fixture, alice_set) ?
  let bob_installed = install_signed_transparency(bob_path, fixture, bob_set) ?
  if alice_installed && linked_installed && bob_installed do
    Ok(fixture)
  else
    Err("transparency_fixture_install_failed")
  end
end
