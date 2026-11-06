from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleSupport import group_account_fixture
from MobileCore import group_send_export
from Identity.Device import issue_hybrid_device_credential
from Mobile.Profile import (
  load_profile,
  open_account,
  open_device,
  open_post_quantum_prekey,
  device_keys
)
from MobileCore import (
  create_account_export,
  attachment_prepare_export,
  start_conversation_export,
  outbox_list_export
)
from Prekeys.Bundle import (
  generate_signed_prekey,
  generate_one_time_prekey,
  build_hybrid_prekey_bundle,
  generate_post_quantum_prekey
)
from Protocol.DirectoryWire import encode_device_set
from Protocol.PrekeyWire import encode_prekey_bundle
from Protocol.V1 import DeviceSet, DirectoryEntry
from Storage.Keys import platform_key
from Tests.GroupConsistencySupport import signed_transparency_view
from Tests.GroupLifecycleSupport import install_signed_transparency
from Tests.GroupLifecycleWire import group_vectors, output_list
from Tests.Support import database_path, write_u32, repeated
from Transparency.Merkle import leaf_hash
from Transport.Packet import decode_client_profile, encode_client_profile

fn fixture_entry(path :: String, mask :: Int, linked :: Bool) -> DirectoryEntry!String do
  let key = platform_key()?
  let profile = decode_client_profile(load_profile(path)?)?
  let account = open_account(profile, key, path)?
  let device = if linked do
    device_keys()
  else
    open_device(profile, key, path)
  end?
  let pq = if linked do
    case generate_post_quantum_prekey() do
      Err(_) -> Err("fixture PQ key")
      Ok(value)
    end
  else
    open_post_quantum_prekey(profile, key, path)
  end?
  let credential = case issue_hybrid_device_credential(account,
    device,
    pq.public_key,
    U64.parse(Int.to_string(mask))?,
    profile.credential.created_at,
    profile.credential.expires_at,
    profile.credential.directory_sequence) do
    Err(_) -> return Err("fixture credential")
    Ok(value) -> value
  end
  let signed = case generate_signed_prekey(device,
    credential,
    U64.parse("7")?,
    credential.expires_at) do
    Err(_) -> return Err("fixture signed prekey")
    Ok(value) -> value
  end
  let one = case generate_one_time_prekey(U64.parse("8")?) do
    Err(_) -> return Err("fixture one-time prekey")
    Ok(value) -> value
  end
  let bundle = case build_hybrid_prekey_bundle(credential, signed, one, pq) do
    Err(_) -> return Err("fixture bundle")
    Ok(value) -> value
  end
  let wire = case encode_prekey_bundle(bundle) do
    Err(_) -> return Err("fixture bundle wire")
    Ok(value) -> value
  end
  Ok(%{profile.entry |
    prekey_bundle: wire,
    mailbox_token: if linked do
      repeated(211, 32)?
    else
      profile.entry.mailbox_token
    end
  })
end

fn exercise(mask :: Int, linked_legacy :: Bool) -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("ach3_sender")?
  let peer_path = database_path("ach3_peer")?
  let own_wire = create_account_export(group_vectors([
    Bytes.from_utf8(path),
    Bytes.from_utf8("sender")
  ])?)?
  let peer_wire = create_account_export(group_vectors([
    Bytes.from_utf8(peer_path),
    Bytes.from_utf8("peer")
  ])?)?
  let own = decode_client_profile(own_wire)?
  let original_peer = decode_client_profile(peer_wire)?
  let peer_entry = fixture_entry(peer_path, mask, false)?
  let peer = encode_client_profile(peer_entry, original_peer.account_id, original_peer.device_id)?
  let entries = if linked_legacy do
    [peer_entry, fixture_entry(peer_path, 9, true)?]
  else
    [peer_entry]
  end
  let own_set = case encode_device_set(DeviceSet {
    version: 1,
    username: own.username,
    account_identity: own.entry.account_identity,
    sequence: own.account.directory_sequence,
    devices: [own.entry],
    revoked_device_ids: []
  }) do
    Err(_) -> return Err("fixture own set")
    Ok(value) -> value
  end
  let peers = case encode_device_set(DeviceSet {
    version: 1,
    username: original_peer.username,
    account_identity: original_peer.entry.account_identity,
    sequence: original_peer.account.directory_sequence,
    devices: entries,
    revoked_device_ids: []
  }) do
    Err(_) -> return Err("fixture peer set")
    Ok(value) -> value
  end
  let view = signed_transparency_view([leaf_hash(own_set)?, leaf_hash(peers)?])?
  assert(install_signed_transparency(path, view, own_set)?)
  assert(install_signed_transparency(path, view, peers)?)
  let material = output_list(attachment_prepare_export(group_vectors([
    Bytes.from_utf8(path),
    Bytes.from_utf8("private.txt"),
    Bytes.from_utf8("text/plain"),
    write_u32(1)?,
    write_u32(1)?
  ])?)?)?
  let before = outbox_list_export(Bytes.from_utf8(path))?
  let sent = start_conversation_export(group_vectors([
    Bytes.from_utf8(path),
    peer,
    Bytes.from_utf8("attachment"),
    List.head(material)
  ])?)
  if mask == 9 || mask == 11 || linked_legacy do
    assert(sent == Err("attachment_recipient_upgrade_required"))
    assert(Bytes.secure_equals(before, outbox_list_export(Bytes.from_utf8(path))?))
    # A header-capable attachment-legacy device is still a valid text recipient.
    let _ = start_conversation_export(group_vectors([
      Bytes.from_utf8(path),
      peer,
      Bytes.from_utf8("text")
    ])?)?
  else
    assert(Result.is_ok(sent))
  end
  File.delete(path)?
  File.delete(peer_path)?
  Ok(nil)
end

test("legacy signed recipient is refused before attachment outbox writes but can receive text") do
  assert(exercise(9, false) == Ok(nil))
end

test("one signed legacy linked recipient prevents partial attachment delivery") do
  assert(exercise(15, true) == Ok(nil))
end

test("authenticated padded-reader recipient can receive a new attachment") do
  assert(exercise(15, false) == Ok(nil))
end

fn group_legacy() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let accounts = group_account_fixture()?
  let legacy_entry = fixture_entry(accounts.bob_path, 3, false)?
  let profile = decode_client_profile(load_profile(accounts.bob_path)?)?
  let legacy_set = case encode_device_set(DeviceSet {
    version: 1,
    username: profile.username,
    account_identity: legacy_entry.account_identity,
    sequence: profile.account.directory_sequence,
    devices: [legacy_entry],
    revoked_device_ids: []
  }) do
    Err(_) -> return Err("fixture group legacy set")
    Ok(value) -> value
  end
  let group = create_group_with_bob(%{accounts | bob_entry: legacy_entry, bob_set: legacy_set})?
  let path = accounts.alice_path
  let material = output_list(attachment_prepare_export(group_vectors([
    Bytes.from_utf8(path),
    Bytes.from_utf8("private.txt"),
    Bytes.from_utf8("text/plain"),
    write_u32(1)?,
    write_u32(1)?
  ])?)?)?
  let before = outbox_list_export(Bytes.from_utf8(path))?
  let result = group_send_export(group_vectors([
    Bytes.from_utf8(path),
    group,
    Bytes.from_utf8("attachment"),
    List.head(material)
  ])?)
  assert(result == Err("attachment_recipient_upgrade_required"))
  assert(Bytes.secure_equals(before, outbox_list_export(Bytes.from_utf8(path))?))
  let _ = group_send_export(group_vectors([
    Bytes.from_utf8(path),
    group,
    Bytes.from_utf8("text")
  ])?)?
  File.delete(accounts.alice_path)?
  File.delete(accounts.linked_path)?
  File.delete(accounts.bob_path)?
  Ok(nil)
end

test("group extensions cannot replace authenticated recipient padded attachment support") do
  case group_legacy() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("an authenticated ACH3-only recipient is not silently selected for new padded writes") do
  assert(exercise(3, false) == Ok(nil))
end
