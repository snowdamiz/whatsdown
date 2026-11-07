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
  start_conversation_export,
  send_fanout_export,
  outbox_list_export
)
from Prekeys.Bundle import (
  normalize_prekey_bundle,
  generate_signed_prekey,
  generate_one_time_prekey,
  build_hybrid_prekey_bundle,
  generate_post_quantum_prekey
)
from Protocol.DirectoryWire import encode_device_set
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import DeviceSet, DirectoryEntry
from Storage.Keys import platform_key
from Storage.Blobs import load_blob
from Tests.GroupConsistencySupport import signed_transparency_view
from Tests.GroupLifecycleSupport import install_signed_transparency
from Tests.GroupLifecycleWire import group_vectors
from Tests.Support import database_path, repeated
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

fn base_entry(entry :: DirectoryEntry) -> DirectoryEntry!String do
  let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
    Err(_) -> return Err("fixture base decode")
    Ok(value) -> value
  end
  let normalized = case normalize_prekey_bundle(bundle) do
    Err(_) -> return Err("fixture base normalize")
    Ok(value) -> value
  end
  let encoded = case encode_prekey_bundle(normalized) do
    Err(_) -> return Err("fixture base encode")
    Ok(value) -> value
  end
  Ok(%{entry | prekey_bundle: encoded})
end

fn exercise(mask :: Int, peer_mixed :: Bool, own_mixed :: Bool) -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("he-capability-sender")?
  let peer_path = database_path("he-capability-peer")?
  let own_wire = create_account_export(group_vectors([
    Bytes.from_utf8(path),
    Bytes.from_utf8("sender")
  ])?)?
  let original_wire = create_account_export(group_vectors([
    Bytes.from_utf8(peer_path),
    Bytes.from_utf8("peer")
  ])?)?
  let own = decode_client_profile(own_wire)?
  let original_peer = decode_client_profile(original_wire)?
  let peer_entry = fixture_entry(peer_path, mask, false)?
  let peer = encode_client_profile(peer_entry, original_peer.account_id, original_peer.device_id)?
  let own_entries = if own_mixed do
    [base_entry(own.entry)?, base_entry(fixture_entry(path, 7, true)?)?]
  else
    [base_entry(own.entry)?]
  end
  let peer_entries = if peer_mixed do
    [base_entry(peer_entry)?, base_entry(fixture_entry(peer_path, 7, true)?)?]
  else
    [base_entry(peer_entry)?]
  end
  let own_set = case encode_device_set(DeviceSet {
    version: 1,
    username: own.username,
    account_identity: own.entry.account_identity,
    sequence: own.account.directory_sequence,
    devices: own_entries,
    revoked_device_ids: []
  }) do
    Err(_) -> return Err("own set")
    Ok(value) -> value
  end
  let peer_set = case encode_device_set(DeviceSet {
    version: 1,
    username: original_peer.username,
    account_identity: original_peer.entry.account_identity,
    sequence: original_peer.account.directory_sequence,
    devices: peer_entries,
    revoked_device_ids: []
  }) do
    Err(_) -> return Err("peer set")
    Ok(value) -> value
  end
  let view = signed_transparency_view([leaf_hash(own_set)?, leaf_hash(peer_set)?])?
  assert(install_signed_transparency(path, view, own_set)?)
  assert(install_signed_transparency(path, view, peer_set)?)
  let before = outbox_list_export(Bytes.from_utf8(path))?
  let direct = start_conversation_export(group_vectors([
    Bytes.from_utf8(path),
    peer,
    Bytes.from_utf8("HE text")
  ])?)
  if mask < 8 || peer_mixed || own_mixed do
    assert(direct == Err("header_recipient_upgrade_required"))
    assert(send_fanout_export(group_vectors([
      Bytes.from_utf8(path),
      peer_set,
      own_set,
      Bytes.from_utf8("HE fanout")
    ])?) == Err("header_recipient_upgrade_required"))
    assert(Bytes.secure_equals(before, outbox_list_export(Bytes.from_utf8(path))?))
    assert(Result.is_err(load_blob(path, "sessions/v1")))
    assert(Result.is_err(load_blob(path,
      "fanout-prekey-claim/v1/#{Bytes.to_hex(original_peer.account_id)}/#{Bytes.to_hex(original_peer.device_id)}")))
  else
    assert(Result.is_ok(direct))
  end
  File.delete(path)?
  File.delete(peer_path)
end

test("valid signed mask7 recipient cannot trigger a latest clear-header text or partial fanout write") do
  case exercise(7, false, false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("one authenticated old peer device refuses every target before prekey/outbox reservation") do
  case exercise(15, true, false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("one authenticated old own device refuses self-sync and peer fanout before effects") do
  case exercise(15, false, true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("text-only authenticated mask9 reader is eligible without falsely advertising attachment support") do
  case exercise(9, false, false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
