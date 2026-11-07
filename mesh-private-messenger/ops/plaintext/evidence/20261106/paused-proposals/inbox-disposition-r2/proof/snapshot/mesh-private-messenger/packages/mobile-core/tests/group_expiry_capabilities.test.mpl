from MobileCore import group_policy_export, group_send_export
from Identity.Device import issue_hybrid_device_credential
from Mobile.Profile import load_profile, open_account, open_device, open_post_quantum_prekey
from Prekeys.Bundle import (
  generate_signed_prekey,
  generate_one_time_prekey,
  build_hybrid_prekey_bundle
)
from Protocol.DirectoryWire import encode_device_set
from Protocol.PrekeyWire import encode_prekey_bundle
from Protocol.V1 import DeviceSet, DirectoryEntry
from Mobile.GroupState import group_state_label, group_history_label
from Storage.Blobs import load_blob
from Storage.Keys import platform_key
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleSupport import group_account_fixture
from Tests.GroupLifecycleWire import group_vectors, output_list
from Tests.Support import write_u32
from Transport.Packet import decode_client_profile

fn legacy_reader(path :: String) -> DirectoryEntry!String do
  let key = platform_key()?
  let profile = decode_client_profile(load_profile(path)?)?
  let account = open_account(profile, key, path)?
  let device = open_device(profile, key, path)?
  let pq = open_post_quantum_prekey(profile, key, path)?
  let credential = case issue_hybrid_device_credential(account,
    device,
    pq.public_key,
    U64.parse("7")?,
    profile.credential.created_at,
    profile.credential.expires_at,
    profile.credential.directory_sequence) do
    Err(_) -> return Err("fixture legacy credential")
    Ok(value) -> value
  end
  let signed = case generate_signed_prekey(device,
    credential,
    U64.parse("99")?,
    credential.expires_at) do
    Err(_) -> return Err("fixture signed prekey")
    Ok(value) -> value
  end
  let one = case generate_one_time_prekey(U64.parse("100")?) do
    Err(_) -> return Err("fixture one-time prekey")
    Ok(value) -> value
  end
  let bundle = case build_hybrid_prekey_bundle(credential, signed, one, pq) do
    Err(_) -> return Err("fixture hybrid bundle")
    Ok(value) -> value
  end
  let wire = case encode_prekey_bundle(bundle) do
    Err(_) -> return Err("fixture prekey wire")
    Ok(value) -> value
  end
  Ok(%{profile.entry | prekey_bundle: wire})
end

fn old_reader_refused() -> Bool!String do
  if !Test.install_in_memory_secure_store() do
    return Err("fixture secure store")
  end
  let original = group_account_fixture()?
  let legacy = legacy_reader(original.bob_path)?
  let set = case encode_device_set(DeviceSet {
    version: 1,
    username: "bob",
    account_identity: legacy.account_identity,
    sequence: decode_client_profile(load_profile(original.bob_path)?)?.account.directory_sequence,
    devices: [legacy],
    revoked_device_ids: []
  }) do
    Err(_) -> return Err("fixture legacy set")
    Ok(value) -> value
  end
  let accounts = %{original | bob_entry: legacy, bob_set: set}
  let group = create_group_with_bob(accounts)?
  let path = Bytes.from_utf8(accounts.alice_path)
  let _ = group_policy_export(group_vectors([path, group, write_u32(60)?])?)?
  let state_label = group_state_label(group)?
  let state = load_blob(accounts.alice_path, state_label)?
  let history = load_blob(accounts.alice_path, group_history_label(group))
  let outbox = load_blob(accounts.alice_path, "outbox/v1")
  if group_send_export(group_vectors([
    path,
    group,
    Bytes.from_utf8("timed refusal")
  ])?) != Err("group_expiry_upgrade_required") do
    return Err("legacy reader accepted timed send")
  end
  if !Bytes.secure_equals(state, load_blob(accounts.alice_path, state_label)?)
    || history != load_blob(accounts.alice_path, group_history_label(group))
    || outbox != load_blob(accounts.alice_path, "outbox/v1") do
    return Err("refused timed send changed state")
  end
  let _ = group_policy_export(group_vectors([path, group, write_u32(0)?])?)?
  let sent = output_list(group_send_export(group_vectors([
    path,
    group,
    Bytes.from_utf8("permanent compatibility")
  ])?)?)?
  Ok(List.length(sent) > 0)
end

test("a genuinely signed witnessed legacy reader refuses timed send atomically while permanent send remains available") do
  case old_reader_refused() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
