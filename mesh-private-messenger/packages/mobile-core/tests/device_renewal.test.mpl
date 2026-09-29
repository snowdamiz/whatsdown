import File
from Identity.Device import (
  AccountKeys,
  DeviceKeys,
  generate_account,
  generate_device,
  issue_hybrid_device_credential
)
from MobileCore import (
  authorize_device_link_for_set_export,
  complete_device_link_export,
  create_account_export,
  create_link_request_export,
  directory_entry_export,
  inspect_device_set_export,
  install_group_transparency_for_test,
  load_profile_export,
  receive_initial_export,
  renew_devices_for_test,
  replenish_prekeys_export,
  start_conversation_export
)
from Mobile.DeviceSet import verified_device_set
from Mobile.Types import MobileVerifiedDeviceSet
from Prekeys.Bundle import (
  PostQuantumPrekeySecrets,
  build_hybrid_prekey_bundle,
  generate_one_time_prekey,
  generate_post_quantum_prekey,
  generate_signed_prekey,
  normalize_prekey_bundle,
  verify_prekey_bundle
)
from Prekeys.Pool import OneTimePrekeyPublic, decode_prekey_publish
from Prekeys.Renewal import bundle_renewal_request
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set, encode_directory_entry
from Protocol.IdentityWire import (
  decode_account_identity,
  decode_device_credential,
  encode_account_identity
)
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import AccountIdentity, DeviceCredential, DeviceSet, DirectoryEntry, PrekeyBundle
from Tests.GroupConsistencySupport import signed_transparency_view
from Tests.Support import append, database_path, vector, write_u32
from Transparency.Merkle import leaf_hash
from Transport.Packet import decode_client_profile, encode_client_profile

fn encode_vectors(values :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_vectors(values, index + 1, append(output, vector(List.get(values, index))?)?)
  end
end

fn request(values :: List<Bytes>) -> Bytes!String do
  encode_vectors(values, 0, Bytes.empty())
end

fn wide(value :: String) -> U64!String do
  case U64.parse(value) do
    Err(_) -> Err("test integer conversion failed")
    Ok(parsed)
  end
end

fn days(count :: Int) -> Int do
  count * 86400000
end

fn entry(input :: Bytes) -> DirectoryEntry!String do
  case decode_directory_entry(input) do
    Err(_) -> Err("directory entry decode failed")
    Ok(value)
  end
end

fn entry_wire(value :: DirectoryEntry) -> Bytes!String do
  case encode_directory_entry(value) do
    Err(_) -> Err("directory entry encode failed")
    Ok(encoded)
  end
end

fn account(input :: Bytes) -> AccountIdentity!String do
  case decode_account_identity(input) do
    Err(_) -> Err("account identity decode failed")
    Ok(value)
  end
end

fn bundle(input :: Bytes) -> PrekeyBundle!String do
  case decode_prekey_bundle(input) do
    Err(_) -> Err("prekey bundle decode failed")
    Ok(value)
  end
end

fn bundle_wire(value :: PrekeyBundle) -> Bytes!String do
  case encode_prekey_bundle(value) do
    Err(_) -> Err("prekey bundle encode failed")
    Ok(encoded)
  end
end

fn credential(input :: Bytes) -> DeviceCredential!String do
  case decode_device_credential(input) do
    Err(_) -> Err("device credential decode failed")
    Ok(value)
  end
end

# What the directory logs: the entry without its one-time prekey.
fn logged(value :: DirectoryEntry) -> DirectoryEntry!String do
  let normalized = case normalize_prekey_bundle(bundle(value.prekey_bundle)?) do
    Err(_) -> Err("bundle normalization failed")
    Ok(output)
  end?
  Ok(%{value | prekey_bundle: bundle_wire(normalized)?})
end

fn set_wire(first :: DirectoryEntry,
  sequence :: String,
  devices :: List<DirectoryEntry>) -> Bytes!String do
  case encode_device_set(DeviceSet {
    version: 1,
    username: first.username,
    account_identity: first.account_identity,
    sequence: wide(sequence)?,
    devices: devices,
    revoked_device_ids: List.new()
  }) do
    Err(_) -> Err("device set encode failed")
    Ok(encoded)
  end
end

# The directory's evidence for a set, as a device holds it after verifying.
fn install(path :: String, device_set :: Bytes) -> Result<(), String> do
  let view = signed_transparency_view([leaf_hash(device_set)?])?
  assert(install_group_transparency_for_test(path,
    view.checkpoint,
    view.consistency,
    view.service_public_key,
    view.witness_a_public_key,
    view.witness_b_public_key,
    device_set)?)
  Ok(nil)
end

fn renew(path :: String, device_set :: Bytes, age :: Int) -> List<Bytes>!String do
  renew_devices_for_test(path, device_set, age)
end

fn inspect_changed(path :: String, device_set :: Bytes) -> Bool!String do
  let output = inspect_device_set_export(request([Bytes.from_utf8(path), device_set])?)?
  # username "alice", account ID, sequence, then the changed flag.
  let flag = Bytes.slice(output, 4 + 5 + 4 + 32 + 4 + 8 + 4, 1)?
  Ok(Bytes.to_hex(flag) == "01")
end

fn current_bundle(path :: String) -> PrekeyBundle!String do
  Ok(decode_client_profile(load_profile_export(Bytes.from_utf8(path))?)?.bundle)
end

fn reusable(path :: String) -> OneTimePrekeyPublic!String do
  let publication = decode_prekey_publish(replenish_prekeys_export(request([
    Bytes.from_utf8(path),
    write_u32(0)?
  ])?)?)?
  case publication.last_resort do
    None -> Err("publication carries no last-resort prekey")
    Some(value) -> Ok(value)
  end
end

# A profile a sender could have been handed for one of the device's logged
# bundles, with its reusable prekey in the one-time slot.
fn handed_out(value :: DirectoryEntry, key :: OneTimePrekeyPublic) -> Bytes!String do
  let claimed = %{bundle(value.prekey_bundle)? |
    one_time_prekey_id: key.id,
    one_time_prekey: key.public_key
  }
  let with_key = %{value | prekey_bundle: bundle_wire(claimed)?}
  let credential_value = credential(claimed.device_credential)?
  encode_client_profile(with_key, credential_value.account_id, credential_value.device_id)
end

fn sealed(sender :: String, peer :: Bytes, body :: String) -> Bytes!String do
  start_conversation_export(request([Bytes.from_utf8(sender), peer, Bytes.from_utf8(body)])?)
end

fn opens(path :: String, outer :: Bytes, body :: String) -> Bool!String do
  case receive_initial_export(request([Bytes.from_utf8(path), outer])?) do
    Err(error) -> Err("#{body}: #{error}")
    Ok(opened) -> Ok(Bytes.secure_equals(opened, Bytes.from_utf8(body)))
  end
end

fn refused(path :: String, outer :: Bytes) -> Bool!String do
  case receive_initial_export(request([Bytes.from_utf8(path), outer])?) do
    Ok(_) -> Ok(false)
    Err(_) -> Ok(true)
  end
end

fn verified(identity :: AccountIdentity, value :: PrekeyBundle) -> Bool!String do
  case verify_prekey_bundle(identity,
    value,
    2,
    wide(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))?,
    identity.directory_sequence) do
    Err(_) -> Ok(false)
    Ok(result)
  end
end

fn created(path :: String, username :: String) -> Bytes!String do
  create_account_export(request([Bytes.from_utf8(path), Bytes.from_utf8(username)])?)
end

fn primary_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let root_path = database_path("renewal-root")?
  let senders = [
    database_path("renewal-sender-a")?,
    database_path("renewal-sender-b")?,
    database_path("renewal-sender-c")?,
    database_path("renewal-sender-d")?,
    database_path("renewal-sender-e")?
  ]
  created(root_path, "alice")?
  created(List.get(senders, 0), "sender_a")?
  created(List.get(senders, 1), "sender_b")?
  created(List.get(senders, 2), "sender_c")?
  created(List.get(senders, 3), "sender_d")?
  created(List.get(senders, 4), "sender_e")?
  let first = logged(entry(directory_entry_export(Bytes.from_utf8(root_path))?)?)?
  let identity = account(first.account_identity)?
  let first_bundle = bundle(first.prekey_bundle)?
  let first_credential = credential(first_bundle.device_credential)?
  let key = reusable(root_path)?
  let first_set = set_wire(first, "1", [first])?
  install(root_path, first_set)?
  assert(!inspect_changed(root_path, first_set)?)
  # A young credential is left alone.
  assert(List.length(renew(root_path, first_set, 0)?) == 0)
  assert(List.length(renew(root_path, first_set, days(89))?) == 0)
  # From ninety days on, the device holding the account key renews itself in
  # one transition: new credential, signed prekey and ML-KEM prekey.
  let due = renew(root_path, first_set, days(91))?
  assert(List.length(due) == 1)
  let next = entry(List.head(due))?
  let next_bundle = bundle(next.prekey_bundle)?
  let next_credential = credential(next_bundle.device_credential)?
  assert(next.username == "alice")
  assert(Bytes.secure_equals(next.mailbox_token, first.mailbox_token))
  assert(Bytes.secure_equals(next.account_identity, first.account_identity))
  assert(Bytes.secure_equals(next_credential.device_id, first_credential.device_id))
  assert(Bytes.secure_equals(next_credential.signing_public_key,
    first_credential.signing_public_key))
  assert(Bytes.secure_equals(next_credential.dh_public_key, first_credential.dh_public_key))
  assert(U64.compare(next_credential.directory_sequence, wide("2")?) == 0)
  assert(next_bundle.suite == 2)
  assert(U64.compare(next_bundle.signed_prekey_id, first_bundle.signed_prekey_id) > 0)
  assert(!Bytes.secure_equals(next_bundle.signed_prekey, first_bundle.signed_prekey))
  assert(!Bytes.secure_equals(next_bundle.post_quantum_prekey, first_bundle.post_quantum_prekey))
  assert(U64.compare(next_credential.expires_at, first_credential.expires_at) >= 0)
  assert(U64.compare(next_bundle.expires_at, first_bundle.expires_at) >= 0)
  assert(List.length(next_bundle.extensions) == 0)
  assert(verified(identity, next_bundle)?)
  # Until the directory holds it, the same renewal is offered again.
  assert(Bytes.secure_equals(List.head(renew(root_path, first_set, days(91))?), List.head(due)))
  assert(Bytes.secure_equals(current_bundle(root_path)?.signed_prekey, first_bundle.signed_prekey))
  # Either bundle may be what a sender was handed meanwhile, and both open.
  assert(opens(root_path,
    sealed(List.get(senders, 0), handed_out(first, key)?, "sealed to the old bundle")?,
    "sealed to the old bundle")?)
  assert(opens(root_path,
    sealed(List.get(senders, 1), handed_out(next, key)?, "sealed to the new bundle")?,
    "sealed to the new bundle")?)
  # The directory logs it. The device takes it as its own, and a renewal is
  # not a change to the account's devices.
  let next_set = set_wire(first, "2", [next])?
  install(root_path, next_set)?
  assert(List.length(renew(root_path, next_set, 0)?) == 0)
  assert(Bytes.secure_equals(current_bundle(root_path)?.signed_prekey, next_bundle.signed_prekey))
  assert(Bytes.secure_equals(current_bundle(root_path)?.post_quantum_prekey,
    next_bundle.post_quantum_prekey))
  assert(!inspect_changed(root_path, next_set)?)
  # A first message sealed to the old bundle can sit in a mailbox for up to 31
  # days, so its secrets outlive the switch...
  let late = sealed(List.get(senders, 2), handed_out(first, key)?, "still in flight")?
  assert(opens(root_path, late, "still in flight")?)
  assert(List.length(renew(root_path, next_set, days(34))?) == 0)
  let later = sealed(List.get(senders, 3), handed_out(first, key)?, "a month on")?
  assert(opens(root_path, later, "a month on")?)
  # ...and are destroyed 35 days after the directory switched.
  assert(List.length(renew(root_path, next_set, days(36))?) == 0)
  assert(refused(root_path, sealed(List.get(senders, 4), handed_out(first, key)?, "too late")?)?)
  assert(opens(root_path,
    sealed(List.get(senders, 4), handed_out(next, key)?, "current")?,
    "current")?)
  File.delete(root_path)?
  File.delete(List.get(senders, 0))?
  File.delete(List.get(senders, 1))?
  File.delete(List.get(senders, 2))?
  File.delete(List.get(senders, 3))?
  File.delete(List.get(senders, 4))?
  Ok(true)
end

test("the device holding the account key renews itself and keeps old secrets only as long as mail can need them") do
  case primary_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn linked_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let root_path = database_path("renewal-link-root")?
  let linked_path = database_path("renewal-link-linked")?
  let first_sender = database_path("renewal-link-sender-a")?
  let second_sender = database_path("renewal-link-sender-b")?
  let third_sender = database_path("renewal-link-sender-c")?
  created(root_path, "alice")?
  created(first_sender, "sender_a")?
  created(second_sender, "sender_b")?
  created(third_sender, "sender_c")?
  let root = logged(entry(directory_entry_export(Bytes.from_utf8(root_path))?)?)?
  let identity = account(root.account_identity)?
  let root_set = set_wire(root, "1", [root])?
  install(root_path, root_set)?
  let link_request = create_link_request_export(Bytes.from_utf8(linked_path))?
  let authorization = authorize_device_link_for_set_export(request([
    Bytes.from_utf8(root_path),
    root_set,
    link_request
  ])?)?
  complete_device_link_export(request([Bytes.from_utf8(linked_path), authorization])?)?
  let linked = logged(entry(directory_entry_export(Bytes.from_utf8(linked_path))?)?)?
  let linked_bundle = bundle(linked.prekey_bundle)?
  let key = reusable(linked_path)?
  let both = set_wire(root, "2", [root, linked])?
  install(root_path, both)?
  install(linked_path, both)?
  assert(List.length(renew(linked_path, both, 0)?) == 0)
  # A linked device holds no account key. When due, it asks in its own bundle,
  # under the credential it has, for the keys it has made for next time.
  let asked = renew(linked_path, both, days(91))?
  assert(List.length(asked) == 1)
  let asking = entry(List.head(asked))?
  let asking_bundle = bundle(asking.prekey_bundle)?
  assert(Bytes.secure_equals(asking_bundle.device_credential, linked_bundle.device_credential))
  assert(Bytes.secure_equals(asking_bundle.signed_prekey, linked_bundle.signed_prekey))
  let wanted = case bundle_renewal_request(asking_bundle) do
    Ok(Some(value)) -> Ok(value)
    _ -> Err("linked device did not ask for renewal")
  end?
  assert(U64.compare(wanted.signed_prekey_id, linked_bundle.signed_prekey_id) > 0)
  assert(!Bytes.secure_equals(wanted.post_quantum_prekey, linked_bundle.post_quantum_prekey))
  assert(Bytes.secure_equals(List.head(renew(linked_path, both, days(91))?), List.head(asked)))
  # Nothing for the account key to answer until the directory logs the request.
  assert(List.length(renew(root_path, both, 0)?) == 0)
  let requested = set_wire(root, "3", [root, asking])?
  install(root_path, requested)?
  install(linked_path, requested)?
  let answers = renew(root_path, requested, 0)?
  assert(List.length(answers) == 1)
  let answer = entry(List.head(answers))?
  let answer_bundle = bundle(answer.prekey_bundle)?
  let answer_credential = credential(answer_bundle.device_credential)?
  assert(Bytes.secure_equals(answer.mailbox_token, linked.mailbox_token))
  assert(Bytes.secure_equals(answer_credential.device_id,
    credential(linked_bundle.device_credential)?.device_id))
  assert(U64.compare(answer_credential.directory_sequence, wide("4")?) == 0)
  assert(U64.compare(answer_bundle.signed_prekey_id, wanted.signed_prekey_id) == 0)
  assert(Bytes.secure_equals(answer_bundle.signed_prekey, wanted.signed_prekey))
  assert(Bytes.secure_equals(answer_bundle.post_quantum_prekey, wanted.post_quantum_prekey))
  assert(List.length(answer_bundle.extensions) == 0)
  assert(verified(identity, answer_bundle)?)
  # The linked device takes on its logged request. Mail still in flight to the
  # bundle from before it opens.
  assert(List.length(renew(linked_path, requested, 0)?) == 0)
  assert(List.length(current_bundle(linked_path)?.extensions) == 2)
  assert(opens(linked_path,
    sealed(first_sender, handed_out(linked, key)?, "to the device before")?,
    "to the device before")?)
  # Due or not, it waits for the answer rather than asking again.
  assert(List.length(renew(linked_path, requested, days(91))?) == 0)
  let answered = set_wire(root, "4", [root, answer])?
  install(linked_path, answered)?
  assert(List.length(renew(linked_path, answered, 0)?) == 0)
  assert(Bytes.secure_equals(current_bundle(linked_path)?.signed_prekey, wanted.signed_prekey))
  assert(Bytes.secure_equals(current_bundle(linked_path)?.post_quantum_prekey,
    wanted.post_quantum_prekey))
  # Mail sealed to its new bundle opens, and so does mail still in flight to
  # the bundle that carried the request.
  assert(opens(linked_path,
    sealed(second_sender, handed_out(answer, key)?, "to the renewed device")?,
    "to the renewed device")?)
  assert(opens(linked_path,
    sealed(third_sender, handed_out(asking, key)?, "to the request bundle")?,
    "to the request bundle")?)
  File.delete(root_path)?
  File.delete(linked_path)?
  File.delete(first_sender)?
  File.delete(second_sender)?
  File.delete(third_sender)?
  Ok(true)
end

test("a linked device asks for renewal in its logged bundle and takes the account key's answer") do
  case linked_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn issued(account_keys :: borrow AccountKeys,
  device_keys :: borrow DeviceKeys,
  keys :: borrow PostQuantumPrekeySecrets,
  created_at :: U64,
  expires_at :: U64,
  sequence :: String) -> DeviceCredential!String do
  case issue_hybrid_device_credential(account_keys,
    device_keys,
    keys.public_key,
    wide("1")?,
    created_at,
    expires_at,
    wide(sequence)?) do
    Err(_) -> Err("credential generation failed")
    Ok(value)
  end
end

fn device_entry(identity_wire :: Bytes,
  device_keys :: borrow DeviceKeys,
  value :: DeviceCredential,
  keys :: borrow PostQuantumPrekeySecrets,
  expires_at :: U64,
  mailbox :: Int) -> DirectoryEntry!String do
  let signed = case generate_signed_prekey(device_keys, value, wide("1")?, expires_at) do
    Err(_) -> Err("signed prekey generation failed")
    Ok(output)
  end?
  let one_time = case generate_one_time_prekey(wide("2")?) do
    Err(_) -> Err("one-time prekey generation failed")
    Ok(output)
  end?
  let built = case build_hybrid_prekey_bundle(value, signed, one_time, keys) do
    Err(_) -> Err("bundle generation failed")
    Ok(output)
  end?
  logged(DirectoryEntry {
    version: 1,
    username: "carol",
    account_identity: identity_wire,
    prekey_bundle: bundle_wire(built)?,
    mailbox_token: case Bytes.repeat(mailbox, 32) do
      Err(_) -> Err("mailbox generation failed")
      Ok(value)
    end?
  })
end

fn post_quantum() -> PostQuantumPrekeySecrets!String do
  case generate_post_quantum_prekey() do
    Err(_) -> Err("post-quantum prekey generation failed")
    Ok(value)
  end
end

fn expiry_proof() -> Bool!String do
  let now = wide(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))?
  let year = wide("31536000000")?
  let long_ago = U64.subtract(now, U64.add(year, year)?)?
  let past = U64.subtract(now, year)?
  let later = U64.add(now, year)?
  let (account_keys, identity) = case generate_account(long_ago, wide("1")?) do
    Err(_) -> Err("account generation failed")
    Ok(value)
  end?
  let identity_wire = case encode_account_identity(identity) do
    Err(_) -> Err("account encoding failed")
    Ok(value)
  end?
  let present = case generate_device() do
    Err(_) -> Err("device generation failed")
    Ok(value)
  end?
  let away = case generate_device() do
    Err(_) -> Err("device generation failed")
    Ok(value)
  end?
  let present_keys = post_quantum()?
  let away_keys = post_quantum()?
  let present_entry = device_entry(identity_wire,
    present,
    issued(account_keys, present, present_keys, now, later, "1")?,
    present_keys,
    later,
    91)?
  let away_entry = device_entry(identity_wire,
    away,
    issued(account_keys, away, away_keys, long_ago, past, "2")?,
    away_keys,
    past,
    92)?
  # A device that stayed away past its expiry is still the account's, signed
  # by its key, but no one encrypts to it; the rest of the account still works.
  let devices = verified_device_set(set_wire(present_entry, "2", [present_entry, away_entry])?)?
  assert(List.length(devices.profiles) == 1)
  assert(List.length(devices.expired) == 1)
  assert(Bytes.secure_equals(List.head(devices.expired).entry.mailbox_token,
    away_entry.mailbox_token))
  # Expired is not unverified: a bundle that never verified, at any time,
  # still invalidates the whole set.
  let forged = device_entry(identity_wire,
    present,
    issued(account_keys, away, away_keys, long_ago, past, "2")?,
    away_keys,
    past,
    93)?
  case verified_device_set(set_wire(present_entry, "2", [present_entry, forged])?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "invalid_device_set")
  end
  Ok(true)
end

test("an expired device leaves the rest of its account reachable") do
  case expiry_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
