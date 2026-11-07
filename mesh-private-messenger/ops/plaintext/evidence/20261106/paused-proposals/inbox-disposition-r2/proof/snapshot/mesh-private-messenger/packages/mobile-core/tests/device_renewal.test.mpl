import File
from Credits.Action import encode_credit_action
from Credits.ActionWire import (
  CreditActionSubmission,
  sign_credit_action_receipt,
  encode_credit_action_receipt
)
from Credits.Retention import (
  CreditRetentionResult,
  sign_credit_retention_request,
  encode_credit_retention_request,
  credit_retention_action,
  encode_credit_retention_result
)
from Credits.Issuer import CreditIssuerKey
from Credits.Policy import issuer_epoch
from Credits.Token import blind_credit, sign_credit_request, finalize_credit
from Credits.Wire import decode_credit_frame
from Mobile.CreditState import CreditWallet
from Mobile.CreditWallet import (
  add_credit_issuer,
  completed_credit_record,
  reserve_credit_spend,
  accept_credit_retention_receipt
)
from Mobile.Codec import current_time, canonical_outer
from Mobile.Profile import open_device, open_account
from Storage.Keys import platform_key, local_context, seal_local
from Storage.Records import store_updated_session
from Storage.Credits import CreditWalletIdentity, load_credit_wallet, commit_credit_wallet
from Protocol.EnvelopeWire import decode_outer_envelope, encode_outer_envelope
from Transparency.Merkle import sign_checkpoint, consistency_proof
from Transparency.Wire import encode_checkpoint, encode_consistency_proof
from Identity.Device import (
  AccountKeys,
  DeviceKeys,
  generate_account,
  generate_device,
  issue_hybrid_device_credential,
  issue_renewed_device_credential
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
from Prekeys.Renewal import (
  RenewalRequest,
  bundle_renewal_request,
  verify_renewal_request,
  encode_renewal_request
)
from Protocol.Capabilities import (
  supports_ach3,
  supports_attachment_buckets,
  supports_header_encryption,
  supports_group_expiry
)
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set, encode_directory_entry
from Protocol.IdentityWire import (
  decode_account_identity,
  decode_device_credential,
  encode_account_identity,
  encode_device_credential
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
fn install_paths(paths :: List<String>, device_set :: Bytes) -> Result<(), String> do
  let view = signed_transparency_view([leaf_hash(device_set)?])?
  for path in paths do
    assert(install_group_transparency_for_test(path,
      view.checkpoint,
      view.consistency,
      view.service_public_key,
      view.witness_a_public_key,
      view.witness_b_public_key,
      device_set)?)
  end
  Ok(nil)
end

fn install(path :: String, device_set :: Bytes) -> Result<(), String> do
  install_paths([path], device_set)
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

# A latest writer can only send to the precise current authenticated set. The
# renewal scenarios retain these real packets across the recipient's later
# local adoption/cleanup; they do not manufacture fresh sends to retired keys.
fn sealed(sender :: String, peer :: Bytes, peer_set :: Bytes, body :: String) -> Bytes!String do
  let own = logged(entry(directory_entry_export(Bytes.from_utf8(sender))?)?)?
  let own_set = set_wire(own, "1", [own])?
  let view = signed_transparency_view([leaf_hash(own_set)?, leaf_hash(peer_set)?])?
  for selected in [own_set, peer_set] do
    assert(install_group_transparency_for_test(sender,
      view.checkpoint,
      view.consistency,
      view.service_public_key,
      view.witness_a_public_key,
      view.witness_b_public_key,
      selected)?)
  end
  start_conversation_export(request([Bytes.from_utf8(sender), peer, Bytes.from_utf8(body)])?)
end

fn opens(path :: String, outer :: Bytes, body :: String) -> Bool!String do
  case receive_initial_export(request([Bytes.from_utf8(path), outer])?) do
    Err(error) -> Err("#{body}: #{error}")
    Ok(opened) -> Ok(declassify(Bytes.secure_equals(opened, Bytes.from_utf8(body)),
      "test-only Boolean assertion of controlled synthetic renewal delivery; no application disclosure"))
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
  let created = create_account_export(request([Bytes.from_utf8(path), Bytes.from_utf8(username)])?)?
  assert(current_readers(credential(current_bundle(path)?.device_credential)?.capabilities))
  Ok(created)
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
  let old_senders = [
    List.get(senders, 0),
    List.get(senders, 2),
    List.get(senders, 3),
    List.get(senders, 4)
  ]
  let old_bodies = ["sealed to the old bundle", "still in flight", "a month on", "too late"]
  let old_mail = for index in 0..4 do
    sealed(List.get(old_senders, index),
      handed_out(first, key)?,
      first_set,
      List.get(old_bodies, index))?
  end
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
  # The directory can already publish the signed successor to a sender while
  # the recipient is still waiting to observe it locally. Both real queued
  # packets open against the old/pending recipient key material.
  let next_set = set_wire(first, "2", [next])?
  let new_mail = sealed(List.get(senders, 1),
    handed_out(next, key)?,
    next_set,
    "sealed to the new bundle")?
  let current_mail = sealed(List.get(senders, 4), handed_out(next, key)?, next_set, "current")?
  install(root_path, first_set)?
  assert(opens(root_path, List.get(old_mail, 0), "sealed to the old bundle")?)
  assert(opens(root_path, new_mail, "sealed to the new bundle")?)
  # The directory logs it. The device takes it as its own, and a renewal is
  # not a change to the account's devices.
  install(root_path, next_set)?
  assert(List.length(renew(root_path, next_set, 0)?) == 0)
  assert(Bytes.secure_equals(current_bundle(root_path)?.signed_prekey, next_bundle.signed_prekey))
  assert(Bytes.secure_equals(current_bundle(root_path)?.post_quantum_prekey,
    next_bundle.post_quantum_prekey))
  assert(!inspect_changed(root_path, next_set)?)
  # A first message sealed to the old bundle can sit in a mailbox for up to 31
  # days, so its secrets outlive the switch...
  assert(opens(root_path, List.get(old_mail, 1), "still in flight")?)
  assert(List.length(renew(root_path, next_set, days(34))?) == 0)
  assert(opens(root_path, List.get(old_mail, 2), "a month on")?)
  # ...and are destroyed 35 days after the directory switched.
  assert(List.length(renew(root_path, next_set, days(36))?) == 0)
  assert(refused(root_path, List.get(old_mail, 3))?)
  assert(opens(root_path, current_mail, "current")?)
  # Missing intermediate transitions must be visible even if the device IDs
  # have returned to the same set and the old transition bytes were pruned.
  let after_absence = set_wire(first, "4", [next])?
  install(root_path, after_absence)?
  assert(inspect_changed(root_path, after_absence)?)
  assert(!inspect_changed(root_path, after_absence)?)
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

fn paid_retention_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("paid-retention-renewal")?
  let sender = database_path("paid-retention-sender")?
  let later_sender = database_path("paid-retention-later-sender")?
  let final_sender = database_path("paid-retention-final-sender")?
  created(path, "alice")?
  created(sender, "sender")?
  created(later_sender, "later_sender")?
  created(final_sender, "final_sender")?
  let first = logged(entry(directory_entry_export(Bytes.from_utf8(path))?)?)?
  let reusable_key = reusable(path)?
  let first_set = set_wire(first, "1", [first])?
  let retained_mail = sealed(sender,
    handed_out(first, reusable_key)?,
    first_set,
    "retained original TTL")?
  let later_mail = sealed(later_sender,
    handed_out(first, reusable_key)?,
    first_set,
    "after original free grace")?
  let final_mail = sealed(final_sender,
    handed_out(first, reusable_key)?,
    first_set,
    "after paid grace")?
  install(path, first_set)?
  let due = renew(path, first_set, days(91))?
  let next = entry(List.head(due))?
  let next_set = set_wire(first, "2", [next])?
  install(path, next_set)?
  renew(path, next_set, 0)?
  # Keep one explicit core pin across this fixture's receipt and history cache.
  let core_pair = case Crypto.signing_generate() do
    Err(_) -> return Err("core key failed")
    Ok(value) -> value
  end
  let witness_a = case Crypto.signing_generate() do
    Err(_) -> return Err("witness key failed")
    Ok(value) -> value
  end
  let witness_b = case Crypto.signing_generate() do
    Err(_) -> return Err("witness key failed")
    Ok(value) -> value
  end
  let leaves = [leaf_hash(next_set)?]
  let checkpoint = sign_checkpoint(core_pair.private_key,
    core_pair.public_key.bytes,
    wide("1")?,
    leaves,
    Bytes.from_hex(String.repeat("00", 32))?,
    current_time()?)?
  install_group_transparency_for_test(path,
    encode_checkpoint(checkpoint)?,
    encode_consistency_proof(consistency_proof([], leaves)?)?,
    core_pair.public_key.bytes,
    witness_a.public_key.bytes,
    witness_b.public_key.bytes,
    next_set)?
  let wrapping = platform_key()?
  let profile = decode_client_profile(load_profile_export(Bytes.from_utf8(path))?)?
  let device = open_device(profile, wrapping, path)?
  let who = CreditWalletIdentity {
    account_id: profile.account_id,
    device_id: profile.device_id,
    service_key: core_pair.public_key.bytes,
    purpose: 1
  }
  let now_ms = current_time()?
  let now = U64.divide(now_ms, wide("1000")?)?
  let signer = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("RSA failed")
    Ok(value) -> value
  end
  let public = case Crypto.blind_rsa_public(signer) do
    Err(_) -> return Err("public failed")
    Ok(value) -> value
  end
  let issuer = CreditIssuerKey {
    epoch: issuer_epoch(now)?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: Crypto.sha256(Bytes.from_utf8("test-only quote key"))
  }
  let purchased = U64.subtract(now, wide("600")?)?
  let before = load_credit_wallet(path, wrapping, who)?
  let base = add_credit_issuer(before.wallet, issuer, now, 1)?
  let tokens = for index in 0..20 do
    let pending = blind_credit(issuer, who.service_key, purchased)?
    let request = pending.request
    completed_credit_record(finalize_credit(issuer,
        pending,
        sign_credit_request(signer, issuer, request)?)?,
      issuer,
      purchased,
      wrapping,
      who)?
  end
  commit_credit_wallet(path,
    wrapping,
    who,
    before,
    CreditWallet { revision: wide("1")?, records: base.records ++ tokens })?
  let mailbox = Crypto.sha256(profile.entry.mailbox_token)
  let request = sign_credit_retention_request(device.signing_private_key,
    mailbox,
    Crypto.sha256(Bytes.from_utf8("retention-operation")),
    62,
    U64.add(now, wide("300")?)?,
    now_ms)?
  let action = credit_retention_action(request)?
  let reserved = reserve_credit_spend(path,
    wrapping,
    who,
    encode_credit_action(action)?,
    encode_credit_retention_request(request)?,
    now)?
  # An issuance/hold response can be lost after the remote effect succeeds.
  # Restarted cleanup must preserve these keys even before CAR is recovered.
  renew(path, next_set, days(40))?
  let outer = canonical_outer(retained_mail)?
  let expired_outer = case encode_outer_envelope(%{outer |
    expiration: U64.subtract(now_ms, wide("1")?)?
  }) do
    Err(_) -> return Err("test outer encoding failed")
    Ok(value) -> value
  end
  assert(opens(path, expired_outer, "retained original TTL")?)
  let submission = CreditActionSubmission {
    action: action,
    request_body: reserved.request_body,
    frame: decode_credit_frame(reserved.frame)?
  }
  let until = U64.add(U64.multiply(now, wide("1000")?)?, wide(Int.to_string(days(62)))?)?
  let result = encode_credit_retention_result(CreditRetentionResult {
    mailbox_hash: mailbox,
    days: 62,
    effective_until_ms: until
  })?
  let receipt = encode_credit_action_receipt(sign_credit_action_receipt(core_pair.private_key,
    submission,
    Crypto.sha256(Bytes.from_utf8("retention-effect")),
    now,
    result)?)?
  accept_credit_retention_receipt(path, wrapping, who, mailbox, receipt)?
  renew(path, next_set, days(65))?
  assert(opens(path, later_mail, "after original free grace")?)
  renew(path, next_set, days(67))?
  assert(refused(path, final_mail)?)
  for file in [path, sender, later_sender, final_sender] do
    File.delete(file)?
  end
  Ok(true)
end

test("paid retention keeps retired keys through pending recovery and signed lease plus safety grace") do
  case paid_retention_proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
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
  let before_mail = sealed(first_sender, handed_out(linked, key)?, both, "to the device before")?
  install_paths([root_path, linked_path], both)?
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
  install_paths([root_path, linked_path], requested)?
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
  let answered = set_wire(root, "4", [root, answer])?
  let renewed_mail = sealed(second_sender,
    handed_out(answer, key)?,
    answered,
    "to the renewed device")?
  let request_mail = sealed(third_sender,
    handed_out(asking, key)?,
    requested,
    "to the request bundle")?
  install_paths([root_path, linked_path], requested)?
  # The linked device takes on its logged request. Mail still in flight to the
  # bundle from before it opens.
  assert(List.length(renew(linked_path, requested, 0)?) == 0)
  assert(List.length(current_bundle(linked_path)?.extensions) == 2)
  assert(opens(linked_path, before_mail, "to the device before")?)
  # Due or not, it waits for the answer rather than asking again.
  assert(List.length(renew(linked_path, requested, days(91))?) == 0)
  install(linked_path, answered)?
  assert(List.length(renew(linked_path, answered, 0)?) == 0)
  assert(Bytes.secure_equals(current_bundle(linked_path)?.signed_prekey, wanted.signed_prekey))
  assert(Bytes.secure_equals(current_bundle(linked_path)?.post_quantum_prekey,
    wanted.post_quantum_prekey))
  # Mail sealed to its new bundle opens, and so does mail still in flight to
  # the bundle that carried the request.
  assert(opens(linked_path, renewed_mail, "to the renewed device")?)
  assert(opens(linked_path, request_mail, "to the request bundle")?)
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

# This fixture reconstructs a pre-upgrade account-signed credential, retaining
# exactly the old device keys/prekeys and the real encrypted local profile.
fn capability_profile(primary_path :: String,
  target_path :: String,
  mask :: U64) -> DirectoryEntry!String do
  let primary = decode_client_profile(load_profile_export(Bytes.from_utf8(primary_path))?)?
  let target = decode_client_profile(load_profile_export(Bytes.from_utf8(target_path))?)?
  let wrapping = platform_key()?
  let account_keys = open_account(primary, wrapping, primary_path)?
  let previous = target.credential
  let legacy = case issue_renewed_device_credential(account_keys,
    %{previous | capabilities: mask},
    previous.post_quantum_public_key,
    previous.created_at,
    previous.expires_at,
    previous.directory_sequence) do
    Err(_) -> return Err("legacy credential fixture failed")
    Ok(value) -> value
  end
  let wire = case encode_device_credential(legacy) do
    Err(_) -> return Err("legacy credential encoding failed")
    Ok(value) -> value
  end
  let legacy_entry = %{target.entry |
    prekey_bundle: bundle_wire(%{target.bundle | device_credential: wire})?
  }
  let profile_wire = encode_client_profile(legacy_entry, target.account_id, target.device_id)?
  store_updated_session(target_path,
    "profile/v1",
    seal_local(profile_wire, wrapping, local_context("profile/v1")?)?)?
  Ok(legacy_entry)
end

fn legacy_capability_profile(primary_path :: String,
  target_path :: String) -> DirectoryEntry!String do
  capability_profile(primary_path, target_path, wide("1")?)
end

fn primary_capability_upgrade_proof_for(mask_text :: String) -> Bool!String do
  let mask = wide(mask_text)?
  assert(Test.install_in_memory_secure_store())
  let path = database_path("ach3-existing-primary")?
  created(path, "alice")?
  let first = logged(capability_profile(path, path, mask)?)?
  let old_bundle = bundle(first.prekey_bundle)?
  let old_credential = credential(old_bundle.device_credential)?
  assert(!supports_ach3(old_credential.capabilities))
  assert(verified(account(first.account_identity)?, old_bundle)?)
  let first_set = set_wire(first, "1", [first])?
  install(path, first_set)?
  let requests = renew(path, first_set, 0)?
  assert(List.length(requests) == 1)
  let asking = entry(List.head(requests))?
  let asking_bundle = bundle(asking.prekey_bundle)?
  assert(Bytes.secure_equals(asking_bundle.device_credential, old_bundle.device_credential))
  let requested = case bundle_renewal_request(asking_bundle) do
    Ok(Some(value)) -> Ok(value)
    _ -> Err("primary capability request missing")
  end?
  assert(requested.version == 2 && verify_renewal_request(old_credential, requested))
  assert(Option.is_some(requested.requested_capabilities))
  assert(U64.compare(Option.unwrap_or(requested.requested_capabilities, wide("0")?),
    wide("31")?) == 0)
  assert(Bytes.secure_equals(List.head(renew(path, first_set, 0)?), List.head(requests)))
  assert(!supports_ach3(credential(current_bundle(path)?.device_credential)?.capabilities))
  let requested_set = set_wire(first, "2", [asking])?
  install(path, requested_set)?
  let answers = renew(path, requested_set, 0)?
  assert(List.length(answers) == 1)
  let answer = entry(List.head(answers))?
  let answer_bundle = bundle(answer.prekey_bundle)?
  assert(current_readers(credential(answer_bundle.device_credential)?.capabilities))
  assert(U64.compare(credential(answer_bundle.device_credential)?.capabilities, wide("31")?) == 0)
  assert(Bytes.secure_equals(answer_bundle.signed_prekey, requested.signed_prekey))
  assert(Bytes.secure_equals(List.head(renew(path, requested_set, 0)?), List.head(answers)))
  # Another transition can advance the global sequence before our answer lands.
  # Rebasing that same answer must retain the already requested capability mask.
  let intervening_set = set_wire(first, "3", [asking])?
  install(path, intervening_set)?
  let rebased = entry(List.head(renew(path, intervening_set, 0)?))?
  let rebased_bundle = bundle(rebased.prekey_bundle)?
  let rebased_credential = credential(rebased_bundle.device_credential)?
  assert(current_readers(rebased_credential.capabilities))
  assert(U64.compare(rebased_credential.directory_sequence, wide("4")?) == 0)
  assert(Bytes.secure_equals(rebased_bundle.signed_prekey, requested.signed_prekey))
  let confirmed = set_wire(first, "4", [rebased])?
  install(path, confirmed)?
  assert(List.length(renew(path, confirmed, 0)?) == 0)
  assert(current_readers(credential(current_bundle(path)?.device_credential)?.capabilities))
  File.delete(path)?
  Ok(true)
end

test("an existing primary upgrades ACH3 only through its own witnessed signed request and exact rebased answer") do
  case primary_capability_upgrade_proof_for("1") do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

# Recreate the exact pending state an older client can leave before updating.
fn legacy_pending_request(path :: String, modern :: RenewalRequest) -> Result<(), String> do
  let profile = decode_client_profile(load_profile_export(Bytes.from_utf8(path))?)?
  let wrapping = platform_key()?
  let device_keys = open_device(profile, wrapping, path)?
  let zero = case Bytes.repeat(0, 64) do
    Err(_) -> return Err("fixture allocation failed")
    Ok(value) -> value
  end
  let unsigned = %{modern | version: 1, requested_capabilities: None, signature: zero}
  let encoded = case encode_renewal_request(unsigned) do
    Err(_) -> return Err("legacy request encoding failed")
    Ok(value) -> value
  end
  let signature = case Crypto.sign(device_keys.signing_private_key,
    append(Bytes.from_utf8("mesh-msg/v1/device-renewal-request"), encoded)?) do
    Err(_) -> return Err("legacy request signing failed")
    Ok(value) -> value
  end
  let legacy = %{unsigned | signature: signature.bytes}
  assert(verify_renewal_request(profile.credential, legacy))
  let wire = case encode_renewal_request(legacy) do
    Err(_) -> return Err("legacy request encoding failed")
    Ok(value) -> value
  end
  store_updated_session(path,
    "renewal-request/v1",
    seal_local(wire, wrapping, local_context("renewal-request/v1")?)?)
end

fn linked_capability_upgrade_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let primary_path = database_path("ach3-existing-linked-primary")?
  let linked_path = database_path("ach3-existing-linked-device")?
  created(primary_path, "alice")?
  let primary = logged(entry(directory_entry_export(Bytes.from_utf8(primary_path))?)?)?
  let root_set = set_wire(primary, "1", [primary])?
  install(primary_path, root_set)?
  let linking = create_link_request_export(Bytes.from_utf8(linked_path))?
  let authorization = authorize_device_link_for_set_export(request([
    Bytes.from_utf8(primary_path),
    root_set,
    linking
  ])?)?
  complete_device_link_export(request([Bytes.from_utf8(linked_path), authorization])?)?
  let linked = logged(legacy_capability_profile(primary_path, linked_path)?)?
  let old_credential = credential(bundle(linked.prekey_bundle)?.device_credential)?
  assert(!supports_ach3(old_credential.capabilities))
  let both = set_wire(primary, "2", [primary, linked])?
  install_paths([primary_path, linked_path], both)?
  assert(List.length(renew(primary_path, both, 0)?) == 0)
  let prepared = entry(List.head(renew(linked_path, both, 0)?))?
  let modern = case bundle_renewal_request(bundle(prepared.prekey_bundle)?) do
    Ok(Some(value)) -> Ok(value)
    _ -> Err("linked capability request missing")
  end?
  assert(modern.version == 2)
  legacy_pending_request(linked_path, modern)?
  let old_requests = renew(linked_path, both, 0)?
  let old_asking = entry(List.head(old_requests))?
  let legacy = case bundle_renewal_request(bundle(old_asking.prekey_bundle)?) do
    Ok(Some(value)) -> Ok(value)
    _ -> Err("legacy linked request missing")
  end?
  assert(legacy.version == 1 && Option.is_none(legacy.requested_capabilities))
  assert(Bytes.secure_equals(List.head(renew(linked_path, both, 0)?), List.head(old_requests)))
  let legacy_published = set_wire(primary, "3", [primary, old_asking])?
  install_paths([primary_path, linked_path], legacy_published)?
  let legacy_answer = entry(List.head(renew(primary_path, legacy_published, 0)?))?
  assert(!supports_ach3(credential(bundle(legacy_answer.prekey_bundle)?.device_credential)?.capabilities))
  let legacy_confirmed = set_wire(primary, "4", [primary, legacy_answer])?
  install_paths([primary_path, linked_path], legacy_confirmed)?
  let new_requests = renew(linked_path, legacy_confirmed, 0)?
  assert(List.length(new_requests) == 1)
  let asking = entry(List.head(new_requests))?
  let asked = case bundle_renewal_request(bundle(asking.prekey_bundle)?) do
    Ok(Some(value)) -> Ok(value)
    _ -> Err("v2 linked request missing")
  end?
  assert(asked.version == 2)
  assert(verify_renewal_request(credential(bundle(legacy_answer.prekey_bundle)?.device_credential)?,
    asked))
  assert(Bytes.secure_equals(List.head(renew(linked_path, legacy_confirmed, 0)?),
    List.head(new_requests)))
  assert(List.length(renew(primary_path, legacy_confirmed, 0)?) == 0)
  let requested = set_wire(primary, "5", [primary, asking])?
  install_paths([primary_path, linked_path], requested)?
  let answer = entry(List.head(renew(primary_path, requested, 0)?))?
  let answer_bundle = bundle(answer.prekey_bundle)?
  assert(current_readers(credential(answer_bundle.device_credential)?.capabilities))
  assert(Bytes.secure_equals(answer_bundle.signed_prekey, asked.signed_prekey))
  assert(Bytes.secure_equals(answer_bundle.post_quantum_prekey, asked.post_quantum_prekey))
  assert(List.length(renew(linked_path, requested, 0)?) == 0)
  let confirmed = set_wire(primary, "6", [primary, answer])?
  install(linked_path, confirmed)?
  assert(List.length(renew(linked_path, confirmed, 0)?) == 0)
  assert(current_readers(credential(current_bundle(linked_path)?.device_credential)?.capabilities))
  File.delete(primary_path)?
  File.delete(linked_path)?
  Ok(true)
end

test("legacy linked requests retain their masks and only a later witnessed RNWv2 upgrades support") do
  case linked_capability_upgrade_proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn current_readers(mask :: U64) -> Bool do
  supports_ach3(mask)
    && supports_attachment_buckets(mask)
    && supports_header_encryption(mask)
    && supports_group_expiry(mask)
end

test("signed reader mask29 missing ACH3 requests and confirms exact current31 rather than skipping renewal") do
  case primary_capability_upgrade_proof_for("29") do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
