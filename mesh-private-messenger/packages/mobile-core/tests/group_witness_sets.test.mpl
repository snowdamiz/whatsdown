from Groups.Mls import GroupState
from Mobile.Codec import current_time, mobile_read_u32
from Mobile.GroupState import decode_group_key_package, group_join_label, load_group
from Mobile.Profile import load_profile
from Mobile.Types import MobileGroupKeyPackage
from MobileCore import (
  group_add_export,
  group_create_export,
  group_key_package_export,
  group_receive_export,
  group_send_export,
  group_invite_export,
  group_invitation_accept_export,
  group_invitation_complete_export,
  group_invitations_export,
  receive_initial_export,
  receive_message_export,
  reserve_fanout_prekey_export,
  verify_transparency_export
)
from Protocol.V1 import DirectoryEntry, PrekeyBundle, DeviceSet, AccountIdentity
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Prekeys.Bundle import normalize_prekey_bundle
from Tests.GroupConsistencySupport import encode_set, decode_account
from Storage.Keys import platform_key
from Storage.Blobs import load_blob
from Storage.Records import compare_and_swap_blobs
from Tests.GroupConsistencySupport import (
  ConsistencyAccount,
  account_fixture,
  request,
  signing_pair,
  signed_transparency_view,
  wide
)
from Tests.GroupLifecycleSupport import install_signed_transparency
from Tests.GroupLifecycleWire import output_list
from Tests.Support import repeated
from Transparency.Config import decode_security_config, encode_security_config, witness_set_id
from Mobile.Platform import native_security_config
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  compact_consistency_proof,
  compact_inclusion_proof,
  leaf_hash,
  sign_checkpoint,
  sign_witness
)
from Transparency.Wire import TransparencyEvidence, encode_transparency_evidence
from Transport.Packet import decode_client_profile

fn assert_received_fixture(value :: Bool) do
  assert(declassify(value,
    "test-only Boolean assertion of controlled synthetic group welcome identities across witness-set rotation; no application disclosure"))
end

fn install(signer :: Bytes, keys :: List<Bytes>, threshold :: Int) -> Bytes!String do
  let delivery = case Crypto.x25519_generate() do
    Err(_) -> Err("test key failed")
    Ok(value)
  end?
  let pins = for index in 0..List.length(keys) do
    "witness-#{index}" <> " " <> Bytes.to_hex(List.get(keys, index)) <> " Operator"
  end
  let frame = Bytes.from_utf8(String.join([
      "2",
      Bytes.to_hex(signer),
      Bytes.to_hex(delivery.public_key.bytes),
      "8",
      Int.to_string(threshold),
      Int.to_string(List.length(keys))
    ]
      ++ pins
      ++ ["-", "0", "-"],
    "\n"))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), frame))
  Ok(decode_security_config(frame)?.set_id)
end

fn verify(owner :: ConsistencyAccount,
  subject :: ConsistencyAccount,
  index :: Int,
  checkpoint :: TransparencyCheckpoint,
  leaves :: List<Bytes>,
  previous :: List<Bytes>,
  attestations :: List<WitnessAttestation>) -> Result<(), String> do
  let evidence = encode_transparency_evidence(TransparencyEvidence {
    entry_bytes: subject.device_set,
    checkpoint: checkpoint,
    inclusion: compact_inclusion_proof(leaves, index)?,
    consistency: compact_consistency_proof(previous, leaves)?,
    witnesses: attestations
  })?
  verify_transparency_export(request([
    Bytes.from_utf8(owner.path),
    Bytes.from_utf8(subject.username),
    evidence
  ])?)?
  Ok(nil)
end

fn envelope(output :: Bytes) -> Bytes!String do
  assert(mobile_read_u32(Bytes.slice(output, 4, 4)?)? == 1)
  let length = mobile_read_u32(Bytes.slice(output, 8, 4)?)?
  assert(Bytes.length(output) == 12 + length)
  Bytes.slice(output, 12, length)
end

fn consume_state(state :: consume GroupState) do
  nil
end

fn legacy_policy() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let owner = account_fixture("group-legacy-wire", "alice")?
  let fixture = signed_transparency_view([leaf_hash(owner.device_set)?])?
  assert(install_signed_transparency(owner.path, fixture, owner.device_set)?)
  let package = group_key_package_export(Bytes.from_utf8(owner.path))?
  assert(Bytes.length(package) == 369)
  assert(Bytes.length(decode_group_key_package(package)?.set_id) == 0)
  let group = group_create_export(Bytes.from_utf8(owner.path))?
  let key = platform_key()?
  let state = load_group(owner.path, decode_client_profile(load_profile(owner.path)?)?, key, group)?
  assert(state.policy.witness_threshold == 2 && Bytes.length(state.policy.set_id) == 0)
  consume_state(state)
  File.delete(owner.path)?
  Ok(true)
end

test("native v1 keeps legacy group wires so old clients can still join") do
  case legacy_policy() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn normalized_account(label :: String, username :: String) -> ConsistencyAccount!String do
  let owner = account_fixture(label, username)?
  let bundle = case decode_prekey_bundle(owner.entry.prekey_bundle) do
    Ok(value) -> value
    Err(_) -> return Err("invalid test bundle")
  end
  let base = case normalize_prekey_bundle(bundle) do
    Ok(value) -> value
    Err(_) -> return Err("invalid test bundle")
  end
  let encoded = case encode_prekey_bundle(base) do
    Ok(value) -> value
    Err(_) -> return Err("invalid test bundle")
  end
  let account = decode_account(owner.entry.account_identity)?
  Ok(%{owner |
    device_set: encode_set(DeviceSet {
      version: 1,
      username: username,
      account_identity: owner.entry.account_identity,
      sequence: account.directory_sequence,
      devices: [%{owner.entry | prekey_bundle: encoded}],
      revoked_device_ids: []
    })?
  })
end

fn proof(joined :: Bool) -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let alice = normalized_account("group-set-alice", "alice")?
  let bob = normalized_account("group-set-bob", "bob")?
  let signer = signing_pair()?
  let a = signing_pair()?
  let b = signing_pair()?
  let c = signing_pair()?
  let d = signing_pair()?
  let e = signing_pair()?
  let keys = [a.public_key.bytes, b.public_key.bytes, c.public_key.bytes]
  let first_set = install(signer.public_key.bytes, keys, 2)?
  let leaves = [leaf_hash(alice.device_set)?, leaf_hash(bob.device_set)?]
  let checkpoint = sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    wide(1)?,
    leaves,
    repeated(0, 32)?,
    current_time()?)?
  let first = sign_witness("witness-0", a.private_key, checkpoint)?
  let third = sign_witness("witness-2", c.private_key, checkpoint)?
  let attestations = [first, third]
  verify(alice, alice, 0, checkpoint, leaves, List.new(), attestations)?
  verify(alice, bob, 1, checkpoint, leaves, leaves, attestations)?
  verify(bob, bob, 1, checkpoint, leaves, List.new(), attestations)?
  verify(bob, alice, 0, checkpoint, leaves, leaves, attestations)?
  let waiting_group = group_create_export(Bytes.from_utf8(alice.path))?
  reserve_fanout_prekey_export(request([
    Bytes.from_utf8(alice.path),
    bob.device_set,
    alice.device_set,
    bob.entry.prekey_bundle
  ])?)?
  let invitation = output_list(group_invite_export(request([
    Bytes.from_utf8(alice.path),
    bob.device_set,
    alice.device_set,
    waiting_group
  ])?)?)?
  receive_initial_export(request([Bytes.from_utf8(bob.path), List.head(invitation)])?)?
  let pending = output_list(List.head(output_list(group_invitations_export(Bytes.from_utf8(bob.path))?)?))?
  let reference = List.get(pending, 0)
  let accepted = output_list(group_invitation_accept_export(request([
    Bytes.from_utf8(bob.path),
    alice.device_set,
    bob.device_set,
    reference
  ])?)?)?
  receive_message_export(request([Bytes.from_utf8(alice.path), List.head(accepted)])?)?
  let ready = output_list(List.head(output_list(group_invitations_export(Bytes.from_utf8(alice.path))?)?))?
  let completion = request([Bytes.from_utf8(alice.path), bob.device_set, List.get(ready, 0)])?
  let old_group = group_create_export(Bytes.from_utf8(alice.path))?
  let old_package = group_key_package_export(Bytes.from_utf8(bob.path))?
  let old_blob = load_blob(bob.path, group_join_label("package"))?
  assert(Bytes.secure_equals(decode_group_key_package(old_package)?.set_id, first_set))
  let old_welcome = envelope(group_add_export(request([
    Bytes.from_utf8(alice.path),
    old_group,
    bob.device_set,
    old_package
  ])?)?)?
  if joined do
    assert_received_fixture(Bytes.secure_equals(group_receive_export(request([
        Bytes.from_utf8(bob.path),
        old_welcome
      ])?)?,
      old_group))
  end
  # A native pin change preserves checkpoint continuity but invalidates the
  # view, the pending key package and an invitation authorized by the old set.
  let next_set = install(signer.public_key.bytes,
    keys ++ [d.public_key.bytes, e.public_key.bytes],
    3)?
  case group_key_package_export(Bytes.from_utf8(bob.path)) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  let fourth = sign_witness("witness-3", d.private_key, checkpoint)?
  let next_attestations = [first, third, fourth]
  verify(alice, alice, 0, checkpoint, leaves, leaves, next_attestations)?
  verify(alice, bob, 1, checkpoint, leaves, leaves, next_attestations)?
  verify(bob, bob, 1, checkpoint, leaves, leaves, next_attestations)?
  verify(bob, alice, 0, checkpoint, leaves, leaves, next_attestations)?
  if joined do
    let deliveries = output_list(group_send_export(request([
      Bytes.from_utf8(alice.path),
      old_group,
      Bytes.from_utf8("after rotation")
    ])?)?)?
    assert(List.length(deliveries) == 2)
    # The signed policy transition precedes the message in the durable outbox.
    group_receive_export(request([Bytes.from_utf8(bob.path), List.get(deliveries, 0)])?)?
    group_receive_export(request([Bytes.from_utf8(bob.path), List.get(deliveries, 1)])?)?
    let wrapping = platform_key()?
    let current = load_group(bob.path,
      decode_client_profile(load_profile(bob.path)?)?,
      wrapping,
      old_group)?
    assert(current.policy.witness_threshold == 3
      && Bytes.secure_equals(current.policy.set_id, next_set))
    consume_state(current)
  end
  case group_receive_export(request([Bytes.from_utf8(bob.path), old_welcome])?) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  # A previously accepted invitation can renew only after the native change
  # has been verified. The inviter must not complete its stale acceptance.
  case group_invitation_complete_export(completion) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  let renewed = output_list(group_invitation_accept_export(request([
    Bytes.from_utf8(bob.path),
    alice.device_set,
    bob.device_set,
    reference
  ])?)?)?
  assert(List.length(renewed) == 1)
  if joined do
    # The migration release has a different preferred RFC set, but until the
    # server cuts over these already-authenticated invitations use its explicit
    # legacy policy. A delayed old-set package still cannot replace them.
    let config = native_security_config()?
    let rfc_pins = List.take(config.witnesses, 3)
    let migration = %{config |
      version: 3,
      wire_version: 3,
      log_version: 2,
      legacy_threshold: config.threshold,
      legacy_witnesses: config.witnesses,
      threshold: 2,
      witnesses: rfc_pins,
      set_id: witness_set_id(rfc_pins, 2)?
    }
    assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
      encode_security_config(migration)?))
  end
  receive_message_export(request([Bytes.from_utf8(alice.path), List.head(renewed)])?)?
  let joined_welcome = output_list(group_invitation_complete_export(completion)?)?
  assert(List.length(joined_welcome) == 1)
  assert_received_fixture(Bytes.secure_equals(group_receive_export(request([
      Bytes.from_utf8(bob.path),
      List.head(joined_welcome)
    ])?)?,
    waiting_group))
  let group = group_create_export(Bytes.from_utf8(alice.path))?
  let package = group_key_package_export(Bytes.from_utf8(bob.path))?
  assert(!Bytes.secure_equals(old_package, package))
  assert(Bytes.secure_equals(decode_group_key_package(package)?.set_id, next_set))
  assert(decode_group_key_package(package)?.witness_count == 3)
  let current_blob = load_blob(bob.path, group_join_label("package"))?
  # A caller that read the old package cannot overwrite a completed rotation,
  # nor replace one of its private-key records when the compare fails.
  let current_init = load_blob(bob.path, group_join_label("init"))?
  case compare_and_swap_blobs(bob.path,
    [group_join_label("package"), group_join_label("init")],
    [old_blob, old_blob],
    old_blob) do
    Err(error) -> assert(error == "local_state_changed")
    Ok(_) -> assert(false)
  end
  assert(Bytes.secure_equals(load_blob(bob.path, group_join_label("package"))?, current_blob))
  assert(Bytes.secure_equals(load_blob(bob.path, group_join_label("init"))?, current_init))
  let welcome = envelope(group_add_export(request([
    Bytes.from_utf8(alice.path),
    group,
    bob.device_set,
    package
  ])?)?)?
  assert_received_fixture(Bytes.secure_equals(group_receive_export(request([
      Bytes.from_utf8(bob.path),
      welcome
    ])?)?,
    group))
  let key = platform_key()?
  let state = load_group(bob.path, decode_client_profile(load_profile(bob.path)?)?, key, group)?
  assert(state.policy.witness_threshold == 3 && Bytes.secure_equals(state.policy.set_id, next_set))
  consume_state(state)
  File.delete(alice.path)?
  File.delete(bob.path)?
  Ok(true)
end

test("group welcomes bind majority pins and reject invitations across a native set change") do
  case proof(false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("existing groups authenticate a new witness policy before sending under changed native pins") do
  case proof(true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
