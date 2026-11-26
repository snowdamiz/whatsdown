import File
from Mobile.Codec import current_time
from MobileCore import (
  group_add_export,
  group_create_export,
  group_key_package_export,
  group_receive_export,
  group_send_export,
  install_transparency_view_for_test,
  network_status_export,
  transparency_anchor_proof_export,
  transparency_anchor_requests_export,
  verify_transparency_export
)
from Protocol.V1 import DirectoryEntry
from Security.Config import SecurityWitness
from Tests.GroupConsistencyCrypto import tamper_last
from Tests.GroupConsistencySupport import (
  ConsistencyAccount,
  account_fixture,
  request,
  signing_pair,
  wide
)
from Tests.GroupLifecycleWire import envelope_for, output_list
from Tests.Support import (
  consistency_v2,
  evidence_v2,
  install_security_config,
  install_witness_config,
  output_list_items,
  repeated,
  supply_anchor_proofs
)
from Transparency.CompactWire import TransparencyTreeQueryV2, transparency_encode_tree_query_v2
from Transparency.Merkle import TransparencyCheckpoint, leaf_hash, sign_checkpoint, sign_witness
from Transparency.Wire import encode_checkpoint

fn delivery_key() -> Bytes!String do
  case Crypto.x25519_generate() do
    Err(_) -> Err("test delivery key generation failed")
    Ok(value) -> Ok(value.public_key.bytes)
  end
end

fn path_of(account :: ConsistencyAccount) -> Bytes do
  Bytes.from_utf8(account.path)
end

fn error_of(result :: Result<Bytes, String>) -> String do
  case result do
    Ok(_) -> ""
    Err(error) -> error
  end
end

fn requests(account :: ConsistencyAccount) -> List<Bytes>!String do
  output_list_items(transparency_anchor_requests_export(path_of(account))?)
end

fn witnessed(signer :: borrow SigningPrivateKey,
  signer_public_key :: Bytes,
  a :: borrow SigningPrivateKey,
  b :: borrow SigningPrivateKey,
  sequence :: Int,
  leaves :: List<Bytes>,
  index :: Int,
  old_size :: Int,
  entry :: Bytes) -> Bytes!String do
  let checkpoint = sign_checkpoint(signer,
    signer_public_key,
    wide(sequence)?,
    leaves,
    repeated(0, 32)?,
    current_time()?)?
  evidence_v2(entry,
    leaves,
    index,
    old_size,
    checkpoint,
    [sign_witness("witness-a", a, checkpoint)?, sign_witness("witness-b", b, checkpoint)?])
end

fn verify(account :: ConsistencyAccount, username :: String, evidence :: Bytes) -> Bytes!String do
  verify_transparency_export(request([path_of(account), Bytes.from_utf8(username), evidence])?)
end

# Bob's key package names a checkpoint Alice never verified, and Bob has never
# seen the group's baseline. Each fetches one consistency proof for that
# anchor, refuses a tampered one, and retries once.

fn anchor_proof() -> Bool!String do
  let alice = account_fixture("anchor-alice", "alice")?
  let bob = account_fixture("anchor-bob", "bob")?
  let log_key = signing_pair()?
  let a = signing_pair()?
  let b = signing_pair()?
  assert(install_security_config(log_key.public_key.bytes,
    a.public_key.bytes,
    b.public_key.bytes,
    delivery_key()?,
    8))
  let alice_leaf = leaf_hash(alice.device_set)?
  let bob_leaf = leaf_hash(bob.device_set)?
  let log = [alice_leaf, bob_leaf, repeated(7, 32)?]
  verify(alice,
    "alice",
    witnessed(log_key.private_key,
      log_key.public_key.bytes,
      a.private_key,
      b.private_key,
      1,
      [alice_leaf],
      0,
      0,
      alice.device_set)?)?
  let group_id = group_create_export(path_of(alice))?
  verify(bob,
    "bob",
    witnessed(log_key.private_key,
      log_key.public_key.bytes,
      a.private_key,
      b.private_key,
      2,
      List.take(log, 2),
      1,
      0,
      bob.device_set)?)?
  let package = group_key_package_export(path_of(bob))?
  verify(alice,
    "bob",
    witnessed(log_key.private_key,
      log_key.public_key.bytes,
      a.private_key,
      b.private_key,
      3,
      log,
      1,
      1,
      bob.device_set)?)?
  let add = request([path_of(alice), group_id, bob.device_set, package])?
  let needed = error_of(group_add_export(add))
  let query = transparency_encode_tree_query_v2(TransparencyTreeQueryV2 {
    old_size: 2,
    new_size: 3,
    tree: 1
  })?
  assert(needed == "transparency_anchor_proof_needed:" <> Bytes.to_hex(query))
  let pending = requests(alice)?
  assert(List.length(pending) == 1)
  assert(Bytes.secure_equals(Bytes.slice(List.head(pending), 0, 21)?, query))
  # A proof that does not connect the anchor to Alice's view is refused.
  let tampered = transparency_anchor_proof_export(request([
    path_of(alice),
    List.head(pending),
    tamper_last(consistency_v2(log, 2, 3)?)?
  ])?)
  assert(error_of(tampered) == "transparency_anchor_proof_invalid")
  assert(List.length(requests(alice)?) == 0)
  assert(String.starts_with(error_of(group_add_export(add)), "transparency_anchor_proof_needed"))
  assert(supply_anchor_proofs(alice.path, log)? == 1)
  let welcome = List.head(output_list(group_add_export(add)?)?)
  assert(List.length(requests(alice)?) == 0)
  # Bob's view ends at 2 leaves; the group's baseline has 1.
  let joining = request([path_of(bob), welcome])?
  assert(String.starts_with(error_of(group_receive_export(joining)),
    "transparency_anchor_proof_needed"))
  assert(supply_anchor_proofs(bob.path, log)? == 1)
  assert(Bytes.secure_equals(group_receive_export(joining)?, group_id))
  File.delete(alice.path)?
  File.delete(bob.path)?
  Ok(true)
end

fn witness(id :: String, key :: Bytes, label :: String) -> SecurityWitness do
  SecurityWitness { witness_id: id, public_key: key, label: label }
end

fn update_required(account :: ConsistencyAccount) -> Bool!String do
  let status = network_status_export(path_of(account))?
  Ok(List.last(Bytes.to_list(status)) == 1 && Bytes.length(status) > 4)
end

fn install_views(account :: ConsistencyAccount,
  checkpoint :: Bytes,
  sets :: List<Bytes>) -> Result<(), String> do
  let installed = for set in sets do
    install_transparency_view_for_test(account.path, checkpoint, set)?
  end
  if List.all(installed, fn value -> value end) do
    Ok(nil)
  else
    Err("view install failed")
  end
end

# Alice's build moves to a 2 of 3 set; Bob's has not. The group moves with
# Alice's next commit, Bob is told to update until he does, and a welcome
# under the new set waits the same way for Carol's old build.

fn set_change_proof() -> Bool!String do
  let alice = account_fixture("sets-alice", "alice")?
  let bob = account_fixture("sets-bob", "bob")?
  let carol = account_fixture("sets-carol", "carol")?
  let log_key = signing_pair()?
  let a = signing_pair()?
  let b = signing_pair()?
  let x = signing_pair()?
  let y = signing_pair()?
  let z = signing_pair()?
  let delivery = delivery_key()?
  let checkpoint = encode_checkpoint(sign_checkpoint(log_key.private_key,
    log_key.public_key.bytes,
    wide(1)?,
    [leaf_hash(alice.device_set)?, leaf_hash(bob.device_set)?, leaf_hash(carol.device_set)?],
    repeated(0, 32)?,
    current_time()?)?)?
  let log_public = log_key.public_key.bytes
  let a_public = a.public_key.bytes
  let b_public = b.public_key.bytes
  let new_set = [
    witness("x-1", x.public_key.bytes, "Morse"),
    witness("y-2", y.public_key.bytes, "Morse"),
    witness("z-3", z.public_key.bytes, "Acme Labs")
  ]
  let old_build = fn -> install_security_config(log_public, a_public, b_public, delivery, 8) end
  let new_build = fn -> install_witness_config(log_public, delivery, new_set) end
  assert(old_build())
  install_views(alice, checkpoint, [alice.device_set, bob.device_set])?
  install_views(bob, checkpoint, [bob.device_set, alice.device_set])?
  let group_id = group_create_export(path_of(alice))?
  let bob_package = group_key_package_export(path_of(bob))?
  let bob_welcome = List.head(output_list(group_add_export(request([
    path_of(alice),
    group_id,
    bob.device_set,
    bob_package
  ])?)?)?)
  assert(Bytes.secure_equals(group_receive_export(request([path_of(bob), bob_welcome])?)?,
    group_id))
  # Alice updates: her cached sets are looked up again under the new set, and
  # her next send moves the group there with a commit first.
  assert(new_build()?)
  install_views(alice, checkpoint, [alice.device_set, bob.device_set, carol.device_set])?
  let body = Bytes.from_utf8("sent from the new set")
  let sent = output_list(group_send_export(request([path_of(alice), group_id, body])?)?)?
  assert(List.length(sent) == 2)
  let commit = request([path_of(bob), List.get(sent, 0)])?
  let message = request([path_of(bob), List.get(sent, 1)])?
  assert(old_build())
  assert(!update_required(bob)?)
  assert(error_of(group_receive_export(commit)) == "group_witness_set_unknown")
  assert(update_required(bob)?)
  # Bob updates.
  assert(new_build()?)
  assert(!update_required(bob)?)
  assert(Bytes.secure_equals(group_receive_export(commit)?, group_id))
  assert(Bytes.secure_equals(group_receive_export(message)?, body))
  # A welcome under the new set.
  install_views(carol, checkpoint, [carol.device_set, alice.device_set])?
  let carol_package = group_key_package_export(path_of(carol))?
  let carol_welcome = envelope_for(output_list(group_add_export(request([
      path_of(alice),
      group_id,
      carol.device_set,
      carol_package
    ])?)?)?,
    carol.entry.mailbox_token,
    0)?
  let join = request([path_of(carol), carol_welcome])?
  assert(old_build())
  assert(error_of(group_receive_export(join)) == "group_witness_set_unknown")
  assert(new_build()?)
  assert(Bytes.secure_equals(group_receive_export(join)?, group_id))
  File.delete(alice.path)?
  File.delete(bob.path)?
  File.delete(carol.path)?
  Ok(true)
end

fn run(name :: String, value :: Result<Bool, String>) -> Bool do
  case value do
    Err(error) -> do
      println(name <> ": " <> error)
      false
    end
    Ok(result) -> result
  end
end

test("group anchors are proven once from a fetched consistency proof and tampering is refused") do
  assert(Test.install_in_memory_secure_store())
  assert(run("anchor", anchor_proof()))
end

test("groups move to the committer's witness set and older builds are told to update") do
  assert(Test.install_in_memory_secure_store())
  assert(run("sets", set_change_proof()))
end
