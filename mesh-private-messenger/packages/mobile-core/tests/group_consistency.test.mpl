import File
from MobileCore import group_add_export, group_create_export, group_key_package_export, group_receive_export
from Tests.GroupConsistencyAdvance import advance_both
from Tests.GroupConsistencyCrypto import checkpoint, expect_group_key_rejection, tamper_last
from Tests.GroupConsistencySupport import account_fixture, evidence_bytes, request, signing_pair, verify_for, wide
from Tests.Support import repeated
from Transparency.Merkle import TransparencyCheckpoint, leaf_hash

fn read_u32_at(input :: Bytes, offset :: Int) -> Int ! String do
  case Bytes.read_u32_be(input, offset) do
    Err(_) -> Err("output decode failed")
    Ok(value) -> case U64.to_int(value) do
      Err(_) -> Err("output decode failed")
      Ok(parsed) -> Ok(parsed)
    end
  end
end

fn welcome_envelope(input :: Bytes) -> Bytes ! String do
  if Bytes.length(input) < 12 do
    Err("output decode failed")
  else
    let marker = read_u32_at(input, 0) ?
    let count = read_u32_at(input, 4) ?
    let length = read_u32_at(input, 8) ?
    if marker != 4 || count != 1 || length <= 0 || Bytes.length(input) != 12 + length do
      Err("output decode failed")
    else
      Bytes.slice(input, 12, length)
    end
  end
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let alice = account_fixture("group-consistency-alice", "alice") ?
  let bob = account_fixture("group-consistency-bob", "bob") ?
  let mallory = account_fixture("group-consistency-mallory", "mallory") ?
  let carol = account_fixture("group-consistency-carol", "carol") ?
  let alice_leaf = leaf_hash(alice.device_set) ?
  let bob_leaf = leaf_hash(bob.device_set) ?
  let mallory_leaf = leaf_hash(mallory.device_set) ?
  let carol_leaf = leaf_hash(carol.device_set) ?
  let baseline_leaves = [alice_leaf]
  let main_leaves = [alice_leaf, bob_leaf, mallory_leaf, carol_leaf]
  let service_pair = signing_pair() ?
  let witness_a_pair = signing_pair() ?
  let witness_b_pair = signing_pair() ?
  let service_public_key = service_pair.public_key.bytes
  let witness_a_public_key = witness_a_pair.public_key.bytes
  let witness_b_public_key = witness_b_pair.public_key.bytes
  let empty_checkpoint = TransparencyCheckpoint {
    version : 1,
    sequence : wide(0) ?,
    tree_size : wide(0) ?,
    tree_root : repeated(0, 32) ?,
    previous_checkpoint_hash : repeated(0, 32) ?,
    timestamp : wide(0) ?,
    service_public_key : service_public_key,
    signature : repeated(0, 64) ?
  }
  let baseline = checkpoint(service_pair.private_key,
  service_public_key,
  1,
  baseline_leaves,
  empty_checkpoint,
  false) ?
  let baseline_evidence = evidence_bytes(alice.device_set,
  baseline_leaves,
  0,
  List.new(),
  baseline,
  witness_a_pair.private_key,
  witness_b_pair.private_key) ?
  assert(Bytes.secure_equals(verify_for(alice,
  "alice",
  baseline_evidence,
  service_public_key,
  witness_a_public_key,
  witness_b_public_key) ?,
  alice.device_set))
  let group_id = group_create_export(Bytes.from_utf8(alice.path)) ?
  let package_checkpoint = checkpoint(service_pair.private_key,
  service_public_key,
  2,
  main_leaves,
  baseline,
  true) ?
  let bob_direct_evidence = evidence_bytes(bob.device_set,
  main_leaves,
  1,
  List.new(),
  package_checkpoint,
  witness_a_pair.private_key,
  witness_b_pair.private_key) ?
  let _ = verify_for(bob,
  "bob",
  bob_direct_evidence,
  service_public_key,
  witness_a_public_key,
  witness_b_public_key) ?
  let bob_package = group_key_package_export(Bytes.from_utf8(bob.path)) ?
  assert(Bytes.length(bob_package) == 369)
  let fork_checkpoint = checkpoint(service_pair.private_key,
  service_public_key,
  2,
  [mallory_leaf],
  baseline,
  true) ?
  let fork_evidence = evidence_bytes(mallory.device_set,
  [mallory_leaf],
  0,
  List.new(),
  fork_checkpoint,
  witness_a_pair.private_key,
  witness_b_pair.private_key) ?
  let _ = verify_for(mallory,
  "mallory",
  fork_evidence,
  service_public_key,
  witness_a_public_key,
  witness_b_public_key) ?
  let fork_package = group_key_package_export(Bytes.from_utf8(mallory.path)) ?
  let cache_checkpoint = checkpoint(service_pair.private_key,
  service_public_key,
  3,
  main_leaves,
  package_checkpoint,
  true) ?
  let alice_cache_bob = evidence_bytes(bob.device_set,
  main_leaves,
  1,
  baseline_leaves,
  cache_checkpoint,
  witness_a_pair.private_key,
  witness_b_pair.private_key) ?
  let _ = verify_for(alice,
  "bob",
  alice_cache_bob,
  service_public_key,
  witness_a_public_key,
  witness_b_public_key) ?
  let alice_cache_mallory = evidence_bytes(mallory.device_set,
  main_leaves,
  2,
  main_leaves,
  cache_checkpoint,
  witness_a_pair.private_key,
  witness_b_pair.private_key) ?
  let _ = verify_for(alice,
  "mallory",
  alice_cache_mallory,
  service_public_key,
  witness_a_public_key,
  witness_b_public_key) ?
  let alice_cache_carol = evidence_bytes(carol.device_set,
  main_leaves,
  3,
  main_leaves,
  cache_checkpoint,
  witness_a_pair.private_key,
  witness_b_pair.private_key) ?
  let _ = verify_for(alice,
  "carol",
  alice_cache_carol,
  service_public_key,
  witness_a_public_key,
  witness_b_public_key) ?
  let bob_cache = evidence_bytes(bob.device_set,
  main_leaves,
  1,
  main_leaves,
  cache_checkpoint,
  witness_a_pair.private_key,
  witness_b_pair.private_key) ?
  let _ = verify_for(bob,
  "bob",
  bob_cache,
  service_public_key,
  witness_a_public_key,
  witness_b_public_key) ?
  let current = advance_both(alice,
  bob,
  main_leaves,
  cache_checkpoint,
  4,
  129,
  service_pair.private_key,
  service_public_key,
  witness_a_pair.private_key,
  witness_a_public_key,
  witness_b_pair.private_key,
  witness_b_public_key) ?
  assert(Bytes.secure_equals(bob_package, group_key_package_export(Bytes.from_utf8(bob.path)) ?))
  assert(expect_group_key_rejection(alice.path,
  group_id,
  bob.device_set,
  tamper_last(bob_package) ?) ?)
  assert(expect_group_key_rejection(alice.path, group_id, mallory.device_set, fork_package) ?)
  let future_checkpoint = checkpoint(service_pair.private_key,
  service_public_key,
  133,
  main_leaves,
  current,
  true) ?
  let future_evidence = evidence_bytes(carol.device_set,
  main_leaves,
  3,
  List.new(),
  future_checkpoint,
  witness_a_pair.private_key,
  witness_b_pair.private_key) ?
  let _ = verify_for(carol,
  "carol",
  future_evidence,
  service_public_key,
  witness_a_public_key,
  witness_b_public_key) ?
  let future_package = group_key_package_export(Bytes.from_utf8(carol.path)) ?
  assert(expect_group_key_rejection(alice.path, group_id, carol.device_set, future_package) ?)
  let current_alice_evidence = evidence_bytes(alice.device_set,
  main_leaves,
  0,
  main_leaves,
  current,
  witness_a_pair.private_key,
  witness_b_pair.private_key) ?
  case verify_for(alice,
  "alice",
  current_alice_evidence,
  repeated(9, 32) ?,
  witness_a_public_key,
  witness_b_public_key) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "transparency_trust_mismatch")
  end
  let welcome_output = group_add_export(request([Bytes.from_utf8(alice.path), group_id, bob.device_set, bob_package]) ?) ?
  let welcome = welcome_envelope(welcome_output) ?
  assert(Bytes.secure_equals(group_receive_export(request([Bytes.from_utf8(bob.path), welcome]) ?) ?,
  group_id))
  File.delete(alice.path) ?
  File.delete(bob.path) ?
  File.delete(mallory.path) ?
  File.delete(carol.path) ?
  Ok(true)
end

test("mobile groups accept portable signed checkpoint prefixes without bounded ancestry") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
