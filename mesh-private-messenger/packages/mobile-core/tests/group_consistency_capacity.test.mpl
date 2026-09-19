import File
from MobileCore import (
  group_key_package_export,
  group_transparency_valid_for_test,
  install_group_transparency_for_test,
  remove_group_transparency_chunk_for_test,
  replace_group_transparency_chunk_for_test
)
from Tests.GroupConsistencyCrypto import checkpoint, tamper_last
from Tests.GroupConsistencySupport import account_fixture, evidence_bytes, signing_pair, verify_for, wide
from Tests.Support import repeated
from Transparency.Merkle import TransparencyCheckpoint, consistency_proof, leaf_hash
from Transparency.Wire import encode_checkpoint, encode_consistency_proof

fn fill_hashes(value :: Bytes, count :: Int, index :: Int, hashes :: List < Bytes >) -> List < Bytes > do
  if index >= count do
    hashes
  else
    fill_hashes(value, count, index + 1, List.append(hashes, value))
  end
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let account = account_fixture("group-consistency-capacity", "capacity") ?
  let account_leaf = leaf_hash(account.device_set) ?
  let filler = repeated(7, 32) ?
  let leaves = fill_hashes(filler, 4096, 1, [account_leaf])
  assert(List.length(leaves) == 4096)
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
  let maximum = checkpoint(service_pair.private_key,
  service_public_key,
  1,
  leaves,
  empty_checkpoint,
  false) ?
  let maximum_consistency = encode_consistency_proof(consistency_proof(List.new(), leaves) ?) ?
  assert(Bytes.length(maximum_consistency) == 131086)
  let maximum_chunk_0 = Bytes.slice(maximum_consistency, 0, 65536) ?
  let maximum_chunk_1 = Bytes.slice(maximum_consistency, 65536, 65536) ?
  let maximum_chunk_2 = Bytes.slice(maximum_consistency, 131072, 14) ?
  let evidence = evidence_bytes(account.device_set,
  leaves,
  0,
  List.new(),
  maximum,
  witness_a_pair.private_key,
  witness_b_pair.private_key) ?
  assert(Bytes.secure_equals(verify_for(account,
  "capacity",
  evidence,
  service_public_key,
  witness_a_public_key,
  witness_b_public_key) ?,
  account.device_set))
  assert(Bytes.length(group_key_package_export(Bytes.from_utf8(account.path)) ?) == 369)
  assert(group_transparency_valid_for_test(account.path) ?)
  assert(remove_group_transparency_chunk_for_test(account.path, 2) ?)
  case group_transparency_valid_for_test(account.path) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "local_state_not_found")
  end
  assert(replace_group_transparency_chunk_for_test(account.path, 2, maximum_chunk_2) ?)
  assert(replace_group_transparency_chunk_for_test(account.path, 0, maximum_chunk_1) ?)
  assert(replace_group_transparency_chunk_for_test(account.path, 1, maximum_chunk_0) ?)
  case group_transparency_valid_for_test(account.path) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "invalid_transparency_view")
  end
  assert(replace_group_transparency_chunk_for_test(account.path, 0, maximum_chunk_0) ?)
  assert(replace_group_transparency_chunk_for_test(account.path, 1, maximum_chunk_1) ?)
  assert(replace_group_transparency_chunk_for_test(account.path, 2, tamper_last(maximum_chunk_2) ?) ?)
  case group_transparency_valid_for_test(account.path) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "invalid_transparency_view")
  end
  assert(replace_group_transparency_chunk_for_test(account.path, 2, maximum_chunk_2) ?)
  assert(group_transparency_valid_for_test(account.path) ?)
  let small_leaves = [account_leaf]
  let small = checkpoint(service_pair.private_key,
  service_public_key,
  1,
  small_leaves,
  empty_checkpoint,
  false) ?
  let small_consistency = encode_consistency_proof(consistency_proof(List.new(), small_leaves) ?) ?
  assert(install_group_transparency_for_test(account.path,
  encode_checkpoint(small) ?,
  small_consistency,
  service_public_key,
  witness_a_public_key,
  witness_b_public_key,
  account.device_set) ?)
  assert(replace_group_transparency_chunk_for_test(account.path, 1, Bytes.from_utf8("extra")) ?)
  case group_transparency_valid_for_test(account.path) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "invalid_transparency_view")
  end
  case consistency_proof(List.new(), List.append(leaves, filler)) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "invalid_consistency_proof")
  end
  File.delete(account.path) ?
  Ok(true)
end

test("mobile transparency preserves 4096 proof leaves and rejects 4097 without truncation") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
