import File
from Mobile.Codec import current_time
from MobileCore import (
  group_key_package_export,
  group_transparency_valid_for_test,
  replace_transparency_view_for_test,
  transparency_view_bytes_for_test
)
from Tests.GroupConsistencyCrypto import tamper_last
from Tests.GroupConsistencySupport import account_fixture, signing_pair, verify_for, wide
from Tests.Support import evidence_v2, repeated
from Transparency.Merkle import leaf_hash, sign_witness, transparency_sign_checkpoint_root
from Transparency.Tree import tlog_list_oracle, tlog_root

fn fill_hashes(value :: Bytes, count :: Int, index :: Int, hashes :: List<Bytes>) -> List<Bytes> do
  if index >= count do
    hashes
  else
    fill_hashes(value, count, index + 1, List.append(hashes, value))
  end
end

# Compact proofs lift the old 4,096-entry ceiling: the device verifies a log
# past it and keeps only the checkpoint and a few hashes, never the leaves.

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let account = account_fixture("group-consistency-capacity", "capacity")?
  let filler = repeated(7, 32)?
  let leaves = fill_hashes(filler, 5000, 0, List.new()) ++ [leaf_hash(account.device_set)?]
  let size = List.length(leaves)
  let service_pair = signing_pair()?
  let witness_a_pair = signing_pair()?
  let witness_b_pair = signing_pair()?
  let checkpoint = transparency_sign_checkpoint_root(service_pair.private_key,
    service_pair.public_key.bytes,
    wide(1)?,
    wide(size)?,
    tlog_root(1, tlog_list_oracle(1, leaves), size)?,
    repeated(0, 32)?,
    current_time()?)?
  let evidence = evidence_v2(account.device_set,
    leaves,
    size - 1,
    0,
    checkpoint,
    [
      sign_witness("witness-a", witness_a_pair.private_key, checkpoint)?,
      sign_witness("witness-b", witness_b_pair.private_key, checkpoint)?
    ])?
  assert(Bytes.length(evidence) < Bytes.length(account.device_set) + 2048)
  assert(Bytes.secure_equals(verify_for(account,
      "capacity",
      evidence,
      service_pair.public_key.bytes,
      witness_a_pair.public_key.bytes,
      witness_b_pair.public_key.bytes)?,
    account.device_set))
  assert(Bytes.length(group_key_package_export(Bytes.from_utf8(account.path))?) == 369)
  # service key, set_id, checkpoint and one known hash
  let view = transparency_view_bytes_for_test(account.path)?
  assert(Bytes.length(view) == 1 + 3 + 32 + 32 + 188 + 2 + 32)
  assert(group_transparency_valid_for_test(account.path)?)
  # A view whose checkpoint is not the one this device stored is refused.
  let other_checkpoint = tamper_last(Bytes.slice(view, 68, 188)?)?
  let tampered = Bytes.concat(Bytes.concat(Bytes.slice(view, 0, 68)?, other_checkpoint)?,
    Bytes.slice(view, 256, Bytes.length(view) - 256)?)?
  assert(replace_transparency_view_for_test(account.path, tampered)?)
  case group_transparency_valid_for_test(account.path) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "invalid_transparency_view")
  end
  assert(replace_transparency_view_for_test(account.path, Bytes.slice(view, 0, 256)?)?)
  case group_transparency_valid_for_test(account.path) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "invalid_transparency_view")
  end
  assert(replace_transparency_view_for_test(account.path, view)?)
  assert(group_transparency_valid_for_test(account.path)?)
  File.delete(account.path)?
  Ok(true)
end

test("mobile transparency verifies compact evidence past 4,096 entries and keeps a small view") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
