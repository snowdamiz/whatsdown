from Transparency.Client import verify_evidence
from Transparency.Merkle import WitnessAttestation, WitnessKey, checkpoint_conflict, checkpoint_hash, consistency_proof, inclusion_proof, leaf_hash, merkle_root, sign_checkpoint, sign_witness, verify_checkpoint, verify_consistency, verify_inclusion, verify_witnesses
from Transparency.Wire import TransparencyEvidence, TransparencyLookup, TransparencyTreeQuery, decode_transparency_evidence, decode_transparency_lookup, decode_transparency_tree_query, decode_witnesses, encode_checkpoint, encode_transparency_evidence, encode_transparency_lookup, encode_transparency_tree_query, encode_witnesses
from Protocol.V1 import DeviceSet, DirectoryEntry, encode_device_set

fn signing_pair() -> SigningKeyPair ! String do
  case Crypto.signing_generate() do
    Err( _) -> Err("signing failed")
    Ok( value) -> Ok(value)
  end
end

fn repeated(value :: Int, count :: Int) -> Bytes ! String do
  case Bytes.repeat(value, count) do
    Err( _) -> Err("bytes failed")
    Ok( output) -> Ok(output)
  end
end

fn maximal_device_entries(username :: String,
account_identity :: Bytes,
prekey_bundle :: Bytes,
index :: Int,
output :: List < DirectoryEntry >) -> List < DirectoryEntry > ! String do
  if index >= 8 do
    Ok(output)
  else
    maximal_device_entries(username,
    account_identity,
    prekey_bundle,
    index + 1,
    List.append(output,
    DirectoryEntry {
      version : 1,
      username : username,
      account_identity : account_identity,
      prekey_bundle : prekey_bundle,
      mailbox_token : repeated(index + 1, 32) ?
    }))
  end
end

fn maximal_revocations(index :: Int, output :: List < Bytes >) -> List < Bytes > ! String do
  if index >= 32 do
    Ok(output)
  else
    maximal_revocations(index + 1, List.append(output, repeated(index + 64, 16) ?))
  end
end

fn maximal_witnesses(index :: Int, output :: List < WitnessAttestation >) -> List < WitnessAttestation > ! String do
  if index >= 16 do
    Ok(output)
  else
    maximal_witnesses(index + 1,
    List.append(output,
    WitnessAttestation {
      witness_id : "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww",
      checkpoint_hash : repeated(index + 1, 32) ?,
      signature : repeated(index + 32, 64) ?
    }))
  end
end

fn maximal_hashes(value :: Bytes, index :: Int, output :: List < Bytes >) -> List < Bytes > do
  if index >= 4096 do
    output
  else
    maximal_hashes(value, index + 1, List.append(output, value))
  end
end

fn maximal_device_set() -> Bytes ! String do
  let username = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  let account_identity = repeated(41, 16582) ?
  let prekey_bundle = repeated(42, 19312) ?
  case encode_device_set(DeviceSet {
    version : 1,
    username : username,
    account_identity : account_identity,
    sequence : wide("1") ?,
    devices : maximal_device_entries(username, account_identity, prekey_bundle, 0, List.new()) ?,
    revoked_device_ids : maximal_revocations(0, List.new()) ?
  }) do
    Err( _) -> Err("device set encoding failed")
    Ok( value) -> Ok(value)
  end
end

fn transparency_capacity_proof() -> Bool ! String do
  let entry = maximal_device_set() ?
  assert(Bytes.length(entry) == 305260)
  let leaf = leaf_hash(entry) ?
  let leaves = maximal_hashes(leaf, 0, List.new())
  let signer = signing_pair() ?
  let checkpoint = sign_checkpoint(signer.private_key,
  signer.public_key.bytes,
  wide("1") ?,
  leaves,
  repeated(0, 32) ?,
  wide("1000") ?) ?
  let encoded_evidence = encode_transparency_evidence(TransparencyEvidence {
    entry_bytes : entry,
    inclusion : inclusion_proof(leaves, 0) ?,
    consistency : consistency_proof(List.new(), leaves) ?,
    checkpoint : checkpoint,
    witnesses : maximal_witnesses(0, List.new()) ?
  }) ?
  assert(Bytes.length(encoded_evidence) == 570274)
  let evidence = decode_transparency_evidence(encoded_evidence) ?
  assert(Bytes.secure_equals(evidence.entry_bytes, entry))
  let oversized_evidence = case Bytes.concat(encoded_evidence, repeated(0, 1) ?) do
    Err( _) -> Err("bytes failed")
    Ok( value) -> Ok(value)
  end ?
  case decode_transparency_evidence(oversized_evidence) do
    Err( _) -> assert(true)
    Ok( _) -> assert(false)
  end
  let oversized = case Bytes.concat(entry, repeated(0, 1) ?) do
    Err( _) -> Err("bytes failed")
    Ok( value) -> Ok(value)
  end ?
  case leaf_hash(oversized) do
    Err( _) -> assert(true)
    Ok( _) -> assert(false)
  end
  case encode_transparency_evidence(TransparencyEvidence {
    entry_bytes : oversized,
    inclusion : evidence.inclusion,
    consistency : evidence.consistency,
    checkpoint : evidence.checkpoint,
    witnesses : evidence.witnesses
  }) do
    Err( _) -> assert(true)
    Ok( _) -> assert(false)
  end
  Ok(true)
end

fn witness_capacity_proof() -> Bool ! String do
  let encoded = encode_witnesses(maximal_witnesses(0, List.new()) ?) ?
  assert(Bytes.length(encoded) == 2630)
  assert(List.length(decode_witnesses(encoded) ?) == 16)
  let trailing = case Bytes.concat(encoded, repeated(0, 1) ?) do
    Err( _) -> Err("bytes failed")
    Ok( value) -> Ok(value)
  end ?
  case decode_witnesses(trailing) do
    Err( _) -> assert(true)
    Ok( _) -> assert(false)
  end
  Ok(true)
end

fn wide(value :: String) -> U64 ! String do
  case U64.parse(value) do
    Err( _) -> Err("integer failed")
    Ok( output) -> Ok(output)
  end
end

fn transparency_proof() -> Bool ! String do
  let first_leaf = leaf_hash(Bytes.from_utf8("alice/device-set/1")) ?
  let second_leaf = leaf_hash(Bytes.from_utf8("bob/device-set/1")) ?
  let third_leaf = leaf_hash(Bytes.from_utf8("alice/device-set/2")) ?
  let first_tree = [first_leaf, second_leaf]
  let second_tree = [first_leaf, second_leaf, third_leaf]
  let first_root = merkle_root(first_tree) ?
  let second_root = merkle_root(second_tree) ?
  let inclusion = inclusion_proof(second_tree, 2) ?
  assert(verify_inclusion(third_leaf, inclusion, second_root) ?)
  assert(!verify_inclusion(second_leaf, inclusion, second_root) ?)
  let consistency = consistency_proof(first_tree, second_tree) ?
  assert(verify_consistency(first_root, second_root, consistency) ?)
  let split_tree = [first_leaf, leaf_hash(Bytes.from_utf8("substituted")) ?, third_leaf]
  assert(!verify_consistency(first_root,
  merkle_root(split_tree) ?,
  consistency_proof(first_tree, split_tree) ?) ?)
  let log_signer = signing_pair() ?
  let service_public = log_signer.public_key
  let service_private = log_signer.private_key
  let zero = repeated(0, 32) ?
  let first_checkpoint = sign_checkpoint(service_private,
  service_public.bytes,
  wide("1") ?,
  first_tree,
  zero,
  wide("1000") ?) ?
  assert(verify_checkpoint(first_checkpoint, service_public) ?)
  let second_checkpoint = sign_checkpoint(service_private,
  service_public.bytes,
  wide("2") ?,
  second_tree,
  checkpoint_hash(first_checkpoint) ?,
  wide("2000") ?) ?
  assert(verify_checkpoint(second_checkpoint, service_public) ?)
  let witness_a = signing_pair() ?
  let witness_a_public = witness_a.public_key
  let witness_a_private = witness_a.private_key
  let witness_b = signing_pair() ?
  let witness_b_public = witness_b.public_key
  let witness_b_private = witness_b.private_key
  let attestation_a = sign_witness("witness-a", witness_a_private, second_checkpoint) ?
  let attestation_b = sign_witness("witness-b", witness_b_private, second_checkpoint) ?
  let trusted_witnesses = [WitnessKey {
    witness_id : "witness-a",
    public_key : witness_a_public.bytes
  }, WitnessKey {
    witness_id : "witness-b",
    public_key : witness_b_public.bytes
  }]
  assert(verify_witnesses(second_checkpoint, [attestation_a, attestation_b], trusted_witnesses, 2) ?)
  assert(!verify_witnesses(second_checkpoint, [attestation_a], trusted_witnesses, 2) ?)
  let lookup = decode_transparency_lookup(encode_transparency_lookup(TransparencyLookup {
    username : "alice",
    previous_tree_size : 2
  }) ?) ?
  assert(lookup.username == "alice" && lookup.previous_tree_size == 2)
  assert(decode_transparency_tree_query(encode_transparency_tree_query(TransparencyTreeQuery { previous_tree_size : 2 }) ?) ?.previous_tree_size == 2)
  let evidence = decode_transparency_evidence(encode_transparency_evidence(TransparencyEvidence {
    entry_bytes : Bytes.from_utf8("alice/device-set/2"),
    inclusion : inclusion,
    consistency : consistency,
    checkpoint : second_checkpoint,
    witnesses : [attestation_a, attestation_b]
  }) ?) ?
  assert(Bytes.secure_equals(evidence.entry_bytes, Bytes.from_utf8("alice/device-set/2")))
  assert(evidence.inclusion.leaf_index == 2 && evidence.inclusion.tree_size == 3)
  assert(evidence.consistency.old_tree_size == 2 && evidence.consistency.new_tree_size == 3)
  assert(Bytes.secure_equals(evidence.checkpoint.tree_root, second_root))
  assert(List.length(evidence.witnesses) == 2)
  assert(verify_evidence(evidence,
  service_public,
  trusted_witnesses,
  2,
  encode_checkpoint(first_checkpoint) ?) ?)
  assert(!verify_evidence(TransparencyEvidence {
    entry_bytes : Bytes.from_utf8("substituted"),
    inclusion : evidence.inclusion,
    consistency : evidence.consistency,
    checkpoint : evidence.checkpoint,
    witnesses : evidence.witnesses
  },
  service_public,
  trusted_witnesses,
  2,
  encode_checkpoint(first_checkpoint) ?) ?)
  assert(!verify_evidence(TransparencyEvidence {
    entry_bytes : evidence.entry_bytes,
    inclusion : evidence.inclusion,
    consistency : evidence.consistency,
    checkpoint : evidence.checkpoint,
    witnesses : [attestation_a]
  },
  service_public,
  trusted_witnesses,
  2,
  encode_checkpoint(first_checkpoint) ?) ?)
  let encoded_evidence = encode_transparency_evidence(evidence) ?
  let trailing = case Bytes.concat(encoded_evidence, repeated(0, 1) ?) do
    Err( _) -> Err("bytes failed")
    Ok( value) -> Ok(value)
  end ?
  case decode_transparency_evidence(trailing) do
    Err( _) -> assert(true)
    Ok( _) -> assert(false)
  end
  let conflicting = sign_checkpoint(service_private,
  service_public.bytes,
  wide("2") ?,
  split_tree,
  checkpoint_hash(first_checkpoint) ?,
  wide("2000") ?) ?
  assert(checkpoint_conflict(second_checkpoint, conflicting, service_public) ?)
  Ok(true)
end

test("transparency proofs detect substitution, split views, and missing witnesses") do
  case transparency_proof() do
    Err( _) -> assert(false)
    Ok( value) -> assert(value)
  end
end

test("maximal device sets round-trip through bounded transparency evidence") do
  case transparency_capacity_proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end

test("maximal witness sets round-trip at the exact wire ceiling") do
  case witness_capacity_proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
