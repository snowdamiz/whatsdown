from Transparency.Merkle import (
  InclusionProof,
  ConsistencyProof,
  verify_inclusion,
  verify_consistency
)
from Transparency.Wire import (
  encode_inclusion_proof,
  decode_inclusion_proof,
  encode_consistency_proof,
  decode_consistency_proof
)
from Transparency.Merkle import (
  leaf_hash_for,
  merkle_root_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  sign_tree_checkpoint_for,
  verify_checkpoint,
  checkpoint_hash,
  sign_witness,
  WitnessKey
)
from Transparency.Wire import (
  TransparencyEvidence,
  encode_checkpoint,
  decode_checkpoint,
  encode_transparency_evidence,
  decode_transparency_evidence
)
from Transparency.Client import verify_evidence
from Transparency.Fork import ForkProof, ForkTarget, fork_same_size, fork_rollback

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn signing_pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("test signing key failed")
    Ok(value)
  end
end

# Independently calculated SHA-256 vectors for RFC 6962 section 2.1,
# with leaf inputs "a", "b", "c". These do not use the Morse tree generator.
fn reference_vectors() -> Bool!String do
  let a = Bytes.from_hex("022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c")?
  let b = Bytes.from_hex("57eb35615d47f34ec714cacdf5fd74608a5e8e102724e80b24b287c0c27b6a31")?
  let c = Bytes.from_hex("597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8")?
  let ab = Bytes.from_hex("b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb")?
  let abc = Bytes.from_hex("36642e73c2540ab121e3a6bf9545b0a24982cd830eb13d3cd19de3ce6c021ec1")?
  let empty = Bytes.from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")?
  assert(Bytes.secure_equals(leaf_hash_for(2, Bytes.from_utf8("a"))?, a))
  assert(Bytes.secure_equals(merkle_root_for(2, [a, b, c])?, abc))
  assert(Bytes.secure_equals(merkle_root_for(2, List.new())?, empty))
  let inclusion = InclusionProof { version: 3, leaf_index: 0, tree_size: 3, leaf_hashes: [b, c] }
  assert(verify_inclusion(a, inclusion, abc)?)
  assert(verify_inclusion(a, decode_inclusion_proof(encode_inclusion_proof(inclusion)?)?, abc)?)
  assert(!verify_inclusion(a, %{inclusion | version: 2}, abc)?)
  assert(!verify_inclusion(a, %{inclusion | leaf_hashes: [c, b]}, abc)?)
  let consistency = ConsistencyProof {
    version: 3,
    old_tree_size: 2,
    new_tree_size: 3,
    leaf_hashes: [c]
  }
  assert(verify_consistency(ab, abc, consistency)?)
  assert(verify_consistency(ab,
    abc,
    decode_consistency_proof(encode_consistency_proof(consistency)?)?)?)
  assert(!verify_consistency(ab, abc, %{consistency | version: 2})?)
  assert(verify_consistency(empty,
    abc,
    %{consistency | old_tree_size: 0, leaf_hashes: List.new()})?)
  assert(!verify_consistency(empty, abc, %{consistency | old_tree_size: 0, leaf_hashes: [c]})?)
  Ok(true)
end

fn signed_profiles() -> Bool!String do
  let signer = signing_pair()?
  let witness = signing_pair()?
  let pins = [WitnessKey { witness_id: "test", public_key: witness.public_key.bytes }]
  let zero = Bytes.from_hex("0000000000000000000000000000000000000000000000000000000000000000")?
  let entry = Bytes.from_utf8("profile-test")
  let tree = [leaf_hash_for(2, entry)?, leaf_hash_for(2, Bytes.from_utf8("second"))?]
  let checkpoint = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(1)?,
    wide(2)?,
    merkle_root_for(2, tree)?,
    zero,
    wide(1000)?)?
  assert(verify_checkpoint(decode_checkpoint(encode_checkpoint(checkpoint)?)?, signer.public_key)?)
  assert(!verify_checkpoint(%{checkpoint | version: 1}, signer.public_key)?)
  assert(!Bytes.secure_equals(checkpoint_hash(checkpoint)?,
    checkpoint_hash(%{checkpoint | version: 1})?))
  let evidence = TransparencyEvidence {
    entry_bytes: entry,
    inclusion: compact_inclusion_proof_for(2, tree, 0)?,
    consistency: compact_consistency_proof_for(2, List.new(), tree)?,
    checkpoint: checkpoint,
    witnesses: [sign_witness("test", witness.private_key, checkpoint)?]
  }
  assert(verify_evidence(evidence, signer.public_key, pins, 1, Bytes.empty())?)
  let encoded = encode_transparency_evidence(evidence)?
  assert(Bytes.get(encoded, 0)? == 2)
  assert(verify_evidence(decode_transparency_evidence(encoded)?,
    signer.public_key,
    pins,
    1,
    Bytes.empty())?)
  assert(!verify_evidence(%{evidence | inclusion: %{evidence.inclusion | version: 2}},
    signer.public_key,
    pins,
    1,
    Bytes.empty())?)
  assert(!verify_evidence(%{evidence | consistency: %{evidence.consistency | version: 2}},
    signer.public_key,
    pins,
    1,
    Bytes.empty())?)
  # A perfectly valid legacy checkpoint cannot silently reset the new log.
  let old = sign_tree_checkpoint_for(1,
    signer.private_key,
    signer.public_key.bytes,
    wide(1)?,
    wide(2)?,
    merkle_root_for(1, tree)?,
    zero,
    wide(1000)?)?
  let same_size = %{evidence | consistency: compact_consistency_proof_for(2, tree, tree)?}
  assert(!verify_evidence(same_size, signer.public_key, pins, 1, encode_checkpoint(old)?)?)
  Ok(true)
end

test("signed log versions bind evidence, wire framing, and cached history") do
  case signed_profiles() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn versioned_forks() -> Bool!String do
  let signer = signing_pair()?
  let zero = Bytes.from_hex("0000000000000000000000000000000000000000000000000000000000000000")?
  let tree = [leaf_hash_for(2, Bytes.from_utf8("a"))?, leaf_hash_for(2, Bytes.from_utf8("b"))?]
  let old = sign_tree_checkpoint_for(1,
    signer.private_key,
    signer.public_key.bytes,
    wide(1)?,
    wide(2)?,
    merkle_root_for(1, tree)?,
    zero,
    wide(1000)?)?
  let current = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(1)?,
    wide(2)?,
    merkle_root_for(2, tree)?,
    zero,
    wide(1000)?)?
  let proof = ForkProof {
    kind: 1,
    finder: zero,
    service_public_key: signer.public_key.bytes,
    first: old,
    second: SignedCheckpoint(current),
    attestations: List.new(),
    contradiction: None
  }
  case fork_same_size(proof, signer.public_key, List.new()) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  case fork_rollback(%{proof | kind: 3}, signer.public_key, List.new()) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  let conflict = sign_tree_checkpoint_for(2,
    signer.private_key,
    signer.public_key.bytes,
    wide(3)?,
    wide(2)?,
    merkle_root_for(2, [List.get(tree, 1), List.get(tree, 0)])?,
    zero,
    wide(2000)?)?
  let proven = fork_same_size(%{proof | first: current, second: SignedCheckpoint(conflict)},
    signer.public_key,
    List.new())?
  assert(Bytes.secure_equals(proven.service_public_key, signer.public_key.bytes))
  Ok(true)
end

test("changing the log hash profile is never itself slashable fork evidence") do
  case versioned_forks() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("versioned compact proofs use RFC 6962 hashes without reinterpreting legacy roots") do
  case reference_vectors() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
