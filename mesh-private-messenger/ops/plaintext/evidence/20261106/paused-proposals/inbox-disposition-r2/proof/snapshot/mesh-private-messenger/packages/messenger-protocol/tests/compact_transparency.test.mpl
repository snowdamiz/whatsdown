from Transparency.Merkle import (
  compact_consistency_proof,
  compact_inclusion_proof,
  consistency_proof,
  inclusion_proof,
  leaf_hash,
  merkle_root,
  verify_consistency,
  verify_inclusion
)
from Transparency.Wire import (
  decode_consistency_proof,
  decode_inclusion_proof,
  decode_transparency_tree_query,
  encode_consistency_range,
  encode_consistency_proof,
  encode_inclusion_proof
)

fn leaves(count :: Int) -> List<Bytes> do
  for index in 0..count do
    Crypto.sha256(Bytes.from_utf8("compact-test/#{index}"))
  end
end

fn prefix(values :: List<Bytes>, count :: Int) -> List<Bytes> do
  for index in 0..count do
    List.get(values, index)
  end
end

# Every prefix pair straddles both balanced and incomplete right subtrees.
# The reference roots use the existing full-tree implementation.
fn all_prefix_pairs() -> Bool!String do
  let all = leaves(65)
  for count in 0..66 do
    let tree = prefix(all, count)
    let root = merkle_root(tree)?
    for old_count in 0..(count + 1) do
      let old_tree = prefix(all, old_count)
      let old_root = merkle_root(old_tree)?
      let proof = compact_consistency_proof(old_tree, tree)?
      assert(proof.version == 2)
      assert(List.length(proof.leaf_hashes) <= 8)
      let decoded = decode_consistency_proof(encode_consistency_proof(proof)?)?
      assert(verify_consistency(old_root, root, decoded)?)
      assert(!verify_consistency(old_root,
        root,
        %{proof | leaf_hashes: List.append(proof.leaf_hashes, root)})?)
      if old_count > 0 do
        assert(!verify_consistency(Crypto.sha256(Bytes.from_utf8("wrong old root")), root, proof)?)
        assert(!verify_consistency(old_root,
          Crypto.sha256(Bytes.from_utf8("wrong new root")),
          proof)?)
      end
    end
    for index in 0..count do
      let proof = compact_inclusion_proof(tree, index)?
      assert(proof.version == 2)
      assert(List.length(proof.leaf_hashes) <= 7)
      let decoded = decode_inclusion_proof(encode_inclusion_proof(proof)?)?
      assert(verify_inclusion(List.get(tree, index), decoded, root)?)
      assert(!verify_inclusion(Crypto.sha256(Bytes.from_utf8("wrong leaf")), proof, root)?)
      assert(!verify_inclusion(List.get(tree, index),
        %{proof | leaf_hashes: List.append(proof.leaf_hashes, root)},
        root)?)
      if List.length(proof.leaf_hashes) > 0 do
        assert(!verify_inclusion(List.get(tree, index),
          %{proof | leaf_hashes: prefix(proof.leaf_hashes, List.length(proof.leaf_hashes) - 1)},
          root)?)
      end
    end
  end
  Ok(true)
end

# RFC 6962 section 2.1.3's seven-leaf example, with Morse's existing domain
# separation. This fixes the path ordering independently of the verifier.
fn example_paths() -> Bool!String do
  let tree = leaves(7)
  let h01 = merkle_root([List.get(tree, 0), List.get(tree, 1)])?
  let h23 = merkle_root([List.get(tree, 2), List.get(tree, 3)])?
  let h45 = merkle_root([List.get(tree, 4), List.get(tree, 5)])?
  let h456 = merkle_root([List.get(tree, 4), List.get(tree, 5), List.get(tree, 6)])?
  let h0123 = merkle_root(prefix(tree, 4))?
  assert(compact_inclusion_proof(tree, 0)?.leaf_hashes == [List.get(tree, 1), h23, h456])
  assert(compact_inclusion_proof(tree, 3)?.leaf_hashes == [List.get(tree, 2), h01, h456])
  assert(compact_inclusion_proof(tree, 6)?.leaf_hashes == [h45, h0123])
  assert(compact_consistency_proof(prefix(tree, 3), tree)?.leaf_hashes == [
      List.get(tree, 2),
      List.get(tree, 3),
      h01,
      h456
    ])
  assert(compact_consistency_proof(prefix(tree, 4), tree)?.leaf_hashes == [h456])
  assert(compact_consistency_proof(prefix(tree, 6), tree)?.leaf_hashes == [
      h45,
      List.get(tree, 6),
      h0123
    ])
  Ok(true)
end

fn compatibility_and_bounds() -> Bool!String do
  let range = decode_transparency_tree_query(encode_consistency_range(4096, 1000000)?)?
  assert(range.previous_tree_size == 4096 && range.new_tree_size == 1000000)
  case encode_consistency_range(10, 9) do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
  let tree = leaves(9)
  let root = merkle_root(tree)?
  let legacy = inclusion_proof(tree, 4)?
  assert(legacy.version == 1)
  assert(verify_inclusion(List.get(tree, 4),
    decode_inclusion_proof(encode_inclusion_proof(legacy)?)?,
    root)?)
  let old_tree = prefix(tree, 3)
  let legacy_consistency = consistency_proof(old_tree, tree)?
  assert(legacy_consistency.version == 1)
  assert(verify_consistency(merkle_root(old_tree)?,
    root,
    decode_consistency_proof(encode_consistency_proof(legacy_consistency)?)?)?)
  let proof = compact_inclusion_proof(tree, 4)?
  assert(!verify_inclusion(List.get(tree, 4), %{proof | version: 3}, root)?)
  assert(!verify_inclusion(List.get(tree, 4), %{proof | leaf_index: 9}, root)?)
  assert(!verify_inclusion(List.get(tree, 4), %{proof | tree_size: 0}, root)?)
  assert(!verify_inclusion(List.get(tree, 4), %{proof | leaf_hashes: [Bytes.empty()]}, root)?)
  let encoded = encode_inclusion_proof(proof)?
  case decode_inclusion_proof(Bytes.concat(encoded, Bytes.from_utf8("x"))?) do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
  # The proof protocol must no longer inherit the 4,096-leaf ceiling.
  let large = leaves(4097)
  let large_proof = compact_inclusion_proof(large, 4096)?
  assert(Bytes.length(encode_inclusion_proof(large_proof)?) <= 14 + 32 * 13)
  assert(verify_inclusion(List.get(large, 4096), large_proof, merkle_root(large)?)?)
  Ok(true)
end

test("compact proofs verify every prefix pair and reject altered or surplus paths") do
  case all_prefix_pairs() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("compact paths follow the RFC 6962 example without changing Morse roots") do
  case example_paths() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("compact wire proofs coexist with bounded legacy proofs and exceed 4096 leaves") do
  case compatibility_and_bounds() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
