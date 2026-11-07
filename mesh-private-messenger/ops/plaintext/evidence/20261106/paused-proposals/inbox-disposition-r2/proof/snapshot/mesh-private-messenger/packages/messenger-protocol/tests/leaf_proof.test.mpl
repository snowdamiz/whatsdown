from Transparency.LeafProof import (
  LeafQuery,
  LeafProof,
  encode_leaf_query,
  decode_leaf_query,
  encode_leaf_proof,
  decode_leaf_proof,
  compact_leaf_proof
)
from Transparency.Merkle import (
  InclusionProof,
  TransparencyCheckpoint,
  compact_inclusion_proof_for,
  merkle_root_for,
  verify_inclusion
)

fn bytes(value :: Int, length :: Int) -> Bytes!String do
  case Bytes.repeat(value, length) do
    Err(_) -> Err("fixture bytes")
    Ok(value)
  end
end

fn proof() -> Bool!String do
  let query = LeafQuery { leaf_index: 3, tree_size: 7 }
  let wire = encode_leaf_query(query)?
  assert(Bytes.to_hex(wire) == "014b54510000000300000007")
  assert(decode_leaf_query(wire)?.leaf_index == 3)
  assert(decode_leaf_query(wire)?.tree_size == 7)
  let leaves = for index in 0..7 do
    Crypto.sha256(Bytes.from_utf8("leaf/#{index}"))
  end
  let checkpoint = TransparencyCheckpoint {
    version: 1,
    sequence: U64.parse("1")?,
    tree_size: U64.parse("7")?,
    tree_root: merkle_root_for(1, leaves)?,
    previous_checkpoint_hash: bytes(0, 32)?,
    timestamp: U64.parse("0")?,
    service_public_key: bytes(0, 32)?,
    signature: bytes(0, 64)?
  }
  let full = LeafProof {
    leaf_hash: List.get(leaves, 3),
    inclusion: InclusionProof { version: 1, leaf_index: 3, tree_size: 7, leaf_hashes: leaves }
  }
  let compacted = compact_leaf_proof(full, checkpoint)?
  assert(compacted.inclusion.version == 2 && List.length(compacted.inclusion.leaf_hashes) == 3)
  assert(verify_inclusion(compacted.leaf_hash, compacted.inclusion, checkpoint.tree_root)?)
  for wrong in [
    %{checkpoint | version: 2},
    %{checkpoint | tree_size: U64.parse("8")?},
    %{checkpoint | tree_root: bytes(0, 32)?}
  ] do
    case compact_leaf_proof(full, wrong) do
      Err(_) -> nil
      Ok(_) -> assert(false)
    end
  end
  for version in [1, 2] do
    let path = compact_inclusion_proof_for(version, leaves, 3)?
    let value = LeafProof { leaf_hash: List.get(leaves, 3), inclusion: path }
    let encoded = encode_leaf_proof(value)?
    let decoded = decode_leaf_proof(encoded)?
    assert(Bytes.secure_equals(encode_leaf_proof(decoded)?, encoded))
    assert(verify_inclusion(decoded.leaf_hash,
      decoded.inclusion,
      merkle_root_for(version, leaves)?)?)
    assert(Bytes.length(encoded) == 50 + List.length(path.leaf_hashes) * 32)
    for invalid in [
      Bytes.slice(encoded, 0, Bytes.length(encoded) - 1)?,
      Bytes.concat(encoded, bytes(0, 1)?)?
    ] do
      case decode_leaf_proof(invalid) do
        Err(_) -> nil
        Ok(_) -> assert(false)
      end
    end
  end
  for invalid in [
    LeafQuery { leaf_index: -1, tree_size: 7 },
    LeafQuery { leaf_index: 7, tree_size: 7 },
    LeafQuery { leaf_index: 0, tree_size: 0 },
    LeafQuery { leaf_index: 0, tree_size: 4294967296 }
  ] do
    case encode_leaf_query(invalid) do
      Err(_) -> nil
      Ok(_) -> assert(false)
    end
  end
  for invalid in [
    Bytes.empty(),
    Bytes.from_hex("014b54510000000700000007")?,
    Bytes.from_hex("024b54510000000300000007")?,
    Bytes.concat(wire, bytes(0, 1)?)?
  ] do
    case decode_leaf_query(invalid) do
      Err(_) -> nil
      Ok(_) -> assert(false)
    end
  end
  # Exact u32 bounds and the largest compact path fit one bounded response.
  let maximum = LeafQuery { leaf_index: 0, tree_size: 4294967295 }
  assert(decode_leaf_query(encode_leaf_query(maximum)?)?.tree_size == 4294967295)
  let large = LeafProof {
    leaf_hash: bytes(1, 32)?,
    inclusion: InclusionProof {
      version: 3,
      leaf_index: 0,
      tree_size: 4294967295,
      leaf_hashes: for _index in 0..32 do
        bytes(2, 32)?
      end
    }
  }
  assert(Bytes.length(encode_leaf_proof(large)?) == 1074)
  assert(Bytes.secure_equals(encode_leaf_proof(decode_leaf_proof(encode_leaf_proof(large)?)?)?,
    encode_leaf_proof(large)?))
  # Legacy full-tree responses cannot bypass this compact endpoint's cap.
  case encode_leaf_proof(%{large | inclusion: %{large.inclusion | version: 1, tree_size: 32}}) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  Ok(true)
end

test("leaf queries reveal only an index and exact size and compact responses have canonical bounded framing") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
