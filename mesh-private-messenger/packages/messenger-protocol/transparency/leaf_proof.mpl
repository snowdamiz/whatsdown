from Transparency.Merkle import (
  InclusionProof,
  TransparencyCheckpoint,
  proof_matches_log,
  verify_inclusion,
  compact_inclusion_proof_for
)
from Transparency.Wire import encode_inclusion_proof, decode_inclusion_proof

# The route selects the log version. Neither this query nor its answer carries
# an account identifier or entry contents. A reader must verify the path against
# an independently authenticated checkpoint of the requested size and version.
pub struct LeafQuery do
  leaf_index :: Int
  tree_size :: Int
end

pub struct LeafProof do
  leaf_hash :: Bytes
  inclusion :: InclusionProof
end

# Check the path/root/size binding before retaining it. Legacy full-tree
# responses become a compact path; callers still authenticate the checkpoint
# signature and the native witness policy before trusting the original lookup.
pub fn compact_leaf_proof(value :: LeafProof,
  checkpoint :: TransparencyCheckpoint) -> LeafProof!String do
  if !proof_matches_log(checkpoint.version, value.inclusion.version)
    || U64.compare(checkpoint.tree_size, U64.parse(Int.to_string(value.inclusion.tree_size))?) != 0
    || !verify_inclusion(value.leaf_hash, value.inclusion, checkpoint.tree_root)? do
    return Err("invalid_private_leaf")
  end
  let path = if value.inclusion.version == 1 do
    compact_inclusion_proof_for(1, value.inclusion.leaf_hashes, value.inclusion.leaf_index)?
  else
    value.inclusion
  end
  let compact = %{value | inclusion: path}
  encode_leaf_proof(compact)?
  Ok(compact)
end

fn cat(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    return Ok(output)
  end
  let next = case Bytes.concat(output, List.get(parts, index)) do
    Err(_) -> return Err("invalid_leaf_proof")
    Ok(value) -> value
  end
  cat(parts, index + 1, next)
end

fn integer(value :: Int) -> Bytes!String do
  case Bytes.write_u32_be(U64.parse(Int.to_string(value))?) do
    Err(_) -> Err("invalid_leaf_query")
    Ok(value)
  end
end

fn read_integer(bytes :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u32_be(bytes, offset) do
    Err(_) -> Err("invalid_leaf_query")
    Ok(value) -> U64.to_int(value)
  end
end

pub fn encode_leaf_query(value :: LeafQuery) -> Bytes!String do
  if value.leaf_index < 0
    || value.leaf_index >= value.tree_size
    || value.tree_size <= 0
    || value.tree_size > 4294967295 do
    return Err("invalid_leaf_query")
  end
  cat([Bytes.from_hex("014b5451")?, integer(value.leaf_index)?, integer(value.tree_size)?],
    0,
    Bytes.empty())
end

pub fn decode_leaf_query(bytes :: Bytes) -> LeafQuery!String do
  if Bytes.length(bytes) != 12 || Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "014b5451" do
    return Err("invalid_leaf_query")
  end
  let value = LeafQuery { leaf_index: read_integer(bytes, 4)?, tree_size: read_integer(bytes, 8)? }
  encode_leaf_query(value)?
  Ok(value)
end

pub fn encode_leaf_proof(value :: LeafProof) -> Bytes!String do
  if Bytes.length(value.leaf_hash) != 32
    || (value.inclusion.version != 2 && value.inclusion.version != 3)
    || List.length(value.inclusion.leaf_hashes) > 32 do
    return Err("invalid_leaf_proof")
  end
  cat([Bytes.from_hex("014b544c")?, value.leaf_hash, encode_inclusion_proof(value.inclusion)?],
    0,
    Bytes.empty())
end

pub fn decode_leaf_proof(bytes :: Bytes) -> LeafProof!String do
  if Bytes.length(bytes) < 50
    || Bytes.length(bytes) > 1074
    || Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "014b544c" do
    return Err("invalid_leaf_proof")
  end
  let value = LeafProof {
    leaf_hash: Bytes.slice(bytes, 4, 32)?,
    inclusion: decode_inclusion_proof(Bytes.slice(bytes, 36, Bytes.length(bytes) - 36)?)?
  }
  encode_leaf_proof(value)?
  Ok(value)
end
