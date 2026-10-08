##! Transparency wire version 2: compact RFC 9162 proofs, u64 tree sizes and
##! Morse (kind 1) or C2SP (kind 2) witness attestations. Version 1 frames
##! stay in Transparency.Wire unchanged.

from Binary.Reader import BinaryReader, reader
from Transparency.Codec import (
  tcodec_done,
  tcodec_join,
  tcodec_path,
  tcodec_start,
  tcodec_take_fixed,
  tcodec_take_path,
  tcodec_take_u16,
  tcodec_take_u64,
  tcodec_take_u8,
  tcodec_take_vector,
  tcodec_u16,
  tcodec_u64,
  tcodec_u8,
  tcodec_vector
)
from Transparency.Merkle import TransparencyCheckpoint
from Transparency.Tree import tlog_size_limit
from Transparency.Wire import (
  TransparencyLookup,
  account_lookup_id,
  decode_checkpoint,
  encode_checkpoint
)

pub struct CompactInclusion do
  leaf_index :: Int
  tree_size :: Int
  path :: List<Bytes>
end

pub struct CompactConsistency do
  old_size :: Int
  new_size :: Int
  path :: List<Bytes>
end

pub struct TransparencyTreeQueryV2 do
  old_size :: Int
  new_size :: Int
  tree :: Int
end

pub struct TransparencyLeafQuery do
  leaf_index :: Int
  tree_size :: Int
  tree :: Int
end

pub struct TransparencyLeafProof do
  leaf_hash :: Bytes
  inclusion :: CompactInclusion
end

# kind 1: Morse statement over checkpoint_hash (timestamp 0).
# kind 2: C2SP cosignature/v1 at timestamp seconds (checkpoint_hash empty).

pub struct WitnessCosignature do
  kind :: Int
  witness_id :: String
  checkpoint_hash :: Bytes
  timestamp :: Int
  signature :: Bytes
end

# c2sp_root and c2sp_path are the RFC 6962 root and the audit path of the same
# leaf index at the same tree size; both empty when no kind-2 entry is present.

pub struct TransparencyEvidenceV2 do
  entry_bytes :: Bytes
  inclusion :: CompactInclusion
  consistency :: CompactConsistency
  checkpoint :: TransparencyCheckpoint
  witnesses :: List<WitnessCosignature>
  c2sp_root :: Bytes
  c2sp_path :: List<Bytes>
end

struct ReadCosignatures do
  state :: BinaryReader
  value :: List<WitnessCosignature>
end

fn valid_size(value :: Int) -> Bool do
  value >= 0 && value < tlog_size_limit()
end

fn valid_tree(value :: Int) -> Bool do
  value == 1 || value == 2
end

pub fn transparency_encode_inclusion_v2(value :: CompactInclusion) -> Bytes!String do
  if value.tree_size < 1
    || !valid_size(value.tree_size)
    || value.leaf_index < 0
    || value.leaf_index >= value.tree_size do
    Err("invalid inclusion proof")
  else
    tcodec_join([
      tcodec_u8(2)?,
      Bytes.from_utf8("KTI"),
      tcodec_u64(value.leaf_index)?,
      tcodec_u64(value.tree_size)?,
      tcodec_path(value.path, 64)?
    ])
  end
end

pub fn transparency_decode_inclusion_v2(input :: Bytes) -> CompactInclusion!String do
  let index = tcodec_take_u64(tcodec_start(input, 2069, 2, "KTI")?)?
  let size = tcodec_take_u64(index.state)?
  let path = tcodec_take_path(size.state, 64)?
  tcodec_done(path.state)?
  let value = CompactInclusion { leaf_index: index.value, tree_size: size.value, path: path.value }
  if value.tree_size < 1 || !valid_size(value.tree_size) || value.leaf_index >= value.tree_size do
    Err("invalid inclusion proof")
  else
    Ok(value)
  end
end

pub fn transparency_encode_consistency_v2(value :: CompactConsistency) -> Bytes!String do
  if value.old_size < 0 || value.old_size > value.new_size || !valid_size(value.new_size) do
    Err("invalid consistency proof")
  else
    tcodec_join([
      tcodec_u8(2)?,
      Bytes.from_utf8("KTC"),
      tcodec_u64(value.old_size)?,
      tcodec_u64(value.new_size)?,
      tcodec_path(value.path, 128)?
    ])
  end
end

pub fn transparency_decode_consistency_v2(input :: Bytes) -> CompactConsistency!String do
  let old_size = tcodec_take_u64(tcodec_start(input, 4117, 2, "KTC")?)?
  let new_size = tcodec_take_u64(old_size.state)?
  let path = tcodec_take_path(new_size.state, 128)?
  tcodec_done(path.state)?
  if old_size.value > new_size.value || !valid_size(new_size.value) do
    Err("invalid consistency proof")
  else
    Ok(CompactConsistency { old_size: old_size.value, new_size: new_size.value, path: path.value })
  end
end

fn valid_username(value :: Bytes) -> Bool do
  Bytes.length(value) > 0
    && Bytes.length(value) <= 64
    && List.all(Bytes.to_list(value),
      fn byte -> (byte >= 97 && byte <= 122)
        || (byte >= 48 && byte <= 57)
        || byte == 45
        || byte == 46
        || byte == 95 end)
end

pub fn transparency_encode_lookup_v2(value :: TransparencyLookup) -> Bytes!String do
  let account_id = account_lookup_id(value.username)?
  let username = Bytes.from_utf8(value.username)
  if !valid_size(value.previous_tree_size) do
    Err("invalid transparency lookup")
  else if Bytes.length(account_id) == 32 do
    tcodec_join([
      tcodec_u8(2)?,
      Bytes.from_utf8("KTA"),
      account_id,
      tcodec_u64(value.previous_tree_size)?
    ])
  else if !valid_username(username) do
    Err("invalid transparency lookup")
  else
    tcodec_join([
      tcodec_u8(2)?,
      Bytes.from_utf8("KTQ"),
      tcodec_vector(username)?,
      tcodec_u64(value.previous_tree_size)?
    ])
  end
end

fn account_frame(input :: Bytes) -> Bool do
  Bytes.length(input) == 44
    && case Bytes.slice(input, 1, 3) do
      Ok(tag) -> Bytes.secure_equals(tag, Bytes.from_utf8("KTA"))
      Err(_) -> false
    end
end

fn decode_account_lookup(input :: Bytes) -> TransparencyLookup!String do
  let account = tcodec_take_fixed(tcodec_start(input, 44, 2, "KTA")?, 32)?
  let previous = tcodec_take_u64(account.state)?
  tcodec_done(previous.state)?
  if !valid_size(previous.value) do
    Err("invalid transparency lookup")
  else
    Ok(TransparencyLookup {
      username: "@" <> Bytes.to_hex(account.value),
      previous_tree_size: previous.value
    })
  end
end

pub fn transparency_decode_lookup_v2(input :: Bytes) -> TransparencyLookup!String do
  if account_frame(input) do
    decode_account_lookup(input)
  else
    let username = tcodec_take_vector(tcodec_start(input, 80, 2, "KTQ")?, 64)?
    let previous = tcodec_take_u64(username.state)?
    tcodec_done(previous.state)?
    if !valid_username(username.value) || !valid_size(previous.value) do
      Err("invalid transparency lookup")
    else
      case Bytes.to_utf8(username.value) do
        Err(_) -> Err("invalid transparency lookup")
        Ok(text) -> Ok(TransparencyLookup { username: text, previous_tree_size: previous.value })
      end
    end
  end
end

pub fn transparency_encode_tree_query_v2(value :: TransparencyTreeQueryV2) -> Bytes!String do
  if !valid_size(value.old_size) || !valid_size(value.new_size) || !valid_tree(value.tree) do
    Err("invalid transparency tree query")
  else if value.new_size != 0 && value.old_size > value.new_size do
    Err("invalid transparency tree query")
  else
    tcodec_join([
      tcodec_u8(2)?,
      Bytes.from_utf8("KTS"),
      tcodec_u64(value.old_size)?,
      tcodec_u64(value.new_size)?,
      tcodec_u8(value.tree)?
    ])
  end
end

# new_size 0 asks for the current tree.

pub fn transparency_decode_tree_query_v2(input :: Bytes) -> TransparencyTreeQueryV2!String do
  let old_size = tcodec_take_u64(tcodec_start(input, 21, 2, "KTS")?)?
  let new_size = tcodec_take_u64(old_size.state)?
  let tree = tcodec_take_u8(new_size.state)?
  tcodec_done(tree.state)?
  let value = TransparencyTreeQueryV2 {
    old_size: old_size.value,
    new_size: new_size.value,
    tree: tree.value
  }
  transparency_encode_tree_query_v2(value)?
  Ok(value)
end

pub fn transparency_encode_leaf_query(value :: TransparencyLeafQuery) -> Bytes!String do
  if value.tree_size < 1
    || !valid_size(value.tree_size)
    || value.leaf_index < 0
    || value.leaf_index >= value.tree_size
    || !valid_tree(value.tree) do
    Err("invalid transparency leaf query")
  else
    tcodec_join([
      tcodec_u8(2)?,
      Bytes.from_utf8("KTP"),
      tcodec_u64(value.leaf_index)?,
      tcodec_u64(value.tree_size)?,
      tcodec_u8(value.tree)?
    ])
  end
end

pub fn transparency_decode_leaf_query(input :: Bytes) -> TransparencyLeafQuery!String do
  let index = tcodec_take_u64(tcodec_start(input, 21, 2, "KTP")?)?
  let size = tcodec_take_u64(index.state)?
  let tree = tcodec_take_u8(size.state)?
  tcodec_done(tree.state)?
  let value = TransparencyLeafQuery {
    leaf_index: index.value,
    tree_size: size.value,
    tree: tree.value
  }
  transparency_encode_leaf_query(value)?
  Ok(value)
end

pub fn transparency_encode_leaf_proof(value :: TransparencyLeafProof) -> Bytes!String do
  if Bytes.length(value.leaf_hash) != 32 do
    Err("invalid transparency leaf proof")
  else
    tcodec_join([
      tcodec_u8(2)?,
      Bytes.from_utf8("KTL"),
      value.leaf_hash,
      tcodec_vector(transparency_encode_inclusion_v2(value.inclusion)?)?
    ])
  end
end

pub fn transparency_decode_leaf_proof(input :: Bytes) -> TransparencyLeafProof!String do
  let leaf = tcodec_take_fixed(tcodec_start(input, 2109, 2, "KTL")?, 32)?
  let inclusion = tcodec_take_vector(leaf.state, 2069)?
  tcodec_done(inclusion.state)?
  Ok(TransparencyLeafProof {
    leaf_hash: leaf.value,
    inclusion: transparency_decode_inclusion_v2(inclusion.value)?
  })
end

fn cosignature_body(value :: WitnessCosignature) -> Bytes!String do
  if value.kind == 1
    && Bytes.length(value.checkpoint_hash) == 32
    && Bytes.length(value.signature) == 64 do
    tcodec_join([value.checkpoint_hash, value.signature])
  else if value.kind == 2 && value.timestamp >= 0 && Bytes.length(value.signature) == 64 do
    tcodec_join([tcodec_u64(value.timestamp)?, value.signature])
  else
    Err("invalid witness attestation")
  end
end

fn encode_cosignature(value :: WitnessCosignature) -> Bytes!String do
  let id = Bytes.from_utf8(value.witness_id)
  if Bytes.length(id) == 0 || Bytes.length(id) > 64 do
    Err("invalid witness attestation")
  else
    tcodec_join([tcodec_u8(value.kind)?, tcodec_vector(id)?, cosignature_body(value)?])
  end
end

pub fn transparency_encode_cosignatures(values :: List<WitnessCosignature>) -> Bytes!String do
  if List.length(values) > 16 do
    Err("invalid witness attestations")
  else
    let entries = for value in values do
      encode_cosignature(value)?
    end
    tcodec_join([tcodec_u8(2)?, Bytes.from_utf8("KTW"), tcodec_u16(List.length(values))?]
      ++ entries)
  end
end

fn read_cosignature(state :: BinaryReader) -> ReadCosignatures!String do
  let kind = tcodec_take_u8(state)?
  let id = tcodec_take_vector(kind.state, 64)?
  let witness_id = case Bytes.to_utf8(id.value) do
    Err(_) -> Err("invalid witness attestation")
    Ok(text)
  end?
  if Bytes.length(id.value) == 0 do
    Err("invalid witness attestation")
  else if kind.value == 1 do
    let hash = tcodec_take_fixed(id.state, 32)?
    let signature = tcodec_take_fixed(hash.state, 64)?
    Ok(ReadCosignatures {
      state: signature.state,
      value: [
        WitnessCosignature {
          kind: 1,
          witness_id: witness_id,
          checkpoint_hash: hash.value,
          timestamp: 0,
          signature: signature.value
        }
      ]
    })
  else if kind.value == 2 do
    let timestamp = tcodec_take_u64(id.state)?
    let signature = tcodec_take_fixed(timestamp.state, 64)?
    Ok(ReadCosignatures {
      state: signature.state,
      value: [
        WitnessCosignature {
          kind: 2,
          witness_id: witness_id,
          checkpoint_hash: Bytes.empty(),
          timestamp: timestamp.value,
          signature: signature.value
        }
      ]
    })
  else
    Err("invalid witness attestation")
  end
end

fn read_cosignatures(state :: BinaryReader,
  count :: Int,
  output :: List<WitnessCosignature>) -> ReadCosignatures!String do
  if List.length(output) >= count do
    Ok(ReadCosignatures { state: state, value: output })
  else
    let next = read_cosignature(state)?
    read_cosignatures(next.state, count, output ++ next.value)
  end
end

pub fn transparency_decode_cosignatures(input :: Bytes) -> List<WitnessCosignature>!String do
  let count = tcodec_take_u16(tcodec_start(input, 2646, 2, "KTW")?)?
  if count.value > 16 do
    Err("invalid witness attestations")
  else
    let values = read_cosignatures(count.state, count.value, List.new())?
    tcodec_done(values.state)?
    Ok(values.value)
  end
end

fn encode_c2sp_view(root :: Bytes, path :: List<Bytes>) -> Bytes!String do
  if Bytes.length(root) == 0 && List.length(path) == 0 do
    Ok(Bytes.empty())
  else if Bytes.length(root) != 32 do
    Err("invalid transparency evidence")
  else
    tcodec_join([root, tcodec_path(path, 64)?])
  end
end

fn any_kind_two(values :: List<WitnessCosignature>) -> Bool do
  List.any(values, fn value -> value.kind == 2 end)
end

fn evidence_consistent(value :: TransparencyEvidenceV2) -> Bool!String do
  let size = U64.to_int(value.checkpoint.tree_size)?
  Ok(value.inclusion.tree_size == size
    && value.consistency.new_size == size
    && (Bytes.length(value.c2sp_root) == 32 || !any_kind_two(value.witnesses)))
end

pub fn transparency_encode_evidence_v2(value :: TransparencyEvidenceV2) -> Bytes!String do
  if Bytes.length(value.entry_bytes) == 0
    || Bytes.length(value.entry_bytes) > 305260
    || !evidence_consistent(value)? do
    Err("invalid transparency evidence")
  else
    tcodec_join([
      tcodec_u8(2)?,
      Bytes.from_utf8("KTE"),
      tcodec_vector(value.entry_bytes)?,
      tcodec_vector(transparency_encode_inclusion_v2(value.inclusion)?)?,
      tcodec_vector(transparency_encode_consistency_v2(value.consistency)?)?,
      tcodec_vector(encode_checkpoint(value.checkpoint)?)?,
      tcodec_vector(transparency_encode_cosignatures(value.witnesses)?)?,
      tcodec_vector(encode_c2sp_view(value.c2sp_root, value.c2sp_path)?)?
    ])
  end
end

fn decode_c2sp_path(input :: Bytes) -> List<Bytes>!String do
  if Bytes.length(input) == 0 do
    Ok(List.new())
  else
    let state = case reader(input, 2081) do
      Err(_) -> Err("invalid transparency evidence")
      Ok(value)
    end?
    let root = tcodec_take_fixed(state, 32)?
    let path = tcodec_take_path(root.state, 64)?
    tcodec_done(path.state)?
    Ok(path.value)
  end
end

fn c2sp_root_of(input :: Bytes) -> Bytes!String do
  if Bytes.length(input) == 0 do
    Ok(Bytes.empty())
  else
    case Bytes.slice(input, 0, 32) do
      Err(_) -> Err("invalid transparency evidence")
      Ok(value)
    end
  end
end

pub fn transparency_decode_evidence_v2(input :: Bytes) -> TransparencyEvidenceV2!String do
  let entry = tcodec_take_vector(tcodec_start(input, 316389, 2, "KTE")?, 305260)?
  let inclusion = tcodec_take_vector(entry.state, 2069)?
  let consistency = tcodec_take_vector(inclusion.state, 4117)?
  let checkpoint = tcodec_take_vector(consistency.state, 188)?
  let witnesses = tcodec_take_vector(checkpoint.state, 2646)?
  let view = tcodec_take_vector(witnesses.state, 2081)?
  tcodec_done(view.state)?
  let value = TransparencyEvidenceV2 {
    entry_bytes: entry.value,
    inclusion: transparency_decode_inclusion_v2(inclusion.value)?,
    consistency: transparency_decode_consistency_v2(consistency.value)?,
    checkpoint: decode_checkpoint(checkpoint.value)?,
    witnesses: transparency_decode_cosignatures(witnesses.value)?,
    c2sp_root: c2sp_root_of(view.value)?,
    c2sp_path: decode_c2sp_path(view.value)?
  }
  if Bytes.length(value.entry_bytes) == 0 || !evidence_consistent(value)? do
    Err("invalid transparency evidence")
  else
    Ok(value)
  end
end
