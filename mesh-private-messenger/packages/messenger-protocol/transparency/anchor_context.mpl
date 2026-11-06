from Binary.Reader import BinaryReader, reader, read_fixed, read_vector, finish
from Transparency.AnchorRing import decode_anchor_header, decode_anchor_entry
from Transparency.AnchorWitnessSet import decode_anchor_witness_set
from Transparency.Wire import decode_checkpoint, decode_witnesses
from Transparency.Fork import decode_fork
from Transparency.LeafProof import decode_leaf_proof

# Local observation context, not a chain proof. A consumer must independently
# authenticate the accounts before using their contents to attribute a fork.
pub struct AnchorEvidenceContext do
  identity :: Bytes
  checked_at :: U64
  context_slot :: U64
  header :: Bytes
  ring_index :: Int
  entry :: Bytes
  checkpoint :: Bytes
  origin :: String
  served_checkpoint :: Bytes
  consistency :: Bytes
  fork :: Bytes
  witnesses :: Bytes
  witness_set :: Bytes
  private_leaf :: Bytes
  served_leaf :: Bytes
end

fn cat(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    return Ok(output)
  end
  let next = case Bytes.concat(output, List.get(parts, index)) do
    Err(_) -> return Err("invalid_anchor_context")
    Ok(value) -> value
  end
  cat(parts, index + 1, next)
end

fn u32(value :: Int) -> Bytes!String do
  case Bytes.write_u32_be(U64.parse(Int.to_string(value))?) do
    Err(_) -> Err("invalid_anchor_context")
    Ok(value)
  end
end

fn u64(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err("invalid_anchor_context")
    Ok(value)
  end
end

fn vector(value :: Bytes) -> Bytes!String do
  cat([u32(Bytes.length(value))?, value], 0, Bytes.empty())
end

fn valid(value :: AnchorEvidenceContext) -> Result<(), String> do
  if Bytes.length(value.identity) != 32
    || value.ring_index < 0
    || value.ring_index >= 4096
    || Bytes.length(Bytes.from_utf8(value.origin)) > 2048
    || Bytes.length(value.served_checkpoint) > 188
    || Bytes.length(value.consistency) > 1070
    || Bytes.length(value.fork) > 8009
    || Bytes.length(value.witnesses) > 2774
    || Bytes.length(value.private_leaf) > 1074
    || Bytes.length(value.served_leaf) > 1074
    || (Bytes.length(value.witness_set) != 0 && Bytes.length(value.witness_set) != 2752) do
    return Err("invalid_anchor_context")
  end
  decode_anchor_header(value.header)?
  decode_anchor_entry(value.entry)?
  decode_checkpoint(value.checkpoint)?
  if Bytes.length(value.fork) > 0 do
    decode_fork(value.fork)?
  end
  if Bytes.length(value.witnesses) > 0 do
    decode_witnesses(value.witnesses)?
  end
  if Bytes.length(value.witness_set) > 0 do
    decode_anchor_witness_set(value.witness_set)?
  end
  if Bytes.length(value.private_leaf) > 0 do
    decode_leaf_proof(value.private_leaf)?
  end
  Ok(nil)
end

pub fn encode_anchor_context(value :: AnchorEvidenceContext) -> Bytes!String do
  valid(value)?
  cat([
      Bytes.from_utf8("ACV3"),
      value.identity,
      u64(value.checked_at)?,
      u64(value.context_slot)?,
      value.header,
      u32(value.ring_index)?,
      value.entry,
      value.checkpoint,
      vector(Bytes.from_utf8(value.origin))?,
      vector(value.served_checkpoint)?,
      vector(value.consistency)?,
      vector(value.fork)?,
      vector(value.witnesses)?,
      vector(value.witness_set)?,
      vector(value.private_leaf)?,
      vector(value.served_leaf)?
    ],
    0,
    Bytes.empty())
end

fn fixed(state :: BinaryReader, count :: Int) -> Result<(BinaryReader, Bytes), String> do
  case read_fixed(state, count) do
    Err(_) -> Err("invalid_anchor_context")
    Ok(value)
  end
end

fn read_bytes(state :: BinaryReader, maximum :: Int) -> Result<(BinaryReader, Bytes), String> do
  case read_vector(state, maximum) do
    Err(_) -> Err("invalid_anchor_context")
    Ok(value)
  end
end

fn read_wide(bytes :: Bytes, offset :: Int) -> U64!String do
  case Bytes.read_u64_be(bytes, offset) do
    Err(_) -> Err("invalid_anchor_context")
    Ok(value)
  end
end

pub fn decode_anchor_context(bytes :: Bytes) -> AnchorEvidenceContext!String do
  let state = case reader(bytes, 19433) do
    Err(_) -> return Err("invalid_anchor_context")
    Ok(value) -> value
  end
  let (state, prefix) = fixed(state, 412)?
  let magic = Bytes.to_utf8(Bytes.slice(prefix, 0, 4)?)?
  if magic != "ACV1" && magic != "ACV2" && magic != "ACV3" do
    return Err("invalid_anchor_context")
  end
  let index = case Bytes.read_u32_be(prefix, 116) do
    Err(_) -> return Err("invalid_anchor_context")
    Ok(value) -> U64.to_int(value)?
  end
  let (state, origin) = read_bytes(state, 2048)?
  let (state, served) = read_bytes(state, 188)?
  let (state, consistency) = read_bytes(state, 1070)?
  let (state, fork) = read_bytes(state, 8009)?
  let (state, witnesses) = if magic != "ACV1" do
    read_bytes(state, 2774)?
  else
    (state, Bytes.empty())
  end
  let (state, set) = if magic != "ACV1" do
    read_bytes(state, 2752)?
  else
    (state, Bytes.empty())
  end
  let (state, private_leaf) = if magic == "ACV3" do
    read_bytes(state, 1074)?
  else
    (state, Bytes.empty())
  end
  let (state, served_leaf) = if magic == "ACV3" do
    read_bytes(state, 1074)?
  else
    (state, Bytes.empty())
  end
  case finish(state) do
    Err(_) -> return Err("invalid_anchor_context")
    Ok(_) -> nil
  end
  let value = AnchorEvidenceContext {
    identity: Bytes.slice(prefix, 4, 32)?,
    checked_at: read_wide(prefix, 36)?,
    context_slot: read_wide(prefix, 44)?,
    header: Bytes.slice(prefix, 52, 64)?,
    ring_index: index,
    entry: Bytes.slice(prefix, 120, 104)?,
    checkpoint: Bytes.slice(prefix, 224, 188)?,
    origin: Bytes.to_utf8(origin)?,
    served_checkpoint: served,
    consistency: consistency,
    fork: fork,
    witnesses: witnesses,
    witness_set: set,
    private_leaf: private_leaf,
    served_leaf: served_leaf
  }
  valid(value)?
  Ok(value)
end
