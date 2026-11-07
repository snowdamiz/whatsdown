from Binary.Reader import BinaryReader, reader, read_fixed, read_u8, read_vector, finish
from Transparency.Wire import (
  encode_checkpoint,
  decode_checkpoint,
  encode_witnesses,
  decode_witnesses
)
from Transparency.Merkle import TransparencyCheckpoint, WitnessAttestation

pub struct CheckpointHint do
  tree_size :: U64
  tree_root :: Bytes
end

pub type GossipControl do
  CheckpointRequest(Bytes, CheckpointHint)
  CheckpointAnswer(Bytes, TransparencyCheckpoint, List<WitnessAttestation>, Bool)
end

fn cat(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    case Bytes.concat(output, List.get(parts, index)) do
      Err(_) -> Err("invalid_checkpoint_gossip")
      Ok(value) -> cat(parts, index + 1, value)
    end
  end
end

fn byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("invalid_checkpoint_gossip")
    Ok(value)
  end
end

fn vector(value :: Bytes) -> Bytes!String do
  let length = case Bytes.write_u32_be(U64.parse(Int.to_string(Bytes.length(value)))?) do
    Err(_) -> return Err("invalid_checkpoint_gossip")
    Ok(value) -> value
  end
  cat([length, value], 0, Bytes.empty())
end

pub fn encode_hint(value :: CheckpointHint) -> Bytes!String do
  if Bytes.length(value.tree_root) != 32 do
    return Err("invalid_checkpoint_hint")
  end
  let size = case Bytes.write_u64_be(value.tree_size) do
    Err(_) -> return Err("invalid_checkpoint_hint")
    Ok(value) -> value
  end
  cat([size, value.tree_root], 0, Bytes.empty())
end

pub fn decode_hint(value :: Bytes) -> CheckpointHint!String do
  if Bytes.length(value) != 40 do
    return Err("invalid_checkpoint_hint")
  end
  let size = case Bytes.read_u64_be(value, 0) do
    Err(_) -> return Err("invalid_checkpoint_hint")
    Ok(value) -> value
  end
  let root = case Bytes.slice(value, 8, 32) do
    Err(_) -> return Err("invalid_checkpoint_hint")
    Ok(value) -> value
  end
  Ok(CheckpointHint { tree_size: size, tree_root: root })
end

pub fn encode_gossip(value :: GossipControl) -> Bytes!String do
  case value do
    CheckpointRequest(id, hint) -> if Bytes.length(id) != 16 do
      Err("invalid_checkpoint_gossip")
    else
      cat([byte(1)?, Bytes.from_utf8("GQR"), id, encode_hint(hint)?], 0, Bytes.empty())
    end
    CheckpointAnswer(id, checkpoint, attestations, request_peer) -> if Bytes.length(id) != 16 do
      Err("invalid_checkpoint_gossip")
    else
      let flag = if request_peer do
        1
      else
        0
      end
      cat([
          byte(1)?,
          Bytes.from_utf8("GQA"),
          id,
          byte(flag)?,
          encode_checkpoint(checkpoint)?,
          vector(encode_witnesses(attestations)?)?
        ],
        0,
        Bytes.empty())
    end
  end
end

fn take(state :: BinaryReader, count :: Int) -> Result<(BinaryReader, Bytes), String> do
  case read_fixed(state, count) do
    Err(_) -> Err("invalid_checkpoint_gossip")
    Ok(value)
  end
end

fn take_byte(state :: BinaryReader) -> Result<(BinaryReader, Int), String> do
  case read_u8(state) do
    Err(_) -> Err("invalid_checkpoint_gossip")
    Ok(value)
  end
end

fn parse_control(state :: BinaryReader,
  magic :: Bytes,
  id :: Bytes) -> Result<(BinaryReader, GossipControl), String> do
  if Bytes.secure_equals(magic, Bytes.from_utf8("GQR")) do
    let (state, hint) = take(state, 40)?
    Ok((state, CheckpointRequest(id, decode_hint(hint)?)))
  else if Bytes.secure_equals(magic, Bytes.from_utf8("GQA")) do
    let (state, flag) = take_byte(state)?
    if flag > 1 do
      return Err("invalid_checkpoint_gossip")
    end
    let (state, checkpoint) = take(state, 188)?
    let (state, attestations) = case read_vector(state, 2774) do
      Err(_) -> return Err("invalid_checkpoint_gossip")
      Ok(value) -> value
    end
    Ok((state,
      CheckpointAnswer(id,
        decode_checkpoint(checkpoint)?,
        decode_witnesses(attestations)?,
        flag == 1)))
  else
    Err("invalid_checkpoint_gossip")
  end
end

pub fn decode_gossip(value :: Bytes) -> GossipControl!String do
  let state = case reader(value, 2987) do
    Err(_) -> return Err("invalid_checkpoint_gossip")
    Ok(value) -> value
  end
  let (state, version) = take_byte(state)?
  if version != 1 do
    return Err("invalid_checkpoint_gossip")
  end
  let (state, magic) = take(state, 3)?
  let (state, id) = take(state, 16)?
  let (state, control) = parse_control(state, magic, id)?
  case finish(state) do
    Err(_) -> return Err("invalid_checkpoint_gossip")
    Ok(_) -> nil
  end
  if !Bytes.secure_equals(encode_gossip(control)?, value) do
    Err("invalid_checkpoint_gossip")
  else
    Ok(control)
  end
end
