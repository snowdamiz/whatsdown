from Binary.Reader import (
  BinaryReader,
  finish,
  read_fixed,
  read_u16_be,
  read_u8,
  read_vector,
  reader
)
from Transparency.Merkle import (
  ConsistencyProof,
  InclusionProof,
  TransparencyCheckpoint,
  WitnessAttestation,
  checkpoint_bytes,
  proof_matches_log,
  consistency_path_length,
  inclusion_path_length
)

pub struct TransparencyLookup do
  username :: String
  previous_tree_size :: Int
end

pub struct TransparencyTreeQuery do
  previous_tree_size :: Int
  # Zero requests the latest tree (legacy KTS v1); v2 fixes both endpoints.
  new_tree_size :: Int
end

pub struct TransparencyEvidence do
  entry_bytes :: Bytes
  inclusion :: InclusionProof
  consistency :: ConsistencyProof
  checkpoint :: TransparencyCheckpoint
  witnesses :: List<WitnessAttestation>
end

struct ReadInt do
  state :: BinaryReader
  value :: Int
end

struct ReadWide do
  state :: BinaryReader
  value :: U64
end

struct ReadBytes do
  state :: BinaryReader
  value :: Bytes
end

struct ReadHashes do
  state :: BinaryReader
  value :: List<Bytes>
end

struct ReadWitnesses do
  state :: BinaryReader
  value :: List<WitnessAttestation>
end

fn append(left :: Bytes, right :: Bytes) -> Bytes!String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("transparency wire allocation failed")
    Ok(value)
  end
end

fn join(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, append(output, List.get(parts, index))?)
  end
end

fn byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("invalid transparency wire integer")
    Ok(output)
  end
end

fn write_u16(value :: Int) -> Bytes!String do
  case Bytes.write_u16_be(value) do
    Err(_) -> Err("invalid transparency wire integer")
    Ok(output)
  end
end

fn int_wide(value :: Int) -> U64!String do
  if value < 0 do
    Err("invalid transparency wire integer")
  else
    U64.parse(Int.to_string(value))
  end
end

fn write_u32(value :: Int) -> Bytes!String do
  case Bytes.write_u32_be(int_wide(value)?) do
    Err(_) -> Err("invalid transparency wire integer")
    Ok(output)
  end
end

fn write_u64(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err("invalid transparency wire integer")
    Ok(output)
  end
end

fn vector(value :: Bytes) -> Bytes!String do
  join([write_u32(Bytes.length(value))?, value], 0, Bytes.empty())
end

fn open(input :: Bytes, maximum :: Int) -> BinaryReader!String do
  if Bytes.length(input) > maximum do
    Err("transparency wire oversized")
  else
    case reader(input, maximum) do
      Err(_) -> Err("invalid transparency wire")
      Ok(state)
    end
  end
end

fn done(state :: BinaryReader) -> Result<(), String> do
  case finish(state) do
    Err(_) -> Err("invalid transparency wire")
    Ok(_) -> Ok(nil)
  end
end

fn take_u8(state :: BinaryReader) -> ReadInt!String do
  case read_u8(state) do
    Err(_) -> Err("invalid transparency wire")
    Ok((next, value)) -> Ok(ReadInt { state: next, value: value })
  end
end

fn take_u16(state :: BinaryReader) -> ReadInt!String do
  case read_u16_be(state) do
    Err(_) -> Err("invalid transparency wire")
    Ok((next, value)) -> Ok(ReadInt { state: next, value: value })
  end
end

fn take_fixed(state :: BinaryReader, length :: Int) -> ReadBytes!String do
  case read_fixed(state, length) do
    Err(_) -> Err("invalid transparency wire")
    Ok((next, value)) -> Ok(ReadBytes { state: next, value: value })
  end
end

fn take_vector(state :: BinaryReader, maximum :: Int) -> ReadBytes!String do
  case read_vector(state, maximum) do
    Err(_) -> Err("invalid transparency wire")
    Ok((next, value)) -> Ok(ReadBytes { state: next, value: value })
  end
end

fn take_u32(state :: BinaryReader) -> ReadInt!String do
  let value = take_fixed(state, 4)?
  case Bytes.read_u32_be(value.value, 0) do
    Err(_) -> Err("invalid transparency wire integer")
    Ok(output) -> case U64.to_int(output) do
      Err(_) -> Err("invalid transparency wire integer")
      Ok(parsed) -> Ok(ReadInt { state: value.state, value: parsed })
    end
  end
end

fn take_u64(state :: BinaryReader) -> ReadWide!String do
  let value = take_fixed(state, 8)?
  case Bytes.read_u64_be(value.value, 0) do
    Err(_) -> Err("invalid transparency wire integer")
    Ok(output) -> Ok(ReadWide { state: value.state, value: output })
  end
end

fn magic(state :: BinaryReader, expected :: String) -> BinaryReader!String do
  let value = take_fixed(state, 3)?
  if Bytes.secure_equals(value.value, Bytes.from_utf8(expected)) do
    Ok(value.state)
  else
    Err("invalid transparency wire")
  end
end

fn start(input :: Bytes, maximum :: Int, expected :: String) -> BinaryReader!String do
  let version = take_u8(open(input, maximum)?)?
  if version.value != 1 do
    Err("unsupported transparency wire version")
  else
    magic(version.state, expected)
  end
end

fn valid_username_byte(value :: Int) -> Bool do
  (value >= 97 && value <= 122)
    || (value >= 48 && value <= 57)
    || value == 45
    || value == 46
    || value == 95
end

fn valid_username(value :: Bytes, index :: Int) -> Bool do
  if index >= Bytes.length(value) do
    Bytes.length(value) > 0 && Bytes.length(value) <= 64
  else
    case Bytes.get(value, index) do
      Err(_) -> false
      Ok(next) -> valid_username_byte(next) && valid_username(value, index + 1)
    end
  end
end

# Internal reference syntax; account lookups have their own fixed-size KTA wire frame.

pub fn account_lookup_id(reference :: String) -> Bytes!String do
  if !String.starts_with(reference, "@") do
    Ok(Bytes.empty())
  else if String.length(reference) != 65 do
    Err("invalid account lookup")
  else
    let suffix = case Bytes.slice(Bytes.from_utf8(reference), 1, 64) do
      Ok(value)
      Err(_) -> Err("invalid account lookup")
    end?
    let text = case Bytes.to_utf8(suffix) do
      Ok(value)
      Err(_) -> Err("invalid account lookup")
    end?
    case Bytes.from_hex(text) do
      Ok(value) -> if Bytes.length(value) == 32 && Bytes.to_hex(value) == text do
        Ok(value)
      else
        Err("invalid account lookup")
      end
      Err(_) -> Err("invalid account lookup")
    end
  end
end

pub fn encode_transparency_lookup(value :: TransparencyLookup) -> Bytes!String do
  let username = Bytes.from_utf8(value.username)
  let account_id = account_lookup_id(value.username)?
  if value.previous_tree_size < 0 || value.previous_tree_size > 4294967295 do
    Err("invalid transparency lookup")
  else if Bytes.length(account_id) == 32 do
    join([byte(1)?, Bytes.from_utf8("KTA"), account_id, write_u32(value.previous_tree_size)?],
      0,
      Bytes.empty())
  else if !valid_username(username, 0) do
    Err("invalid transparency lookup")
  else
    join([
        byte(1)?,
        Bytes.from_utf8("KTQ"),
        vector(username)?,
        write_u32(value.previous_tree_size)?
      ],
      0,
      Bytes.empty())
  end
end

pub fn decode_transparency_lookup(input :: Bytes) -> TransparencyLookup!String do
  let account_frame = if Bytes.length(input) == 40 do
    case Bytes.slice(input, 1, 3) do
      Ok(tag) -> Bytes.secure_equals(tag, Bytes.from_utf8("KTA"))
      Err(_) -> false
    end
  else
    false
  end
  if account_frame do
    let account = take_fixed(start(input, 40, "KTA")?, 32)?
    let previous = take_u32(account.state)?
    done(previous.state)?
    if previous.value > 4294967295 do
      Err("invalid transparency lookup")
    else
      Ok(TransparencyLookup {
        username: "@" <> Bytes.to_hex(account.value),
        previous_tree_size: previous.value
      })
    end
  else
    let username = take_vector(start(input, 76, "KTQ")?, 64)?
    let previous = take_u32(username.state)?
    done(previous.state)?
    if !valid_username(username.value, 0) || previous.value > 4294967295 do
      Err("invalid transparency lookup")
    else
      case Bytes.to_utf8(username.value) do
        Err(_) -> Err("invalid transparency lookup")
        Ok(value) -> Ok(TransparencyLookup { username: value, previous_tree_size: previous.value })
      end
    end
  end
end

pub fn encode_transparency_tree_query(value :: TransparencyTreeQuery) -> Bytes!String do
  if value.new_tree_size != 0 do
    return encode_consistency_range(value.previous_tree_size, value.new_tree_size)
  end
  if value.previous_tree_size < 0 || value.previous_tree_size > 4294967295 do
    Err("invalid transparency tree query")
  else
    join([byte(1)?, Bytes.from_utf8("KTS"), write_u32(value.previous_tree_size)?], 0, Bytes.empty())
  end
end

pub fn encode_consistency_range(old_size :: Int, new_size :: Int) -> Bytes!String do
  if old_size < 0 || new_size <= 0 || old_size > new_size || new_size > 4294967295 do
    Err("invalid transparency tree query")
  else
    join([byte(2)?, Bytes.from_utf8("KTS"), write_u32(old_size)?, write_u32(new_size)?],
      0,
      Bytes.empty())
  end
end

pub fn decode_transparency_tree_query(input :: Bytes) -> TransparencyTreeQuery!String do
  let header = take_u8(open(input, 12)?)?
  if header.value != 1 && header.value != 2 do
    return Err("unsupported transparency tree query")
  end
  let previous = take_u32(magic(header.state, "KTS")?)?
  let current = if header.value == 2 do
    take_u32(previous.state)?
  else
    ReadInt { state: previous.state, value: 0 }
  end
  done(current.state)?
  if header.value == 2 && (current.value == 0 || previous.value > current.value) do
    Err("invalid transparency tree query")
  else
    Ok(TransparencyTreeQuery { previous_tree_size: previous.value, new_tree_size: current.value })
  end
end

fn encode_hashes(values :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(values) do
    Ok(output)
  else if Bytes.length(List.get(values, index)) != 32 do
    Err("invalid transparency hashes")
  else
    encode_hashes(values, index + 1, append(output, List.get(values, index))?)
  end
end

fn read_hashes(state :: BinaryReader,
  count :: Int,
  index :: Int,
  output :: List<Bytes>) -> ReadHashes!String do
  if index >= count do
    Ok(ReadHashes { state: state, value: output })
  else
    let value = take_fixed(state, 32)?
    read_hashes(value.state, count, index + 1, List.append(output, value.value))
  end
end

fn take_hashes(state :: BinaryReader) -> ReadHashes!String do
  let count = take_u16(state)?
  if count.value > 4096 do
    Err("invalid transparency hashes")
  else
    read_hashes(count.state, count.value, 0, List.new())
  end
end

pub fn encode_inclusion_proof(value :: InclusionProof) -> Bytes!String do
  if !valid_inclusion_shape(value) do
    Err("invalid inclusion proof")
  else
    join([
        byte(value.version)?,
        Bytes.from_utf8("KTI"),
        write_u32(value.leaf_index)?,
        write_u32(value.tree_size)?,
        write_u16(List.length(value.leaf_hashes))?,
        encode_hashes(value.leaf_hashes, 0, Bytes.empty())?
      ],
      0,
      Bytes.empty())
  end
end

fn valid_inclusion_shape(value :: InclusionProof) -> Bool do
  if value.tree_size <= 0
    || value.tree_size > 4294967295
    || value.leaf_index < 0
    || value.leaf_index >= value.tree_size do
    false
  else if value.version == 1 do
    value.tree_size <= 4096 && List.length(value.leaf_hashes) == value.tree_size
  else if value.version == 2 || value.version == 3 do
    List.length(value.leaf_hashes) == inclusion_path_length(value.leaf_index, value.tree_size)
  else
    false
  end
end

fn proof_header(input :: Bytes, expected :: String) -> ReadInt!String do
  let version = take_u8(open(input, 131086)?)?
  if version.value != 1 && version.value != 2 && version.value != 3 do
    Err("unsupported transparency proof version")
  else
    Ok(ReadInt { state: magic(version.state, expected)?, value: version.value })
  end
end

pub fn decode_inclusion_proof(input :: Bytes) -> InclusionProof!String do
  let header = proof_header(input, "KTI")?
  let leaf_index = take_u32(header.state)?
  let tree_size = take_u32(leaf_index.state)?
  let hashes = take_hashes(tree_size.state)?
  done(hashes.state)?
  let proof = InclusionProof {
    version: header.value,
    leaf_index: leaf_index.value,
    tree_size: tree_size.value,
    leaf_hashes: hashes.value
  }
  if !valid_inclusion_shape(proof) do
    Err("invalid inclusion proof")
  else
    Ok(proof)
  end
end

pub fn encode_consistency_proof(value :: ConsistencyProof) -> Bytes!String do
  if !valid_consistency_shape(value) do
    Err("invalid consistency proof")
  else
    join([
        byte(value.version)?,
        Bytes.from_utf8("KTC"),
        write_u32(value.old_tree_size)?,
        write_u32(value.new_tree_size)?,
        write_u16(List.length(value.leaf_hashes))?,
        encode_hashes(value.leaf_hashes, 0, Bytes.empty())?
      ],
      0,
      Bytes.empty())
  end
end

fn valid_consistency_shape(value :: ConsistencyProof) -> Bool do
  if value.old_tree_size < 0
    || value.old_tree_size > value.new_tree_size
    || value.new_tree_size > 4294967295 do
    false
  else if value.version == 1 do
    value.new_tree_size <= 4096 && List.length(value.leaf_hashes) == value.new_tree_size
  else if value.version == 2 || value.version == 3 do
    List.length(value.leaf_hashes) == consistency_path_length(value.old_tree_size,
        value.new_tree_size)
  else
    false
  end
end

pub fn decode_consistency_proof(input :: Bytes) -> ConsistencyProof!String do
  let header = proof_header(input, "KTC")?
  let old_size = take_u32(header.state)?
  let new_size = take_u32(old_size.state)?
  let hashes = take_hashes(new_size.state)?
  done(hashes.state)?
  let proof = ConsistencyProof {
    version: header.value,
    old_tree_size: old_size.value,
    new_tree_size: new_size.value,
    leaf_hashes: hashes.value
  }
  if !valid_consistency_shape(proof) do
    Err("invalid consistency proof")
  else
    Ok(proof)
  end
end

pub fn encode_checkpoint(value :: TransparencyCheckpoint) -> Bytes!String do
  checkpoint_bytes(value)
end

pub fn decode_checkpoint(input :: Bytes) -> TransparencyCheckpoint!String do
  let version = take_u8(open(input, 188)?)?
  if version.value != 1 && version.value != 2 do
    return Err("unsupported transparency checkpoint version")
  end
  let sequence = take_u64(magic(version.state, "KTK")?)?
  let tree_size = take_u64(sequence.state)?
  let tree_root = take_fixed(tree_size.state, 32)?
  let previous = take_fixed(tree_root.state, 32)?
  let timestamp = take_u64(previous.state)?
  let public_key = take_fixed(timestamp.state, 32)?
  let signature = take_fixed(public_key.state, 64)?
  done(signature.state)?
  Ok(TransparencyCheckpoint {
    version: version.value,
    sequence: sequence.value,
    tree_size: tree_size.value,
    tree_root: tree_root.value,
    previous_checkpoint_hash: previous.value,
    timestamp: timestamp.value,
    service_public_key: public_key.value,
    signature: signature.value
  })
end

fn encode_witness_entries(version :: Int,
  values :: List<WitnessAttestation>,
  index :: Int,
  output :: Bytes) -> Bytes!String do
  if index >= List.length(values) do
    Ok(output)
  else
    let value = List.get(values, index)
    let witness_id = Bytes.from_utf8(value.witness_id)
    if Bytes.length(witness_id) == 0
      || Bytes.length(witness_id) > 64
      || Bytes.length(value.checkpoint_hash) != 32
      || (Bytes.length(value.signature) != 64 && Bytes.length(value.signature) != 72) do
      Err("invalid witness attestation")
    else
      let tag = if version == 1 do
        Bytes.empty()
      else if Bytes.length(value.signature) == 64 do
        byte(0)?
      else
        byte(4)?
      end
      encode_witness_entries(version,
        values,
        index + 1,
        append(output,
          join([vector(witness_id)?, value.checkpoint_hash, tag, value.signature],
            0,
            Bytes.empty())?)?)
    end
  end
end

pub fn encode_witnesses(values :: List<WitnessAttestation>) -> Bytes!String do
  let version = if List.any(values, fn(value) -> Bytes.length(value.signature) == 72 end) do
    2
  else
    1
  end
  if List.length(values) > 16 do
    Err("invalid witness attestations")
  else
    join([
        byte(version)?,
        Bytes.from_utf8("KTW"),
        write_u16(List.length(values))?,
        encode_witness_entries(version, values, 0, Bytes.empty())?
      ],
      0,
      Bytes.empty())
  end
end

fn read_witnesses(version :: Int,
  state :: BinaryReader,
  count :: Int,
  index :: Int,
  output :: List<WitnessAttestation>) -> ReadWitnesses!String do
  if index >= count do
    Ok(ReadWitnesses { state: state, value: output })
  else
    let witness_id = take_vector(state, 64)?
    let checkpoint_hash = take_fixed(witness_id.state, 32)?
    let tag = if version == 1 do
      ReadInt { state: checkpoint_hash.state, value: 0 }
    else
      take_u8(checkpoint_hash.state)?
    end
    if tag.value != 0 && tag.value != 4 do
      return Err("unsupported witness signature")
    end
    let length = if tag.value == 0 do
      64
    else
      72
    end
    let signature = take_fixed(tag.state, length)?
    case Bytes.to_utf8(witness_id.value) do
      Err(_) -> Err("invalid witness attestation")
      Ok(id) -> if String.length(id) == 0 do
        Err("invalid witness attestation")
      else
        read_witnesses(version,
          signature.state,
          count,
          index + 1,
          List.append(output,
            WitnessAttestation {
              witness_id: id,
              checkpoint_hash: checkpoint_hash.value,
              signature: signature.value
            }))
      end
    end
  end
end

pub fn decode_witnesses(input :: Bytes) -> List<WitnessAttestation>!String do
  let version = take_u8(open(input, 2774)?)?
  if version.value != 1 && version.value != 2 do
    return Err("unsupported witness wire version")
  end
  let count = take_u16(magic(version.state, "KTW")?)?
  if count.value > 16 do
    Err("invalid witness attestations")
  else
    let values = read_witnesses(version.value, count.state, count.value, 0, List.new())?
    done(values.state)?
    if !Bytes.secure_equals(encode_witnesses(values.value)?, input) do
      Err("noncanonical witness attestations")
    else
      Ok(values.value)
    end
  end
end

pub fn encode_transparency_evidence(value :: TransparencyEvidence) -> Bytes!String do
  if Bytes.length(value.entry_bytes) == 0
    || Bytes.length(value.entry_bytes) > 305260
    || !proof_matches_log(value.checkpoint.version, value.inclusion.version)
    || !proof_matches_log(value.checkpoint.version, value.consistency.version) do
    Err("invalid transparency evidence")
  else
    join([
        byte(value.checkpoint.version)?,
        Bytes.from_utf8("KTE"),
        vector(value.entry_bytes)?,
        vector(encode_inclusion_proof(value.inclusion)?)?,
        vector(encode_consistency_proof(value.consistency)?)?,
        vector(encode_checkpoint(value.checkpoint)?)?,
        vector(encode_witnesses(value.witnesses)?)?
      ],
      0,
      Bytes.empty())
  end
end

pub fn decode_transparency_evidence(input :: Bytes) -> TransparencyEvidence!String do
  let version = take_u8(open(input, 570418)?)?
  if version.value != 1 && version.value != 2 do
    return Err("unsupported transparency evidence version")
  end
  let entry = take_vector(magic(version.state, "KTE")?, 305260)?
  let inclusion_bytes = take_vector(entry.state, 131086)?
  let consistency_bytes = take_vector(inclusion_bytes.state, 131086)?
  let checkpoint_bytes = take_vector(consistency_bytes.state, 188)?
  let witness_bytes = take_vector(checkpoint_bytes.state, 2774)?
  done(witness_bytes.state)?
  let inclusion = decode_inclusion_proof(inclusion_bytes.value)?
  let consistency = decode_consistency_proof(consistency_bytes.value)?
  let checkpoint = decode_checkpoint(checkpoint_bytes.value)?
  let checkpoint_size = U64.to_int(checkpoint.tree_size)?
  if version.value != checkpoint.version
    || !proof_matches_log(checkpoint.version, inclusion.version)
    || !proof_matches_log(checkpoint.version, consistency.version)
    || inclusion.tree_size != checkpoint_size
    || consistency.new_tree_size != checkpoint_size do
    Err("invalid transparency evidence")
  else
    Ok(TransparencyEvidence {
      entry_bytes: entry.value,
      inclusion: inclusion,
      consistency: consistency,
      checkpoint: checkpoint,
      witnesses: decode_witnesses(witness_bytes.value)?
    })
  end
end
