from Binary.Reader import BinaryReader, finish, read_fixed, read_u16_be, read_u8, read_vector, reader
from Transparency.Merkle import ConsistencyProof, InclusionProof, TransparencyCheckpoint, WitnessAttestation

pub struct TransparencyLookup do
  username :: String
  previous_tree_size :: Int
end

pub struct TransparencyTreeQuery do
  previous_tree_size :: Int
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
  (value >= 97 && value <= 122) || (value >= 48 && value <= 57) || value == 45 || value == 46 || value == 95
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
  if value.previous_tree_size < 0 || value.previous_tree_size > 4096 do
    Err("invalid transparency lookup")
  else if Bytes.length(account_id) == 32 do
    join([byte(1)?, Bytes.from_utf8("KTA"), account_id, write_u32(value.previous_tree_size)?],
      0,
      Bytes.empty())
  else if !valid_username(username, 0) do
    Err("invalid transparency lookup")
  else
    join([byte(1)?, Bytes.from_utf8("KTQ"), vector(username)?, write_u32(value.previous_tree_size)?],
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
    if previous.value > 4096 do
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
    if !valid_username(username.value, 0) || previous.value > 4096 do
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
  if value.previous_tree_size < 0 || value.previous_tree_size > 4096 do
    Err("invalid transparency tree query")
  else
    join([byte(1)?, Bytes.from_utf8("KTS"), write_u32(value.previous_tree_size)?], 0, Bytes.empty())
  end
end

pub fn decode_transparency_tree_query(input :: Bytes) -> TransparencyTreeQuery!String do
  let previous = take_u32(start(input, 8, "KTS")?)?
  done(previous.state)?
  if previous.value > 4096 do
    Err("invalid transparency tree query")
  else
    Ok(TransparencyTreeQuery { previous_tree_size: previous.value })
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

fn read_hashes(state :: BinaryReader, count :: Int, index :: Int, output :: List<Bytes>) -> ReadHashes!String do
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
  if value.tree_size != List.length(value.leaf_hashes) || value.tree_size <= 0 || value.tree_size > 4096 || value.leaf_index < 0 || value.leaf_index >= value.tree_size do
    Err("invalid inclusion proof")
  else
    join([
        byte(1)?,
        Bytes.from_utf8("KTI"),
        write_u32(value.leaf_index)?,
        write_u32(value.tree_size)?,
        write_u16(value.tree_size)?,
        encode_hashes(value.leaf_hashes, 0, Bytes.empty())?
      ],
      0,
      Bytes.empty())
  end
end

pub fn decode_inclusion_proof(input :: Bytes) -> InclusionProof!String do
  let leaf_index = take_u32(start(input, 131086, "KTI")?)?
  let tree_size = take_u32(leaf_index.state)?
  let hashes = take_hashes(tree_size.state)?
  done(hashes.state)?
  if tree_size.value != List.length(hashes.value) || tree_size.value <= 0 || leaf_index.value >= tree_size.value do
    Err("invalid inclusion proof")
  else
    Ok(InclusionProof {
      leaf_index: leaf_index.value,
      tree_size: tree_size.value,
      leaf_hashes: hashes.value
    })
  end
end

pub fn encode_consistency_proof(value :: ConsistencyProof) -> Bytes!String do
  if value.old_tree_size < 0 || value.old_tree_size > value.new_tree_size || value.new_tree_size != List.length(value.leaf_hashes) || value.new_tree_size > 4096 do
    Err("invalid consistency proof")
  else
    join([
        byte(1)?,
        Bytes.from_utf8("KTC"),
        write_u32(value.old_tree_size)?,
        write_u32(value.new_tree_size)?,
        write_u16(value.new_tree_size)?,
        encode_hashes(value.leaf_hashes, 0, Bytes.empty())?
      ],
      0,
      Bytes.empty())
  end
end

pub fn decode_consistency_proof(input :: Bytes) -> ConsistencyProof!String do
  let old_size = take_u32(start(input, 131086, "KTC")?)?
  let new_size = take_u32(old_size.state)?
  let hashes = take_hashes(new_size.state)?
  done(hashes.state)?
  if old_size.value > new_size.value || new_size.value != List.length(hashes.value) do
    Err("invalid consistency proof")
  else
    Ok(ConsistencyProof {
      old_tree_size: old_size.value,
      new_tree_size: new_size.value,
      leaf_hashes: hashes.value
    })
  end
end

pub fn encode_checkpoint(value :: TransparencyCheckpoint) -> Bytes!String do
  if value.version != 1 || Bytes.length(value.tree_root) != 32 || Bytes.length(value.previous_checkpoint_hash) != 32 || Bytes.length(value.service_public_key) != 32 || Bytes.length(value.signature) != 64 do
    Err("invalid transparency checkpoint")
  else
    join([
        byte(1)?,
        Bytes.from_utf8("KTK"),
        write_u64(value.sequence)?,
        write_u64(value.tree_size)?,
        value.tree_root,
        value.previous_checkpoint_hash,
        write_u64(value.timestamp)?,
        value.service_public_key,
        value.signature
      ],
      0,
      Bytes.empty())
  end
end

pub fn decode_checkpoint(input :: Bytes) -> TransparencyCheckpoint!String do
  let sequence = take_u64(start(input, 188, "KTK")?)?
  let tree_size = take_u64(sequence.state)?
  let tree_root = take_fixed(tree_size.state, 32)?
  let previous = take_fixed(tree_root.state, 32)?
  let timestamp = take_u64(previous.state)?
  let public_key = take_fixed(timestamp.state, 32)?
  let signature = take_fixed(public_key.state, 64)?
  done(signature.state)?
  Ok(TransparencyCheckpoint {
    version: 1,
    sequence: sequence.value,
    tree_size: tree_size.value,
    tree_root: tree_root.value,
    previous_checkpoint_hash: previous.value,
    timestamp: timestamp.value,
    service_public_key: public_key.value,
    signature: signature.value
  })
end

fn encode_witness_entries(values :: List<WitnessAttestation>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(values) do
    Ok(output)
  else
    let value = List.get(values, index)
    let witness_id = Bytes.from_utf8(value.witness_id)
    if Bytes.length(witness_id) == 0 || Bytes.length(witness_id) > 64 || Bytes.length(value.checkpoint_hash) != 32 || Bytes.length(value.signature) != 64 do
      Err("invalid witness attestation")
    else
      encode_witness_entries(values,
        index + 1,
        append(output,
          join([vector(witness_id)?, value.checkpoint_hash, value.signature], 0, Bytes.empty())?)?)
    end
  end
end

pub fn encode_witnesses(values :: List<WitnessAttestation>) -> Bytes!String do
  if List.length(values) > 16 do
    Err("invalid witness attestations")
  else
    join([
        byte(1)?,
        Bytes.from_utf8("KTW"),
        write_u16(List.length(values))?,
        encode_witness_entries(values, 0, Bytes.empty())?
      ],
      0,
      Bytes.empty())
  end
end

fn read_witnesses(state :: BinaryReader,
  count :: Int,
  index :: Int,
  output :: List<WitnessAttestation>) -> ReadWitnesses!String do
  if index >= count do
    Ok(ReadWitnesses { state: state, value: output })
  else
    let witness_id = take_vector(state, 64)?
    let checkpoint_hash = take_fixed(witness_id.state, 32)?
    let signature = take_fixed(checkpoint_hash.state, 64)?
    case Bytes.to_utf8(witness_id.value) do
      Err(_) -> Err("invalid witness attestation")
      Ok(id) -> if String.length(id) == 0 do
        Err("invalid witness attestation")
      else
        read_witnesses(signature.state,
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
  let count = take_u16(start(input, 2630, "KTW")?)?
  if count.value > 16 do
    Err("invalid witness attestations")
  else
    let values = read_witnesses(count.state, count.value, 0, List.new())?
    done(values.state)?
    Ok(values.value)
  end
end

pub fn encode_transparency_evidence(value :: TransparencyEvidence) -> Bytes!String do
  if Bytes.length(value.entry_bytes) == 0 || Bytes.length(value.entry_bytes) > 305260 do
    Err("invalid transparency evidence")
  else
    join([
        byte(1)?,
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
  let entry = take_vector(start(input, 570274, "KTE")?, 305260)?
  let inclusion_bytes = take_vector(entry.state, 131086)?
  let consistency_bytes = take_vector(inclusion_bytes.state, 131086)?
  let checkpoint_bytes = take_vector(consistency_bytes.state, 188)?
  let witness_bytes = take_vector(checkpoint_bytes.state, 2630)?
  done(witness_bytes.state)?
  let inclusion = decode_inclusion_proof(inclusion_bytes.value)?
  let consistency = decode_consistency_proof(consistency_bytes.value)?
  let checkpoint = decode_checkpoint(checkpoint_bytes.value)?
  let checkpoint_size = U64.to_int(checkpoint.tree_size)?
  if inclusion.tree_size != checkpoint_size || consistency.new_tree_size != checkpoint_size do
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
