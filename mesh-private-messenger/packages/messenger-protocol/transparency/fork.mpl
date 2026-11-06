from Binary.Reader import BinaryReader, reader, read_fixed, read_u8, finish
from Transparency.Wire import encode_checkpoint, decode_checkpoint
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  WitnessKey,
  InclusionProof,
  checkpoint_hash,
  verify_checkpoint,
  verify_inclusion,
  verify_witnesses
)

pub type ForkTarget do
  SignedCheckpoint(TransparencyCheckpoint)
  AnchorReference(Int)
end

pub struct ForkPaths do
  leaf_index :: U64
  first_path :: List<Bytes>
  first_leaf :: Bytes
  second_path :: List<Bytes>
  second_leaf :: Bytes
end

pub struct ForkProof do
  kind :: Int
  finder :: Bytes
  service_public_key :: Bytes
  first :: TransparencyCheckpoint
  second :: ForkTarget
  attestations :: List<WitnessAttestation>
  contradiction :: Option<ForkPaths>
end

pub struct ForkVerdict do
  service_public_key :: Bytes
  witnesses :: List<WitnessKey>
end

# Supplied only by an authenticated chain reader or validated judge accounts,
# never decoded from FRK or copied from an untrusted RPC response.
pub struct ForkAnchor do
  ring_index :: Int
  log_version :: Int
  service_public_key :: Bytes
  sequence :: U64
  tree_size :: U64
  tree_root :: Bytes
  checkpoint_hash :: Bytes
  cosigners :: List<WitnessKey>
  native_cosigners :: List<WitnessKey>
end

fn validate_pins(pins :: List<WitnessKey>) -> Result<(), String> do
  if List.length(pins) > 16 do
    return Err("invalid_fork_pins")
  end
  for index in 0..List.length(pins) do
    let pin = List.get(pins, index)
    let length = Bytes.length(Bytes.from_utf8(pin.witness_id))
    if length < 1 || length > 64 || Bytes.length(pin.public_key) != 32 do
      return Err("invalid_fork_pins")
    end
    for previous in 0..index do
      let other = List.get(pins, previous)
      if other.witness_id == pin.witness_id
        || Bytes.secure_equals(other.public_key, pin.public_key) do
        return Err("duplicate_fork_pin")
      end
    end
  end
  Ok(nil)
end

fn contains_key(keys :: List<WitnessKey>, key :: WitnessKey, index :: Int) -> Bool do
  if index >= List.length(keys) do
    false
  else
    let candidate = List.get(keys, index)
    (candidate.witness_id == key.witness_id
      && Bytes.secure_equals(candidate.public_key, key.public_key))
      || contains_key(keys, key, index + 1)
  end
end

# Evidence can contain untrusted or repeated attestations. A forged duplicate
# must not hide a later valid signature by the same key on the same checkpoint.
fn signed_by(checkpoint :: TransparencyCheckpoint,
  attestations :: List<WitnessAttestation>,
  pin :: WitnessKey,
  index :: Int,
  native_only :: Bool) -> Bool!String do
  if index >= List.length(attestations) do
    Ok(false)
  else if (!native_only || Bytes.length(List.get(attestations, index).signature) == 64)
    && verify_witnesses(checkpoint, [List.get(attestations, index)], [pin], 1)? do
    Ok(true)
  else
    signed_by(checkpoint, attestations, pin, index + 1, native_only)
  end
end

# The caller authenticated either a signed checkpoint or a chain entry before
# supplying this position. This helper never decides whether an anchor is trusted.
fn relation(proof :: ForkProof,
  sequence :: U64,
  size :: U64,
  root :: Bytes,
  hash :: Bytes) -> Bool!String do
  if proof.kind == 1 do
    Ok(U64.compare(proof.first.tree_size, size) == 0
      && !Bytes.secure_equals(proof.first.tree_root, root))
  else if proof.kind == 3 do
    let sequence_order = U64.compare(proof.first.sequence, sequence)
    let size_order = U64.compare(proof.first.tree_size, size)
    Ok((sequence_order < 0 && size_order > 0)
      || (sequence_order > 0 && size_order < 0)
      || (sequence_order == 0 && !Bytes.secure_equals(checkpoint_hash(proof.first)?, hash)))
  else
    let paths = case proof.contradiction do
      None -> return Err("invalid_fork")
      Some(value) -> value
    end
    if Bytes.secure_equals(paths.first_leaf, paths.second_leaf)
      || U64.compare(paths.leaf_index, proof.first.tree_size) >= 0
      || U64.compare(paths.leaf_index, size) >= 0 do
      return Ok(false)
    end
    let first_path = InclusionProof {
      version: proof.first.version + 1,
      leaf_index: U64.to_int(paths.leaf_index)?,
      tree_size: U64.to_int(proof.first.tree_size)?,
      leaf_hashes: paths.first_path
    }
    let second_path = InclusionProof {
      version: proof.first.version + 1,
      leaf_index: first_path.leaf_index,
      tree_size: U64.to_int(size)?,
      leaf_hashes: paths.second_path
    }
    Ok(verify_inclusion(paths.first_leaf, first_path, proof.first.tree_root)?
      && verify_inclusion(paths.second_leaf, second_path, root)?)
  end
end

pub fn fork_at_anchor(proof :: ForkProof,
  trusted_log :: SigningPublicKey,
  pins :: List<WitnessKey>,
  trusted_anchor :: ForkAnchor) -> ForkVerdict!String do
  encode_fork(proof)?
  validate_pins(pins)?
  validate_pins(trusted_anchor.cosigners)?
  validate_pins(trusted_anchor.native_cosigners)?
  let index = case proof.second do
    SignedCheckpoint(_) -> return Err("fork_anchor_reference_required")
    AnchorReference(value) -> value
  end
  if index != trusted_anchor.ring_index
    || proof.first.version != trusted_anchor.log_version
    || Bytes.length(trusted_anchor.tree_root) != 32
    || Bytes.length(trusted_anchor.checkpoint_hash) != 32
    || !Bytes.secure_equals(trusted_anchor.service_public_key, trusted_log.bytes)
    || !verify_checkpoint(proof.first, trusted_log)? do
    return Err("fork_anchor_mismatch")
  end
  if !relation(proof,
    trusted_anchor.sequence,
    trusted_anchor.tree_size,
    trusted_anchor.tree_root,
    trusted_anchor.checkpoint_hash)? do
    return Err("fork_not_proven")
  end
  let accused = for pin in pins when contains_key(trusted_anchor.cosigners, pin, 0)
    && (proof.kind != 3 || contains_key(trusted_anchor.native_cosigners, pin, 0))
    && signed_by(proof.first, proof.attestations, pin, 0, proof.kind == 3)? do
    pin
  end
  Ok(ForkVerdict { service_public_key: proof.service_public_key, witnesses: accused })
end

fn verify_signed(proof :: ForkProof,
  kind :: Int,
  trusted_log :: SigningPublicKey,
  pins :: List<WitnessKey>) -> ForkVerdict!String do
  encode_fork(proof)?
  validate_pins(pins)?
  if proof.kind != kind do
    return Err("invalid_fork_kind")
  end
  let second = case proof.second do
    SignedCheckpoint(checkpoint) -> checkpoint
    AnchorReference(_) -> return Err("fork_anchor_resolution_required")
  end
  if proof.first.version != second.version do
    return Err("fork_log_version_mismatch")
  end
  if !verify_checkpoint(proof.first, trusted_log)? || !verify_checkpoint(second, trusted_log)? do
    return Err("fork_checkpoint_signature_failed")
  end
  if !relation(proof,
    second.sequence,
    second.tree_size,
    second.tree_root,
    checkpoint_hash(second)?)? do
    return Err("fork_not_proven")
  end
  let accused = for pin in pins when signed_by(proof.first,
    proof.attestations,
    pin,
    0,
    proof.kind == 3)?
    && signed_by(second, proof.attestations, pin, 0, proof.kind == 3)? do
    pin
  end
  Ok(ForkVerdict { service_public_key: proof.service_public_key, witnesses: accused })
end

pub fn fork_same_size(proof :: ForkProof,
  trusted_log :: SigningPublicKey,
  pins :: List<WitnessKey>) -> ForkVerdict!String do
  verify_signed(proof, 1, trusted_log, pins)
end

pub fn fork_contradiction(proof :: ForkProof,
  trusted_log :: SigningPublicKey,
  pins :: List<WitnessKey>) -> ForkVerdict!String do
  verify_signed(proof, 2, trusted_log, pins)
end

pub fn fork_rollback(proof :: ForkProof,
  trusted_log :: SigningPublicKey,
  pins :: List<WitnessKey>) -> ForkVerdict!String do
  verify_signed(proof, 3, trusted_log, pins)
end

# FRK is independently bounded before allocation or signature verification.
# 447-byte header, up to 32 * 170-byte v3 attestations, two paths and metadata.
fn join(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    case Bytes.concat(output, List.get(parts, index)) do
      Err(_) -> Err("invalid_fork_wire")
      Ok(value) -> join(parts, index + 1, value)
    end
  end
end

fn cat(parts :: List<Bytes>) -> Bytes!String do
  join(parts, 0, Bytes.empty())
end

fn byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("invalid_fork_wire")
    Ok(value)
  end
end

fn target_wire(value :: ForkTarget) -> Bytes!String do
  case value do
    SignedCheckpoint(checkpoint) -> cat([byte(0)?, encode_checkpoint(checkpoint)?])
    AnchorReference(index) -> if index < 0 || index >= 4096 do
      Err("invalid_fork_anchor_index")
    else
      let encoded = case Bytes.write_u32_be(U64.parse(Int.to_string(index))?) do
        Err(_) -> return Err("invalid_fork_wire")
        Ok(value) -> value
      end
      cat([byte(1)?, encoded])
    end
  end
end

fn attestation_wire(version :: Int, value :: WitnessAttestation) -> Bytes!String do
  let id = Bytes.from_utf8(value.witness_id)
  if Bytes.length(id) < 1
    || Bytes.length(id) > 64
    || Bytes.length(value.checkpoint_hash) != 32
    || (Bytes.length(value.signature) != 64 && Bytes.length(value.signature) != 72) do
    Err("invalid_fork_attestation")
  else
    let tag = if version == 1 do
      Bytes.empty()
    else if Bytes.length(value.signature) == 64 do
      byte(0)?
    else
      byte(4)?
    end
    cat([byte(Bytes.length(id))?, id, value.checkpoint_hash, tag, value.signature])
  end
end

fn path_wire(path :: List<Bytes>, leaf :: Bytes) -> Bytes!String do
  if List.length(path) > 32 || Bytes.length(leaf) != 32 do
    return Err("invalid_fork_path")
  end
  for hash in path do
    if Bytes.length(hash) != 32 do
      return Err("invalid_fork_path")
    end
  end
  cat([byte(List.length(path))?] ++ path ++ [leaf])
end

pub fn encode_fork(proof :: ForkProof) -> Bytes!String do
  let version = if List.length(proof.attestations) > 16 do
    3
  else if List.any(proof.attestations, fn(value) -> Bytes.length(value.signature) == 72 end) do
    2
  else
    1
  end
  if proof.kind < 1
    || proof.kind > 3
    || Bytes.length(proof.finder) != 32
    || Bytes.length(proof.service_public_key) != 32
    || List.length(proof.attestations) > 32
    || !Bytes.secure_equals(proof.first.service_public_key, proof.service_public_key) do
    return Err("invalid_fork_wire")
  end
  case proof.second do
    SignedCheckpoint(value) -> if !Bytes.secure_equals(value.service_public_key,
      proof.service_public_key) do
      return Err("invalid_fork_log")
    end
    AnchorReference(_) -> nil
  end
  let extension = case proof.contradiction do
    None -> if proof.kind == 2 do
      return Err("invalid_fork_path")
    else
      Bytes.empty()
    end
    Some(paths) -> do
      if proof.kind != 2 do
        return Err("invalid_fork_path")
      end
      let index = case Bytes.write_u64_be(paths.leaf_index) do
        Err(_) -> return Err("invalid_fork_wire")
        Ok(value) -> value
      end
      cat([
        index,
        path_wire(paths.first_path, paths.first_leaf)?,
        path_wire(paths.second_path, paths.second_leaf)?
      ])?
    end
  end
  let entries = for attestation in proof.attestations do
    attestation_wire(version, attestation)?
  end
  cat([
    byte(version)?,
    Bytes.from_utf8("FRK"),
    byte(proof.kind)?,
    proof.finder,
    proof.service_public_key,
    encode_checkpoint(proof.first)?,
    target_wire(proof.second)?,
    byte(List.length(entries))?
  ]
    ++ entries
    ++ [extension])
end

fn take(state :: BinaryReader, count :: Int) -> Result<(BinaryReader, Bytes), String> do
  case read_fixed(state, count) do
    Err(_) -> Err("invalid_fork_wire")
    Ok(value)
  end
end

fn take_byte(state :: BinaryReader) -> Result<(BinaryReader, Int), String> do
  case read_u8(state) do
    Err(_) -> Err("invalid_fork_wire")
    Ok(value)
  end
end

fn read_target(state :: BinaryReader) -> Result<(BinaryReader, ForkTarget), String> do
  let (state, tag) = take_byte(state)?
  if tag == 0 do
    let (state, wire) = take(state, 188)?
    Ok((state, SignedCheckpoint(decode_checkpoint(wire)?)))
  else if tag == 1 do
    let (state, wire) = take(state, 4)?
    let wide = case Bytes.read_u32_be(wire, 0) do
      Err(_) -> return Err("invalid_fork_wire")
      Ok(value) -> value
    end
    let index = U64.to_int(wide)?
    if index >= 4096 do
      Err("invalid_fork_anchor_index")
    else
      Ok((state, AnchorReference(index)))
    end
  else
    Err("invalid_fork_target")
  end
end

fn read_attestations(version :: Int,
  state :: BinaryReader,
  count :: Int,
  values :: List<WitnessAttestation>) -> Result<(BinaryReader, List<WitnessAttestation>), String> do
  if count == 0 do
    Ok((state, values))
  else
    let (state, length) = take_byte(state)?
    if length < 1 || length > 64 do
      return Err("invalid_fork_attestation")
    end
    let (state, id_bytes) = take(state, length)?
    let id = case Bytes.to_utf8(id_bytes) do
      Err(_) -> return Err("invalid_fork_attestation")
      Ok(value) -> value
    end
    let (state, hash) = take(state, 32)?
    let (state, algorithm) = if version == 1 do
      (state, 0)
    else
      take_byte(state)?
    end
    if algorithm != 0 && algorithm != 4 do
      return Err("unsupported_fork_signature")
    end
    let size = if algorithm == 0 do
      64
    else
      72
    end
    let (state, signature) = take(state, size)?
    read_attestations(version,
      state,
      count - 1,
      List.append(values,
        WitnessAttestation { witness_id: id, checkpoint_hash: hash, signature: signature }))
  end
end

fn read_path(state :: BinaryReader,
  count :: Int,
  values :: List<Bytes>) -> Result<(BinaryReader, List<Bytes>), String> do
  if count == 0 do
    Ok((state, values))
  else
    let (state, value) = take(state, 32)?
    read_path(state, count - 1, List.append(values, value))
  end
end

fn take_path(state :: BinaryReader) -> Result<(BinaryReader, List<Bytes>), String> do
  let (state, length) = take_byte(state)?
  if length > 32 do
    Err("invalid_fork_path")
  else
    read_path(state, length, [])
  end
end

fn read_contradiction(state :: BinaryReader,
  kind :: Int) -> Result<(BinaryReader, Option<ForkPaths>), String> do
  if kind != 2 do
    Ok((state, None))
  else
    let (state, index) = take(state, 8)?
    let index = case Bytes.read_u64_be(index, 0) do
      Err(_) -> return Err("invalid_fork_wire")
      Ok(value) -> value
    end
    let (state, first_path) = take_path(state)?
    let (state, first_leaf) = take(state, 32)?
    let (state, second_path) = take_path(state)?
    let (state, second_leaf) = take(state, 32)?
    Ok((state,
      Some(ForkPaths {
        leaf_index: index,
        first_path: first_path,
        first_leaf: first_leaf,
        second_path: second_path,
        second_leaf: second_leaf
      })))
  end
end

pub fn decode_fork(input :: Bytes) -> ForkProof!String do
  let state = case reader(input, 8009) do
    Err(_) -> return Err("invalid_fork_wire")
    Ok(value) -> value
  end
  let (state, version) = take_byte(state)?
  let (state, magic) = take(state, 3)?
  let (state, kind) = take_byte(state)?
  if (version != 1 && version != 2 && version != 3)
    || (version == 1 && Bytes.length(input) > 5145)
    || (version == 2 && Bytes.length(input) > 5289)
    || !Bytes.secure_equals(magic, Bytes.from_utf8("FRK"))
    || kind < 1
    || kind > 3 do
    return Err("invalid_fork_wire")
  end
  let (state, finder) = take(state, 32)?
  let (state, key) = take(state, 32)?
  let (state, first) = take(state, 188)?
  let (state, second) = read_target(state)?
  let (state, count) = take_byte(state)?
  if count > 32 || (version != 3 && count > 16) || (version == 3 && count <= 16) do
    return Err("invalid_fork_attestation")
  end
  let (state, attestations) = read_attestations(version, state, count, [])?
  let (state, paths) = read_contradiction(state, kind)?
  case finish(state) do
    Err(_) -> return Err("invalid_fork_wire")
    Ok(_) -> nil
  end
  let proof = ForkProof {
    kind: kind,
    finder: finder,
    service_public_key: key,
    first: decode_checkpoint(first)?,
    second: second,
    attestations: attestations,
    contradiction: paths
  }
  if !Bytes.secure_equals(encode_fork(proof)?, input) do
    Err("invalid_fork_wire")
  else
    Ok(proof)
  end
end

# SHA-256 over all canonical FRK bytes except the 32-byte finder at offset 5.
# Signature checks and the judge's time/pay-once policy are separate.
pub fn fork_hash(proof :: ForkProof) -> Bytes!String do
  let wire = encode_fork(proof)?
  let first = case Bytes.slice(wire, 0, 5) do
    Err(_) -> return Err("invalid_fork_wire")
    Ok(value) -> value
  end
  let rest = case Bytes.slice(wire, 37, Bytes.length(wire) - 37) do
    Err(_) -> return Err("invalid_fork_wire")
    Ok(value) -> value
  end
  Ok(Crypto.sha256(cat([first, rest])?))
end
