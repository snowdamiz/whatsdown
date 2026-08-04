pub struct InclusionProof do
  leaf_index :: Int
  tree_size :: Int
  leaf_hashes :: List < Bytes >
end

pub struct ConsistencyProof do
  old_tree_size :: Int
  new_tree_size :: Int
  leaf_hashes :: List < Bytes >
end

pub struct TransparencyCheckpoint do
  version :: Int
  sequence :: U64
  tree_size :: U64
  tree_root :: Bytes
  previous_checkpoint_hash :: Bytes
  timestamp :: U64
  service_public_key :: Bytes
  signature :: Bytes
end

pub struct WitnessKey do
  witness_id :: String
  public_key :: Bytes
end

pub struct WitnessAttestation do
  witness_id :: String
  checkpoint_hash :: Bytes
  signature :: Bytes
end

fn append(left :: Bytes, right :: Bytes) -> Bytes ! String do
  case Bytes.concat(left, right) do
    Err( _) -> Err("transparency_encoding_failed")
    Ok( value) -> Ok(value)
  end
end

fn wide(value :: Int) -> U64 ! String do
  case U64.parse(Int.to_string(value)) do
    Err( _) -> Err("transparency_integer_failed")
    Ok( parsed) -> Ok(parsed)
  end
end

fn write_u64(value :: U64) -> Bytes ! String do
  case Bytes.write_u64_be(value) do
    Err( _) -> Err("transparency_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn write_u16(value :: Int) -> Bytes ! String do
  case Bytes.write_u16_be(value) do
    Err( _) -> Err("transparency_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn concat_parts(parts :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(parts) do
    Ok(output)
  else
    concat_parts(parts, index + 1, append(output, List.get(parts, index)) ?)
  end
end

fn hash_parts(label :: String, parts :: List < Bytes >) -> Bytes ! String do
  Ok(Crypto.sha256(concat_parts(parts, 0, Bytes.from_utf8(label)) ?))
end

pub fn leaf_hash(entry :: Bytes) -> Bytes ! String do
  if Bytes.length(entry) == 0 || Bytes.length(entry) > 286400 do
    Err("invalid_transparency_leaf")
  else
    hash_parts("mesh-msg/v1/transparency-leaf", [entry])
  end
end

fn valid_hashes(values :: List < Bytes >, index :: Int) -> Bool do
  if index >= List.length(values) do
    true
  else if Bytes.length(List.get(values, index)) != 32 do
    false
  else
    valid_hashes(values, index + 1)
  end
end

fn split_power(count :: Int, power :: Int) -> Int do
  if power * 2 < count do
    split_power(count, power * 2)
  else
    power
  end
end

fn root_range(values :: List < Bytes >, start :: Int, count :: Int) -> Bytes ! String do
  if count == 1 do
    Ok(List.get(values, start))
  else
    let split = split_power(count, 1)
    hash_parts("mesh-msg/v1/transparency-node",
    [root_range(values, start, split) ?, root_range(values, start + split, count - split) ?])
  end
end

pub fn merkle_root(values :: List < Bytes >) -> Bytes ! String do
  let count = List.length(values)
  if count > 4096 || !valid_hashes(values, 0) do
    Err("invalid_transparency_tree")
  else if count == 0 do
    hash_parts("mesh-msg/v1/transparency-empty", List.new())
  else
    root_range(values, 0, count)
  end
end

# ponytail: proofs carry bounded leaf commitments; replace with compact RFC 6962 paths when log bandwidth matters.

pub fn inclusion_proof(values :: List < Bytes >, leaf_index :: Int) -> InclusionProof ! String do
  if leaf_index < 0 || leaf_index >= List.length(values) || List.length(values) > 4096 || !valid_hashes(values,
  0) do
    Err("invalid_inclusion_proof")
  else
    Ok(InclusionProof {
      leaf_index : leaf_index,
      tree_size : List.length(values),
      leaf_hashes : values
    })
  end
end

pub fn verify_inclusion(value :: Bytes, proof :: InclusionProof, expected_root :: Bytes) -> Bool ! String do
  let valid = proof.tree_size == List.length(proof.leaf_hashes) && proof.tree_size > 0 && proof.leaf_index >= 0 && proof.leaf_index < proof.tree_size && Bytes.length(value) == 32 && Bytes.length(expected_root) == 32 && valid_hashes(proof.leaf_hashes,
  0)
  if !valid do
    Ok(false)
  else
    Ok(Bytes.secure_equals(List.get(proof.leaf_hashes, proof.leaf_index), value) && Bytes.secure_equals(merkle_root(proof.leaf_hashes) ?,
    expected_root))
  end
end

pub fn consistency_proof(old_values :: List < Bytes >, new_values :: List < Bytes >) -> ConsistencyProof ! String do
  let old_size = List.length(old_values)
  let new_size = List.length(new_values)
  if old_size < 0 || old_size > new_size || new_size > 4096 || !valid_hashes(old_values, 0) || !valid_hashes(new_values,
  0) do
    Err("invalid_consistency_proof")
  else
    Ok(ConsistencyProof {
      old_tree_size : old_size,
      new_tree_size : new_size,
      leaf_hashes : new_values
    })
  end
end

fn prefix(values :: List < Bytes >, count :: Int, index :: Int, output :: List < Bytes >) -> List < Bytes > do
  if index >= count do
    output
  else
    prefix(values, count, index + 1, List.append(output, List.get(values, index)))
  end
end

pub fn verify_consistency(old_root :: Bytes, new_root :: Bytes, proof :: ConsistencyProof) -> Bool ! String do
  let valid = proof.old_tree_size >= 0 && proof.old_tree_size <= proof.new_tree_size && proof.new_tree_size == List.length(proof.leaf_hashes) && proof.new_tree_size <= 4096 && Bytes.length(old_root) == 32 && Bytes.length(new_root) == 32 && valid_hashes(proof.leaf_hashes,
  0)
  if !valid do
    Ok(false)
  else
    Ok(Bytes.secure_equals(merkle_root(prefix(proof.leaf_hashes, proof.old_tree_size, 0, List.new())) ?,
    old_root) && Bytes.secure_equals(merkle_root(proof.leaf_hashes) ?, new_root))
  end
end

fn checkpoint_statement(sequence :: U64,
tree_size :: U64,
tree_root :: Bytes,
previous_checkpoint_hash :: Bytes,
timestamp :: U64,
service_public_key :: Bytes) -> Bytes ! String do
  if Bytes.length(tree_root) != 32 || Bytes.length(previous_checkpoint_hash) != 32 || Bytes.length(service_public_key) != 32 do
    Err("invalid_checkpoint")
  else
    concat_parts([Bytes.from_utf8("mesh-key-transparency-v1"), write_u16(1) ?, write_u64(sequence) ?, write_u64(tree_size) ?, tree_root, previous_checkpoint_hash, write_u64(timestamp) ?, service_public_key],
    0,
    Bytes.empty())
  end
end

pub fn sign_checkpoint(signing_key :: borrow SigningPrivateKey,
service_public_key :: Bytes,
sequence :: U64,
leaf_hashes :: List < Bytes >,
previous_checkpoint_hash :: Bytes,
timestamp :: U64) -> TransparencyCheckpoint ! String do
  let root = merkle_root(leaf_hashes) ?
  let tree_size = wide(List.length(leaf_hashes)) ?
  let statement = checkpoint_statement(sequence,
  tree_size,
  root,
  previous_checkpoint_hash,
  timestamp,
  service_public_key) ?
  let signature = case Crypto.sign(signing_key, statement) do
    Err( _) -> Err("checkpoint_signing_failed")
    Ok( value) -> Ok(value)
  end ?
  let bound = case Crypto.verify(SigningPublicKey { bytes : service_public_key },
  statement,
  signature) do
    Err( _) -> Err("checkpoint_signing_failed")
    Ok( value) -> Ok(value)
  end ?
  if !bound do
    Err("checkpoint_signing_failed")
  else
    Ok(TransparencyCheckpoint {
      version : 1,
      sequence : sequence,
      tree_size : tree_size,
      tree_root : root,
      previous_checkpoint_hash : previous_checkpoint_hash,
      timestamp : timestamp,
      service_public_key : service_public_key,
      signature : signature.bytes
    })
  end
end

pub fn verify_checkpoint(value :: TransparencyCheckpoint, trusted_key :: SigningPublicKey) -> Bool ! String do
  if value.version != 1 || !Bytes.secure_equals(value.service_public_key, trusted_key.bytes) || Bytes.length(value.signature) != 64 do
    Ok(false)
  else
    let statement = checkpoint_statement(value.sequence,
    value.tree_size,
    value.tree_root,
    value.previous_checkpoint_hash,
    value.timestamp,
    value.service_public_key) ?
    case Crypto.verify(trusted_key, statement, Signature { bytes : value.signature }) do
      Err( _) -> Err("checkpoint_verification_failed")
      Ok( valid) -> Ok(valid)
    end
  end
end

pub fn checkpoint_hash(value :: TransparencyCheckpoint) -> Bytes ! String do
  hash_parts("mesh-msg/v1/transparency-checkpoint",
  [checkpoint_statement(value.sequence,
  value.tree_size,
  value.tree_root,
  value.previous_checkpoint_hash,
  value.timestamp,
  value.service_public_key) ?, value.signature])
end

pub fn sign_witness(witness_id :: String,
signing_key :: borrow SigningPrivateKey,
checkpoint :: TransparencyCheckpoint) -> WitnessAttestation ! String do
  if String.length(witness_id) == 0 || String.length(witness_id) > 64 do
    Err("invalid_witness")
  else
    let hash = checkpoint_hash(checkpoint) ?
    let statement = concat_parts([Bytes.from_utf8("mesh-msg/v1/transparency-witness"), Bytes.from_utf8(witness_id), hash],
    0,
    Bytes.empty()) ?
    let signature = case Crypto.sign(signing_key, statement) do
      Err( _) -> Err("witness_signing_failed")
      Ok( value) -> Ok(value)
    end ?
    Ok(WitnessAttestation {
      witness_id : witness_id,
      checkpoint_hash : hash,
      signature : signature.bytes
    })
  end
end

fn trusted_witness(keys :: List < WitnessKey >, witness_id :: String, index :: Int) -> WitnessKey ! String do
  if index >= List.length(keys) do
    Err("untrusted_witness")
  else
    let value = List.get(keys, index)
    if value.witness_id == witness_id do
      Ok(value)
    else
      trusted_witness(keys, witness_id, index + 1)
    end
  end
end

fn contains_witness(values :: List < String >, witness_id :: String, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else if List.get(values, index) == witness_id do
    true
  else
    contains_witness(values, witness_id, index + 1)
  end
end

fn count_valid_witnesses(checkpoint :: TransparencyCheckpoint,
checkpoint_digest :: Bytes,
attestations :: List < WitnessAttestation >,
trusted_keys :: List < WitnessKey >,
index :: Int,
seen :: List < String >,
count :: Int) -> Int ! String do
  if index >= List.length(attestations) do
    Ok(count)
  else
    let attestation = List.get(attestations, index)
    if contains_witness(seen, attestation.witness_id, 0) || !Bytes.secure_equals(attestation.checkpoint_hash,
    checkpoint_digest) || Bytes.length(attestation.signature) != 64 do
      count_valid_witnesses(checkpoint,
      checkpoint_digest,
      attestations,
      trusted_keys,
      index + 1,
      seen,
      count)
    else
      case trusted_witness(trusted_keys, attestation.witness_id, 0) do
        Err( _) -> count_valid_witnesses(checkpoint,
        checkpoint_digest,
        attestations,
        trusted_keys,
        index + 1,
        seen,
        count)
        Ok( trusted) -> do
          let statement = concat_parts([Bytes.from_utf8("mesh-msg/v1/transparency-witness"), Bytes.from_utf8(attestation.witness_id), checkpoint_digest],
          0,
          Bytes.empty()) ?
          let valid = case Crypto.verify(SigningPublicKey { bytes : trusted.public_key },
          statement,
          Signature { bytes : attestation.signature }) do
            Err( _) -> false
            Ok( value) -> value
          end
          count_valid_witnesses(checkpoint,
          checkpoint_digest,
          attestations,
          trusted_keys,
          index + 1,
          List.append(seen, attestation.witness_id),
          if valid do
            count + 1
          else
            count
          end)
        end
      end
    end
  end
end

pub fn verify_witnesses(checkpoint :: TransparencyCheckpoint,
attestations :: List < WitnessAttestation >,
trusted_keys :: List < WitnessKey >,
threshold :: Int) -> Bool ! String do
  if threshold < 1 || threshold > List.length(trusted_keys) || List.length(attestations) > 16 || List.length(trusted_keys) > 16 do
    Ok(false)
  else
    let digest = checkpoint_hash(checkpoint) ?
    Ok(count_valid_witnesses(checkpoint, digest, attestations, trusted_keys, 0, List.new(), 0) ? >= threshold)
  end
end

pub fn checkpoint_conflict(first :: TransparencyCheckpoint,
second :: TransparencyCheckpoint,
trusted_key :: SigningPublicKey) -> Bool ! String do
  let same_position = U64.compare(first.sequence, second.sequence) == 0 && U64.compare(first.tree_size,
  second.tree_size) == 0
  Ok(same_position && !Bytes.secure_equals(first.tree_root, second.tree_root) && verify_checkpoint(first,
  trusted_key) ? && verify_checkpoint(second, trusted_key) ?)
end
