from Transparency.C2spText import verify_checkpoint_cosignature, cosignature_fresh_at

pub struct InclusionProof do
  version :: Int
  leaf_index :: Int
  tree_size :: Int
  # v1: every legacy leaf; v2: compact legacy path; v3: RFC 6962 hashes.
  leaf_hashes :: List<Bytes>
end

pub struct ConsistencyProof do
  version :: Int
  old_tree_size :: Int
  new_tree_size :: Int
  # v1: every legacy leaf; v2: compact legacy path; v3: RFC 6962 hashes.
  leaf_hashes :: List<Bytes>
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
  # Native: 64-byte signature; C2SP: timestamp u64 + 64-byte Ed25519 signature.
  signature :: Bytes
end

pub fn proof_matches_log(log_version :: Int, proof_version :: Int) -> Bool do
  (log_version == 1 && (proof_version == 1 || proof_version == 2))
    || (log_version == 2 && proof_version == 3)
end

fn append(left :: Bytes, right :: Bytes) -> Bytes!String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("transparency_encoding_failed")
    Ok(value)
  end
end

fn wide(value :: Int) -> U64!String do
  case U64.parse(Int.to_string(value)) do
    Err(_) -> Err("transparency_integer_failed")
    Ok(parsed)
  end
end

fn write_u64(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err("transparency_encoding_failed")
    Ok(encoded)
  end
end

fn write_u16(value :: Int) -> Bytes!String do
  case Bytes.write_u16_be(value) do
    Err(_) -> Err("transparency_encoding_failed")
    Ok(encoded)
  end
end

fn concat_parts(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    concat_parts(parts, index + 1, append(output, List.get(parts, index))?)
  end
end

fn hash_parts(label :: String, parts :: List<Bytes>) -> Bytes!String do
  Ok(Crypto.sha256(concat_parts(parts, 0, Bytes.from_utf8(label))?))
end

pub fn leaf_hash(entry :: Bytes) -> Bytes!String do
  leaf_hash_for(1, entry)
end

# Checkpoint v1 is the archived Morse hash profile; v2 is RFC 6962.
pub fn leaf_hash_for(version :: Int, entry :: Bytes) -> Bytes!String do
  if version != 1 && version != 2 do
    return Err("unsupported_transparency_log")
  end
  if Bytes.length(entry) == 0 || Bytes.length(entry) > 305260 do
    Err("invalid_transparency_leaf")
  else if version == 2 do
    Ok(Crypto.sha256(append(Bytes.from_hex("00")?, entry)?))
  else
    hash_parts("mesh-msg/v1/transparency-leaf", [entry])
  end
end

fn valid_hashes(values :: List<Bytes>, index :: Int) -> Bool do
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

fn root_range(version :: Int, values :: List<Bytes>, start :: Int, count :: Int) -> Bytes!String do
  if count == 1 do
    Ok(List.get(values, start))
  else
    let split = split_power(count, 1)
    node_hash_for(version,
      root_range(version, values, start, split)?,
      root_range(version, values, start + split, count - split)?)
  end
end

pub fn node_hash(left :: Bytes, right :: Bytes) -> Bytes!String do
  node_hash_for(1, left, right)
end

pub fn node_hash_for(version :: Int, left :: Bytes, right :: Bytes) -> Bytes!String do
  if version != 1 && version != 2 do
    return Err("unsupported_transparency_log")
  end
  if Bytes.length(left) != 32 || Bytes.length(right) != 32 do
    Err("invalid_transparency_node")
  else if version == 2 do
    Ok(Crypto.sha256(concat_parts([Bytes.from_hex("01")?, left, right], 0, Bytes.empty())?))
  else
    hash_parts("mesh-msg/v1/transparency-node", [left, right])
  end
end

pub fn merkle_root(values :: List<Bytes>) -> Bytes!String do
  merkle_root_for(1, values)
end

pub fn merkle_root_for(version :: Int, values :: List<Bytes>) -> Bytes!String do
  if version != 1 && version != 2 do
    return Err("unsupported_transparency_log")
  end
  let count = List.length(values)
  if count > 4294967295 || !valid_hashes(values, 0) do
    Err("invalid_transparency_tree")
  else if count == 0 do
    if version == 2 do
      Ok(Crypto.sha256(Bytes.empty()))
    else
      hash_parts("mesh-msg/v1/transparency-empty", List.new())
    end
  else
    root_range(version, values, 0, count)
  end
end

# Legacy generators stay bounded for the one-release migration window.

pub fn inclusion_proof(values :: List<Bytes>, leaf_index :: Int) -> InclusionProof!String do
  if leaf_index < 0
    || leaf_index >= List.length(values)
    || List.length(values) > 4096
    || !valid_hashes(values, 0) do
    Err("invalid_inclusion_proof")
  else
    Ok(InclusionProof {
      version: 1,
      leaf_index: leaf_index,
      tree_size: List.length(values),
      leaf_hashes: values
    })
  end
end

pub fn verify_inclusion(value :: Bytes,
  proof :: InclusionProof,
  expected_root :: Bytes) -> Bool!String do
  if proof.version == 2 || proof.version == 3 do
    return verify_compact_inclusion(value, proof, expected_root)
  end
  let valid = proof.tree_size == List.length(proof.leaf_hashes)
    && proof.version == 1
    && proof.tree_size <= 4096
    && proof.tree_size > 0
    && proof.leaf_index >= 0
    && proof.leaf_index < proof.tree_size
    && Bytes.length(value) == 32
    && Bytes.length(expected_root) == 32
    && valid_hashes(proof.leaf_hashes, 0)
  if !valid do
    Ok(false)
  else
    Ok(Bytes.secure_equals(List.get(proof.leaf_hashes, proof.leaf_index), value)
      && Bytes.secure_equals(merkle_root(proof.leaf_hashes)?, expected_root))
  end
end

pub fn consistency_proof(old_values :: List<Bytes>,
  new_values :: List<Bytes>) -> ConsistencyProof!String do
  let old_size = List.length(old_values)
  let new_size = List.length(new_values)
  if old_size < 0
    || old_size > new_size
    || new_size > 4096
    || !valid_hashes(old_values, 0)
    || !valid_hashes(new_values, 0) do
    Err("invalid_consistency_proof")
  else
    Ok(ConsistencyProof {
      version: 1,
      old_tree_size: old_size,
      new_tree_size: new_size,
      leaf_hashes: new_values
    })
  end
end

fn prefix(values :: List<Bytes>,
  count :: Int,
  index :: Int,
  output :: List<Bytes>) -> List<Bytes> do
  if index >= count do
    output
  else
    prefix(values, count, index + 1, List.append(output, List.get(values, index)))
  end
end

pub fn verify_consistency(old_root :: Bytes,
  new_root :: Bytes,
  proof :: ConsistencyProof) -> Bool!String do
  if proof.version == 2 || proof.version == 3 do
    return verify_compact_consistency(old_root, new_root, proof)
  end
  let valid = proof.old_tree_size >= 0
    && proof.version == 1
    && proof.old_tree_size <= proof.new_tree_size
    && proof.new_tree_size == List.length(proof.leaf_hashes)
    && proof.new_tree_size <= 4096
    && Bytes.length(old_root) == 32
    && Bytes.length(new_root) == 32
    && valid_hashes(proof.leaf_hashes, 0)
  if !valid do
    Ok(false)
  else
    Ok(Bytes.secure_equals(merkle_root(prefix(proof.leaf_hashes,
        proof.old_tree_size,
        0,
        List.new()))?,
      old_root)
      && Bytes.secure_equals(merkle_root(proof.leaf_hashes)?, new_root))
  end
end

# RFC 6962 section 2.1. The tree shape is shared by both hash profiles.
# The signed checkpoint version selects the profile; u32 sizes bound depth to 32.

fn audit_path(version :: Int,
  values :: List<Bytes>,
  start :: Int,
  count :: Int,
  index :: Int) -> List<Bytes>!String do
  if count == 1 do
    Ok(List.new())
  else
    let split = split_power(count, 1)
    if index < split do
      Ok(List.append(audit_path(version, values, start, split, index)?,
        root_range(version, values, start + split, count - split)?))
    else
      Ok(List.append(audit_path(version, values, start + split, count - split, index - split)?,
        root_range(version, values, start, split)?))
    end
  end
end

pub fn compact_inclusion_proof(values :: List<Bytes>, leaf_index :: Int) -> InclusionProof!String do
  compact_inclusion_proof_for(1, values, leaf_index)
end

pub fn compact_inclusion_proof_for(version :: Int,
  values :: List<Bytes>,
  leaf_index :: Int) -> InclusionProof!String do
  if version != 1 && version != 2 do
    return Err("unsupported_transparency_log")
  end
  let count = List.length(values)
  if leaf_index < 0 || leaf_index >= count || count > 4294967295 || !valid_hashes(values, 0) do
    Err("invalid_inclusion_proof")
  else
    Ok(InclusionProof {
      version: version + 1,
      leaf_index: leaf_index,
      tree_size: count,
      leaf_hashes: audit_path(version, values, 0, count, leaf_index)?
    })
  end
end

pub fn inclusion_path_length(index :: Int, count :: Int) -> Int do
  if count <= 1 do
    0
  else
    let split = split_power(count, 1)
    if index < split do
      1 + inclusion_path_length(index, split)
    else
      1 + inclusion_path_length(index - split, count - split)
    end
  end
end

struct AuditRoot do
  hash :: Bytes
  next :: Int
end

fn audit_root(version :: Int,
  value :: Bytes,
  index :: Int,
  count :: Int,
  path :: List<Bytes>) -> AuditRoot!String do
  if count == 1 do
    Ok(AuditRoot { hash: value, next: 0 })
  else
    let split = split_power(count, 1)
    if index < split do
      let child = audit_root(version, value, index, split, path)?
      Ok(AuditRoot {
        hash: node_hash_for(version, child.hash, List.get(path, child.next))?,
        next: child.next + 1
      })
    else
      let child = audit_root(version, value, index - split, count - split, path)?
      Ok(AuditRoot {
        hash: node_hash_for(version, List.get(path, child.next), child.hash)?,
        next: child.next + 1
      })
    end
  end
end

fn verify_compact_inclusion(value :: Bytes,
  proof :: InclusionProof,
  expected_root :: Bytes) -> Bool!String do
  let version = proof.version - 1
  if proof.tree_size <= 0
    || proof.tree_size > 4294967295
    || proof.leaf_index < 0
    || proof.leaf_index >= proof.tree_size
    || Bytes.length(value) != 32
    || Bytes.length(expected_root) != 32
    || List.length(proof.leaf_hashes) != inclusion_path_length(proof.leaf_index, proof.tree_size)
    || !valid_hashes(proof.leaf_hashes, 0) do
    Ok(false)
  else
    Ok(Bytes.secure_equals(audit_root(version,
        value,
        proof.leaf_index,
        proof.tree_size,
        proof.leaf_hashes)?.hash,
      expected_root))
  end
end

fn consistency_path(version :: Int,
  values :: List<Bytes>,
  start :: Int,
  old_size :: Int,
  count :: Int,
  known :: Bool) -> List<Bytes>!String do
  if old_size == count do
    if known do
      Ok(List.new())
    else
      Ok([root_range(version, values, start, count)?])
    end
  else
    let split = split_power(count, 1)
    if old_size <= split do
      Ok(List.append(consistency_path(version, values, start, old_size, split, known)?,
        root_range(version, values, start + split, count - split)?))
    else
      Ok(List.append(consistency_path(version,
          values,
          start + split,
          old_size - split,
          count - split,
          false)?,
        root_range(version, values, start, split)?))
    end
  end
end

pub fn compact_consistency_proof(old_values :: List<Bytes>,
  new_values :: List<Bytes>) -> ConsistencyProof!String do
  compact_consistency_proof_for(1, old_values, new_values)
end

pub fn compact_consistency_proof_for(version :: Int,
  old_values :: List<Bytes>,
  new_values :: List<Bytes>) -> ConsistencyProof!String do
  if version != 1 && version != 2 do
    return Err("unsupported_transparency_log")
  end
  let old_size = List.length(old_values)
  let new_size = List.length(new_values)
  if old_size > new_size
    || new_size > 4294967295
    || !valid_hashes(old_values, 0)
    || !valid_hashes(new_values, 0) do
    Err("invalid_consistency_proof")
  else
    let path = if old_size == 0 do
      List.new()
    else
      consistency_path(version, new_values, 0, old_size, new_size, true)?
    end
    Ok(ConsistencyProof {
      version: version + 1,
      old_tree_size: old_size,
      new_tree_size: new_size,
      leaf_hashes: path
    })
  end
end

fn subproof_length(old_size :: Int, new_size :: Int, known :: Bool) -> Int do
  if old_size == new_size do
    if known do
      0
    else
      1
    end
  else
    let split = split_power(new_size, 1)
    if old_size <= split do
      1 + subproof_length(old_size, split, known)
    else
      1 + subproof_length(old_size - split, new_size - split, false)
    end
  end
end

pub fn consistency_path_length(old_size :: Int, new_size :: Int) -> Int do
  if old_size == 0 do
    0
  else
    subproof_length(old_size, new_size, true)
  end
end

struct ConsistentRoots do
  old_root :: Bytes
  new_root :: Bytes
  next :: Int
end

fn consistent_roots(version :: Int,
  old_size :: Int,
  new_size :: Int,
  known :: Bool,
  old_root :: Bytes,
  path :: List<Bytes>) -> ConsistentRoots!String do
  if old_size == new_size do
    if known do
      Ok(ConsistentRoots { old_root: old_root, new_root: old_root, next: 0 })
    else
      Ok(ConsistentRoots { old_root: List.head(path), new_root: List.head(path), next: 1 })
    end
  else
    let split = split_power(new_size, 1)
    if old_size <= split do
      let child = consistent_roots(version, old_size, split, known, old_root, path)?
      Ok(ConsistentRoots {
        old_root: child.old_root,
        new_root: node_hash_for(version, child.new_root, List.get(path, child.next))?,
        next: child.next + 1
      })
    else
      let child = consistent_roots(version,
        old_size - split,
        new_size - split,
        false,
        old_root,
        path)?
      let left = List.get(path, child.next)
      Ok(ConsistentRoots {
        old_root: node_hash_for(version, left, child.old_root)?,
        new_root: node_hash_for(version, left, child.new_root)?,
        next: child.next + 1
      })
    end
  end
end

fn verify_compact_consistency(old_root :: Bytes,
  new_root :: Bytes,
  proof :: ConsistencyProof) -> Bool!String do
  let version = proof.version - 1
  if proof.old_tree_size < 0
    || proof.new_tree_size < proof.old_tree_size
    || proof.new_tree_size > 4294967295
    || Bytes.length(old_root) != 32
    || Bytes.length(new_root) != 32
    || List.length(proof.leaf_hashes) != consistency_path_length(proof.old_tree_size,
        proof.new_tree_size)
    || !valid_hashes(proof.leaf_hashes, 0) do
    Ok(false)
  else if proof.old_tree_size == 0 do
    let empty = merkle_root_for(version, List.new())?
    Ok(Bytes.secure_equals(old_root, empty)
      && (proof.new_tree_size > 0 || Bytes.secure_equals(new_root, empty)))
  else
    let roots = consistent_roots(version,
      proof.old_tree_size,
      proof.new_tree_size,
      true,
      old_root,
      proof.leaf_hashes)?
    Ok(Bytes.secure_equals(roots.old_root, old_root)
      && Bytes.secure_equals(roots.new_root, new_root))
  end
end

pub fn checkpoint_statement(version :: Int,
  sequence :: U64,
  tree_size :: U64,
  tree_root :: Bytes,
  previous_checkpoint_hash :: Bytes,
  timestamp :: U64,
  service_public_key :: Bytes) -> Bytes!String do
  if (version != 1 && version != 2)
    || Bytes.length(tree_root) != 32
    || Bytes.length(previous_checkpoint_hash) != 32
    || Bytes.length(service_public_key) != 32 do
    Err("invalid_checkpoint")
  else
    concat_parts([
        Bytes.from_utf8("mesh-key-transparency-v1"),
        write_u16(version)?,
        write_u64(sequence)?,
        write_u64(tree_size)?,
        tree_root,
        previous_checkpoint_hash,
        write_u64(timestamp)?,
        service_public_key
      ],
      0,
      Bytes.empty())
  end
end

pub fn sign_checkpoint(signing_key :: borrow SigningPrivateKey,
  service_public_key :: Bytes,
  sequence :: U64,
  leaf_hashes :: List<Bytes>,
  previous_checkpoint_hash :: Bytes,
  timestamp :: U64) -> TransparencyCheckpoint!String do
  let root = merkle_root(leaf_hashes)?
  let tree_size = wide(List.length(leaf_hashes))?
  sign_tree_checkpoint(signing_key,
    service_public_key,
    sequence,
    tree_size,
    root,
    previous_checkpoint_hash,
    timestamp)
end

# The directory obtains this root from its incremental tree, in the same
# transaction as its size. The signing statement is unchanged from v1.
pub fn sign_tree_checkpoint(signing_key :: borrow SigningPrivateKey,
  service_public_key :: Bytes,
  sequence :: U64,
  tree_size :: U64,
  root :: Bytes,
  previous_checkpoint_hash :: Bytes,
  timestamp :: U64) -> TransparencyCheckpoint!String do
  sign_tree_checkpoint_for(1,
    signing_key,
    service_public_key,
    sequence,
    tree_size,
    root,
    previous_checkpoint_hash,
    timestamp)
end

pub fn sign_tree_checkpoint_for(version :: Int,
  signing_key :: borrow SigningPrivateKey,
  service_public_key :: Bytes,
  sequence :: U64,
  tree_size :: U64,
  root :: Bytes,
  previous_checkpoint_hash :: Bytes,
  timestamp :: U64) -> TransparencyCheckpoint!String do
  let statement = checkpoint_statement(version,
    sequence,
    tree_size,
    root,
    previous_checkpoint_hash,
    timestamp,
    service_public_key)?
  let signature = case Crypto.sign(signing_key, statement) do
    Err(_) -> Err("checkpoint_signing_failed")
    Ok(value)
  end?
  let bound = case Crypto.verify(SigningPublicKey { bytes: service_public_key },
    statement,
    signature) do
    Err(_) -> Err("checkpoint_signing_failed")
    Ok(value)
  end?
  if !bound do
    Err("checkpoint_signing_failed")
  else
    Ok(TransparencyCheckpoint {
      version: version,
      sequence: sequence,
      tree_size: tree_size,
      tree_root: root,
      previous_checkpoint_hash: previous_checkpoint_hash,
      timestamp: timestamp,
      service_public_key: service_public_key,
      signature: signature.bytes
    })
  end
end

pub fn verify_checkpoint(value :: TransparencyCheckpoint,
  trusted_key :: SigningPublicKey) -> Bool!String do
  if (value.version != 1 && value.version != 2)
    || !Bytes.secure_equals(value.service_public_key, trusted_key.bytes)
    || Bytes.length(value.signature) != 64 do
    Ok(false)
  else
    let statement = checkpoint_statement(value.version,
      value.sequence,
      value.tree_size,
      value.tree_root,
      value.previous_checkpoint_hash,
      value.timestamp,
      value.service_public_key)?
    case Crypto.verify(trusted_key, statement, Signature { bytes: value.signature }) do
      Err(_) -> Err("checkpoint_verification_failed")
      Ok(valid)
    end
  end
end

pub fn checkpoint_hash(value :: TransparencyCheckpoint) -> Bytes!String do
  hash_parts("mesh-msg/v1/transparency-checkpoint",
    [
      checkpoint_statement(value.version,
        value.sequence,
        value.tree_size,
        value.tree_root,
        value.previous_checkpoint_hash,
        value.timestamp,
        value.service_public_key)?,
      value.signature
    ])
end

# One canonical serializer serves the binary wire and the C2SP extension.
pub fn checkpoint_bytes(value :: TransparencyCheckpoint) -> Bytes!String do
  if (value.version != 1 && value.version != 2)
    || Bytes.length(value.tree_root) != 32
    || Bytes.length(value.previous_checkpoint_hash) != 32
    || Bytes.length(value.service_public_key) != 32
    || Bytes.length(value.signature) != 64 do
    return Err("invalid transparency checkpoint")
  end
  let header = if value.version == 1 do
    Bytes.from_hex("014b544b")?
  else
    Bytes.from_hex("024b544b")?
  end
  concat_parts([
      header,
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

pub fn sign_witness(witness_id :: String,
  signing_key :: borrow SigningPrivateKey,
  checkpoint :: TransparencyCheckpoint) -> WitnessAttestation!String do
  if String.length(witness_id) == 0 || String.length(witness_id) > 64 do
    Err("invalid_witness")
  else
    let hash = checkpoint_hash(checkpoint)?
    let statement = concat_parts([
        Bytes.from_utf8("mesh-msg/v1/transparency-witness"),
        Bytes.from_utf8(witness_id),
        hash
      ],
      0,
      Bytes.empty())?
    let signature = case Crypto.sign(signing_key, statement) do
      Err(_) -> Err("witness_signing_failed")
      Ok(value)
    end?
    Ok(WitnessAttestation {
      witness_id: witness_id,
      checkpoint_hash: hash,
      signature: signature.bytes
    })
  end
end

fn trusted_witness(keys :: List<WitnessKey>,
  witness_id :: String,
  index :: Int) -> WitnessKey!String do
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

fn contains_witness(values :: List<String>, witness_id :: String, index :: Int) -> Bool do
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
  attestations :: List<WitnessAttestation>,
  trusted_keys :: List<WitnessKey>,
  index :: Int,
  seen :: List<String>,
  count :: Int) -> Int!String do
  if index >= List.length(attestations) do
    Ok(count)
  else
    let attestation = List.get(attestations, index)
    if contains_witness(seen, attestation.witness_id, 0)
      || !Bytes.secure_equals(attestation.checkpoint_hash, checkpoint_digest)
      || (Bytes.length(attestation.signature) != 64 && Bytes.length(attestation.signature) != 72) do
      count_valid_witnesses(checkpoint,
        checkpoint_digest,
        attestations,
        trusted_keys,
        index + 1,
        seen,
        count)
    else
      case trusted_witness(trusted_keys, attestation.witness_id, 0) do
        Err(_) -> count_valid_witnesses(checkpoint,
          checkpoint_digest,
          attestations,
          trusted_keys,
          index + 1,
          seen,
          count)
        Ok(trusted) -> do
          let valid = witness_signature_valid(checkpoint, attestation, trusted)?
          count_valid_witnesses(checkpoint,
            checkpoint_digest,
            attestations,
            trusted_keys,
            index + 1,
            if valid do
              List.append(seen, attestation.witness_id)
            else
              seen
            end,
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

fn witness_signature_valid(checkpoint :: TransparencyCheckpoint,
  attestation :: WitnessAttestation,
  trusted :: WitnessKey) -> Bool!String do
  if Bytes.length(attestation.signature) == 72 do
    return verify_checkpoint_cosignature(checkpoint_bytes(checkpoint)?,
      attestation.signature,
      SigningPublicKey { bytes: trusted.public_key })
  end
  let statement = concat_parts([
      Bytes.from_utf8("mesh-msg/v1/transparency-witness"),
      Bytes.from_utf8(attestation.witness_id),
      attestation.checkpoint_hash
    ],
    0,
    Bytes.empty())?
  case Crypto.verify(SigningPublicKey { bytes: trusted.public_key },
    statement,
    Signature { bytes: attestation.signature }) do
    Err(_) -> Ok(false)
    Ok(valid)
  end
end

# Historic evidence uses verify_witnesses. Authorization additionally requires
# the C2SP signer's own timestamp, since it does not interpret KTK metadata.
pub fn verify_witnesses_at(checkpoint :: TransparencyCheckpoint,
  attestations :: List<WitnessAttestation>,
  trusted_keys :: List<WitnessKey>,
  threshold :: Int,
  now :: U64) -> Bool!String do
  if List.length(attestations) > 16 do
    return Ok(false)
  end
  let recent = for attestation in attestations when Bytes.length(attestation.signature) == 64
    || cosignature_fresh_at(attestation.signature, now)? do
    attestation
  end
  verify_witnesses(checkpoint, recent, trusted_keys, threshold)
end

pub fn verify_witnesses(checkpoint :: TransparencyCheckpoint,
  attestations :: List<WitnessAttestation>,
  trusted_keys :: List<WitnessKey>,
  threshold :: Int) -> Bool!String do
  if threshold < 1
    || threshold > List.length(trusted_keys)
    || List.length(attestations) > 16
    || List.length(trusted_keys) > 16 do
    Ok(false)
  else
    let digest = checkpoint_hash(checkpoint)?
    Ok(count_valid_witnesses(checkpoint,
      digest,
      attestations,
      trusted_keys,
      0,
      List.new(),
      0)? >= threshold)
  end
end

pub fn checkpoint_conflict(first :: TransparencyCheckpoint,
  second :: TransparencyCheckpoint,
  trusted_key :: SigningPublicKey) -> Bool!String do
  let same_position = first.version == second.version
    && U64.compare(first.sequence, second.sequence) == 0
    && U64.compare(first.tree_size, second.tree_size) == 0
  Ok(same_position
    && !Bytes.secure_equals(first.tree_root, second.tree_root)
    && verify_checkpoint(first, trusted_key)?
    && verify_checkpoint(second, trusted_key)?)
end
