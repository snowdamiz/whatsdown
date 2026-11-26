from Transparency.Merkle import (
  WitnessKey,
  checkpoint_hash,
  leaf_hash,
  merkle_root,
  verify_checkpoint,
  verify_consistency,
  verify_inclusion,
  verify_witnesses
)
from Transparency.CompactWire import TransparencyEvidenceV2, WitnessCosignature
from Transparency.Note import note_checkpoint_body, note_verify_cosignature
from Transparency.Tree import (
  tlog_empty_root,
  tlog_leaf,
  tlog_verify_consistency,
  tlog_verify_inclusion
)
from Transparency.Wire import TransparencyEvidence, decode_checkpoint, encode_checkpoint

pub fn verify_evidence(evidence :: TransparencyEvidence,
  trusted_service_key :: SigningPublicKey,
  trusted_witnesses :: List<WitnessKey>,
  witness_threshold :: Int,
  previous_checkpoint_bytes :: Bytes) -> Bool!String do
  let current_size = U64.to_int(evidence.checkpoint.tree_size)?
  let current_valid = evidence.inclusion.tree_size == current_size
    && evidence.consistency.new_tree_size == current_size
    && verify_checkpoint(evidence.checkpoint, trusted_service_key)?
    && verify_inclusion(leaf_hash(evidence.entry_bytes)?,
      evidence.inclusion,
      evidence.checkpoint.tree_root)?
    && verify_witnesses(evidence.checkpoint,
      evidence.witnesses,
      trusted_witnesses,
      witness_threshold)?
  if !current_valid do
    Ok(false)
  else if Bytes.length(previous_checkpoint_bytes) == 0 do
    Ok(evidence.consistency.old_tree_size == 0
      && verify_consistency(merkle_root(List.new())?,
        evidence.checkpoint.tree_root,
        evidence.consistency)?)
  else
    let previous = decode_checkpoint(previous_checkpoint_bytes)?
    let previous_size = U64.to_int(previous.tree_size)?
    let sequence_order = U64.compare(evidence.checkpoint.sequence, previous.sequence)
    let size_order = U64.compare(evidence.checkpoint.tree_size, previous.tree_size)
    let same_sequence = sequence_order == 0
    let same_checkpoint = Bytes.secure_equals(checkpoint_hash(evidence.checkpoint)?,
      checkpoint_hash(previous)?)
    if !verify_checkpoint(previous, trusted_service_key)?
      || sequence_order < 0
      || size_order < 0
      || (same_sequence && !same_checkpoint)
      || evidence.consistency.old_tree_size != previous_size do
      Ok(false)
    else
      verify_consistency(previous.tree_root, evidence.checkpoint.tree_root, evidence.consistency)
    end
  end
end

# Authorization uses the signed timestamp, never the time a replay arrived.

pub fn checkpoint_fresh_at(timestamp :: U64, now :: U64) -> Bool do
  case U64.to_int(timestamp) do
    Err(_) -> false
    Ok(stamp) -> case U64.to_int(now) do
      Err(_) -> false
      Ok(current) -> if stamp > current do
        stamp - current <= 60000
      else
        current - stamp <= 300000
      end
    end
  end
end

# Version 2 evidence: compact proofs, and attestations that are either Morse
# statements (kind 1) or C2SP cosignatures (kind 2). A kind-2 attestation
# counts only through the dual inclusion rule: the RFC 6962 audit path proves
# the same entry at the same index and size under the cosigned RFC 6962 root,
# the body rebuilt from the pinned origin verifies, and the cosignature is
# fresh. c2sp_origin "" or "-" means kind-2 attestations never count.

fn kind_two_body(evidence :: TransparencyEvidenceV2,
  leaf :: Bytes,
  c2sp_origin :: String) -> String do
  let size = evidence.inclusion.tree_size
  let proven = c2sp_origin != ""
    && c2sp_origin != "-"
    && Bytes.length(evidence.c2sp_root) == 32
    && case tlog_leaf(2, leaf) do
      Err(_) -> false
      Ok(wrapped) -> tlog_verify_inclusion(2,
        wrapped,
        evidence.inclusion.leaf_index,
        size,
        evidence.c2sp_path,
        evidence.c2sp_root)
    end
  let body = case encode_checkpoint(evidence.checkpoint) do
    Err(_) -> Err("unencodable")
    Ok(checkpoint) -> note_checkpoint_body(c2sp_origin, size, evidence.c2sp_root, checkpoint)
  end
  case body do
    Ok(text) -> if proven do
      text
    else
      ""
    end
    Err(_) -> ""
  end
end

fn cosignature_fresh(timestamp :: Int, now :: U64) -> Bool do
  timestamp >= 0
    && timestamp < 1_000_000_000_000_000
    && case U64.parse(Int.to_string(timestamp * 1000)) do
      Ok(stamp) -> checkpoint_fresh_at(stamp, now)
      Err(_) -> false
    end
end

fn morse_statement_valid(value :: WitnessCosignature, key :: Bytes, digest :: Bytes) -> Bool do
  let statement = Bytes.concat(Bytes.from_utf8("mesh-msg/v1/transparency-witness"
      <> value.witness_id),
    digest)
  Bytes.secure_equals(value.checkpoint_hash, digest)
    && Bytes.length(value.signature) == 64
    && case statement do
      Err(_) -> false
      Ok(message) -> case Crypto.verify(SigningPublicKey { bytes: key },
        message,
        Signature { bytes: value.signature }) do
        Ok(valid) -> valid
        Err(_) -> false
      end
    end
end

fn cosignature_valid(value :: WitnessCosignature,
  key :: Bytes,
  digest :: Bytes,
  body :: String,
  now :: U64) -> Bool do
  if value.kind == 1 do
    morse_statement_valid(value, key, digest)
  else if value.kind == 2 do
    body != ""
      && cosignature_fresh(value.timestamp, now)
      && note_verify_cosignature(key, value.timestamp, value.signature, body)
  else
    false
  end
end

fn distinct_ids(keys :: List<WitnessKey>) -> Bool do
  List.all(keys,
    fn key -> List.length(List.filter(keys,
      fn other -> other.witness_id == key.witness_id end)) == 1 end)
end

# Each pinned witness counts once, whichever kind of attestation it signed.

fn attested_witnesses(evidence :: TransparencyEvidenceV2,
  trusted_witnesses :: List<WitnessKey>,
  digest :: Bytes,
  body :: String,
  now :: U64) -> Int do
  List.length(List.filter(trusted_witnesses,
    fn trusted -> List.any(evidence.witnesses,
      fn value -> value.witness_id == trusted.witness_id
        && cosignature_valid(value, trusted.public_key, digest, body, now) end) end))
end

fn previous_consistent(evidence :: TransparencyEvidenceV2,
  trusted_service_key :: SigningPublicKey,
  previous_checkpoint_bytes :: Bytes) -> Bool!String do
  let consistency = evidence.consistency
  if Bytes.length(previous_checkpoint_bytes) == 0 do
    Ok(consistency.old_size == 0
      && tlog_verify_consistency(1,
        0,
        consistency.new_size,
        consistency.path,
        tlog_empty_root(1)?,
        evidence.checkpoint.tree_root))
  else
    let previous = decode_checkpoint(previous_checkpoint_bytes)?
    let sequence_order = U64.compare(evidence.checkpoint.sequence, previous.sequence)
    let same_checkpoint = Bytes.secure_equals(checkpoint_hash(evidence.checkpoint)?,
      checkpoint_hash(previous)?)
    Ok(verify_checkpoint(previous, trusted_service_key)?
      && sequence_order >= 0
      && U64.compare(evidence.checkpoint.tree_size, previous.tree_size) >= 0
      && (sequence_order != 0 || same_checkpoint)
      && consistency.old_size == U64.to_int(previous.tree_size)?
      && tlog_verify_consistency(1,
        consistency.old_size,
        consistency.new_size,
        consistency.path,
        previous.tree_root,
        evidence.checkpoint.tree_root))
  end
end

pub fn transparency_verify_evidence_v2(evidence :: TransparencyEvidenceV2,
  trusted_service_key :: SigningPublicKey,
  trusted_witnesses :: List<WitnessKey>,
  witness_threshold :: Int,
  c2sp_origin :: String,
  previous_checkpoint_bytes :: Bytes,
  now :: U64) -> Bool!String do
  let size = U64.to_int(evidence.checkpoint.tree_size)?
  let leaf = leaf_hash(evidence.entry_bytes)?
  let shape_valid = evidence.inclusion.tree_size == size
    && evidence.consistency.new_size == size
    && witness_threshold >= 1
    && witness_threshold <= List.length(trusted_witnesses)
    && List.length(trusted_witnesses) <= 16
    && List.length(evidence.witnesses) <= 16
    && distinct_ids(trusted_witnesses)
  if !shape_valid
    || !verify_checkpoint(evidence.checkpoint, trusted_service_key)?
    || !tlog_verify_inclusion(1,
      leaf,
      evidence.inclusion.leaf_index,
      size,
      evidence.inclusion.path,
      evidence.checkpoint.tree_root) do
    Ok(false)
  else
    let digest = checkpoint_hash(evidence.checkpoint)?
    let body = kind_two_body(evidence, leaf, c2sp_origin)
    if attested_witnesses(evidence, trusted_witnesses, digest, body, now) < witness_threshold do
      Ok(false)
    else
      previous_consistent(evidence, trusted_service_key, previous_checkpoint_bytes)
    end
  end
end
