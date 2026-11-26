##! Fork evidence FRK v1: two service-signed checkpoints that cannot both be
##! true, with the Morse witness attestations that implicate every witness
##! that signed both. Kinds: 1 same size, 2 contradiction (the same leaf index
##! reads differently), 3 rollback (sequence and size disagree). The second
##! checkpoint may be an anchor ring reference, checked against the ring entry.

from Binary.Reader import BinaryReader
from Transparency.Codec import (
  tcodec_done,
  tcodec_join,
  tcodec_path,
  tcodec_start,
  tcodec_take_fixed,
  tcodec_take_path,
  tcodec_take_u32,
  tcodec_take_u64,
  tcodec_take_u8,
  tcodec_u32,
  tcodec_u64,
  tcodec_u8
)
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  WitnessKey,
  checkpoint_hash,
  verify_checkpoint
)
from Transparency.Tree import tlog_verify_inclusion
from Transparency.Wire import decode_checkpoint, encode_checkpoint

# second is None for a ring reference (form 1) to ring_index. The leaf and
# path fields are used by kind 2 only (empty otherwise).

pub struct ForkEvidence do
  kind :: Int
  finder :: Bytes
  service_public_key :: Bytes
  first :: TransparencyCheckpoint
  second :: Option<TransparencyCheckpoint>
  ring_index :: Int
  attestations :: List<WitnessAttestation>
  leaf_index :: Int
  first_path :: List<Bytes>
  first_leaf :: Bytes
  second_path :: List<Bytes>
  second_leaf :: Bytes
end

# An anchor ring entry as the judge stores it: post_anchor verified its
# service signature, and cosign bitmap bit i is the log's witness i.

pub struct ForkRingEntry do
  sequence :: U64
  tree_size :: U64
  root :: Bytes
  checkpoint_hash :: Bytes
  cosign_bitmap :: Int
end

# The log a proof is judged against: its service key and its witness list, in
# the order the Log account lists them.

pub struct ForkLog do
  service_public_key :: Bytes
  witnesses :: List<WitnessKey>
end

struct ForkSide do
  sequence :: U64
  tree_size :: U64
  root :: Bytes
  checkpoint_hash :: Bytes
  signers :: List<String>
end

struct ReadAttestations do
  state :: BinaryReader
  value :: List<WitnessAttestation>
end

fn valid_attestation(value :: WitnessAttestation) -> Bool do
  let id = Bytes.length(Bytes.from_utf8(value.witness_id))
  id >= 1
    && id <= 64
    && Bytes.length(value.checkpoint_hash) == 32
    && Bytes.length(value.signature) == 64
end

fn encode_attestation(value :: WitnessAttestation) -> Bytes!String do
  let id = Bytes.from_utf8(value.witness_id)
  tcodec_join([tcodec_u8(Bytes.length(id))?, id, value.checkpoint_hash, value.signature])
end

fn encode_second(value :: ForkEvidence) -> Bytes!String do
  case value.second do
    Some(checkpoint) -> tcodec_join([tcodec_u8(0)?, encode_checkpoint(checkpoint)?])
    None -> if value.ring_index < 0 || value.ring_index > 4_294_967_295 do
      Err("invalid fork evidence")
    else
      tcodec_join([tcodec_u8(1)?, tcodec_u32(value.ring_index)?])
    end
  end
end

fn encode_contradiction(value :: ForkEvidence) -> Bytes!String do
  if value.kind != 2 do
    Ok(Bytes.empty())
  else if Bytes.length(value.first_leaf) != 32 || Bytes.length(value.second_leaf) != 32 do
    Err("invalid fork evidence")
  else
    tcodec_join([
      tcodec_u64(value.leaf_index)?,
      tcodec_path(value.first_path, 64)?,
      value.first_leaf,
      tcodec_path(value.second_path, 64)?,
      value.second_leaf
    ])
  end
end

pub fn fork_encode(value :: ForkEvidence) -> Bytes!String do
  if value.kind < 1
    || value.kind > 3
    || Bytes.length(value.finder) != 32
    || Bytes.length(value.service_public_key) != 32
    || List.length(value.attestations) > 16
    || !List.all(value.attestations, fn attestation -> valid_attestation(attestation) end) do
    Err("invalid fork evidence")
  else
    let attestations = for attestation in value.attestations do
      encode_attestation(attestation)?
    end
    let output = tcodec_join([
      tcodec_u8(1)?,
      Bytes.from_utf8("FRK"),
      tcodec_u8(value.kind)?,
      value.finder,
      value.service_public_key,
      encode_checkpoint(value.first)?,
      encode_second(value)?,
      tcodec_u8(List.length(value.attestations))?
    ]
      ++ attestations
      ++ [encode_contradiction(value)?])?
    if Bytes.length(output) > 8192 do
      Err("invalid fork evidence")
    else
      Ok(output)
    end
  end
end

fn read_attestations(state :: BinaryReader,
  count :: Int,
  output :: List<WitnessAttestation>) -> ReadAttestations!String do
  if List.length(output) >= count do
    Ok(ReadAttestations { state: state, value: output })
  else
    let length = tcodec_take_u8(state)?
    let id = tcodec_take_fixed(length.state, length.value)?
    let hash = tcodec_take_fixed(id.state, 32)?
    let signature = tcodec_take_fixed(hash.state, 64)?
    let witness_id = case Bytes.to_utf8(id.value) do
      Err(_) -> Err("invalid fork evidence")
      Ok(text)
    end?
    if length.value < 1 || length.value > 64 do
      Err("invalid fork evidence")
    else
      read_attestations(signature.state,
        count,
        List.append(output,
          WitnessAttestation {
            witness_id: witness_id,
            checkpoint_hash: hash.value,
            signature: signature.value
          }))
    end
  end
end

struct ReadSecond do
  state :: BinaryReader
  second :: Option<TransparencyCheckpoint>
  ring_index :: Int
end

fn read_second(state :: BinaryReader) -> ReadSecond!String do
  let form = tcodec_take_u8(state)?
  if form.value == 0 do
    let checkpoint = tcodec_take_fixed(form.state, 188)?
    Ok(ReadSecond {
      state: checkpoint.state,
      second: Some(decode_checkpoint(checkpoint.value)?),
      ring_index: 0
    })
  else if form.value == 1 do
    let index = tcodec_take_u32(form.state)?
    Ok(ReadSecond { state: index.state, second: None, ring_index: index.value })
  else
    Err("invalid fork evidence")
  end
end

fn read_contradiction(state :: BinaryReader, base :: ForkEvidence) -> ForkEvidence!String do
  let index = tcodec_take_u64(state)?
  let first_path = tcodec_take_path(index.state, 64)?
  let first_leaf = tcodec_take_fixed(first_path.state, 32)?
  let second_path = tcodec_take_path(first_leaf.state, 64)?
  let second_leaf = tcodec_take_fixed(second_path.state, 32)?
  tcodec_done(second_leaf.state)?
  Ok(%{base |
    leaf_index: index.value,
    first_path: first_path.value,
    first_leaf: first_leaf.value,
    second_path: second_path.value,
    second_leaf: second_leaf.value
  })
end

pub fn fork_decode(input :: Bytes) -> ForkEvidence!String do
  let kind = tcodec_take_u8(tcodec_start(input, 8192, 1, "FRK")?)?
  let finder = tcodec_take_fixed(kind.state, 32)?
  let service_key = tcodec_take_fixed(finder.state, 32)?
  let first = tcodec_take_fixed(service_key.state, 188)?
  let second = read_second(first.state)?
  let count = tcodec_take_u8(second.state)?
  if kind.value < 1 || kind.value > 3 || count.value > 16 do
    Err("invalid fork evidence")
  else
    let attestations = read_attestations(count.state, count.value, List.new())?
    let base = ForkEvidence {
      kind: kind.value,
      finder: finder.value,
      service_public_key: service_key.value,
      first: decode_checkpoint(first.value)?,
      second: second.second,
      ring_index: second.ring_index,
      attestations: attestations.value,
      leaf_index: 0,
      first_path: List.new(),
      first_leaf: Bytes.empty(),
      second_path: List.new(),
      second_leaf: Bytes.empty()
    }
    if kind.value == 2 do
      read_contradiction(attestations.state, base)
    else
      tcodec_done(attestations.state)?
      Ok(base)
    end
  end
end

# Keys the judge's pay-once record: every byte except the finder address.

pub fn fork_proof_hash(input :: Bytes) -> Bytes!String do
  if Bytes.length(input) < 69 do
    Err("invalid fork evidence")
  else
    let head = case Bytes.slice(input, 0, 5) do
      Err(_) -> Err("invalid fork evidence")
      Ok(value)
    end?
    let tail = case Bytes.slice(input, 37, Bytes.length(input) - 37) do
      Err(_) -> Err("invalid fork evidence")
      Ok(value)
    end?
    Ok(Crypto.sha256(tcodec_join([Bytes.from_utf8("morse-frk-v1/proof"), head, tail])?))
  end
end

fn attested(key :: WitnessKey, digest :: Bytes, attestations :: List<WitnessAttestation>) -> Bool do
  let statement = Bytes.concat(Bytes.from_utf8("mesh-msg/v1/transparency-witness"
      <> key.witness_id),
    digest)
  case statement do
    Err(_) -> false
    Ok(message) -> List.any(attestations,
      fn value -> value.witness_id == key.witness_id
        && Bytes.secure_equals(value.checkpoint_hash, digest)
        && Bytes.length(value.signature) == 64
        && case Crypto.verify(SigningPublicKey { bytes: key.public_key },
          message,
          Signature { bytes: value.signature }) do
          Ok(valid) -> valid
          Err(_) -> false
        end end)
  end
end

fn inline_side(checkpoint :: TransparencyCheckpoint,
  evidence :: ForkEvidence,
  log :: ForkLog) -> ForkSide!String do
  if !verify_checkpoint(checkpoint, SigningPublicKey { bytes: evidence.service_public_key })? do
    Err("fork_checkpoint_unsigned")
  else
    let digest = checkpoint_hash(checkpoint)?
    Ok(ForkSide {
      sequence: checkpoint.sequence,
      tree_size: checkpoint.tree_size,
      root: checkpoint.tree_root,
      checkpoint_hash: digest,
      signers: for key in List.filter(log.witnesses,
        fn key -> attested(key, digest, evidence.attestations) end) do
        key.witness_id
      end
    })
  end
end

fn bit_set(bitmap :: Int, index :: Int) -> Bool do
  if index <= 0 do
    bitmap % 2 == 1
  else
    bit_set(bitmap / 2, index - 1)
  end
end

fn ring_side(entry :: ForkRingEntry, log :: ForkLog) -> ForkSide!String do
  if Bytes.length(entry.root) != 32
    || Bytes.length(entry.checkpoint_hash) != 32
    || entry.cosign_bitmap < 0 do
    Err("invalid fork ring entry")
  else
    let signers = for index in 0..List.length(log.witnesses) when bit_set(entry.cosign_bitmap,
      index) do
      List.get(log.witnesses, index).witness_id
    end
    Ok(ForkSide {
      sequence: entry.sequence,
      tree_size: entry.tree_size,
      root: entry.root,
      checkpoint_hash: entry.checkpoint_hash,
      signers: signers
    })
  end
end

fn sides(evidence :: ForkEvidence,
  log :: ForkLog,
  ring :: Option<ForkRingEntry>) -> (ForkSide, ForkSide)!String do
  if !Bytes.secure_equals(evidence.service_public_key, log.service_public_key) do
    Err("fork_wrong_log")
  else
    let first = inline_side(evidence.first, evidence, log)?
    let second = case evidence.second do
      Some(checkpoint) -> inline_side(checkpoint, evidence, log)
      None -> case ring do
        Some(entry) -> ring_side(entry, log)
        None -> Err("fork_ring_entry_required")
      end
    end?
    Ok((first, second))
  end
end

fn implicated(first :: ForkSide, second :: ForkSide, log :: ForkLog) -> List<String> do
  for key in log.witnesses when List.contains(first.signers, key.witness_id)
    && List.contains(second.signers, key.witness_id) do
    key.witness_id
  end
end

fn same_size_holds(first :: ForkSide, second :: ForkSide) -> Bool do
  U64.compare(first.tree_size, second.tree_size) == 0
    && !Bytes.secure_equals(first.root, second.root)
end

fn rollback_holds(first :: ForkSide, second :: ForkSide) -> Bool do
  let sequence = U64.compare(first.sequence, second.sequence)
  let size = U64.compare(first.tree_size, second.tree_size)
  (sequence < 0 && size > 0)
    || (sequence > 0 && size < 0)
    || (sequence == 0 && !Bytes.secure_equals(first.checkpoint_hash, second.checkpoint_hash))
end

fn contradiction_holds(evidence :: ForkEvidence, first :: ForkSide, second :: ForkSide) -> Bool do
  let index = evidence.leaf_index
  case U64.to_int(first.tree_size) do
    Err(_) -> false
    Ok(first_size) -> case U64.to_int(second.tree_size) do
      Err(_) -> false
      Ok(second_size) -> index >= 0
        && index < first_size
        && index < second_size
        && !Bytes.secure_equals(evidence.first_leaf, evidence.second_leaf)
        && tlog_verify_inclusion(1,
          evidence.first_leaf,
          index,
          first_size,
          evidence.first_path,
          first.root)
        && tlog_verify_inclusion(1,
          evidence.second_leaf,
          index,
          second_size,
          evidence.second_path,
          second.root)
    end
  end
end

fn judged(holds :: Bool,
  first :: ForkSide,
  second :: ForkSide,
  log :: ForkLog) -> List<String>!String do
  if holds do
    Ok(implicated(first, second, log))
  else
    Err("not_a_fork")
  end
end

pub fn fork_same_size(evidence :: ForkEvidence,
  log :: ForkLog,
  ring :: Option<ForkRingEntry>) -> List<String>!String do
  let (first, second) = sides(evidence, log, ring)?
  judged(same_size_holds(first, second), first, second, log)
end

pub fn fork_contradiction(evidence :: ForkEvidence,
  log :: ForkLog,
  ring :: Option<ForkRingEntry>) -> List<String>!String do
  let (first, second) = sides(evidence, log, ring)?
  judged(contradiction_holds(evidence, first, second), first, second, log)
end

pub fn fork_rollback(evidence :: ForkEvidence,
  log :: ForkLog,
  ring :: Option<ForkRingEntry>) -> List<String>!String do
  let (first, second) = sides(evidence, log, ring)?
  judged(rollback_holds(first, second), first, second, log)
end

# Checks the kind the proof claims. Returns the implicated witness IDs in the
# log's order; an error means the proof is not a valid fork.

pub fn fork_verify(evidence :: ForkEvidence,
  log :: ForkLog,
  ring :: Option<ForkRingEntry>) -> List<String>!String do
  if evidence.kind == 1 do
    fork_same_size(evidence, log, ring)
  else if evidence.kind == 2 do
    fork_contradiction(evidence, log, ring)
  else if evidence.kind == 3 do
    fork_rollback(evidence, log, ring)
  else
    Err("invalid fork evidence")
  end
end

# Which fork two checkpoints prove on their own: 1 (same size, preferred: it
# reveals only two roots), 3 (rollback), or 0 when only a consistency proof
# or a leaf comparison (kind 2) can tell. Signatures are the caller's to check.

pub fn fork_kind_between(first :: TransparencyCheckpoint,
  second :: TransparencyCheckpoint) -> Int!String do
  let first_side = ForkSide {
    sequence: first.sequence,
    tree_size: first.tree_size,
    root: first.tree_root,
    checkpoint_hash: checkpoint_hash(first)?,
    signers: List.new()
  }
  let second_side = ForkSide {
    sequence: second.sequence,
    tree_size: second.tree_size,
    root: second.tree_root,
    checkpoint_hash: checkpoint_hash(second)?,
    signers: List.new()
  }
  if same_size_holds(first_side, second_side) do
    Ok(1)
  else if rollback_holds(first_side, second_side) do
    Ok(3)
  else
    Ok(0)
  end
end
