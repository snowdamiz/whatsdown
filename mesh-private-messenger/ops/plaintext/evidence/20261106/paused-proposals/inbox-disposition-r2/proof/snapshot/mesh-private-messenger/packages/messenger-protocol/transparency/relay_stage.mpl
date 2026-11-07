from Solana.Read import Pubkey, pubkey_equal
from Solana.Address import ProgramDerivedAddress, find_program_address
from Transparency.AnchorBond import bond_witness_identity
from Transparency.AnchorWrite import (
  AnchorInstructionPair,
  anchor_post_instructions,
  anchor_cosign_instructions
)
from Transparency.Relay import RelayVerification
from Transparency.Fork import ForkProof, ForkTarget, ForkVerdict, decode_fork, fork_hash
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  WitnessKey,
  checkpoint_hash,
  verify_witnesses
)

pub struct RelayStageSignature do
  ordinal :: Int
  witness :: Option<Pubkey>
  pair :: AnchorInstructionPair
end

pub struct RelayStageWitness do
  key :: WitnessKey
  address :: Pubkey
end

pub struct RelayStagePlan do
  stage :: Pubkey
  full_hash :: Bytes
  proof_hash :: Bytes
  finder :: Bytes
  initialize :: Bytes
  append :: List<Bytes>
  seal :: Bytes
  close :: Bytes
  signatures :: List<RelayStageSignature>
  witnesses :: List<RelayStageWitness>
end

fn cat(parts :: List<Bytes>) -> Bytes!String do
  if List.length(parts) == 0 do
    Ok(Bytes.empty())
  else
    Bytes.concat(List.head(parts), cat(List.tail(parts))?)
  end
end

fn narrow(value :: Int) -> Bytes!String do
  Bytes.write_uint_le(Int.to_string(value), 2)
end

fn pair(ordinal :: Int, ed25519 :: Bytes) -> AnchorInstructionPair!String do
  Ok(AnchorInstructionPair {
    ed25519: ed25519,
    judge: cat([
      Bytes.from_hex("0d")?,
      Bytes.write_uint_le(Int.to_string(ordinal), 1)?,
      narrow(0)?
    ])?
  })
end

fn service_step(checkpoint :: TransparencyCheckpoint,
  ordinal :: Int) -> RelayStageSignature!String do
  Ok(RelayStageSignature {
    ordinal: ordinal,
    witness: None,
    pair: pair(ordinal,
      anchor_post_instructions(checkpoint, checkpoint.service_public_key, 0)?.ed25519)?
  })
end

fn witness_step(program :: Pubkey,
  log_id :: Bytes,
  proof :: ForkProof,
  keys :: List<WitnessKey>,
  index :: Int) -> Option<RelayStageSignature>!String do
  let attestation = List.get(proof.attestations, index)
  if proof.kind == 3 && Bytes.length(attestation.signature) != 64 do
    return Ok(None)
  end
  let checkpoint = if Bytes.secure_equals(attestation.checkpoint_hash,
    checkpoint_hash(proof.first)?) do
    proof.first
  else
    case proof.second do
      AnchorReference(_) -> return Ok(None)
      SignedCheckpoint(second) -> if Bytes.secure_equals(attestation.checkpoint_hash,
        checkpoint_hash(second)?) do
        second
      else
        return Ok(None)
      end
    end
  end
  for key in keys when key.witness_id == attestation.witness_id do
    if verify_witnesses(checkpoint, [attestation], [key], 1)? do
      let address = find_program_address(program,
        [
          Bytes.from_utf8("witness"),
          log_id,
          bond_witness_identity(key.witness_id, key.public_key)?
        ])?.address
      let prepared = anchor_cosign_instructions(checkpoint, attestation, key, 0, 0, 0)?
      return Ok(Some(RelayStageSignature {
        ordinal: index + 2,
        witness: Some(address),
        pair: pair(index + 2, prepared.ed25519)?
      }))
    end
  end
  Ok(None)
end

fn belongs(step :: RelayStageSignature,
  address :: Pubkey,
  proof :: ForkProof,
  hash :: Bytes) -> Bool do
  case step.witness do
    None -> false
    Some(value) -> pubkey_equal(value, address)
      && Bytes.secure_equals(List.get(proof.attestations, step.ordinal - 2).checkpoint_hash, hash)
  end
end

# Consume the pinned preflight result locally. This does not decide custody or
# proof-age admission. The writer must obtain that separate settlement plan
# before funding any upload. Ed25519 indices are zero placeholders, patched by
# the transaction assembler to their actual earlier positions in each packet.
pub fn prepare_relay_stage(program :: Pubkey,
  log_id :: Bytes,
  submitter :: Pubkey,
  verified :: RelayVerification) -> RelayStagePlan!String do
  let proof = decode_fork(verified.proof)?
  if Bytes.length(program.bytes) != 32
    || Bytes.length(log_id) != 32
    || Bytes.length(submitter.bytes) != 32
    || Bytes.to_hex(submitter.bytes) == String.repeat("00", 32)
    || !Bytes.secure_equals(fork_hash(proof)?, verified.proof_hash)
    || !Bytes.secure_equals(proof.finder, verified.finder)
    || !Bytes.secure_equals(proof.service_public_key, verified.verdict.service_public_key)
    || List.length(verified.verdict.witnesses) > 16 do
    return Err("invalid_relay_stage")
  end
  let full_hash = Crypto.sha256(verified.proof)
  let stage = find_program_address(program,
    [Bytes.from_utf8("stage"), submitter.bytes, full_hash])?.address
  let keys = verified.verdict.witnesses
  let subjects = for index in 0..List.length(keys) do
    let key = List.get(keys, index)
    let identity = bond_witness_identity(key.witness_id, key.public_key)?
    for earlier in 0..index do
      let other = List.get(keys, earlier)
      if other.witness_id == key.witness_id
        && Bytes.secure_equals(other.public_key, key.public_key) do
        return Err("invalid_relay_stage")
      end
    end
    RelayStageWitness {
      key: key,
      address: find_program_address(program,
        [Bytes.from_utf8("witness"), log_id, identity])?.address
    }
  end
  let service_steps = case proof.second do
    AnchorReference(_) -> [service_step(proof.first, 0)?]
    SignedCheckpoint(second) -> [service_step(proof.first, 0)?, service_step(second, 1)?]
  end
  let optional_steps = List.flat_map(for index in 0..List.length(proof.attestations) do
      case witness_step(program, log_id, proof, keys, index)? do
        None -> []
        Some(value) -> [value]
      end
    end,
    fn(values) -> values end)
  let first_hash = checkpoint_hash(proof.first)?
  for subject in subjects do
    if List.length(List.filter(optional_steps,
      fn(step) -> belongs(step, subject.address, proof, first_hash) end)) == 0 do
      return Err("invalid_relay_stage")
    end
    case proof.second do
      AnchorReference(_) -> nil
      SignedCheckpoint(second) -> do
        let second_hash = checkpoint_hash(second)?
        if List.length(List.filter(optional_steps,
          fn(step) -> belongs(step, subject.address, proof, second_hash) end)) == 0 do
          return Err("invalid_relay_stage")
        end
      end
    end
  end
  # Judge account triples follow first verified first-side appearance, not the
  # registry or RPC result order; duplicates must not create extra victims.
  let ordered = List.flat_map(for index in 0..List.length(optional_steps) do
      let step = List.get(optional_steps, index)
      let prior = List.take(optional_steps, index)
      for subject in subjects when belongs(step, subject.address, proof, first_hash)
        && List.length(List.filter(prior,
          fn(previous) -> belongs(previous, subject.address, proof, first_hash) end)) == 0 do
        subject
      end
    end,
    fn(values) -> values end)
  let length = Bytes.length(verified.proof)
  let chunks = for index in 0..((length + 899) / 900) do
    let offset = index * 900
    let count = if length - offset < 900 do
      length - offset
    else
      900
    end
    cat([Bytes.from_hex("0b")?, narrow(offset)?, Bytes.slice(verified.proof, offset, count)?])?
  end
  Ok(RelayStagePlan {
    stage: stage,
    full_hash: full_hash,
    proof_hash: verified.proof_hash,
    finder: if Bytes.to_hex(proof.finder) == String.repeat("00", 32) do
      submitter.bytes
    else
      proof.finder
    end,
    initialize: cat([Bytes.from_hex("0a")?, narrow(length)?, full_hash])?,
    append: chunks,
    seal: Bytes.from_hex("0c")?,
    close: Bytes.from_hex("0e")?,
    signatures: service_steps ++ optional_steps,
    witnesses: ordered
  })
end
