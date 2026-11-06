##! Bind a permanent judge verdict to this phone's frozen FRK, not relay JSON.
from Mobile.ForkFilingState import FilingObservation
from Transparency.Fork import ForkProof, ForkTarget, encode_fork, fork_hash
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessKey,
  checkpoint_hash,
  verify_witnesses
)
from Transparency.TokenProofWrite import TokenPreparedProof
from Transparency.AnchorBond import bond_witness_identity
from Solana.Read import Pubkey
from Solana.Address import find_program_address

fn stage(program :: Pubkey, submitter :: Bytes, proof :: ForkProof) -> Bytes!String do
  Ok(find_program_address(program,
    [Bytes.from_utf8("stage"), submitter, Crypto.sha256(encode_fork(proof)?)])?.address.bytes)
end

fn signed_for(proof :: ForkProof,
  checkpoint :: TransparencyCheckpoint,
  key :: WitnessKey) -> Bool!String do
  for attestation in proof.attestations do
    if (proof.kind != 3 || Bytes.length(attestation.signature) == 64)
      && verify_witnesses(checkpoint, [attestation], [key], 1)? do
      return Ok(true)
    end
  end
  Ok(false)
end

fn row_in_proof(proof :: ForkProof, identity :: Bytes, public_key :: Bytes) -> Bool!String do
  for attestation in proof.attestations do
    let key = WitnessKey { witness_id: attestation.witness_id, public_key: public_key }
    if bond_witness_identity(key.witness_id, key.public_key)? == identity do
      let first = signed_for(proof, proof.first, key)?
      return case proof.second do
        AnchorReference(_) -> Ok(first)
        SignedCheckpoint(second) -> Ok(first && signed_for(proof, second, key)?)
      end
    end
  end
  Ok(false)
end

pub fn mixed_filing_observation(program :: Pubkey,
  log_id :: Bytes,
  proof :: ForkProof,
  second_hash :: Bytes,
  receipt :: TokenPreparedProof,
  slot :: U64) -> FilingObservation!String do
  let anchored = case proof.second do
    SignedCheckpoint(_) -> false
    AnchorReference(_) -> true
  end
  if receipt.kind != proof.kind
    || receipt.anchored != anchored
    || receipt.log_id != log_id
    || receipt.proof_hash != fork_hash(proof)?
    || receipt.first_hash != checkpoint_hash(proof.first)?
    || Bytes.length(second_hash) != 32
    || receipt.second_hash != second_hash do
    return Err("invalid_filing_receipt")
  end
  # Finder is outside the chain proof hash. Rebuild the winning wire without
  # changing any signed evidence, including the zero-finder submitter fallback.
  let winning = %{proof | finder: receipt.finder}
  let exact = stage(program, receipt.submitter, winning)? == receipt.stage
  let fallback = receipt.finder == receipt.submitter
    && stage(program,
      receipt.submitter,
      %{proof | finder: Bytes.from_hex(String.repeat("00", 32))?})? == receipt.stage
  if !exact && !fallback do
    return Err("invalid_filing_receipt_stage")
  end
  for row in receipt.rows do
    let witness = find_program_address(program,
      [Bytes.from_utf8("witness"), log_id, row.identity])?.address
    if witness.bytes != row.witness || !row_in_proof(proof, row.identity, row.public_key)? do
      return Err("invalid_filing_receipt_rows")
    end
  end
  let zero = U64.parse("0")?
  Ok(FilingObservation {
    status: if receipt.settled do
      "settled"
    else
      "prepared"
    end,
    context_slot: slot,
    finder: receipt.finder,
    units: if receipt.settled do
      receipt.usdc_finder
    else
      zero
    end,
    morse_units: if receipt.settled do
      receipt.morse_finder
    else
      zero
    end,
    receipt_format: 2,
    receipt_binding: Bytes.empty()
  })
end
