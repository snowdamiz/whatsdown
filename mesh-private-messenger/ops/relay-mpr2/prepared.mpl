##! Reuse the collateral verifier with the authenticated permanent winner.
from ProofRead import CollateralProofIntent
from Read import CollateralOperatorPins
from Receipt import RelayReceiptState, PermanentReceipt
from Transparency.Relay import validate_relay_submission
from Transparency.Fork import encode_fork, fork_hash
from Transparency.TokenProofWrite import token_proof_stage_address
from Solana.Read import Pubkey

pub fn prepared_intent(pins :: CollateralOperatorPins,
  original :: CollateralProofIntent,
  receipt :: RelayReceiptState) -> CollateralProofIntent!String do
  if receipt.status != "prepared" do
    return Ok(original)
  end
  let winner = case receipt.value do
    Some(MixedReceipt(value)) -> value
    _ -> return Err("relay_prepared_receipt_required")
  end
  let proof = validate_relay_submission(pins.service_key, pins.log_version, original.wire)?
  if winner.settled || winner.proof_hash != fork_hash(proof)? do
    return Err("relay_prepared_proof_binding")
  end
  let submitter = Pubkey { bytes: winner.submitter }
  # A zero wire finder resolves to the submitter. The stage PDA disambiguates
  # that canonical wire from an explicitly encoded finder equal to submitter.
  let finders = if winner.finder == winner.submitter do
    [winner.finder, Bytes.from_hex(String.repeat("00", 32))?]
  else
    [winner.finder]
  end
  for finder in finders do
    let wire = encode_fork(%{proof | finder: finder})?
    if token_proof_stage_address(pins.context, submitter, wire)?.bytes == winner.stage do
      return Ok(%{original | submitter: submitter, wire: wire})
    end
  end
  Err("relay_prepared_stage_binding")
end
