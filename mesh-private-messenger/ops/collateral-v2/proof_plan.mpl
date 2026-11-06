from ProofRead import CollateralProofIntent, CollateralProofState, collateral_proof_selection
from Read import CollateralOperatorPins
from Plan import CollateralOperationPlan
from Transparency.TokenProofWrite import (
  token_proof_initialize_instruction,
  token_proof_append_instruction,
  token_proof_seal_instruction,
  token_proof_close_instruction,
  token_proof_signature_instructions,
  token_proof_prepare_instruction,
  token_proof_settle_instruction,
  token_proof_payout_setup_instructions
)
from Solana.Tx import Instruction
from Solana.Read import Pubkey

fn proof_result(intent :: CollateralProofIntent,
  state :: CollateralProofState,
  status :: String,
  reason :: String,
  instructions :: List<Instruction>) -> CollateralOperationPlan do
  let all = List.flatten(for ix in instructions do
    for meta in ix.accounts when meta.signer do
      meta.pubkey
    end
  end)
  let keys = List.reduce(all,
    [],
    fn(keys, key) do
      if List.contains(keys, key) do
        keys
      else
        keys ++ [key]
      end
    end)
  CollateralOperationPlan {
    state: status,
    reason: reason,
    slot: state.base.slot,
    digest: state.digest,
    fee_payer: intent.fee_payer,
    instruction_signers: keys,
    rent_payers: if reason == "initialize_proof_stage" do
      [intent.submitter]
    else if reason == "payout_accounts" || reason == "prepare_permanent_receipt" do
      [intent.fee_payer]
    else
      []
    end,
    governance_required: false,
    wait_until: None,
    instructions: instructions
  }
end

pub fn plan_collateral_proof(pins :: CollateralOperatorPins,
  intent :: CollateralProofIntent,
  state :: CollateralProofState) -> CollateralOperationPlan!String do
  if state.selection != collateral_proof_selection(pins, intent)?
    || state.plan.full_hash != Crypto.sha256(intent.wire) do
    return Err("collateral_proof_plan_binding")
  end
  let c = pins.context
  if intent.close do
    if state.stage.status == "missing" do
      return Ok(proof_result(intent, state, "complete", "stage_absent", []))
    end
    return Ok(proof_result(intent,
      state,
      "ready",
      "explicit_stage_close",
      [token_proof_close_instruction(c, intent.submitter, intent.wire)?]))
  end
  case state.receipt do
    Some(receipt) ->
      if receipt.settled do
        return Ok(proof_result(intent, state, "complete", "proof_settled", []))
      end
      if List.length(state.payout_missing) > 0 do
        # At most four ATA creations. No token transfer or finder mutation.
        return Ok(proof_result(intent,
          state,
          "ready",
          "payout_accounts",
          token_proof_payout_setup_instructions(c, intent.fee_payer, receipt)?))
      end
      return Ok(proof_result(intent,
        state,
        "ready",
        "settle_mixed_assets",
        [token_proof_settle_instruction(c, receipt)?]))
    None -> nil
  end
  if state.stage.status == "missing" do
    return Ok(proof_result(intent,
      state,
      "ready",
      "initialize_proof_stage",
      [token_proof_initialize_instruction(c, intent.submitter, intent.wire)?]))
  end
  if state.stage.received_bytes < state.stage.total_bytes do
    return Ok(proof_result(intent,
      state,
      "ready",
      "append_proof_stage",
      [
        token_proof_append_instruction(c,
          intent.submitter,
          intent.wire,
          state.stage.received_bytes)?
      ]))
  end
  if !state.stage.sealed do
    return Ok(proof_result(intent,
      state,
      "ready",
      "seal_proof_stage",
      [token_proof_seal_instruction(c, intent.submitter, intent.wire)?]))
  end
  for signature in state.plan.signatures do
    if List.length(List.filter(state.stage.verified,
      fn(step) do step.ordinal == signature.ordinal end)) == 0 do
      let key = case signature.witness do
        None
        Some(address) ->
          let matches = List.filter(state.plan.witnesses, fn(row) do row.address == address end)
          if List.length(matches) != 1 do
            return Err("collateral_proof_signature_key")
          end
          Some(List.head(matches).key)
      end
      # This exact packet has Ed25519 at index0 immediately before judge13.
      # A transaction assembler must preserve this order/index.
      return Ok(proof_result(intent,
        state,
        "ready",
        "verify_one_signature",
        token_proof_signature_instructions(c,
          intent.submitter,
          intent.wire,
          signature.ordinal,
          key,
          0)?))
    end
  end
  Ok(proof_result(intent,
    state,
    "ready",
    "prepare_permanent_receipt",
    [
      token_proof_prepare_instruction(c,
        intent.fee_payer,
        intent.submitter,
        intent.wire,
        state.plan,
        state.second_hash,
        state.anchor_generation)?
    ]))
end
