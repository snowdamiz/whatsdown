from Input import RelayConfig
from ProofRead import CollateralProofIntent, CollateralProofState
from Plan import CollateralOperationPlan
from Receipt import RelayReceiptState, permanent_receipt_report
from Lookup import lookup_report
from Transparency.RelayLookup import RelayLookupPlan
from Transparency.TokenCollateralWrite import (
  token_collateral_addresses,
  token_collateral_subject,
  TokenCollateralSubject
)
from Transparency.TokenProofWrite import token_proof_stage_address
from Transparency.Relay import validate_relay_submission
from Transparency.Fork import fork_hash
from Transparency.SlashReceipt import slash_receipt_address
from Solana.Read import Pubkey, pubkey_string
from Solana.Tx import instruction_report_json, compute_unit_limit_instruction

fn key(value :: Pubkey) -> String do
  Json.encode_string(pubkey_string(value))
end

fn hex(value :: Bytes) -> String do
  Json.encode_string(Bytes.to_hex(value))
end

pub fn effect_descriptor(wire :: Bytes,
  state :: CollateralProofState,
  plan :: CollateralOperationPlan) -> String!String do
  let extra = if plan.reason == "migrate_legacy_bond" do
    let subject = List.head(state.legacy_subjects)
    let raw = case subject do
      CollateralDirectory -> "{\"kind\":\"directory\"}"
      CollateralWitness(witness) -> "{\"kind\":\"witness\",\"witness_id\":#{Json.encode_string(witness.witness_id)},\"public_key\":#{hex(witness.public_key)}}"
    end
    ",\"subject\":#{raw},\"bond\":#{key(List.get(List.head(plan.instructions).accounts, 3).pubkey)}"
  else if plan.reason == "append_proof_stage" do
    let ix = List.head(plan.instructions)
    let offset = U64.to_int(U64.parse(Bytes.read_uint_le(ix.data, 1, 2)?)?)?
    ",\"append_end\":#{offset + Bytes.length(ix.data) - 3}"
  else if plan.reason == "verify_one_signature" do
    let ix = List.get(plan.instructions, 1)
    let ordinal = Bytes.get(ix.data, 1)?
    let signature = List.head(List.filter(state.plan.signatures,
      fn(step) do step.ordinal == ordinal end))
    let public_key = case signature.witness do
      None -> validate_relay_submission(state.base.log.service_public_key,
        state.base.log.version,
        wire)?.service_public_key
      Some(address) -> List.head(List.filter(state.plan.witnesses,
        fn(row) do row.address == address end)).key.public_key
    end
    ",\"ordinal\":#{ordinal},\"public_key\":#{hex(public_key)}"
  else
    ""
  end
  Ok("""{"schema_version":1,"full_hash":#{hex(Crypto.sha256(wire))},"reason":#{Json.encode_string(plan.reason)}#{extra}}""")
end

pub fn ready_report(config :: RelayConfig,
  intent :: CollateralProofIntent,
  state :: CollateralProofState,
  plan :: CollateralOperationPlan,
  lookup :: RelayLookupPlan) -> String!String do
  let a = token_collateral_addresses(config.operator.pins.context)?
  let receipt = token_receipt_address(config, state.plan.proof_hash)?
  let rents = if plan.reason == "initialize_proof_stage" do
    ["""{"address":#{key(state.plan.stage)},"space":#{1152 + Bytes.length(intent.wire)}}"""]
  else if plan.reason == "prepare_permanent_receipt" do
    ["""{"address":#{key(receipt)},"space":#{400 + List.length(state.plan.witnesses) * 144}}"""]
  else if plan.reason == "payout_accounts" do
    for ix in plan.instructions do
      """{"address":#{key(List.get(ix.accounts, 1).pubkey)},"space":165}"""
    end
  else
    []
  end
  let instructions = String.join(for ix in plan.instructions do
      instruction_report_json(ix)
    end,
    ",")
  Ok("""{"schema_version":2,"status":"ready","program":#{key(config.operator.pins.context.judge)},"log":#{key(a.log)},"submitter":#{key(config.submitter)},"fee_payer":#{key(config.fee_payer)},"usdc_mint":#{key(config.operator.pins.context.usdc_mint)},"morse_mint":#{key(a.morse_mint)},"proof_hex":#{hex(intent.wire)},"proof_hash":#{hex(state.plan.proof_hash)},"finder":#{Json.encode_string(Bytes.to_base58(state.plan.finder))},"receipt":#{key(receipt)},"context_slot":"#{U64.to_string(state.base.slot)}","stage":{"address":#{key(state.plan.stage)},"full_hash":#{hex(state.plan.full_hash)}},"digest":#{hex(state.digest)},"selection":#{hex(state.selection)},"compute_budget":#{instruction_report_json(compute_unit_limit_instruction(1400000)?)},"operation":{"reason":#{Json.encode_string(plan.reason)},"instructions":[#{instructions}],"rent_allocations":[#{String.join(rents,
    ",")}],"effect":#{effect_descriptor(intent.wire,
    state,
    plan)?}},"lookup":#{lookup_report(lookup)}}""")
end

pub fn token_receipt_address(config :: RelayConfig, hash :: Bytes) -> Pubkey!String do
  let a = token_collateral_addresses(config.operator.pins.context)?
  slash_receipt_address(config.operator.pins.context.judge, a.log_id, hash)
end

pub fn settled_report(config :: RelayConfig,
  wire :: Bytes,
  state :: RelayReceiptState) -> String!String do
  let a = token_collateral_addresses(config.operator.pins.context)?
  let proof = validate_relay_submission(config.operator.pins.service_key,
    config.operator.pins.log_version,
    wire)?
  let finder = if Bytes.to_hex(proof.finder) == String.repeat("00", 32) do
    config.submitter.bytes
  else
    proof.finder
  end
  Ok("""{"schema_version":2,"status":"settled","program":#{key(config.operator.pins.context.judge)},"log":#{key(a.log)},"submitter":#{key(config.submitter)},"usdc_mint":#{key(config.operator.pins.context.usdc_mint)},"morse_mint":#{key(a.morse_mint)},"proof_hex":#{hex(wire)},"proof_hash":#{hex(fork_hash(proof)?)},"finder":#{Json.encode_string(Bytes.to_base58(finder))},"receipt":#{key(state.address)},"context_slot":"#{U64.to_string(state.context_slot)}","stage":{"address":#{key(token_proof_stage_address(config.operator.pins.context,
    config.submitter,
    wire)?)},"full_hash":#{hex(Crypto.sha256(wire))}},"digest":#{hex(state.digest)},"selection":#{hex(Crypto.sha256(wire))},"operation":null,"lookup":null,"settled_receipt":#{permanent_receipt_report(state)}}""")
end
