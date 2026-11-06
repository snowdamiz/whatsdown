##! Operator pin adapter and byte-compatible permanent receipt reports.
from Transparency.RpcTransport import RpcTransport, rpc_urls, require_rpc_current
from Transparency.PermanentReceipt import (
  PermanentReceiptPins,
  PermanentReceiptState,
  PermanentReceipt,
  permanent_receipt_keys,
  decode_permanent_receipt_snapshot,
  read_permanent_receipt
)
from Read import (
  CollateralOperatorPins,
  validate_collateral_operator_pins,
  validate_collateral_operator_sources
)
from Solana.Read import Pubkey, OptionalAccountSlicesAtSlot, pubkey_string
from Transparency.SlashReceiptRead import ConfirmedSlashReceipt, slash_receipt_report

fn permanent_pins(pins :: CollateralOperatorPins) -> PermanentReceiptPins!String do
  validate_collateral_operator_pins(pins)?
  Ok(PermanentReceiptPins {
    judge: pins.context.judge,
    token: pins.context.token,
    log_name: pins.context.log_name,
    usdc: pins.context.usdc_mint,
    judge_slot: pins.judge_slot,
    service_key: pins.service_key,
    log_version: pins.log_version
  })
end

pub fn receipt_keys(pins :: CollateralOperatorPins, proof_hash :: Bytes) -> List<Pubkey>!String do
  permanent_receipt_keys(permanent_pins(pins)?, proof_hash)
end

pub fn decode_receipt_snapshot(pins :: CollateralOperatorPins,
  proof_hash :: Bytes,
  minimum :: U64,
  snapshot :: OptionalAccountSlicesAtSlot) -> PermanentReceiptState!String do
  decode_permanent_receipt_snapshot(permanent_pins(pins)?, proof_hash, minimum, snapshot)
end

pub fn read_receipt(rpc :: RpcTransport,
  pins :: CollateralOperatorPins,
  hash :: Bytes,
  minimum :: U64) -> PermanentReceiptState!String do
  require_rpc_current(rpc.require_current)?
  validate_collateral_operator_sources(rpc_urls(rpc))?
  case read_permanent_receipt(rpc, permanent_pins(pins)?, hash, minimum) do
    Err("anchor_rpc_unavailable") -> Err("relay_receipt_quorum")
    Err("anchor_rpc_disagree") -> Err("relay_receipt_quorum")
    result
  end
end

fn key(value :: Bytes) -> String do
  Json.encode_string(Bytes.to_base58(value))
end

fn hex(value :: Bytes) -> String do
  Json.encode_string(Bytes.to_hex(value))
end

fn units(value :: U64) -> String do
  Json.encode_string(U64.to_string(value))
end

pub fn permanent_receipt_report(state :: PermanentReceiptState) -> String do
  let r = case state.value do
    None -> return "null"
    Some(value) -> value
  end
  case r do
    MixedReceipt(v) ->
      let rows = for row in v.rows do
        """{"identity":#{hex(row.identity)},"witness":#{key(row.witness)},"public_key":#{hex(row.public_key)},"asset":#{row.asset},"bonded_at":#{units(row.bonded_at)},"principal_units":#{units(row.principal)},"slashed_units":#{units(row.slashed)},"finder_units":#{units(row.finder)}}"""
      end
      """{"schema_version":2,"format":"MPR2","status":#{Json.encode_string(state.status)},"log_id":#{hex(v.log_id)},"proof_hash":#{hex(v.proof_hash)},"kind":#{v.kind},"anchored":#{v.anchored},"finder":#{key(v.finder)},"submitter":#{key(v.submitter)},"usdc_mint":#{key(v.usdc_mint)},"morse_mint":#{key(v.morse_mint)},"first_checkpoint":#{hex(v.first_hash)},"second_checkpoint":#{hex(v.second_hash)},"prepared_at":#{units(v.prepared_at)},"settled_at":#{units(v.settled_at)},"usdc_slashed_units":#{units(v.usdc_slashed)},"usdc_finder_units":#{units(v.usdc_finder)},"directory_usdc_units":#{units(v.directory_usdc)},"morse_slashed_units":#{units(v.morse_slashed)},"morse_finder_units":#{units(v.morse_finder)},"directory_morse_units":#{units(v.directory_morse)},"stage":#{key(v.stage)},"deadline_ms":#{units(v.deadline_ms)},"directory_bonded_at":#{units(v.directory_bonded_at)},"directory_asset":#{v.directory_asset},"verified_signature_mask":#{units(v.verified_signature_mask)},"context_slot":#{units(state.context_slot)},"witnesses":[#{String.join(rows,
        ",")}]}"""
    LegacyReceipt(v) -> slash_receipt_report(ConfirmedSlashReceipt {
      receipt: v,
      context_slot: state.context_slot
    })
  end
end

pub fn receipt_report(state :: PermanentReceiptState) -> String do
  """{"schema_version":2,"status":#{Json.encode_string(state.status)},"address":#{Json.encode_string(pubkey_string(state.address))},"proof_hash":#{hex(state.proof_hash)},"context_slot":#{units(state.context_slot)},"digest":#{hex(state.digest)},"receipt":#{permanent_receipt_report(state)}}"""
end
