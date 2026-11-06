##! Existing schema-v1 jobs keep the original public protocol boundary.
from Transparency.RpcTransport import RpcTransport
from Input import RelayConfig
from Recovery import read_recovery
from Receipt import read_receipt, PermanentReceipt, permanent_receipt_report, receipt_report
from Transparency.AnchorChain import AnchorPins, anchor_addresses
from Transparency.RelayAdmission import admit_relay_fork
from Transparency.RelayReport import relay_admission_report
from Transparency.RelayStageRead import read_relay_stage, relay_stage_report
from Transparency.RelayDestinations import (
  RelayDestinationState,
  RelayDestinationsState,
  relay_destinations_report
)
from Transparency.TokenCollateralWrite import token_collateral_addresses, collateral_derived
from Transparency.TokenChain import token_payout_address
from Solana.Read import Pubkey
from Transparency.Relay import validate_relay_submission
from Transparency.Fork import fork_hash

pub fn legacy_execute(rpc :: RpcTransport,
  config :: RelayConfig,
  method :: String,
  wire :: Bytes,
  minimum :: U64) -> String!String do
  let p = config.operator.pins
  if method == "legacy-destinations" do
    let state = read_recovery(rpc, config, wire, minimum)?
    let proof = validate_relay_submission(p.service_key, p.log_version, wire)?
    let finder = Pubkey {
      bytes: if Bytes.to_hex(proof.finder) == String.repeat("00", 32) do
        config.submitter.bytes
      else
        proof.finder
      end
    }
    let a = token_collateral_addresses(p.context)?
    let locked = collateral_derived(p.context.judge, [Bytes.from_utf8("locked"), a.log_id])?
    return Ok(relay_destinations_report(RelayDestinationsState {
      proof_hash: fork_hash(proof)?,
      mint: p.context.usdc_mint,
      context_slot: state.context_slot,
      finder: RelayDestinationState {
        address: token_payout_address(finder, p.context.usdc_mint)?,
        owner: finder,
        present: List.get(state.destination_present, 0)
      },
      locked: RelayDestinationState {
        address: token_payout_address(locked, p.context.usdc_mint)?,
        owner: locked,
        present: List.get(state.destination_present, 1)
      }
    }))
  end
  if method == "legacy-admit" || method == "legacy-receipt" do
    let proof = validate_relay_submission(p.service_key, p.log_version, wire)?
    let state = read_receipt(rpc, p, fork_hash(proof)?, minimum)?
    if method == "legacy-receipt" do
      return Ok(receipt_report(state))
    end
    let legacy = case state.value do
      None
      Some(LegacyReceipt(value)) -> Some(value)
      Some(MixedReceipt(_)) -> return Err("relay_legacy_receipt_upgraded")
    end
    case legacy do
      Some(_) -> return Ok("{\"schema_version\":1,\"status\":\"settled\",\"receipt\":#{permanent_receipt_report(state)}}")
      None -> nil
    end
  end
  let addresses = anchor_addresses(p.context.judge, p.context.log_name)?
  let pins = AnchorPins {
    program: p.context.judge,
    log_name: p.context.log_name,
    log_id: addresses.log_id,
    ring: addresses.ring,
    rpc: rpc
  }
  case method do
    "legacy-admit" -> Ok(relay_admission_report(admit_relay_fork(pins,
      p.service_key,
      p.log_version,
      p.context.usdc_mint,
      config.submitter,
      wire,
      minimum)?))
    "legacy-stage" -> Ok(relay_stage_report(read_relay_stage(pins,
      p.service_key,
      p.log_version,
      config.submitter,
      wire,
      minimum)?))
    _ -> Err("relay_legacy_method")
  end
end
