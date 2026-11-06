##! Reconcile old operations without readmission through mutable collateral.
from Transparency.RpcTransport import (
  RpcTransport,
  RpcEndpoint,
  rpc_urls,
  rpc_fatal_error,
  require_rpc_current
)
from Transparency.AnchorRpc import read_anchor_rpc_response
from Input import RelayConfig, text
from Receipt import (
  RelayReceiptState,
  PermanentReceipt,
  read_receipt,
  receipt_keys,
  decode_receipt_snapshot
)
from Accounts import operator_snapshot_digest, operator_absent
from Solana.Read import (
  Pubkey,
  OptionalAccountSlicesAtSlot,
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response
)
from Transparency.TokenCollateralWrite import token_collateral_addresses, collateral_derived
from Transparency.TokenProofWrite import token_proof_stage_address
from Transparency.TokenChain import token_payout_address
from Transparency.RelayDestinations import check_relay_destination
from Transparency.Relay import validate_relay_submission
from Transparency.Fork import fork_hash
from Transparency.RelayStageRead import RelayStageState, decode_relay_stage, relay_stage_report
from Read import validate_collateral_operator_sources

pub struct RecoveryState do
  receipt :: RelayReceiptState
  stage :: RelayStageState
  destination_present :: List<Bool>
  destinations_ready :: Bool
  context_slot :: U64
  digest :: Bytes
end

fn payout_finder(config :: RelayConfig,
  wire :: Bytes,
  receipt :: RelayReceiptState) -> Pubkey!String do
  case receipt.value do
    Some(MixedReceipt(value)) -> return Ok(Pubkey { bytes: value.finder })
    Some(LegacyReceipt(value)) -> return Ok(Pubkey { bytes: value.finder })
    None -> nil
  end
  let proof = validate_relay_submission(config.operator.pins.service_key,
    config.operator.pins.log_version,
    wire)?
  Ok(Pubkey {
    bytes: if Bytes.to_hex(proof.finder) == String.repeat("00", 32) do
      config.submitter.bytes
    else
      proof.finder
    end
  })
end

pub fn recovery_keys(config :: RelayConfig,
  wire :: Bytes,
  finder :: Pubkey) -> List<Pubkey>!String do
  let pins = config.operator.pins
  let proof = validate_relay_submission(pins.service_key, pins.log_version, wire)?
  let a = token_collateral_addresses(pins.context)?
  let locked = collateral_derived(pins.context.judge, [Bytes.from_utf8("locked"), a.log_id])?
  Ok(receipt_keys(pins, fork_hash(proof)?)?
    ++ [token_proof_stage_address(pins.context, config.submitter, wire)?]
    ++ List.flatten(for mint in [pins.context.usdc_mint, a.morse_mint] do
      for owner in [finder, locked] do
        token_payout_address(owner, mint)?
      end
    end))
end

pub fn decode_recovery_snapshot(config :: RelayConfig,
  wire :: Bytes,
  minimum :: U64,
  finder :: Pubkey,
  snapshot :: OptionalAccountSlicesAtSlot) -> RecoveryState!String do
  let keys = recovery_keys(config, wire, finder)?
  if List.length(snapshot.accounts) != List.length(keys) do
    return Err("relay_recovery_snapshot")
  end
  let pins = config.operator.pins
  let a = token_collateral_addresses(pins.context)?
  let proof = validate_relay_submission(pins.service_key, pins.log_version, wire)?
  let receipt = decode_receipt_snapshot(pins,
    fork_hash(proof)?,
    minimum,
    OptionalAccountSlicesAtSlot { slot: snapshot.slot, accounts: List.take(snapshot.accounts, 4) })?
  let account = case List.get(snapshot.accounts, 4) do
    None
    Some(v) ->
      if v.space != U64.parse(Int.to_string(1152 + Bytes.length(wire)))?
        && !operator_absent(Some(v)) do
        return Err("relay_recovery_stage_space")
      end
      Some(v.info)
  end
  let stage = decode_relay_stage(pins.context.judge,
    a.log_id,
    config.submitter,
    wire,
    account,
    snapshot.slot)?
  if payout_finder(config, wire, receipt)? != finder do
    return Err("relay_recovery_winner_changed")
  end
  let locked = collateral_derived(pins.context.judge, [Bytes.from_utf8("locked"), a.log_id])?
  let destinations = for index in 0..4 do
    let slice = List.get(snapshot.accounts, 5 + index)
    let account = if operator_absent(slice) do
      None
    else
      case slice do
        None
        Some(value) ->
          if value.space != U64.parse("165")? do
            return Err("relay_destination_space")
          end
          Some(value.info)
      end
    end
    check_relay_destination(account,
      if index % 2 == 0 do
        finder
      else
        locked
      end,
      if index < 2 do
        pins.context.usdc_mint
      else
        a.morse_mint
      end,
      U64.parse("0")?,
      index % 2 == 1)?
  end
  Ok(RecoveryState {
    receipt: receipt,
    stage: stage,
    context_slot: snapshot.slot,
    destination_present: destinations,
    destinations_ready: List.all(destinations, fn(value) do value end),
    digest: operator_snapshot_digest(keys, snapshot)?
  })
end

fn origin(rpc :: RpcTransport,
  endpoint :: RpcEndpoint,
  config :: RelayConfig,
  wire :: Bytes,
  finder :: Pubkey,
  minimum :: U64) -> RecoveryState!String do
  let request = get_multiple_accounts_slice_request(1,
    recovery_keys(config, wire, finder)?,
    "finalized",
    0,
    9216,
    Some(minimum))?
  decode_recovery_snapshot(config,
    wire,
    minimum,
    finder,
    optional_accounts_slice_from_response(read_anchor_rpc_response(rpc,
      endpoint,
      request,
      262144)?)?)
end

pub fn read_recovery(rpc :: RpcTransport,
  config :: RelayConfig,
  wire :: Bytes,
  minimum :: U64) -> RecoveryState!String do
  require_rpc_current(rpc.require_current)?
  validate_collateral_operator_sources(rpc_urls(rpc))?
  let proof = validate_relay_submission(config.operator.pins.service_key,
    config.operator.pins.log_version,
    wire)?
  let receipt = read_receipt(rpc, config.operator.pins, fork_hash(proof)?, minimum)?
  let finder = payout_finder(config, wire, receipt)?
  let floor = receipt.context_slot
  let results = for endpoint in List.take(rpc.sources, 3) do
    let result = origin(rpc, endpoint, config, wire, finder, floor)
    case result do
      Err(error) when rpc_fatal_error(error) -> return Err(error)
      _ -> result
    end
  end
  require_rpc_current(rpc.require_current)?
  let first = List.get(results, 0)
  let second = List.get(results, 1)
  let third = List.get(results, 2)
  for pair in [(first, second), (first, third), (second, third)] do
    case pair do
      (Ok(a), Ok(b)) -> if a.digest == b.digest do
        require_rpc_current(rpc.require_current)?
        return Ok(a)
      end
      _ -> nil
    end
  end
  Err("relay_recovery_quorum")
end

pub fn stage_report(state :: RecoveryState) -> String!String do
  Ok(String.replace(relay_stage_report(state.stage),
    "\"schema_version\":1",
    "\"schema_version\":2"))
end

pub fn effect_present(wire :: Bytes, descriptor :: Json, state :: RecoveryState) -> Bool!String do
  if Json.as_int(Json.object_get(descriptor, "schema_version")?)? != 1
    || text(descriptor, "full_hash")? != Bytes.to_hex(Crypto.sha256(wire)) do
    return Err("relay_effect_binding")
  end
  let reason = text(descriptor, "reason")?
  let settled = state.receipt.status == "settled"
  let prepared = state.receipt.status == "prepared"
  if reason == "settle_mixed_assets" do
    return Ok(settled)
  end
  if reason == "prepare_permanent_receipt" do
    return Ok(prepared || settled)
  end
  if reason == "explicit_stage_close" do
    if !settled do
      return Err("relay_close_requires_settled_receipt")
    end
    return Ok(state.stage.status == "missing")
  end
  if reason == "payout_accounts" do
    return Ok(settled || state.destinations_ready)
  end
  if reason == "initialize_proof_stage" do
    return Ok(settled || prepared || state.stage.status != "missing")
  end
  if reason == "append_proof_stage" do
    let end_at = Json.as_int(Json.object_get(descriptor, "append_end")?)?
    if end_at < 1 || end_at > Bytes.length(wire) do
      return Err("relay_effect_append")
    end
    return Ok(settled || prepared || state.stage.received_bytes >= end_at)
  end
  if reason == "seal_proof_stage" do
    return Ok(settled || prepared || state.stage.sealed)
  end
  if reason == "verify_one_signature" do
    let ordinal = Json.as_int(Json.object_get(descriptor, "ordinal")?)?
    let key = Bytes.from_hex(text(descriptor, "public_key")?)?
    if ordinal < 0 || ordinal >= 34 || Bytes.length(key) != 32 do
      return Err("relay_effect_signature")
    end
    let earned = List.filter(state.stage.verified, fn(step) do step.ordinal == ordinal end)
    if List.length(earned) == 1 && List.head(earned).public_key != key do
      return Err("relay_effect_signature_changed")
    end
    return Ok(settled || prepared || List.length(earned) == 1)
  end
  Err("relay_effect_reason")
end
