from Transparency.RpcTransport import webpki_rpc_transport
from Input import RelayConfig, RelayRequest, parse_config, parse_request
from ProofRead import CollateralProofIntent, read_collateral_proof
from ProofPlan import plan_collateral_proof
from Prepared import prepared_intent
from Read import read_collateral_operator_unpriced
from Transparency.TokenCollateralWrite import TokenCollateralSubject
from Receipt import read_receipt, receipt_report
from Recovery import read_recovery, stage_report, effect_present
from Lookup import plan_lookup, lookup_report, retained_lookup
from LookupEffect import lookup_effect
from Legacy import legacy_execute
from Migration import migration_operation, migration_effect
from RelayMpr2Report import ready_report, settled_report
from Transparency.Relay import validate_relay_submission
from Transparency.Fork import fork_hash
from Transparency.TokenProofWrite import token_proof_close_instruction
from Transparency.RelayLookupRead import (
  read_relay_lookup,
  read_relay_lookup_cooldown,
  relay_lookup_report,
  relay_lookup_cooldown_report
)
from Solana.Tx import instruction_report_json

fn bounded(path :: String, maximum :: Int) -> Bytes!String do
  let size = File.size(path)?
  if size < 1 || size > maximum do
    return Err("relay_input_bound")
  end
  let bytes = File.read_bytes(path, 0, size)?
  if Bytes.length(bytes) != size do
    return Err("relay_input_changed")
  end
  Ok(bytes)
end

fn execute(client :: Int,
  config :: RelayConfig,
  wire :: Bytes,
  request :: RelayRequest) -> String!String do
  let pins = config.operator.pins
  let rpc = webpki_rpc_transport(config.operator.sources)?
  let proof = validate_relay_submission(pins.service_key, pins.log_version, wire)?
  let hash = fork_hash(proof)?
  if List.contains(["legacy-admit", "legacy-stage", "legacy-destinations", "legacy-receipt"],
    request.method) do
    return legacy_execute(rpc, config, request.method, wire, request.minimum)
  end
  if request.method == "lookup-plan" do
    case request.lookup do
      Some(value) -> return Ok(lookup_report(retained_lookup(config, value)?))
      None -> nil
    end
  end
  if request.method == "effect" do
    case request.effect do
      Some(value) -> case Json.object_get(value, "kind") do
        Ok(kind) -> if List.contains([
            "create-table",
            "extend-table",
            "deactivate-table",
            "close-table"
          ],
          Json.as_string(kind)?) do
          return lookup_effect(config, value, request.minimum)
        end
        Err(_) -> nil
      end
      None -> nil
    end
  end
  if request.method == "lookup" || request.method == "lookup-close" do
    let lookup = case request.lookup do
      None -> return Err("relay_lookup_required")
      Some(value) -> value
    end
    if request.method == "lookup-close" do
      return Ok(relay_lookup_cooldown_report(read_relay_lookup_cooldown(rpc,
        config.submitter,
        lookup.creation_slot,
        lookup.addresses,
        request.minimum)?))
    end
    return Ok(relay_lookup_report(read_relay_lookup(rpc,
      config.submitter,
      lookup.creation_slot,
      lookup.addresses,
      request.minimum)?))
  end
  if request.method == "effect" do
    case request.effect do
      Some(value) -> case Json.object_get(value, "reason") do
        Ok(reason) -> if Json.as_string(reason)? == "migrate_legacy_bond" do
          return migration_effect(rpc, config, wire, value, request.minimum)
        end
        Err(_) -> nil
      end
      None -> nil
    end
  end
  if request.method == "stage" || request.method == "effect" do
    let state = read_recovery(rpc, config, wire, request.minimum)?
    if request.method == "stage" do
      return stage_report(state)
    end
    let effect = case request.effect do
      None -> return Err("relay_effect_required")
      Some(value) -> value
    end
    let present = effect_present(wire, effect, state)?
    return Ok("""{"schema_version":2,"state":"#{if present do
      "present"
    else
      "absent"
    end}","slot":"#{U64.to_string(state.context_slot)}"}""")
  end
  let receipt = read_receipt(rpc, pins, hash, request.minimum)?
  if request.method == "receipt" do
    return Ok(receipt_report(receipt))
  end
  if request.method == "close" do
    if receipt.status != "settled" do
      return Err("relay_close_requires_settled_receipt")
    end
    let state = read_recovery(rpc, config, wire, request.minimum)?
    if state.receipt.status != "settled" do
      return Err("relay_close_requires_settled_receipt")
    end
    let report = settled_report(config, wire, state.receipt)?
    if state.stage.status == "missing" do
      return Ok(report)
    end
    let ix = token_proof_close_instruction(pins.context, config.submitter, wire)?
    let effect = """{"schema_version":1,"reason":"explicit_stage_close","full_hash":"#{Bytes.to_hex(Crypto.sha256(wire))}"}"""
    let operation = """{"reason":"explicit_stage_close","instructions":[#{instruction_report_json(ix)}],"rent_allocations":[],"effect":#{effect}}"""
    return Ok(String.replace(String.replace(report,
        "\"operation\":null",
        "\"operation\":#{operation}"),
      "\"status\":\"settled\",\"program\"",
      "\"status\":\"ready\",\"program\""))
  end
  if receipt.status == "settled" do
    return settled_report(config, wire, receipt)
  end
  if request.method == "resume" && receipt.status != "prepared" do
    let base = read_collateral_operator_unpriced(client,
      config.operator.sources,
      pins,
      CollateralDirectory,
      config.submitter,
      request.minimum)?
    let active = case base.binding do
      None -> false
      Some(value) -> value.activated_at != U64.parse("0")?
    end
    if base.legacy_economics || !active do
      return legacy_execute(rpc, config, "legacy-admit", wire, request.minimum)
    end
  end
  let intent = CollateralProofIntent {
    fee_payer: config.fee_payer,
    submitter: config.submitter,
    wire: wire,
    witnesses: config.witnesses,
    close: false
  }
  let effective = prepared_intent(pins, intent, receipt)?
  let state = read_collateral_proof(client,
    config.operator.sources,
    pins,
    effective,
    receipt.context_slot)?
  if receipt.status == "prepared" && state.receipt == None do
    return Err("relay_prepared_receipt_changed")
  end
  let operation = if List.length(state.legacy_subjects) > 0 do
    migration_operation(config, effective, state)?
  else
    plan_collateral_proof(pins, effective, state)?
  end
  if operation.state != "ready" do
    return Err("relay_readmission_changed")
  end
  let lookup = plan_lookup(config, effective, state, request.lookup)?
  if request.method == "lookup-plan" do
    return Ok(lookup_report(lookup))
  end
  ready_report(config, intent, state, operation, lookup)
end

fn run() -> String!String do
  let args = Env.args()
  if List.length(args) != 7
    || List.get(args, 1) != "--pins"
    || List.get(args, 3) != "--input"
    || List.get(args, 5) != "--request" do
    return Err("usage: relay-mpr2 --pins operator.json --input evidence.frk --request request.json")
  end
  let config = parse_config(Json.parse(Bytes.to_utf8(bounded(List.get(args, 2), 65536)?)?)?)?
  let wire = bounded(List.get(args, 4), 8009)?
  let request = parse_request(Json.parse(Bytes.to_utf8(bounded(List.get(args, 6), 32768)?)?)?)?
  let client = Http.client()
  let result = execute(client, config, wire, request)
  Http.client_close(client)
  result
end

fn main() do
  case run() do
    Ok(report) -> println(report)
    Err(error) -> do
      println("{\"schema_version\":2,\"status\":\"refused\",\"error\":#{Json.encode_string(error)}}")
      Process.exit(1)
    end
  end
end
