from Request import (
  CollateralOperatorConfig,
  CollateralOperatorRequest,
  parse_collateral_operator_config,
  parse_collateral_operator_request
)
from Read import read_collateral_operator_unpriced
from Plan import plan_collateral_operation
from ProofRead import read_collateral_proof
from ProofPlan import plan_collateral_proof
from CloseRead import (
  CollateralStageCloseIntent,
  read_collateral_stage_close,
  plan_collateral_stage_close
)
from Report import collateral_operation_report

fn bounded_file(path :: String) -> String!String do
  let size = File.size(path)?
  if size < 0 || size > 32768 do
    return Err("collateral_operator_input_bound")
  end
  Bytes.to_utf8(File.read_bytes(path, 0, size)?)
end

fn run() -> String!String do
  let args = Env.args()
  if List.length(args) != 5 || List.get(args, 1) != "--pins" || List.get(args, 3) != "--input" do
    return Err("usage: collateral-v2 --pins pins.json --input request.json")
  end
  let config = parse_collateral_operator_config(Json.parse(bounded_file(List.get(args, 2))?)?)?
  let request = parse_collateral_operator_request(Json.parse(bounded_file(List.get(args, 4))?)?)?
  let client = Http.client()
  let result = plan_request(client, config, request)
  Http.client_close(client)
  result
end

fn plan_request(client :: Int,
  config :: CollateralOperatorConfig,
  request :: CollateralOperatorRequest) -> String!String do
  let result = case request do
    CollateralRequest(operation, minimum) ->
      let state = read_collateral_operator_unpriced(client,
        config.sources,
        config.pins,
        operation.subject,
        operation.operator,
        minimum)?
      plan_collateral_operation(config.pins, operation, state)
    CollateralProofRequest(intent, minimum) ->
      if intent.close do
        let owner = CollateralStageCloseIntent {
          fee_payer: intent.fee_payer,
          submitter: intent.submitter,
          full_hash: Crypto.sha256(intent.wire)
        }
        let state = read_collateral_stage_close(client,
          config.sources,
          config.pins,
          owner,
          minimum)?
        plan_collateral_stage_close(config.pins, owner, state)
      else
        let state = read_collateral_proof(client, config.sources, config.pins, intent, minimum)?
        plan_collateral_proof(config.pins, intent, state)
      end
    CollateralStageCloseRequest(intent, minimum) ->
      let state = read_collateral_stage_close(client, config.sources, config.pins, intent, minimum)?
      plan_collateral_stage_close(config.pins, intent, state)
  end
  Ok(collateral_operation_report(result?))
end

fn main() do
  case run() do
    Ok(value) -> println(value)
    Err(error) -> do
      println("{\"schema_version\":1,\"state\":\"refused\",\"error\":#{Json.encode_string(error)}}")
      Process.exit(1)
    end
  end
end
