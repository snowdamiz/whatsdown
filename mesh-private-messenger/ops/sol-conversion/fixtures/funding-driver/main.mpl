from Runtime.SolConversionConfig import parse_sol_conversion_operator
from Runtime.SolConversionFunding import prepare_sol_witness_output, reconcile_sol_witness_output
from Storage.SolConversionFunding import sol_witness_funding_instruction
from Transparency.RewardsWrite import RewardWriteContext
from Solana.Read import Hash, pubkey
from Solana.Tx import (
  compile_legacy_message,
  serialize_legacy_message,
  compute_unit_limit_instruction
)

fn text(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn ensure(value :: Bool) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err("owned_funding_check_failed")
  end
end

fn run() -> Result<(), String> do
  let args = Env.args()
  let config = parse_sol_conversion_operator(File.read(List.get(args, 1))?)?
  let root = Json.parse(File.read(List.get(args, 2))?)?
  let conversion = Bytes.from_hex(List.get(args, 3))?
  let pool = Pool.open(config.database_url, 1, 8, 5000)?
  if List.length(args) == 6 && List.get(args, 5) == "reconcile" do
    let saved = reconcile_sol_witness_output(pool,
      config.worker,
      Bytes.from_hex(text(root, "funding_id")?)?)?
    ensure(saved.state == 1)?
    let again = prepare_sol_witness_output(pool, config.worker, conversion)?
    ensure(again.intent_id == saved.intent_id && again.state == 1)?
    Pool.close(pool)
    println("owned actual-USDC output reconciled to permanent exact funding receipt")
    return Ok(nil)
  end
  let result = prepare_sol_witness_output(pool, config.worker, conversion)
  let intent = result?
  ensure(intent.intent_id == Bytes.from_hex(text(root, "funding_id")?)?)?
  ensure(intent.amount == U64.parse(text(root, "amount")?)?)?
  let ctx = RewardWriteContext {
    program: pubkey(text(root, "program")?)?,
    judge: pubkey(text(root, "judge")?)?,
    log_name: text(root, "log_name")?,
    mint: config.worker.profile.usdc
  }
  let instruction = sol_witness_funding_instruction(intent, ctx, config.worker.profile)?
  let message = serialize_legacy_message(compile_legacy_message(config.worker.profile.payer,
    Hash { bytes: Bytes.from_base58(text(root, "blockhash")?)? },
    [compute_unit_limit_instruction(300000)?, instruction])?)?
  File.write(List.get(args, 4), Bytes.to_base64(message))?
  let again = prepare_sol_witness_output(pool, config.worker, conversion)?
  ensure(again.intent_id == intent.intent_id && again.amount == intent.amount)?
  Pool.close(pool)
  println("owned actual-output funding instruction matches immutable bridge")
  Ok(nil)
end

fn main() do
  case run() do
    Ok(_) -> nil
    Err(error) -> do
      println(error)
      Process.exit(1)
    end
  end
end
