from Client.BondsV2 import run_bonds_v2_command
from Transparency.Config import (
  SecurityConfig,
  LogWitnessPolicy,
  witness_policy_for_log,
  valid_witness_id
)
from Client.ChainRead import ChainReadOptions, load_chain_read_options
from Transparency.AnchorCustody import AnchorCustody, read_anchor_custody
from Transparency.AnchorCustodyReport import anchor_custody_report

pub fn parse_bonds_command(args :: List<String>) -> String!String do
  if List.length(args) != 4
    || List.get(args, 1) != "bonds"
    || List.get(args, 2) != "--log"
    || !valid_witness_id(List.get(args, 3))
    || String.length(List.get(args, 3)) > 32 do
    Err("usage: morse bonds --log LOG_NAME")
  else
    Ok(List.get(args, 3))
  end
end

pub fn run_bonds_command(args :: List<String>) -> Int!String do
  if List.length(args) == 6 && List.get(args, 4) == "--v2-config" do
    parse_bonds_command(List.take(args, 4))?
    return run_bonds_v2_command(args)
  end
  let name = parse_bonds_command(args)?
  let options = load_chain_read_options(name, "bonds")?
  let result = read_anchor_custody(options.pins,
    options.config.service_public_key,
    options.version,
    options.mint,
    witness_policy_for_log(options.config, options.version)?.keys,
    options.minimum_slot)?
  println(anchor_custody_report(result, options.mint)?)
  Ok(0)
end
