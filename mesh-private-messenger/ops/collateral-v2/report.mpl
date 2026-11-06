from Plan import CollateralOperationPlan
from Solana.Read import Pubkey, pubkey_string
from Solana.Tx import instruction_report_json

fn keys(values :: List<Pubkey>) -> String do
  "[#{String.join(List.map(values, fn(key) do Json.encode_string(pubkey_string(key)) end), ",")}]"
end

pub fn collateral_operation_report(plan :: CollateralOperationPlan) -> String do
  let signers = if List.length(plan.instructions) == 0 do
    []
  else
    List.reduce([plan.fee_payer] ++ plan.instruction_signers,
      [],
      fn(keys, key) do
        if List.contains(keys, key) do
          keys
        else
          keys ++ [key]
        end
      end)
  end
  let accounts = List.reduce(List.flatten(for ix in plan.instructions do
      [ix.program_id] ++ List.map(ix.accounts, fn(meta) do meta.pubkey end)
    end),
    [],
    fn(keys, key) do
      if List.contains(keys, key) do
        keys
      else
        keys ++ [key]
      end
    end)
  let instructions = String.join(List.map(plan.instructions,
      fn(ix) do instruction_report_json(ix) end),
    ",")
  let until = case plan.wait_until do
    None -> "null"
    Some(value) -> Json.encode_string(U64.to_string(value))
  end
  let lookup = if List.length(accounts) > 30 do
    "true"
  else
    "false"
  end
  "{\"schema_version\":1,\"state\":#{Json.encode_string(plan.state)},\"reason\":#{Json.encode_string(plan.reason)},\"context_slot\":#{Json.encode_string(U64.to_string(plan.slot))},\"snapshot_sha256\":#{Json.encode_string(Bytes.to_hex(plan.digest))},\"fee_payer\":#{Json.encode_string(pubkey_string(plan.fee_payer))},\"rent_payers\":#{keys(plan.rent_payers)},\"instruction_signers\":#{keys(plan.instruction_signers)},\"transaction_signers\":#{keys(signers)},\"governance_required\":#{if plan.governance_required do
    "true"
  else
    "false"
  end},\"wait_until\":#{until},\"requires_address_lookup_table\":#{lookup},\"selected_transaction_accounts\":#{keys(accounts)},\"instructions\":[#{instructions}]}"
end
