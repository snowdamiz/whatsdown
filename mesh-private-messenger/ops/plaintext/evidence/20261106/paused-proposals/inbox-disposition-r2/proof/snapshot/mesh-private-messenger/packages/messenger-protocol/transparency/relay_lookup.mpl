from Solana.Read import Pubkey, pubkey_equal
from Solana.Tx import Instruction, AccountMeta
from Solana.LookupTable import (
  LookupTableCreation,
  create_lookup_table_instruction,
  extend_lookup_table_instruction,
  deactivate_lookup_table_instruction,
  close_lookup_table_instruction
)

pub struct RelayLookupPlan do
  table :: Pubkey
  recent_slot :: U64
  addresses :: List<Pubkey>
  create :: Instruction
  extend :: List<Instruction>
  deactivate :: Instruction
  close :: Instruction
end

fn unique_keys(values :: List<AccountMeta>,
  payer :: Pubkey,
  output :: List<Pubkey>) -> List<Pubkey> do
  if List.length(values) == 0 do
    return output
  end
  let value = List.head(values)
  let present = List.length(List.filter(output, fn(key) -> pubkey_equal(key, value.pubkey) end)) > 0
  let output = if value.signer || pubkey_equal(value.pubkey, payer) || present do
    output
  else
    List.append(output, value.pubkey)
  end
  unique_keys(List.tail(values), payer, output)
end

fn extensions(table :: Pubkey,
  payer :: Pubkey,
  addresses :: List<Pubkey>,
  offset :: Int) -> List<Instruction>!String do
  if offset >= List.length(addresses) do
    return Ok([])
  end
  let remaining = List.length(addresses) - offset
  let count = if remaining > 20 do
    20
  else
    remaining
  end
  let keys = for index in offset..(offset + count) do
    List.get(addresses, index)
  end
  Ok([extend_lookup_table_instruction(table, payer, Some(payer), keys)?]
    ++ extensions(table, payer, addresses, offset + count)?)
end

# Preparation does not allocate a table. The writer may avoid it if a plain
# transaction fits. It must bind any existing table to this authority and exact
# contents, wait past its last extension slot, and journal creation/extension
# before broadcasting. A different job at the same wallet/slot is a collision,
# never permission to reinterpret or overwrite the table.
pub fn prepare_relay_lookup(payer :: Pubkey,
  settlement :: Instruction,
  recent_slot :: U64) -> RelayLookupPlan!String do
  let addresses = unique_keys(settlement.accounts, payer, [])
  if List.length(addresses) == 0 || List.length(addresses) > 256 do
    return Err("invalid_relay_lookup_accounts")
  end
  let creation = create_lookup_table_instruction(payer, payer, recent_slot)?
  Ok(RelayLookupPlan {
    table: creation.address,
    recent_slot: recent_slot,
    addresses: addresses,
    create: creation.instruction,
    extend: extensions(creation.address, payer, addresses, 0)?,
    deactivate: deactivate_lookup_table_instruction(creation.address, payer)?,
    close: close_lookup_table_instruction(creation.address, payer, payer)?
  })
end
