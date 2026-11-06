from Transparency.RpcTransport import RpcEndpoint, RpcTransport, rpc_urls, rpc_fatal_error
from Solana.Read import (
  Pubkey,
  AccountInfo,
  OptionalAccountsAtSlot,
  SolanaClock,
  clock_sysvar_address,
  clock_sysvar,
  pubkey,
  pubkey_equal,
  pubkey_string
)
from Solana.LookupTable import (
  LookupTableCreation,
  LookupTableAccount,
  LookupTableStatus,
  create_lookup_table_instruction,
  lookup_table_account,
  lookup_table_status
)
from Solana.SlotHashes import (
  SlotHashes,
  SlotHashEntry,
  slot_hashes_sysvar_address,
  slot_hashes_sysvar
)
from Transparency.AnchorBatch import read_anchor_accounts, read_anchor_accounts_from
from Transparency.AnchorRpc import validate_anchor_sources

pub struct RelayLookupState do
  status :: String
  address :: Pubkey
  authority :: Pubkey
  creation_slot :: U64
  context_slot :: U64
  last_extended_slot :: U64
  deactivation_slot :: U64
  addresses :: List<Pubkey>
end

fn absent(value :: Option<AccountInfo>) -> Bool do
  case value do
    None -> true
    Some(account) -> !account.executable
      && Bytes.length(account.data) == 0
      && Bytes.to_hex(account.owner.bytes) == String.repeat("00", 32)
  end
end

# A journaled creation slot and exact expected address order identify this
# table across restarts. Missing accounts permit initialization; exact prefixes
# permit continuing extensions. Unexpected authority, suffixes, frozen tables
# and conflicting providers are errors, never permission to spend again.
fn initial_state(authority :: Pubkey,
  creation_slot :: U64,
  expected :: List<Pubkey>,
  minimum_slot :: U64) -> RelayLookupState!String do
  if List.length(expected) < 1 || List.length(expected) > 63 do
    return Err("invalid_relay_lookup_accounts")
  end
  for index in 0..List.length(expected) do
    let key = List.get(expected, index)
    if Bytes.length(key.bytes) != 32
      || pubkey_equal(key, authority)
      || List.length(List.filter(List.take(expected, index),
        fn(prior) -> pubkey_equal(prior, key) end)) > 0 do
      return Err("invalid_relay_lookup_accounts")
    end
  end
  let table = create_lookup_table_instruction(authority, authority, creation_slot)?.address
  let minimum = if U64.compare(minimum_slot, creation_slot) < 0 do
    creation_slot
  else
    minimum_slot
  end
  let state = RelayLookupState {
    status: "missing",
    address: table,
    authority: authority,
    creation_slot: creation_slot,
    context_slot: minimum,
    last_extended_slot: U64.parse("0")?,
    deactivation_slot: U64.parse("18446744073709551615")?,
    addresses: []
  }
  Ok(state)
end

fn decode(initial :: RelayLookupState,
  expected :: List<Pubkey>,
  account :: Option<AccountInfo>,
  context_slot :: U64) -> RelayLookupState!String do
  let state = %{initial | context_slot: context_slot}
  let authority = state.authority
  let creation_slot = state.creation_slot
  if absent(account) do
    return Ok(state)
  end
  let account = case account do
    Some(value) -> value
    None -> return Err("relay_lookup_missing")
  end
  let decoded = lookup_table_account(account)?
  if decoded.authority != Some(authority)
    || List.length(decoded.addresses) > List.length(expected)
    || U64.compare(decoded.last_extended_slot, context_slot) > 0
    || (List.length(decoded.addresses) > 0
      && U64.compare(decoded.last_extended_slot, creation_slot) < 0) do
    return Err("relay_lookup_changed")
  end
  for index in 0..List.length(decoded.addresses) do
    if !pubkey_equal(List.get(decoded.addresses, index), List.get(expected, index)) do
      return Err("relay_lookup_changed")
    end
  end
  let status = if decoded.deactivation_slot != state.deactivation_slot do
    if U64.compare(decoded.deactivation_slot, context_slot) > 0
      || U64.compare(decoded.deactivation_slot, decoded.last_extended_slot) < 0
      || U64.compare(decoded.deactivation_slot, creation_slot) < 0 do
      return Err("relay_lookup_changed")
    end
    "cooling"
  else if List.length(decoded.addresses) < List.length(expected) do
    "extending"
  else if decoded.last_extended_slot == context_slot do
    "warm"
  else
    "ready"
  end
  Ok(%{state |
    status: status,
    last_extended_slot: decoded.last_extended_slot,
    deactivation_slot: decoded.deactivation_slot,
    addresses: decoded.addresses
  })
end

pub fn read_relay_lookup(rpc :: RpcTransport,
  authority :: Pubkey,
  creation_slot :: U64,
  expected :: List<Pubkey>,
  minimum_slot :: U64) -> RelayLookupState!String do
  let initial = initial_state(authority, creation_slot, expected, minimum_slot)?
  let snapshot = read_anchor_accounts(rpc, [initial.address], initial.context_slot)?
  decode(initial, expected, List.head(snapshot.accounts), snapshot.slot)
end

pub struct RelayLookupCooldown do
  table :: RelayLookupState
  remaining_blocks :: Int
end

struct CooldownObservation do
  value :: RelayLookupCooldown
  table_hash :: Bytes
end

fn required(account :: Option<AccountInfo>) -> AccountInfo!String do
  case account do
    None -> Err("relay_lookup_sysvar_missing")
    Some(value) -> Ok(value)
  end
end

fn cooldown(rpc :: RpcTransport, endpoint :: RpcEndpoint,
  initial :: RelayLookupState,
  expected :: List<Pubkey>) -> CooldownObservation!String do
  let snapshot = read_anchor_accounts_from(rpc, endpoint,
    [initial.address, clock_sysvar_address()?, slot_hashes_sysvar_address()?],
    initial.context_slot,
    20488)?
  let clock = clock_sysvar(required(List.get(snapshot.accounts, 1))?)?
  if clock.slot != snapshot.slot do
    return Err("relay_lookup_clock_mismatch")
  end
  let hashes = slot_hashes_sysvar(required(List.get(snapshot.accounts, 2))?)?
  for entry in hashes.entries do
    if U64.compare(entry.slot, snapshot.slot) > 0 do
      return Err("relay_lookup_future_history")
    end
  end
  let account = List.head(snapshot.accounts)
  let table = decode(initial, expected, account, snapshot.slot)?
  if table.status == "missing" do
    return Ok(CooldownObservation {
      value: RelayLookupCooldown { table: table, remaining_blocks: 0 },
      table_hash: Crypto.sha256(Bytes.empty())
    })
  end
  let account = required(account)?
  let status = lookup_table_status(lookup_table_account(account)?, snapshot.slot, hashes)?
  let value = case status do
    Activated -> RelayLookupCooldown { table: table, remaining_blocks: 0 }
    Deactivating(remaining) -> RelayLookupCooldown {
      table: %{table | status: "cooling"},
      remaining_blocks: remaining
    }
    Deactivated -> RelayLookupCooldown { table: %{table | status: "closable"}, remaining_blocks: 0 }
  end
  Ok(CooldownObservation { value: value, table_hash: Crypto.sha256(account.data) })
end

fn agree_cooldown(first :: CooldownObservation!String,
  second :: CooldownObservation!String) -> Option<RelayLookupCooldown> do
  case (first, second) do
    (Ok(a), Ok(b)) -> if a.value.table.status == b.value.table.status
      && Bytes.secure_equals(a.table_hash, b.table_hash) do
      Some(%{a.value |
        table: %{a.value.table |
          context_slot: if U64.compare(a.value.table.context_slot,
            b.value.table.context_slot) < 0 do
            a.value.table.context_slot
          else
            b.value.table.context_slot
          end
        },
        remaining_blocks: if a.value.remaining_blocks > b.value.remaining_blocks do
          a.value.remaining_blocks
        else
          b.value.remaining_blocks
        end
      })
    else
      None
    end
    _ -> None
  end
end

# Histories and Clocks evolve between finalized banks. Require two independently
# valid decisions over the same authenticated table bytes, not identical sysvar
# bytes. This remains a prerequisite for sending close, never proof of a refund.
pub fn read_relay_lookup_cooldown(rpc :: RpcTransport,
  authority :: Pubkey,
  creation_slot :: U64,
  expected :: List<Pubkey>,
  minimum_slot :: U64) -> RelayLookupCooldown!String do
  validate_anchor_sources(rpc_urls(rpc))?
  let initial = initial_state(authority, creation_slot, expected, minimum_slot)?
  let first = cooldown(rpc, List.get(rpc.sources, 0), initial, expected)
  case first do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    _ -> nil
  end
  let second = cooldown(rpc, List.get(rpc.sources, 1), initial, expected)
  case second do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    _ -> nil
  end
  case agree_cooldown(first, second) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let third = cooldown(rpc, List.get(rpc.sources, 2), initial, expected)
  case third do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    _ -> nil
  end
  case agree_cooldown(first, third) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  case agree_cooldown(second, third) do
    Some(value) -> Ok(value)
    None -> Err("relay_lookup_cooldown_unavailable")
  end
end

pub fn relay_lookup_report(value :: RelayLookupState) -> String do
  let addresses = String.join(for key in value.addresses do
      Json.encode_string(pubkey_string(key))
    end,
    ",")
  """{"schema_version":1,"status":#{Json.encode_string(value.status)},"address":#{Json.encode_string(pubkey_string(value.address))},"authority":#{Json.encode_string(pubkey_string(value.authority))},"creationSlot":"#{U64.to_string(value.creation_slot)}","contextSlot":"#{U64.to_string(value.context_slot)}","lastExtendedSlot":"#{U64.to_string(value.last_extended_slot)}","deactivationSlot":"#{U64.to_string(value.deactivation_slot)}","addresses":[#{addresses}]}"""
end

pub fn relay_lookup_cooldown_report(value :: RelayLookupCooldown) -> String do
  let base = relay_lookup_report(value.table)
  String.slice(base, 0, String.length(base) - 1)
    <> ",\"remainingBlocks\":#{value.remaining_blocks}}"
end
