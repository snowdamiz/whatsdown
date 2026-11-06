from Solana.Read import (
  Pubkey,
  AccountInfo,
  OptionalAccountsAtSlot,
  get_multiple_accounts_context_request,
  optional_accounts_from_response,
  pubkey_equal
)
from Transparency.AnchorRpc import validate_anchor_sources, read_anchor_rpc_response

# Whole-batch agreement prevents mixing individually authentic accounts across
# deposits, withdrawals, witness rotation or slashes. Owners remain part of the
# agreement and must also be checked against each account's expected program.
pub fn read_anchor_accounts(endpoints :: List<String>,
  addresses :: List<Pubkey>,
  minimum_slot :: U64) -> OptionalAccountsAtSlot!String do
  read_anchor_accounts_bounded(endpoints, addresses, minimum_slot, 4096)
end

# Larger fixed-layout readers opt in explicitly. The response cap still bounds
# the whole batch; this does not permit fetching an unbounded ring or registry.
pub fn read_anchor_accounts_bounded(endpoints :: List<String>,
  addresses :: List<Pubkey>,
  minimum_slot :: U64,
  maximum_account_bytes :: Int) -> OptionalAccountsAtSlot!String do
  validate_anchor_sources(endpoints)?
  if List.length(addresses) < 1
    || List.length(addresses) > 64
    || maximum_account_bytes < 1
    || maximum_account_bytes > 32768 do
    return Err("invalid_anchor_batch")
  end
  let first = read_anchor_accounts_from(List.get(endpoints, 0),
    addresses,
    minimum_slot,
    maximum_account_bytes)
  let second = read_anchor_accounts_from(List.get(endpoints, 1),
    addresses,
    minimum_slot,
    maximum_account_bytes)
  case agree(first, second) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let third = read_anchor_accounts_from(List.get(endpoints, 2),
    addresses,
    minimum_slot,
    maximum_account_bytes)
  case agree(first, third) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  case agree(second, third) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let valid = List.filter([first, second, third],
    fn(result) do
      case result do
        Ok(_) -> true
        Err(_) -> false
      end
    end)
  if List.length(valid) >= 2 do
    Err("anchor_rpc_disagree")
  else
    Err("anchor_rpc_unavailable")
  end
end

# A single response is untrusted. This supports decision quorums for changing
# sysvars; callers validate independent sources and authenticate each account.
pub fn read_anchor_accounts_from(endpoint :: String,
  addresses :: List<Pubkey>,
  minimum_slot :: U64,
  maximum_account_bytes :: Int) -> OptionalAccountsAtSlot!String do
  if List.length(addresses) < 1
    || List.length(addresses) > 64
    || maximum_account_bytes < 1
    || maximum_account_bytes > 32768 do
    return Err("invalid_anchor_batch")
  end
  let request = get_multiple_accounts_context_request(1,
    addresses,
    "finalized",
    Some(minimum_slot))?
  let response = read_anchor_rpc_response(endpoint, request, 65536)?
  let value = optional_accounts_from_response(response)?
  if List.length(value.accounts) != List.length(addresses)
    || U64.compare(value.slot, minimum_slot) < 0 do
    return Err("invalid_anchor_response")
  end
  # This reader only serves bounded fixed-layout accounts. Even a
  # provider returning many valid JSON accounts cannot enlarge the workload.
  for account in value.accounts do
    case account do
      None -> nil
      Some(account) -> if Bytes.length(account.data) > maximum_account_bytes do
        return Err("invalid_anchor_response")
      end
    end
  end
  Ok(value)
end

fn agree(first :: OptionalAccountsAtSlot!String,
  second :: OptionalAccountsAtSlot!String) -> Option<OptionalAccountsAtSlot> do
  let a = case first do
    Err(_) -> return None
    Ok(value) -> value
  end
  let b = case second do
    Err(_) -> return None
    Ok(value) -> value
  end
  if List.length(a.accounts) != List.length(b.accounts) do
    return None
  end
  for index in 0..List.length(a.accounts) do
    case (List.get(a.accounts, index), List.get(b.accounts, index)) do
      (None, None) -> nil
      (Some(x), Some(y)) -> if !pubkey_equal(x.owner, y.owner)
        || x.executable != y.executable
        || !Bytes.secure_equals(x.data, y.data)
        || x.lamports != y.lamports do
        return None
      end
      _ -> return None
    end
  end
  Some(%{a |
    slot: if U64.compare(a.slot, b.slot) < 0 do
      a.slot
    else
      b.slot
    end
  })
end
