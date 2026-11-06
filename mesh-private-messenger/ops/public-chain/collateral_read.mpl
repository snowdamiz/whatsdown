from CollateralPins import CollateralSelection, collateral_bond_keys, collateral_receipt_keys
from CollateralState import PublicBonds, PublicSlashes, decode_public_bonds, decode_public_slashes
from CollateralReport import public_bonds_report, public_slashes_report, unavailable_collateral
from Solana.Read import (
  Pubkey,
  OptionalAccountSlicesAtSlot,
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response,
  rpc_send
)

fn snapshot(client :: Int,
  url :: String,
  keys :: List<Pubkey>,
  minimum :: U64) -> OptionalAccountSlicesAtSlot!String do
  let request = get_multiple_accounts_slice_request(1, keys, "finalized", 0, 8416, Some(minimum))?
  optional_accounts_slice_from_response(rpc_send(client, url, request, 5000, 524288)?)
end

fn bonds(client :: Int,
  url :: String,
  selected :: CollateralSelection,
  minimum :: U64) -> PublicBonds!String do
  decode_public_bonds(selected,
    snapshot(client, url, collateral_bond_keys(selected)?, minimum)?,
    minimum)
end

fn slashes(client :: Int,
  url :: String,
  selected :: CollateralSelection,
  minimum :: U64) -> PublicSlashes!String do
  decode_public_slashes(selected,
    snapshot(client, url, collateral_receipt_keys(selected)?, minimum)?,
    minimum)
end

fn agree_bonds(a :: PublicBonds!String, b :: PublicBonds!String) -> Option<PublicBonds> do
  case a do
    Err(_) -> None
    Ok(first) -> case b do
      Err(_) -> None
      Ok(second) -> if first.digest == second.digest do
        Some(first)
      else
        None
      end
    end
  end
end

fn agree_slashes(a :: PublicSlashes!String, b :: PublicSlashes!String) -> Option<PublicSlashes> do
  case a do
    Err(_) -> None
    Ok(first) -> case b do
      Err(_) -> None
      Ok(second) -> if first.digest == second.digest do
        Some(first)
      else
        None
      end
    end
  end
end

pub fn read_public_bonds(client :: Int,
  sources :: List<String>,
  selected :: CollateralSelection,
  minimum :: U64) -> String!String do
  let a = bonds(client, List.get(sources, 0), selected, minimum)
  let b = bonds(client, List.get(sources, 1), selected, minimum)
  let c = bonds(client, List.get(sources, 2), selected, minimum)
  for pair in [agree_bonds(a, b), agree_bonds(a, c), agree_bonds(b, c)] do
    case pair do
      None -> nil
      Some(value) -> return public_bonds_report(selected, value)
    end
  end
  let valid = for value in [a, b, c] do
    case value do
      Ok(_) -> 1
      Err(_) -> 0
    end
  end
  Ok(unavailable_collateral(if List.reduce(valid, 0, fn(sum, value) do sum + value end) >= 2 do
    "disagreed"
  else
    "unavailable"
  end))
end

pub fn read_public_slashes(client :: Int,
  sources :: List<String>,
  selected :: CollateralSelection,
  minimum :: U64) -> String!String do
  let a = slashes(client, List.get(sources, 0), selected, minimum)
  let b = slashes(client, List.get(sources, 1), selected, minimum)
  let c = slashes(client, List.get(sources, 2), selected, minimum)
  for pair in [agree_slashes(a, b), agree_slashes(a, c), agree_slashes(b, c)] do
    case pair do
      None -> nil
      Some(value) -> return public_slashes_report(selected, value)
    end
  end
  let valid = for value in [a, b, c] do
    case value do
      Ok(_) -> 1
      Err(_) -> 0
    end
  end
  Ok(unavailable_collateral(if List.reduce(valid, 0, fn(sum, value) do sum + value end) >= 2 do
    "disagreed"
  else
    "unavailable"
  end))
end
