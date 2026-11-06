##! Bounded group reads reuse the public collateral decoder and its exact roles.
from Read import (
  CollateralOperatorPins,
  CollateralOperatorState,
  collateral_operator_keys,
  decode_collateral_operator_unpriced_snapshot
)
from Transparency.TokenCollateralWrite import TokenCollateralSubject
from Solana.Read import (
  Pubkey,
  OptionalAccountSlicesAtSlot,
  clock_sysvar,
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response,
  rpc_send
)

fn index(keys :: List<Pubkey>, key :: Pubkey) -> Int!String do
  for at in 0..List.length(keys) do
    if List.get(keys, at) == key do
      return Ok(at)
    end
  end
  Err("collateral_assessment_role_missing")
end

fn read_group(client :: Int,
  url :: String,
  pins :: CollateralOperatorPins,
  subjects :: List<TokenCollateralSubject>,
  payer :: Pubkey,
  minimum :: U64,
  test_mode :: Bool) -> List<CollateralOperatorState>!String do
  if List.length(subjects) < 1 || List.length(subjects) > 14 do
    return Err("collateral_assessment_group_bound")
  end
  let roles = for subject in subjects do
    collateral_operator_keys(pins, subject, payer)?
  end
  let keys = List.reduce(List.flatten(roles),
    [],
    fn(keys, key) do
      if List.contains(keys, key) do
        keys
      else
        keys ++ [key]
      end
    end)
  if List.length(keys) > 100 do
    return Err("collateral_assessment_account_bound")
  end
  let request = get_multiple_accounts_slice_request(4, keys, "finalized", 0, 9216, Some(minimum))?
  let snapshot = optional_accounts_slice_from_response(rpc_send(client,
    url,
    request,
    5000,
    1048576)?)?
  if List.length(snapshot.accounts) != List.length(keys) do
    return Err("collateral_assessment_snapshot_bound")
  end
  let clock = case List.get(snapshot.accounts, index(keys, List.get(List.head(roles), 9))?) do
    None -> return Err("collateral_assessment_clock_missing")
    Some(value) -> clock_sysvar(value.info)?
  end
  let reference = if test_mode do
    U64.parse(Int.to_string(clock.unix_timestamp))?
  else
    U64.parse(Int.to_string(DateTime.to_unix_secs(DateTime.utc_now())))?
  end
  Ok(for at in 0..List.length(subjects) do
    let selected = OptionalAccountSlicesAtSlot {
      slot: snapshot.slot,
      accounts: for key in List.get(roles, at) do
        List.get(snapshot.accounts, index(keys, key)?)
      end
    }
    decode_collateral_operator_unpriced_snapshot(pins,
      List.get(subjects, at),
      payer,
      minimum,
      reference,
      selected)?
  end)
end

# Callers validate their configured providers before this read. Exactly two
# matching complete decoded groups are required, with a third only on disagreement.
pub fn read_collateral_assessment_group(client :: Int,
  urls :: List<String>,
  pins :: CollateralOperatorPins,
  subjects :: List<TokenCollateralSubject>,
  payer :: Pubkey,
  minimum :: U64,
  test_mode :: Bool) -> List<CollateralOperatorState>!String do
  if List.length(urls) != 3 do
    return Err("collateral_assessment_sources")
  end
  let a = read_group(client, List.get(urls, 0), pins, subjects, payer, minimum, test_mode)
  let b = read_group(client, List.get(urls, 1), pins, subjects, payer, minimum, test_mode)
  case (a, b) do
    (Ok(x), Ok(y)) when x == y -> return Ok(x)
    (Err(x), Err(y)) when x == y -> return Err(x)
    _ -> nil
  end
  let c = read_group(client, List.get(urls, 2), pins, subjects, payer, minimum, test_mode)
  for pair in [(a, c), (b, c)] do
    case pair do
      (Ok(x), Ok(y)) when x == y -> return Ok(x)
      _ -> nil
    end
  end
  Err("collateral_assessment_no_agreement")
end
