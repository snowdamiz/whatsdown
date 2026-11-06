# Whole-list/context agreement only. No discovery result is a global balance.
from HistoryIndex import (
  PublicHistoryScope,
  PublicHistoryAccount,
  PublicHistorySnapshot,
  PublicHistoryIndex,
  decode_public_history
)
from CollateralPins import CollateralSelection, collateral_context_keys
from CollateralAccounts import collateral_context, collateral_digest
from Transparency.TokenBurnRead import TokenBurnReadPins, token_burn_rpc_sources
from Transparency.TokenBurnCarryRead import (
  token_burn_carry_read_keys,
  decode_token_burn_carry_snapshot
)
from Transparency.TokenChain import token_addresses
from Transparency.AnchorChain import anchor_addresses
from Solana.Address import find_program_address
from Solana.Read import (
  RpcResponse,
  ProgramAccountFilter,
  program_accounts_context_request,
  program_accounts_from_response,
  memcmp_filter,
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response,
  rpc_send
)

pub struct PublicHistoryDiscovery do
  scope :: PublicHistoryScope
  index :: PublicHistoryIndex
  timestamp :: U64
  code_current :: Bool
  digest :: Bytes
end

pub struct PublicHistoryResult do
  availability :: String
  observation :: Option<PublicHistoryDiscovery>
end

pub fn public_history_scope(base :: TokenBurnReadPins,
  selected :: Option<CollateralSelection>,
  kind :: Int) -> PublicHistoryScope!String do
  if kind == 0 do
    Ok(PublicHistoryScope {
      kind: 0,
      program: base.program,
      binding: find_program_address(base.program, [Bytes.from_utf8("swap")])?.address.bytes,
      usdc: base.usdc.bytes,
      morse: token_addresses(base.program)?.mint.bytes,
      treasury: base.treasury.bytes
    })
  else
    let pins = case selected do
      None -> return Err("public_history_collateral_not_configured")
      Some(value) -> value.pins
    end
    if kind != 1 && kind != 2 do
      return Err("public_history_kind")
    end
    Ok(PublicHistoryScope {
      kind: kind,
      program: pins.judge,
      binding: anchor_addresses(pins.judge, pins.log_name)?.log_id,
      usdc: pins.usdc.bytes,
      morse: pins.morse.bytes,
      treasury: Bytes.empty()
    })
  end
end

pub fn public_history_filters(scope :: PublicHistoryScope) -> List<ProgramAccountFilter>!String do
  if scope.kind == 0 do
    Ok([
      memcmp_filter(0, Bytes.to_base58(Bytes.from_utf8("MT")))?,
      memcmp_filter(4, Bytes.to_base58(scope.binding))?
    ])
  else if scope.kind == 1 do
    Ok([
      memcmp_filter(0, Bytes.to_base58(Bytes.from_utf8("MWI")))?,
      memcmp_filter(200, Bytes.to_base58(scope.binding))?
    ])
  else if scope.kind == 2 do
    Ok([
      memcmp_filter(0, Bytes.to_base58(Bytes.from_utf8("MPR")))?,
      memcmp_filter(8, Bytes.to_base58(scope.binding))?
    ])
  else
    Err("public_history_kind")
  end
end

fn numeric(value :: Json) -> U64!String do
  let raw = Json.encode(value)
  let bytes = Bytes.from_utf8(raw)
  if Bytes.length(bytes) < 1 || Bytes.length(bytes) > 20 do
    return Err("public_history_numeric_field")
  end
  for index in 0..Bytes.length(bytes) do
    let digit = Bytes.get(bytes, index)?
    if digit < 48 || digit > 57 do
      return Err("public_history_numeric_field")
    end
  end
  let result = U64.parse(raw)?
  if U64.to_string(result) != raw do
    Err("public_history_numeric_field")
  else
    Ok(result)
  end
end

pub fn public_history_response(response :: RpcResponse,
  maximum :: Int) -> PublicHistorySnapshot!String do
  let parsed = program_accounts_from_response(response, maximum)?
  let root = Json.parse(response.result_json)?
  let values = Json.object_get(root, "value")?
  let rows = for index in 0..List.length(parsed.accounts) do
    let account = List.get(parsed.accounts, index)
    let raw = Json.object_get(Json.array_get(values, index)?, "account")?
    PublicHistoryAccount {
      address: account.address,
      account: account.account,
      space: numeric(Json.object_get(raw, "space")?)?
    }
  end
  Ok(PublicHistorySnapshot { slot: parsed.slot, accounts: rows })
end

fn observation(client :: Int,
  url :: String,
  base :: TokenBurnReadPins,
  selected :: Option<CollateralSelection>,
  kind :: Int,
  minimum :: U64,
  maximum :: Int) -> PublicHistoryDiscovery!String do
  let scope = public_history_scope(base, selected, kind)?
  let request = program_accounts_context_request(40 + kind,
    scope.program,
    public_history_filters(scope)?,
    "finalized",
    Some(minimum))?
  let snapshot = public_history_response(rpc_send(client, url, request, 5000, 524288)?, maximum)?
  let index = decode_public_history(scope, snapshot, minimum, maximum)?
  let (time, current, context_digest) = case selected do
    Some(value) -> do
      let keys = collateral_context_keys(value.pins)?
      let context_request = get_multiple_accounts_slice_request(50 + kind,
        keys,
        "finalized",
        0,
        8416,
        Some(index.slot))?
      let context = optional_accounts_slice_from_response(rpc_send(client,
        url,
        context_request,
        5000,
        524288)?)?
      if context.slot != index.slot do
        return Err("public_history_context_moved")
      end
      let verified = collateral_context(value.pins, context, index.slot)?
      (verified.timestamp,
        verified.code_current,
        collateral_digest(keys, context, "morse-public-history-context-v1")?)
    end
    None -> do
      if kind != 0 do
        return Err("public_history_collateral_not_configured")
      end
      let epochs = List.flat_map(index.records,
        fn(row) do
          case row.epoch do
            None -> []
            Some(value) -> [value]
          end
        end)
      let epoch = if List.length(epochs) == 0 do
        U64.parse("0")?
      else
        List.head(epochs)
      end
      let keys = token_burn_carry_read_keys(base, epoch)?
      let context_request = get_multiple_accounts_slice_request(50,
        keys,
        "finalized",
        0,
        2240,
        Some(index.slot))?
      let context = optional_accounts_slice_from_response(rpc_send(client,
        url,
        context_request,
        5000,
        131072)?)?
      if context.slot != index.slot do
        return Err("public_history_context_moved")
      end
      let verified = decode_token_burn_carry_snapshot(base, epoch, index.slot, context)?
      (U64.parse(Int.to_string(verified.timestamp))?, verified.code_current, verified.digest)
    end
  end
  Ok(PublicHistoryDiscovery {
    scope: scope,
    index: index,
    timestamp: time,
    code_current: current,
    digest: Crypto.sha256(Bytes.concat(index.digest, context_digest)?)
  })
end

fn agree(first :: PublicHistoryDiscovery!String,
  second :: PublicHistoryDiscovery!String) -> Option<PublicHistoryDiscovery> do
  case first do
    Err(_) -> None
    Ok(a) -> case second do
      Err(_) -> None
      Ok(b) -> if a.digest == b.digest do
        Some(a)
      else
        None
      end
    end
  end
end

fn valid(value :: PublicHistoryDiscovery!String) -> Int do
  case value do
    Err(_) -> 0
    Ok(_) -> 1
  end
end

pub fn read_public_history_index(client :: Int,
  sources :: List<String>,
  test_mode :: Bool,
  base :: TokenBurnReadPins,
  selected :: Option<CollateralSelection>,
  kind :: Int,
  minimum :: U64,
  maximum :: Int) -> PublicHistoryResult!String do
  token_burn_rpc_sources(sources, test_mode)?
  if kind < 0 || kind > 2 || maximum < 1 || maximum > 128 do
    return Err("public_history_bound")
  end
  if kind != 0 && selected == None do
    return Ok(PublicHistoryResult { availability: "not-configured", observation: None })
  end
  let a = observation(client, List.get(sources, 0), base, selected, kind, minimum, maximum)
  let b = observation(client, List.get(sources, 1), base, selected, kind, minimum, maximum)
  let c = observation(client, List.get(sources, 2), base, selected, kind, minimum, maximum)
  for value in [agree(a, b), agree(a, c), agree(b, c)] do
    case value do
      None -> nil
      Some(result) -> return Ok(PublicHistoryResult {
        availability: "available",
        observation: Some(result)
      })
    end
  end
  Ok(PublicHistoryResult {
    availability: if valid(a) + valid(b) + valid(c) >= 2 do
      "disagreed"
    else
      "unavailable"
    end,
    observation: None
  })
end
