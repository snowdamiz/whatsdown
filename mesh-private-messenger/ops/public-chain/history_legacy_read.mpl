from HistoryLegacyPins import LegacyHistoryPins, legacy_context_keys, legacy_bond_keys
from HistoryLegacyContext import legacy_context, legacy_digest
from HistoryLegacyState import legacy_bonds, legacy_proofs, legacy_proof_keys
from HistoryIndex import PublicHistoryScope, decode_legacy_public_history, PublicHistoryRecord
from HistoryRead import (
  PublicHistoryDiscovery,
  PublicHistoryResult,
  public_history_response,
  public_history_filters
)
from Transparency.AnchorChain import anchor_addresses
from Transparency.Merkle import WitnessKey
from Solana.Read import (
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response,
  program_accounts_context_request,
  rpc_send
)

fn observe(client :: Int,
  source :: String,
  pins :: LegacyHistoryPins,
  kind :: Int,
  minimum :: U64,
  maximum :: Int) -> PublicHistoryDiscovery!String do
  let anchor = anchor_addresses(pins.judge, pins.log_name)?
  let scope = PublicHistoryScope {
    kind: kind,
    program: pins.judge,
    binding: anchor.log_id,
    usdc: pins.mint.bytes,
    morse: Bytes.empty(),
    treasury: Bytes.empty()
  }
  let request = program_accounts_context_request(140 + kind,
    scope.program,
    public_history_filters(scope)?,
    "finalized",
    Some(minimum))?
  let index = decode_legacy_public_history(scope,
    public_history_response(rpc_send(client, source, request, 5000, 524288)?, maximum)?,
    minimum,
    maximum)?
  let keys = legacy_context_keys(pins)?
  let response = optional_accounts_slice_from_response(rpc_send(client,
    source,
    get_multiple_accounts_slice_request(150 + kind, keys, "finalized", 0, 8416, Some(index.slot))?,
    5000,
    524288)?)?
  if response.slot != index.slot || List.length(response.accounts) != List.length(keys) do
    return Err("legacy_history_context_moved_or_length")
  end
  let context = legacy_context(pins, response, index.slot)?
  let digest = Crypto.sha256(Bytes.concat(index.digest,
    legacy_digest(keys, response, "morse-public-history-legacy-context-v1")?)?)
  Ok(PublicHistoryDiscovery {
    scope: scope,
    index: index,
    timestamp: context.timestamp,
    code_current: context.code_current,
    digest: digest
  })
end

fn agree(a :: PublicHistoryDiscovery!String,
  b :: PublicHistoryDiscovery!String) -> Option<PublicHistoryDiscovery> do
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

pub fn read_legacy_discovery(client :: Int,
  sources :: List<String>,
  pins :: LegacyHistoryPins,
  kind :: Int,
  minimum :: U64,
  maximum :: Int) -> PublicHistoryResult!String do
  if List.length(sources) != 3 || (kind != 1 && kind != 2) do
    return Err("legacy_history_sources_or_kind")
  end
  let a = observe(client, List.get(sources, 0), pins, kind, minimum, maximum)
  let b = observe(client, List.get(sources, 1), pins, kind, minimum, maximum)
  let c = observe(client, List.get(sources, 2), pins, kind, minimum, maximum)
  for pair in [agree(a, b), agree(a, c), agree(b, c)] do
    case pair do
      None -> nil
      Some(value) -> return Ok(PublicHistoryResult {
        availability: "available",
        observation: Some(value)
      })
    end
  end
  let valid = List.reduce([a, b, c],
    0,
    fn(total, value) do total
      + if Result.is_ok(value) do
        1
      else
        0
      end end)
  Ok(PublicHistoryResult {
    availability: if valid >= 2 do
      "disagreed"
    else
      "unavailable"
    end,
    observation: None
  })
end

fn values(client :: Int,
  source :: String,
  pins :: LegacyHistoryPins,
  kind :: Int,
  rows :: List<PublicHistoryRecord>,
  minimum :: U64) -> (String, Bytes)!String do
  let keys = if kind == 1 do
    legacy_bond_keys(pins,
      for row in rows do
        WitnessKey { witness_id: row.witness_id, public_key: row.public_key }
      end)?
  else
    legacy_proof_keys(pins, rows)?
  end
  let snapshot = optional_accounts_slice_from_response(rpc_send(client,
    source,
    get_multiple_accounts_slice_request(1, keys, "finalized", 0, 8416, Some(minimum))?,
    5000,
    524288)?)?
  if kind == 1 do
    legacy_bonds(pins, rows, snapshot, minimum)
  else
    legacy_proofs(pins, rows, snapshot, minimum)
  end
end

fn agree_values(a :: (String, Bytes)!String, b :: (String, Bytes)!String) -> Option<String> do
  case a do
    Err(_) -> None
    Ok(first) -> case b do
      Err(_) -> None
      Ok(second) -> do
        let (body, hash) = first
        let (_, other) = second
        if hash == other do
          Some(body)
        else
          None
        end
      end
    end
  end
end

pub fn read_legacy_values(client :: Int,
  sources :: List<String>,
  pins :: LegacyHistoryPins,
  kind :: Int,
  rows :: List<PublicHistoryRecord>,
  minimum :: U64) -> String!String do
  if List.length(sources) != 3
    || List.length(rows) < 1
    || List.length(rows) > 16
    || (kind != 1 && kind != 2) do
    return Err("legacy_history_page")
  end
  let a = values(client, List.get(sources, 0), pins, kind, rows, minimum)
  let b = values(client, List.get(sources, 1), pins, kind, rows, minimum)
  let c = values(client, List.get(sources, 2), pins, kind, rows, minimum)
  for pair in [agree_values(a, b), agree_values(a, c), agree_values(b, c)] do
    case pair do
      None -> nil
      Some(body) -> return Ok(body)
    end
  end
  let valid = List.reduce([a, b, c],
    0,
    fn(total, value) do total
      + if Result.is_ok(value) do
        1
      else
        0
      end end)
  Ok("{\"availability\":"
    <> Json.encode_string(if valid >= 2 do
      "disagreed"
    else
      "unavailable"
    end)
    <> "}")
end
