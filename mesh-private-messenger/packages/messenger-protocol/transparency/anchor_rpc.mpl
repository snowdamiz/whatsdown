from Transparency.RpcTransport import (RpcTls, RpcEndpoint, RpcTransport, rpc_urls, require_rpc_endpoint, require_rpc_current, rpc_fatal_error)
from Solana.Read import (
  Pubkey,
  AccountInfo,
  AccountAtSlot,
  RpcRequest,
  RpcResponse,
  get_account_info_slice_request,
  rpc_request_json,
  rpc_response,
  account_from_response,
  get_block_time_request,
  block_time_from_response,
  pubkey_equal
)

pub struct AnchorAgreement do
  data :: Bytes
  context_slot :: U64
end

# The slot comes from an already-finalized, quorum-authenticated ring header.
# An unknown block time never becomes zero, nor a duration estimated from slots.
pub fn read_anchor_time_quorum(rpc :: RpcTransport, slot :: U64) -> Int!String do
  validate_anchor_sources(rpc_urls(rpc))?
  let first = read_block_time(rpc, List.get(rpc.sources, 0), slot)
  case first do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    _ -> nil
  end
  let second = read_block_time(rpc, List.get(rpc.sources, 1), slot)
  case second do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    _ -> nil
  end
  case agree_time(first, second) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let third = read_block_time(rpc, List.get(rpc.sources, 2), slot)
  case third do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    _ -> nil
  end
  case agree_time(first, third) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  case agree_time(second, third) do
    Some(value) -> Ok(value)
    None -> do
      let valid = List.length(List.filter([first, second, third],
        fn(result) do
          case result do
            Ok(_) -> true
            Err(_) -> false
          end
        end))
      if valid >= 2 do
        Err("anchor_rpc_disagree")
      else
        Err("anchor_rpc_unavailable")
      end
    end
  end
end

fn agree_time(first :: Int!String, second :: Int!String) -> Option<Int> do
  case (first, second) do
    (Ok(a), Ok(b)) when a == b -> Some(a)
    _ -> None
  end
end

fn read_block_time(rpc :: RpcTransport, endpoint :: RpcEndpoint, slot :: U64) -> Int!String do
  let response = read_anchor_rpc_response(rpc, endpoint, get_block_time_request(1, slot)?, 1024)?
  case block_time_from_response(response) do
    Ok(Some(value)) when value >= 0 -> Ok(value)
    Ok(None) -> Err("anchor_rpc_unavailable")
    _ -> Err("invalid_anchor_response")
  end
end

# Endpoints are ordered by the caller's random sample. Query the third only
# when the first two fail to agree. A context slot is not account content: two
# providers can observe identical bytes at different finalized slots.
pub fn read_anchor_quorum(rpc :: RpcTransport,
  address :: Pubkey,
  program :: Pubkey,
  offset :: Int,
  length :: Int,
  minimum_slot :: U64) -> AnchorAgreement!String do
  validate_anchor_sources(rpc_urls(rpc))?
  let first = read_anchor_account(rpc, List.get(rpc.sources, 0),
    address,
    program,
    offset,
    length,
    minimum_slot)
  case first do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    _ -> nil
  end
  let second = read_anchor_account(rpc, List.get(rpc.sources, 1),
    address,
    program,
    offset,
    length,
    minimum_slot)
  case second do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    _ -> nil
  end
  case agree(first, second) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let third = read_anchor_account(rpc, List.get(rpc.sources, 2),
    address,
    program,
    offset,
    length,
    minimum_slot)
  case third do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    _ -> nil
  end
  case agree(first, third) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  case agree(second, third) do
    Some(value) -> Ok(value)
    None -> do
      let valid = for result in [first, second, third] do
        case result do
          Ok(_) -> 1
          Err(_) -> 0
        end
      end
      if List.get(valid, 0) + List.get(valid, 1) + List.get(valid, 2) >= 2 do
        Err("anchor_rpc_disagree")
      else
        Err("anchor_rpc_unavailable")
      end
    end
  end
end

fn agree(first :: AccountAtSlot!String,
  second :: AccountAtSlot!String) -> Option<AnchorAgreement> do
  let a = case first do
    Err(_) -> return None
    Ok(value) -> value
  end
  let b = case second do
    Err(_) -> return None
    Ok(value) -> value
  end
  if !Bytes.secure_equals(a.account.data, b.account.data) do
    None
  else
    # Use the lower context: a dishonest provider cannot pin subsequent reads
    # to an arbitrarily distant slot by lying about its own context metadata.
    Some(AnchorAgreement {
      data: a.account.data,
      context_slot: if U64.compare(a.slot, b.slot) < 0 do
        a.slot
      else
        b.slot
      end
    })
  end
end

# Origins are canonicalized by the URL parser before reaching this helper.
# A public host does not become another quorum source by changing its port or
# adding the DNS root dot. Separate exact loopback origins support local banks;
# they never establish independent-provider qualification.
fn source_host(origin :: String) -> String do
  let authority = List.get(String.split(origin, "://"), 1)
  if String.starts_with(authority, "[") do
    List.head(String.split(authority, "]")) <> "]"
  else
    List.head(String.split(authority, ":"))
  end
end

fn source_identity(origin :: String, separate_loopback_origins :: Bool) -> String do
  let host = source_host(origin)
  let folded = String.to_lower(host)
  let identity = if String.starts_with(folded, "[") || !String.ends_with(folded, ".") do
    folded
  else
    String.slice(folded, 0, String.length(folded) - 1)
  end
  if separate_loopback_origins
    && (identity == "127.0.0.1" || identity == "localhost" || identity == "[::1]") do
    return String.replace(origin, host, identity)
  end
  identity
end

pub fn validate_anchor_sources(endpoints :: List<String>) -> Result<(), String> do
  validate_anchor_provider_sources(endpoints, true)
end

pub fn validate_anchor_provider_sources(endpoints :: List<String>,
  separate_loopback_origins :: Bool) -> Result<(), String> do
  if List.length(endpoints) < 3 || List.length(endpoints) > 8 do
    return Err("invalid_anchor_sources")
  end
  for index in 0..List.length(endpoints) do
    let endpoint = List.get(endpoints, index)
    let origin = case Http.url_origin(endpoint) do
      Err(_) -> return Err("invalid_anchor_sources")
      Ok(value) -> value
    end
    let host = source_host(origin)
    # HTTP is limited to loopback for local validators and tests. Native
    # release configuration additionally requires HTTPS for every provider.
    # Canonical mapped IPv6 has exactly two hextets after ::ffff:; the prefix
    # alone also matches nonmapped addresses. Refuse only the mapped shape.
    if String.length(endpoint) > 2048
      || (String.starts_with(host, "[::ffff:") && List.length(String.split(host, ":")) == 5)
      || String.contains(endpoint, "@")
      || String.contains(endpoint, "#")
      || String.contains(endpoint, "\\")
      || (!String.starts_with(origin, "https://")
        && !String.starts_with(origin, "http://127.0.0.1:"))
      || (endpoint != origin
        && !String.starts_with(endpoint, origin <> "/")
        && !String.starts_with(endpoint, origin <> "?")) do
      return Err("invalid_anchor_sources")
    end
    for previous in 0..index do
      if source_identity(origin,
        separate_loopback_origins) == source_identity(Http.url_origin(List.get(endpoints,
            previous))?,
          separate_loopback_origins) do
        return Err("invalid_anchor_sources")
      end
    end
  end
  Ok(nil)
end

# Callers select the endpoint, account and expected program from native pins.
# One RPC response is transport data only; the quorum reader establishes trust.
pub fn read_anchor_account(rpc :: RpcTransport, endpoint :: RpcEndpoint,
  address :: Pubkey,
  program :: Pubkey,
  offset :: Int,
  length :: Int,
  minimum_slot :: U64) -> AccountAtSlot!String do
  if length <= 0 || length > 4096 do
    return Err("invalid_anchor_slice")
  end
  let request = get_account_info_slice_request(1,
    address,
    "finalized",
    offset,
    length,
    Some(minimum_slot))?
  let decoded = read_anchor_rpc_response(rpc, endpoint, request, 8192)?
  let account = case account_from_response(decoded) do
    Err(_) -> return Err("invalid_anchor_response")
    Ok(value) -> value
  end
  if account.account.executable
    || !pubkey_equal(account.account.owner, program)
    || Bytes.length(account.account.data) != length
    || U64.compare(account.slot, minimum_slot) < 0
    || U64.compare(account.account.lamports, U64.parse("0")?) == 0 do
    return Err("invalid_anchor_response")
  end
  Ok(account)
end

pub fn read_anchor_rpc_response(rpc :: RpcTransport, endpoint :: RpcEndpoint,
  request :: RpcRequest,
  maximum_bytes :: Int) -> RpcResponse!String do
  require_rpc_endpoint(rpc, endpoint)?
  require_rpc_current(rpc.require_current)?
  let builder = Http.build(:post, endpoint.url)
    |> Http.header("Content-Type", "application/json")
    |> Http.body(rpc_request_json(request))
    |> Http.timeout(3000)
    |> Http.max_response_bytes(maximum_bytes)
    |> Http.max_redirects(0)
  let builder = case endpoint.tls do
    WebPki -> builder
    OriginRoots(_, pem) -> Http.trust_root_pem(builder, pem)
  end
  let sent = Http.send(builder)
  require_rpc_current(rpc.require_current)?
  let response = case sent do
    Err(error) -> if String.starts_with(error, "INVALID_TLS_ROOTS:") do
      return Err("rpc_tls_config_invalid")
    else
      return Err("anchor_rpc_unavailable")
    end
    Ok(value) -> value
  end
  if response.status != 200 do
    return Err("anchor_rpc_unavailable")
  end
  let decoded = case rpc_response(response.body) do
    Err(_) -> return Err("invalid_anchor_response")
    Ok(value) -> value
  end
  if decoded.id != request.id do
    return Err("invalid_anchor_response")
  end
  Ok(decoded)
end
