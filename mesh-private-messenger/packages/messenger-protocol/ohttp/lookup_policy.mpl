##! Fixed native directory/proof read policy, not a generic proxy or work authority.
from Ohttp.Types import BhttpRequest, BhttpResponse, BhttpField

pub type OhttpLookupOperation do
  OhttpDirectoryLookup(Int)
  OhttpConsistencyLookup(Int)
  OhttpLegacyBridgeLookup
end deriving(Eq, Debug)

pub struct OhttpLookupQuery do
  operation :: OhttpLookupOperation
  body :: Bytes
end

pub struct OhttpLookupResult do
  status :: Int
  body :: Bytes
end

struct OhttpLookupTarget do
  scheme :: Bytes
  authority :: Bytes
end

fn lookup_target(origin :: String, development :: Bool) -> OhttpLookupTarget!String do
  if String.length(origin) < 8
    || String.length(origin) > 2048
    || !Regex.is_match(~r/^[\x21-\x7e]+$/, origin)
    || String.contains(origin, "\\")
    || String.contains(origin, "@")
    || String.contains(origin, "?")
    || String.contains(origin, "#") do
    return Err("ohttp_invalid_core_origin")
  end
  let canonical = case Http.url_origin(origin) do
    Err(_) -> return Err("ohttp_invalid_core_origin")
    Ok(value) -> value
  end
  if canonical != origin do
    return Err("ohttp_invalid_core_origin")
  end
  if !String.starts_with(origin, "https://")
    && !(development
      && Regex.is_match(~r/^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:[1-9][0-9]{0,4})?$/,
        origin)) do
    return Err("ohttp_invalid_core_origin")
  end
  let parts = String.split(origin, "://")
  if List.length(parts) != 2 do
    return Err("ohttp_invalid_core_origin")
  end
  Ok(OhttpLookupTarget {
    scheme: Bytes.from_utf8(List.get(parts, 0)),
    authority: Bytes.from_utf8(List.get(parts, 1))
  })
end

fn lookup_headers() -> List<BhttpField> do
  [
    BhttpField {
      name: Bytes.from_utf8("content-type"),
      value: Bytes.from_utf8("application/octet-stream")
    },
    BhttpField { name: Bytes.from_utf8("cache-control"), value: Bytes.from_utf8("no-store") }
  ]
end

fn lookup_header_kind(field :: BhttpField) -> Int!String do
  if Bytes.length(field.name) > 13 || Bytes.length(field.value) > 24 do
    return Err("ohttp_invalid_lookup_headers")
  end
  let name = case Bytes.to_utf8(field.name) do
    Err(_) -> return Err("ohttp_invalid_lookup_headers")
    Ok(value) -> String.to_lower(value)
  end
  if name == "content-type"
    && Bytes.secure_equals(field.value, Bytes.from_utf8("application/octet-stream")) do
    Ok(1)
  else if name == "cache-control"
    && Bytes.secure_equals(field.value, Bytes.from_utf8("no-store")) do
    Ok(2)
  else
    Err("ohttp_invalid_lookup_headers")
  end
end

fn require_lookup_headers(fields :: List<BhttpField>) -> Result<(), String> do
  if List.length(fields) != 2 do
    return Err("ohttp_invalid_lookup_headers")
  end
  let first = lookup_header_kind(List.get(fields, 0))?
  let second = lookup_header_kind(List.get(fields, 1))?
  if first == second do
    Err("ohttp_invalid_lookup_headers")
  else
    Ok(nil)
  end
end

fn operation_path(operation :: OhttpLookupOperation) -> String!String do
  case operation do
    OhttpDirectoryLookup(version) -> if version == 1 do
      Ok("/v1/devices/resolve")
    else if version == 2 do
      Ok("/v2/devices/resolve")
    else
      Err("ohttp_invalid_lookup_operation")
    end
    OhttpConsistencyLookup(version) -> if version == 1 do
      Ok("/v1/transparency/consistency")
    else if version == 2 do
      Ok("/v2/transparency/consistency")
    else
      Err("ohttp_invalid_lookup_operation")
    end
    OhttpLegacyBridgeLookup -> Ok("/v2/transparency/legacy-bridge")
  end
end

fn operation_for_path(path :: Bytes) -> OhttpLookupOperation!String do
  if Bytes.secure_equals(path, Bytes.from_utf8("/v1/devices/resolve")) do
    Ok(OhttpDirectoryLookup(1))
  else if Bytes.secure_equals(path, Bytes.from_utf8("/v2/devices/resolve")) do
    Ok(OhttpDirectoryLookup(2))
  else if Bytes.secure_equals(path, Bytes.from_utf8("/v1/transparency/consistency")) do
    Ok(OhttpConsistencyLookup(1))
  else if Bytes.secure_equals(path, Bytes.from_utf8("/v2/transparency/consistency")) do
    Ok(OhttpConsistencyLookup(2))
  else if Bytes.secure_equals(path, Bytes.from_utf8("/v2/transparency/legacy-bridge")) do
    Ok(OhttpLegacyBridgeLookup)
  else
    Err("ohttp_lookup_target_refused")
  end
end

fn require_body(operation :: OhttpLookupOperation, body :: Bytes) -> Result<(), String> do
  operation_path(operation)?
  let valid = case operation do
    OhttpDirectoryLookup(_) -> Bytes.length(body) <= 96
    _ -> Bytes.length(body) == 12
  end
  if valid do
    Ok(nil)
  else
    Err("ohttp_invalid_lookup_request_size")
  end
end

fn response_maximum(operation :: OhttpLookupOperation) -> Int!String do
  operation_path(operation)?
  Ok(case operation do
    OhttpDirectoryLookup(_) -> 570418
    OhttpConsistencyLookup(_) -> 1070
    OhttpLegacyBridgeLookup -> 4942
  end)
end

pub fn lookup_request(core_origin :: String,
  development :: Bool,
  operation :: OhttpLookupOperation,
  body :: Bytes) -> BhttpRequest!String do
  let target = lookup_target(core_origin, development)?
  require_body(operation, body)?
  Ok(BhttpRequest {
    method: Bytes.from_utf8("POST"),
    scheme: target.scheme,
    authority: target.authority,
    path: Bytes.from_utf8(operation_path(operation)?),
    fields: lookup_headers(),
    content: body,
    trailers: []
  })
end

# Resolve bodies remain untrusted unpaid work. Only the established gateway
# admission/domain functions verify/spend work; proof queries keep read authority.
pub fn admit_lookup_request(request :: BhttpRequest,
  core_origin :: String,
  development :: Bool) -> OhttpLookupQuery!String do
  let target = lookup_target(core_origin, development)?
  if !Bytes.secure_equals(request.method, Bytes.from_utf8("POST"))
    || !Bytes.secure_equals(request.scheme, target.scheme)
    || !Bytes.secure_equals(request.authority, target.authority) do
    return Err("ohttp_lookup_target_refused")
  end
  let operation = operation_for_path(request.path)?
  require_lookup_headers(request.fields)?
  if List.length(request.trailers) != 0 do
    return Err("ohttp_lookup_trailers_refused")
  end
  require_body(operation, request.content)?
  Ok(OhttpLookupQuery { operation: operation, body: request.content })
end

pub fn lookup_response(operation :: OhttpLookupOperation,
  status :: Int,
  body :: Bytes) -> BhttpResponse!String do
  let maximum = response_maximum(operation)?
  if status < 200 || status > 599 do
    return Err("ohttp_invalid_lookup_response_status")
  end
  if Bytes.length(body) > maximum do
    return Err("ohttp_lookup_response_too_large")
  end
  Ok(BhttpResponse {
    informational: [],
    status: status,
    fields: lookup_headers(),
    content: body,
    trailers: []
  })
end

pub fn open_lookup_response(operation :: OhttpLookupOperation,
  response :: BhttpResponse) -> OhttpLookupResult!String do
  let maximum = response_maximum(operation)?
  if response.status < 200 || response.status > 599 do
    return Err("ohttp_invalid_lookup_response_status")
  end
  require_lookup_headers(response.fields)?
  if List.length(response.informational) != 0 || List.length(response.trailers) != 0 do
    return Err("ohttp_invalid_lookup_response_sections")
  end
  if Bytes.length(response.content) > maximum do
    return Err("ohttp_lookup_response_too_large")
  end
  Ok(OhttpLookupResult { status: response.status, body: response.content })
end
