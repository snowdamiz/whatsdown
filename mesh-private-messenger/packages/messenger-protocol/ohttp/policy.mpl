##! Fixed prekey-claim application policy; no network or proof-of-work authority.
from Ohttp.Types import BhttpRequest, BhttpResponse, BhttpField

struct OhttpPolicyTarget do
  scheme :: Bytes
  authority :: Bytes
end

fn prekey_target(origin :: String, development :: Bool) -> OhttpPolicyTarget!String do
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
  Ok(OhttpPolicyTarget {
    scheme: Bytes.from_utf8(List.get(parts, 0)),
    authority: Bytes.from_utf8(List.get(parts, 1))
  })
end

fn prekey_headers() -> List<BhttpField> do
  [
    BhttpField {
      name: Bytes.from_utf8("content-type"),
      value: Bytes.from_utf8("application/octet-stream")
    },
    BhttpField { name: Bytes.from_utf8("cache-control"), value: Bytes.from_utf8("no-store") }
  ]
end

fn prekey_header_kind(field :: BhttpField) -> Int!String do
  if Bytes.length(field.name) > 13 || Bytes.length(field.value) > 24 do
    return Err("ohttp_invalid_prekey_headers")
  end
  let name = case Bytes.to_utf8(field.name) do
    Err(_) -> return Err("ohttp_invalid_prekey_headers")
    Ok(value) -> String.to_lower(value)
  end
  if name == "content-type"
    && Bytes.secure_equals(field.value, Bytes.from_utf8("application/octet-stream")) do
    Ok(1)
  else if name == "cache-control"
    && Bytes.secure_equals(field.value, Bytes.from_utf8("no-store")) do
    Ok(2)
  else
    Err("ohttp_invalid_prekey_headers")
  end
end

fn require_prekey_headers(fields :: List<BhttpField>) -> Result<(), String> do
  if List.length(fields) != 2 do
    return Err("ohttp_invalid_prekey_headers")
  end
  let first = prekey_header_kind(List.get(fields, 0))?
  let second = prekey_header_kind(List.get(fields, 1))?
  if first == second do
    Err("ohttp_invalid_prekey_headers")
  else
    Ok(nil)
  end
end

pub fn prekey_claim_request(core_origin :: String,
  development :: Bool,
  stamped :: Bytes) -> BhttpRequest!String do
  let target = prekey_target(core_origin, development)?
  if Bytes.length(stamped) > 120 do
    return Err("ohttp_prekey_request_too_large")
  end
  Ok(BhttpRequest {
    method: Bytes.from_utf8("POST"),
    scheme: target.scheme,
    authority: target.authority,
    path: Bytes.from_utf8("/v1/prekeys/bundle"),
    fields: prekey_headers(),
    content: stamped,
    trailers: []
  })
end

# The returned body is still untrusted, unpaid PWR input. The gateway must
# pass it unchanged to the established prekey admission/domain operation.
pub fn admit_prekey_claim_request(request :: BhttpRequest,
  core_origin :: String,
  development :: Bool) -> Bytes!String do
  let target = prekey_target(core_origin, development)?
  if !Bytes.secure_equals(request.method, Bytes.from_utf8("POST"))
    || !Bytes.secure_equals(request.scheme, target.scheme)
    || !Bytes.secure_equals(request.authority, target.authority)
    || !Bytes.secure_equals(request.path, Bytes.from_utf8("/v1/prekeys/bundle")) do
    return Err("ohttp_prekey_target_refused")
  end
  require_prekey_headers(request.fields)?
  if List.length(request.trailers) != 0 do
    return Err("ohttp_prekey_trailers_refused")
  end
  if Bytes.length(request.content) > 120 do
    Err("ohttp_prekey_request_too_large")
  else
    Ok(request.content)
  end
end

pub fn prekey_claim_response(status :: Int, body :: Bytes) -> BhttpResponse!String do
  if status < 200 || status > 599 do
    return Err("ohttp_invalid_prekey_response_status")
  end
  if Bytes.length(body) > 19312 do
    return Err("ohttp_prekey_response_too_large")
  end
  Ok(BhttpResponse {
    informational: [],
    status: status,
    fields: prekey_headers(),
    content: body,
    trailers: []
  })
end

pub fn open_prekey_claim_response(response :: BhttpResponse) -> Bytes!String do
  if response.status != 200 do
    return Err("ohttp_prekey_claim_failed")
  end
  require_prekey_headers(response.fields)?
  if List.length(response.informational) != 0 || List.length(response.trailers) != 0 do
    return Err("ohttp_invalid_prekey_response_sections")
  end
  if Bytes.length(response.content) > 19312 do
    Err("ohttp_prekey_response_too_large")
  else
    Ok(response.content)
  end
end
