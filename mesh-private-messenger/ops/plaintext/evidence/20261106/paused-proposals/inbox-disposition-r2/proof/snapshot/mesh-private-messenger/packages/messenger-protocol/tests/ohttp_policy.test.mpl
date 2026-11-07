from Ohttp.Types import BhttpRequest, BhttpResponse, BhttpField, BhttpInformational
from Ohttp.Policy import (
  prekey_claim_request,
  admit_prekey_claim_request,
  prekey_claim_response,
  open_prekey_claim_response
)

fn policy_bytes(value :: String) -> Bytes do
  Bytes.from_utf8(value)
end

fn policy_field(name :: String, value :: String) -> BhttpField do
  BhttpField { name: policy_bytes(name), value: policy_bytes(value) }
end

fn policy_body() -> Bytes do
  # Arbitrary exact bytes stand for the existing stamped request. Routing does
  # not verify or spend its work; the established admission layer still must.
  case Bytes.from_hex("015057520000000000000001000000020000000400ff0a00") do
    Err(_) -> panic("invalid independent policy fixture")
    Ok(value) -> value
  end
end

fn policy_request() -> BhttpRequest do
  case prekey_claim_request("https://directory.example", false, policy_body()) do
    Err(_) -> panic("expected valid policy fixture")
    Ok(value) -> value
  end
end

fn policy_admitted(value :: BhttpRequest) -> Bytes!String do
  admit_prekey_claim_request(value, "https://directory.example", false)
end

test("prekey route preserves the exact work envelope with fixed private target") do
  let value = policy_request()
  assert(Bytes.secure_equals(value.method, policy_bytes("POST")))
  assert(Bytes.secure_equals(value.scheme, policy_bytes("https")))
  assert(Bytes.secure_equals(value.authority, policy_bytes("directory.example")))
  assert(Bytes.secure_equals(value.path, policy_bytes("/v1/prekeys/bundle")))
  assert(List.length(value.fields) == 2 && List.length(value.trailers) == 0)
  assert(Bytes.secure_equals(policy_admitted(value)?, policy_body()))
  # An empty/malformed stamped body is left to existing PoW admission, where
  # its established malformed/unpaid priority is authoritative.
  assert(Bytes.length(policy_admitted(%{value | content: Bytes.empty()})?) == 0)
  Ok(nil)
end

test("configured origins must be canonical and development HTTP stays loopback only") do
  for invalid in [
    "https://directory.example/",
    "https://DIRECTORY.example",
    "https://directory.example:443",
    "https://user@directory.example",
    "https://directory.example?x=1",
    "https://directory.example#x",
    "https://directory.example/path",
    "https://directory.example\\x",
    "http://directory.example",
    "http://127.0.0.1:24371",
    "https://directory.example\n"
  ] do
    assert(Result.is_err(prekey_claim_request(invalid, false, policy_body())))
    assert(Result.is_err(admit_prekey_claim_request(policy_request(), invalid, false)))
  end
  for origin in ["http://127.0.0.1:24371", "http://localhost:24371", "http://[::1]:24371"] do
    let value = prekey_claim_request(origin, true, policy_body())?
    assert(Bytes.secure_equals(admit_prekey_claim_request(value, origin, true)?, policy_body()))
    assert(Result.is_err(admit_prekey_claim_request(value, origin, false)))
  end
  assert(Result.is_err(prekey_claim_request("http://other.example", true, policy_body())))
  Ok(nil)
end

test("method target and authority aliases never acquire gateway dispatch authority") do
  let value = policy_request()
  for path in [
    "/v1/prekeys/bundle/",
    "/v1/prekeys/%62undle",
    "/v1/prekeys/bundle?x=1",
    "/v1/prekeys/bundle#x",
    "/v1/../v1/prekeys/bundle",
    "https://directory.example/v1/prekeys/bundle",
    "/v1/directory/resolve",
    "//v1/prekeys/bundle"
  ] do
    assert(Result.is_err(policy_admitted(%{value | path: policy_bytes(path)})))
  end
  for method in ["GET", "post", "CONNECT", "POST "] do
    assert(Result.is_err(policy_admitted(%{value | method: policy_bytes(method)})))
  end
  for authority in [
    "",
    "other.example",
    "DIRECTORY.example",
    "directory.example:443",
    "user@directory.example"
  ] do
    assert(Result.is_err(policy_admitted(%{value | authority: policy_bytes(authority)})))
  end
  assert(Result.is_err(policy_admitted(%{value | scheme: policy_bytes("http")})))
  Ok(nil)
end

test("only the two fixed content headers are admitted with no duplicates or trailers") do
  let value = policy_request()
  let headers = [
    policy_field("Content-Type", "application/octet-stream"),
    policy_field("CACHE-CONTROL", "no-store")
  ]
  assert(Bytes.secure_equals(policy_admitted(%{value | fields: headers})?, policy_body()))
  for forbidden in [
    "authorization",
    "cookie",
    "host",
    "forwarded",
    "x-forwarded-for",
    "user-agent",
    "traceparent",
    "tracestate",
    "baggage",
    "x-request-id",
    "content-length",
    "transfer-encoding",
    "expect",
    "connection",
    ":protocol",
    "x-unknown"
  ] do
    assert(Result.is_err(policy_admitted(%{value |
      fields: List.append(headers, policy_field(forbidden, "x"))
    })))
    assert(Result.is_err(policy_admitted(%{value |
      fields: [List.get(headers, 0), policy_field(forbidden, "x")]
    })))
  end
  for invalid in [
    [],
    [List.get(headers, 0)],
    List.append(headers, policy_field("content-type", "application/octet-stream")),
    [policy_field("content-type", "text/plain"), List.get(headers, 1)],
    [List.get(headers, 0), policy_field("cache-control", "no-store, private")]
  ] do
    assert(Result.is_err(policy_admitted(%{value | fields: invalid})))
  end
  assert(Result.is_err(policy_admitted(%{value | trailers: [policy_field("x-extra", "x")]})))
  Ok(nil)
end

test("request cap retains the existing 100 byte claim plus 20 byte work envelope") do
  let exact = policy_bytes(String.repeat("x", 120))
  let over = policy_bytes(String.repeat("x", 121))
  assert(Bytes.length(policy_admitted(%{policy_request() | content: exact})?) == 120)
  assert(Result.is_err(policy_admitted(%{policy_request() | content: over})))
  assert(Result.is_err(prekey_claim_request("https://directory.example", false, over)))
  Ok(nil)
end

test("gateway responses retain inner errors and exact no-store semantics") do
  let body = policy_bytes("opaque claimed prekeys")
  let success = prekey_claim_response(200, body)?
  assert(Bytes.secure_equals(open_prekey_claim_response(success)?, body))
  assert(List.length(success.fields) == 2 && List.length(success.informational) == 0)
  for status in [400, 401, 429, 500, 503, 599] do
    let failure = prekey_claim_response(status, Bytes.empty())?
    assert(failure.status == status)
    assert(Result.is_err(open_prekey_claim_response(failure)))
  end
  for status in [-1, 0, 100, 199, 600] do
    assert(Result.is_err(prekey_claim_response(status, body)))
  end
  assert(Result.is_err(open_prekey_claim_response(%{success | fields: []})))
  assert(Result.is_err(open_prekey_claim_response(%{success |
    fields: [
      policy_field("content-type", "application/octet-stream"),
      policy_field("cache-control", "max-age=0")
    ]
  })))
  assert(Result.is_err(open_prekey_claim_response(%{success |
    fields: List.append(success.fields, policy_field("Cache-Control", "no-store"))
  })))
  assert(Result.is_err(open_prekey_claim_response(%{success | trailers: [policy_field("x", "y")]})))
  assert(Result.is_err(open_prekey_claim_response(%{success |
    informational: [BhttpInformational { status: 103, fields: [] }]
  })))
  Ok(nil)
end

test("prekey response keeps its exact existing 19312 byte ceiling") do
  let exact = policy_bytes(String.repeat("x", 19312))
  let over = policy_bytes(String.repeat("x", 19313))
  let response = prekey_claim_response(200, exact)?
  assert(Bytes.length(open_prekey_claim_response(response)?) == 19312)
  assert(Result.is_err(prekey_claim_response(200, over)))
  assert(Result.is_err(open_prekey_claim_response(%{response | content: over})))
  Ok(nil)
end
