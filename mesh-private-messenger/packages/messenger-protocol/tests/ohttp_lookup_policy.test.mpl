from Ohttp.LookupPolicy import (
  OhttpLookupOperation,
  lookup_request,
  admit_lookup_request,
  lookup_response,
  open_lookup_response
)
from Ohttp.Types import BhttpField, BhttpInformational

fn bytes(value :: String) -> Bytes do
  Bytes.from_utf8(value)
end

fn repeated(size :: Int) -> Bytes do
  case Bytes.repeat(0, size) do
    Err(_) -> panic("fixture allocation")
    Ok(value) -> value
  end
end

fn field(name :: String, value :: String) -> BhttpField do
  BhttpField { name: bytes(name), value: bytes(value) }
end

fn policy_cases() -> Result<(), String> do
  let operations = [
    OhttpDirectoryLookup(1),
    OhttpDirectoryLookup(2),
    OhttpConsistencyLookup(1),
    OhttpConsistencyLookup(2),
    OhttpLegacyBridgeLookup
  ]
  let paths = [
    "/v1/devices/resolve",
    "/v2/devices/resolve",
    "/v1/transparency/consistency",
    "/v2/transparency/consistency",
    "/v2/transparency/legacy-bridge"
  ]
  for index in 0..5 do
    let operation = List.get(operations, index)
    let body = repeated(if index < 2 do
      96
    else
      12
    end)
    let request = lookup_request("https://core.example", false, operation, body)?
    assert(Bytes.secure_equals(request.path, bytes(List.get(paths, index))))
    let admitted = admit_lookup_request(request, "https://core.example", false)?
    assert(admitted.operation == operation)
    assert(Bytes.secure_equals(admitted.body, body))
    assert(Result.is_err(lookup_request("https://core.example",
      false,
      operation,
      repeated(if index < 2 do
        97
      else
        13
      end))))
    if index >= 2 do
      assert(Result.is_err(lookup_request("https://core.example", false, operation, repeated(11))))
    end
    for method in ["GET", "post", "CONNECT"] do
      assert(Result.is_err(admit_lookup_request(%{request | method: bytes(method)},
        "https://core.example",
        false)))
    end
    for path in [
      "/v1/prekeys/bundle",
      "/v1/envelopes/batch",
      "/v2/transparency/inclusion",
      "/v2/transparency/witnesses",
      List.get(paths, index) <> "?x=1",
      List.get(paths, index) <> "/"
    ] do
      assert(Result.is_err(admit_lookup_request(%{request | path: bytes(path)},
        "https://core.example",
        false)))
    end
    assert(Result.is_err(admit_lookup_request(%{request | authority: bytes("other.example")},
      "https://core.example",
      false)))
    assert(Result.is_err(admit_lookup_request(%{request | trailers: [field("x-extra", "1")]},
      "https://core.example",
      false)))
    assert(Result.is_err(admit_lookup_request(%{request |
        fields: List.append(request.fields, field("authorization", "secret"))
      },
      "https://core.example",
      false)))
    assert(Result.is_err(admit_lookup_request(%{request |
        fields: [
          field("content-type", "application/octet-stream"),
          field("content-type", "application/octet-stream")
        ]
      },
      "https://core.example",
      false)))
  end
  for operation in [
    OhttpDirectoryLookup(0),
    OhttpDirectoryLookup(3),
    OhttpConsistencyLookup(0),
    OhttpConsistencyLookup(3)
  ] do
    assert(Result.is_err(lookup_request("https://core.example", false, operation, repeated(12))))
  end
  for origin in [
    "https://core.example/",
    "https://core.example?x=1",
    "https://user@core.example",
    "http://core.example",
    "https://CORE.example"
  ] do
    assert(Result.is_err(lookup_request(origin, false, OhttpDirectoryLookup(1), repeated(96))))
  end
  let local = lookup_request("http://127.0.0.1:20120", true, OhttpDirectoryLookup(1), repeated(96))?
  admit_lookup_request(local, "http://127.0.0.1:20120", true)?
  assert(Result.is_err(admit_lookup_request(local, "http://127.0.0.1:20120", false)))
  Ok(nil)
end

fn response_cases() -> Result<(), String> do
  let operations = [OhttpDirectoryLookup(1), OhttpConsistencyLookup(2), OhttpLegacyBridgeLookup]
  let limits = [570418, 1070, 4942]
  for index in 0..3 do
    let operation = List.get(operations, index)
    let maximum = List.get(limits, index)
    let response = lookup_response(operation, 200, repeated(maximum))?
    let opened = open_lookup_response(operation, response)?
    assert(opened.status == 200 && Bytes.length(opened.body) == maximum)
    assert(Result.is_err(lookup_response(operation, 200, repeated(maximum + 1))))
    assert(Result.is_err(open_lookup_response(operation,
      %{response | content: repeated(maximum + 1)})))
    assert(Result.is_err(open_lookup_response(operation,
      %{response | informational: [BhttpInformational { status: 103, fields: [] }]})))
    assert(Result.is_err(open_lookup_response(operation,
      %{response | trailers: [field("x-extra", "1")]})))
    assert(Result.is_err(open_lookup_response(operation,
      %{response | fields: [field("content-type", "application/octet-stream")]})))
    assert(Result.is_err(lookup_response(operation, 199, Bytes.empty())))
    assert(Result.is_err(lookup_response(operation, 600, Bytes.empty())))
  end
  # Preserve authenticated target status/body; the caller alone applies its
  # already-permitted cutover transition. An outer404 never reaches this API.
  let response = lookup_response(OhttpDirectoryLookup(2), 404, bytes("transparency_v2_not_active"))?
  let opened = open_lookup_response(OhttpDirectoryLookup(2), response)?
  assert(opened.status == 404
    && Bytes.secure_equals(opened.body, bytes("transparency_v2_not_active")))
  Ok(nil)
end

test("lookup policy grants only exact pinned five-path read authority") do
  case policy_cases() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> println("m3-lookup-policy-requests:passed")
  end
end

test("lookup response caps and encrypted status remain operation specific") do
  case response_cases() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> println("m3-lookup-policy-responses:passed")
  end
end
