from Ohttp.Types import (
  BhttpError,
  BhttpLimits,
  BhttpField,
  BhttpInformational,
  BhttpRequest,
  BhttpResponse,
  BhttpFraming,
  default_bhttp_limits
)
from Ohttp.BinaryHttp import decode_request, decode_response, encode_request, encode_response

# Primary wire vectors: RFC 9292 Figures 8, 9, 11 and 13.
# https://www.rfc-editor.org/rfc/rfc9292.html#section-5
# The expected wire values do not come from this codec's encoder.
fn hex(value :: String) -> Bytes do
  case Bytes.from_hex(value) do
    Ok(output) -> output
    Err(_) -> panic("invalid public Binary HTTP test vector")
  end
end

fn bytes(value :: String) -> Bytes do
  Bytes.from_utf8(value)
end

fn append(left :: Bytes, right :: Bytes) -> Bytes do
  case Bytes.concat(left, right) do
    Ok(output) -> output
    Err(_) -> panic("Binary HTTP fixture concatenation failed")
  end
end

fn part(value :: Bytes, offset :: Int, count :: Int) -> Bytes do
  case Bytes.slice(value, offset, count) do
    Ok(output) -> output
    Err(_) -> panic("Binary HTTP fixture slice failed")
  end
end

fn field(name :: String, value :: String) -> BhttpField do
  BhttpField { name: bytes(name), value: bytes(value) }
end

fn rfc_request_known() -> Bytes do
  hex("0003474554056874747073000a2f68656c6c6f2e747874406c0a757365722d61"
    <> "67656e74346375726c2f372e31362e33206c69626375726c2f372e31362e3320"
    <> "4f70656e53534c2f302e392e376c207a6c69622f312e322e3304686f73740f77"
    <> "77772e6578616d706c652e636f6d0f6163636570742d6c616e67756167650665"
    <> "6e2c206d690000")
end

fn rfc_request_indeterminate() -> Bytes do
  hex("0203474554056874747073000a2f68656c6c6f2e7478740a757365722d616765"
    <> "6e74346375726c2f372e31362e33206c69626375726c2f372e31362e33204f70"
    <> "656e53534c2f302e392e376c207a6c69622f312e322e3304686f73740f777777"
    <> "2e6578616d706c652e636f6d0f6163636570742d6c616e677561676506656e2c"
    <> "206d6900000000000000000000000000")
end

fn rfc_response_indeterminate() -> Bytes do
  hex("0340660772756e6e696e670a22736c65657020313522004067046c696e6b233c"
    <> "2f7374796c652e6373733e3b2072656c3d7072656c6f61643b2061733d737479"
    <> "6c65046c696e6b243c2f7363726970742e6a733e3b2072656c3d7072656c6f61"
    <> "643b2061733d7363726970740040c804646174651d4d6f6e2c203237204a756c"
    <> "20323030392031323a32383a353320474d540673657276657206417061636865"
    <> "0d6c6173742d6d6f6469666965641d5765642c203232204a756c203230303920"
    <> "31393a31353a353620474d5404657461671422333461613338372d642d313536"
    <> "3865623030220d6163636570742d72616e6765730562797465730e636f6e7465"
    <> "6e742d6c656e67746802353104766172790f4163636570742d456e636f64696e"
    <> "670c636f6e74656e742d747970650a746578742f706c61696e003348656c6c6f"
    <> "20576f726c6421204d7920636f6e74656e7420696e636c756465732061207472"
    <> "61696c696e672043524c462e0d0a0000")
end

fn rfc_response_known() -> Bytes do
  hex("0140c8001d5468697320636f6e74656e7420636f6e7461696e732043524c462e"
    <> "0d0a0d07747261696c65720474657874")
end

fn empty_request() -> BhttpRequest do
  BhttpRequest {
    method: bytes("GET"),
    scheme: bytes("https"),
    authority: bytes("example.com"),
    path: bytes("/"),
    fields: [],
    content: Bytes.empty(),
    trailers: []
  }
end

fn empty_response() -> BhttpResponse do
  BhttpResponse { informational: [], status: 200, fields: [], content: Bytes.empty(), trailers: [] }
end

fn request(input :: Bytes) -> BhttpRequest do
  case decode_request(input, default_bhttp_limits()) do
    Ok(output) -> output
    Err(_) -> panic("expected a valid Binary HTTP request")
  end
end

fn response(input :: Bytes) -> BhttpResponse do
  case decode_response(input, default_bhttp_limits()) do
    Ok(output) -> output
    Err(_) -> panic("expected a valid Binary HTTP response")
  end
end

fn encoded_request(value :: BhttpRequest, framing :: BhttpFraming) -> Bytes do
  case encode_request(value, framing, default_bhttp_limits()) do
    Ok(output) -> output
    Err(_) -> panic("expected request encoding to succeed")
  end
end

fn encoded_response(value :: BhttpResponse, framing :: BhttpFraming) -> Bytes do
  case encode_response(value, framing, default_bhttp_limits()) do
    Ok(output) -> output
    Err(_) -> panic("expected response encoding to succeed")
  end
end

fn request_error(input :: Bytes, limits :: BhttpLimits) -> BhttpError do
  case decode_request(input, limits) do
    Err(error) -> error
    Ok(_) -> panic("expected Binary HTTP request refusal")
  end
end

fn response_error(input :: Bytes, limits :: BhttpLimits) -> BhttpError do
  case decode_response(input, limits) do
    Err(error) -> error
    Ok(_) -> panic("expected Binary HTTP response refusal")
  end
end

fn equals(left :: Bytes, right :: Bytes) -> Bool do
  Bytes.secure_equals(left, right)
end

fn byte(value :: Int) -> Bytes do
  case Bytes.from_list([value]) do
    Ok(output) -> output
    Err(_) -> panic("invalid one-byte Binary HTTP fixture")
  end
end

# Independent malformed-frame construction: none of the codec's encoders is
# used to produce decoder rejection inputs, including names it must reject.
fn raw_field_response(name :: Bytes, value :: Bytes) -> Bytes do
  let line = append(append(byte(Bytes.length(name)), name),
    append(byte(Bytes.length(value)), value))
  assert(Bytes.length(line) < 64)
  append(append(hex("0140c8"), append(byte(Bytes.length(line)), line)), hex("0000"))
end

test("RFC9292 known request has exact independent wire bytes and preserves fields") do
  let wire = rfc_request_known()
  let value = request(wire)
  assert(equals(value.method, bytes("GET")))
  assert(equals(value.scheme, bytes("https")))
  assert(Bytes.length(value.authority) == 0)
  assert(equals(value.path, bytes("/hello.txt")))
  assert(List.length(value.fields) == 3)
  assert(equals(List.get(value.fields, 0).name, bytes("user-agent")))
  assert(equals(List.get(value.fields, 1).value, bytes("www.example.com")))
  assert(equals(List.get(value.fields, 2).value, bytes("en, mi")))
  assert(Bytes.length(value.content) == 0 && List.length(value.trailers) == 0)
  assert(equals(encoded_request(value, BhttpKnownLength), wire))
end

test("RFC9292 indeterminate request accepts padding and equivalent empty truncations") do
  let wire = rfc_request_indeterminate()
  let canonical = encoded_request(request(wire), BhttpKnownLength)
  assert(equals(canonical, rfc_request_known()))
  assert(equals(encoded_request(request(wire), BhttpIndeterminateLength),
    part(wire, 0, Bytes.length(wire) - 10)))
  for removed in [0, 1, 2, 3, 10, 11, 12] do
    assert(equals(encoded_request(request(part(wire, 0, Bytes.length(wire) - removed)),
        BhttpKnownLength),
      canonical))
  end
  let known = rfc_request_known()
  for removed in [1, 2] do
    assert(equals(encoded_request(request(part(known, 0, Bytes.length(known) - removed)),
        BhttpKnownLength),
      known))
  end
end

test("RFC9292 informational responses keep duplicate field order and complete content") do
  let wire = rfc_response_indeterminate()
  let value = response(wire)
  assert(value.status == 200 && List.length(value.informational) == 2)
  assert(List.get(value.informational, 0).status == 102)
  let hints = List.get(value.informational, 1)
  assert(hints.status == 103 && List.length(hints.fields) == 2)
  assert(equals(List.get(hints.fields, 0).name, bytes("link")))
  assert(equals(List.get(hints.fields, 1).name, bytes("link")))
  assert(equals(List.get(hints.fields, 1).value, bytes("</script.js>; rel=preload; as=script")))
  assert(List.length(value.fields) == 8 && List.length(value.trailers) == 0)
  assert(equals(value.content, bytes("Hello World! My content includes a trailing CRLF.\r\n")))
  assert(equals(encoded_response(value, BhttpIndeterminateLength), wire))
  let known = encoded_response(value, BhttpKnownLength)
  assert(equals(encoded_response(response(known), BhttpIndeterminateLength), wire))
end

test("RFC9292 known response preserves its content and actual trailer") do
  let wire = rfc_response_known()
  let value = response(wire)
  assert(value.status == 200 && List.length(value.fields) == 0)
  assert(equals(value.content, bytes("This content contains CRLF.\r\n")))
  assert(List.length(value.trailers) == 1)
  assert(equals(List.get(value.trailers, 0).name, bytes("trailer")))
  assert(equals(List.get(value.trailers, 0).value, bytes("text")))
  assert(equals(encoded_response(value, BhttpKnownLength), wire))
end

test("legal nonminimal integers and omitted wholly empty trailing sections are accepted") do
  let minimal = hex("00034745540568747470730b6578616d706c652e636f6d012f")
  for ending in ["", "00", "0000", "000000", "0000000000"] do
    assert(equals(encoded_request(request(append(minimal, hex(ending))), BhttpKnownLength),
      encoded_request(empty_request(), BhttpKnownLength)))
  end
  for wire in ["0140c8", "0140c800", "0140c80000", "0340c8", "0340c80000"] do
    assert(equals(encoded_response(response(hex(wire)), BhttpKnownLength), hex("0140c8000000")))
  end
  # Each integer width is legal even when a smaller width suffices.
  let wide = hex("800000004003474554800000056874747073c00000000000000040012f"
    <> "400080000000c000000000000000")
  assert(Bytes.length(request(wide).authority) == 0)
  assert(equals(request(wide).path, bytes("/")))
  assert(equals(response(hex("0340c84000400161800000004000")).content, bytes("a")))
end

test("truncation inside an integer field content or nonempty section is refused") do
  let limits = default_bhttp_limits()
  for wire in ["", "40", "800000", "c0000000000000", "000347", "0140", "0140c840"] do
    assert(Result.is_err(decode_request(hex(wire), limits)))
    assert(Result.is_err(decode_response(hex(wire), limits)))
  end
  for wire in [
    "0140c8030261",
    "0140c8000361",
    "0340c801610162",
    "0340c8000161",
    "0340c8000001610162"
  ] do
    assert(response_error(hex(wire), limits) == BhttpUnexpectedEnd)
  end
  # A field cannot borrow bytes from the next section to finish its name.
  assert(Result.is_err(decode_response(hex("0140c80203616263640000"), limits)))
end

test("framing status and nonzero padding failures stay structural errors") do
  let limits = default_bhttp_limits()
  for wire in ["04", "4004", "3f", "ff00000000000000"] do
    assert(request_error(hex(wire), limits) == BhttpInvalidFraming)
    assert(response_error(hex(wire), limits) == BhttpInvalidFraming)
  end
  assert(request_error(hex("0140c8"), limits) == BhttpInvalidFraming)
  assert(response_error(encoded_request(empty_request(), BhttpKnownLength),
    limits) == BhttpInvalidFraming)
  for wire in ["0100", "014063", "014258"] do
    assert(response_error(hex(wire), limits) == BhttpInvalidStatus)
  end
  assert(response_error(hex("01406400"), limits) == BhttpUnexpectedEnd)
  assert(response_error(hex("0140c800000001"), limits) == BhttpInvalidPadding)
  assert(response_error(hex("0340c8000000ff"), limits) == BhttpInvalidPadding)
end

test("structural field validation rejects delimiters values and misplaced pseudo fields") do
  let limits = default_bhttp_limits()
  for name in ["", "a b", "a:b", ":method", ":scheme", ":authority", ":path", ":status"] do
    assert(Result.is_err(encode_response(%{empty_response() | fields: [field(name, "ok")]},
      BhttpKnownLength,
      limits)))
    assert(response_error(raw_field_response(bytes(name), bytes("ok")),
      limits) == BhttpInvalidField)
  end
  for value in ["a\r\nb", "a\nb", " leading", "trailing ", "\tleading", "trailing\t"] do
    assert(Result.is_err(encode_response(%{empty_response() | fields: [field("x", value)]},
      BhttpKnownLength,
      limits)))
    assert(response_error(raw_field_response(bytes("x"), bytes(value)),
      limits) == BhttpInvalidField)
  end
  let nul = BhttpField { name: bytes("x"), value: hex("610062") }
  assert(Result.is_err(encode_response(%{empty_response() | fields: [nul]},
    BhttpKnownLength,
    limits)))
  assert(response_error(raw_field_response(nul.name, nul.value), limits) == BhttpInvalidField)
  # Zero name inside a nonempty known-length section is not its terminator.
  assert(response_error(hex("0140c8020000"), limits) == BhttpInvalidField)
  let extension = field(":protocol", "fixture")
  assert(Result.is_err(encode_request(%{empty_request() | fields: [field("x", "a"), extension]},
    BhttpKnownLength,
    limits)))
  assert(Result.is_err(encode_request(%{empty_request() | trailers: [extension]},
    BhttpIndeterminateLength,
    limits)))
  assert(Result.is_err(encode_request(%{empty_request() | fields: [extension, extension]},
    BhttpKnownLength,
    limits)))
  for bad in [
    %{empty_request() | method: Bytes.empty()},
    %{empty_request() | method: bytes("GET\r\n")},
    %{empty_request() | scheme: bytes("bad scheme")},
    %{empty_request() | path: Bytes.empty()},
    %{empty_request() | authority: bytes("host\r\n")}
  ] do
    assert(Result.is_err(encode_request(bad, BhttpKnownLength, limits)))
  end
end

test("structural parsing preserves duplicates opaque values and later gateway policy choices") do
  let opaque = BhttpField { name: bytes("x-opaque"), value: hex("80ff") }
  let value = %{empty_request() |
    method: bytes("CUSTOM"),
    scheme: bytes("custom+scheme"),
    authority: bytes("other.example:8443"),
    path: bytes("/not-a-gateway-route?x=y"),
    fields: [
      field(":protocol", "fixture"),
      field("connection", "keep-alive"),
      field("authorization", "not-a-secret-fixture"),
      field("cookie", "a=1"),
      field("cookie", "b=2"),
      opaque
    ],
    content: hex("000d0aff"),
    trailers: [field("x-result", "complete")]
  }
  for framing in [BhttpKnownLength, BhttpIndeterminateLength] do
    let decoded = request(encoded_request(value, framing))
    assert(List.length(decoded.fields) == 6)
    assert(equals(decoded.path, value.path) && equals(decoded.authority, value.authority))
    assert(equals(List.get(decoded.fields, 3).value, bytes("a=1")))
    assert(equals(List.get(decoded.fields, 4).value, bytes("b=2")))
    assert(equals(List.get(decoded.fields, 5).value, hex("80ff")))
    assert(equals(decoded.content, hex("000d0aff")))
    assert(equals(List.get(decoded.trailers, 0).value, bytes("complete")))
  end
  # Binary HTTP framing is independent of HEAD/204 response body semantics.
  assert(equals(response(encoded_response(%{empty_response() | status: 204, content: bytes("a")},
      BhttpKnownLength)).content,
    bytes("a")))
end

test("field information control and chunk budgets apply before accumulation") do
  let limits = default_bhttp_limits()
  let sample = %{empty_response() |
    informational: [BhttpInformational { status: 103, fields: [field("a", "b")] }],
    fields: [field("c", "d")],
    trailers: [field("e", "f")]
  }
  let wire = encoded_response(sample, BhttpKnownLength)
  assert(response_error(wire, %{limits | field_count: 2}) == BhttpLimitExceeded)
  assert(response_error(wire, %{limits | field_bytes: 5}) == BhttpLimitExceeded)
  assert(response_error(wire, %{limits | informational_count: 0}) == BhttpLimitExceeded)
  assert(Result.is_ok(decode_response(wire, %{limits | field_count: 3, field_bytes: 6})))
  assert(response_error(rfc_response_indeterminate(),
    %{limits | informational_count: 1}) == BhttpLimitExceeded)
  assert(request_error(encoded_request(empty_request(), BhttpKnownLength),
    %{limits | control_bytes: 19}) == BhttpLimitExceeded)
  let chunks = hex("0340c8000161026263036465660000")
  assert(equals(response(chunks).content, bytes("abcdef")))
  assert(response_error(chunks, %{limits | content_chunks: 2}) == BhttpLimitExceeded)
  assert(response_error(chunks, %{limits | content_bytes: 5}) == BhttpLimitExceeded)
end

test("declared huge lengths are refused before conversion slicing or allocation") do
  let limits = default_bhttp_limits()
  for wire in ["0140c8ffffffffffffffff", "0140c800ffffffffffffffff", "0340c800ffffffffffffffff"] do
    assert(response_error(hex(wire), limits) == BhttpLimitExceeded)
  end
  let prefix = hex("0003474554")
  assert(request_error(append(prefix, hex("ffffffffffffffff")), limits) == BhttpLimitExceeded)
end

test("invalid caller limits are distinct from malformed wire and cover every cap") do
  let limits = default_bhttp_limits()
  for bad in [
    %{limits | wire_bytes: -1},
    %{limits | wire_bytes: 1048577},
    %{limits | content_bytes: -1},
    %{limits | content_bytes: 1048577},
    %{limits | field_bytes: -1},
    %{limits | field_bytes: 8193},
    %{limits | field_count: -1},
    %{limits | field_count: 17},
    %{limits | control_bytes: -1},
    %{limits | control_bytes: 4097},
    %{limits | informational_count: -1},
    %{limits | informational_count: 5},
    %{limits | content_chunks: -1},
    %{limits | content_chunks: 1025}
  ] do
    assert(request_error(Bytes.empty(), bad) == BhttpInvalidLimits)
    assert(response_error(Bytes.empty(), bad) == BhttpInvalidLimits)
    assert(Result.is_err(encode_response(empty_response(), BhttpKnownLength, bad)))
  end
end

test("large existing directory response and integer width boundaries survive both modes") do
  let limits = default_bhttp_limits()
  for length in [0, 1, 63, 64, 16383, 16384, 570418] do
    let content = bytes(String.repeat("x", length))
    let value = %{empty_response() | content: content}
    for framing in [BhttpKnownLength, BhttpIndeterminateLength] do
      let wire = encoded_response(value, framing)
      assert(equals(response(wire).content, content))
      assert(Result.is_ok(decode_response(wire, %{limits | content_bytes: length})))
      if length > 0 do
        assert(response_error(wire, %{limits | content_bytes: length - 1}) == BhttpLimitExceeded)
      end
    end
  end
  assert(equals(part(encoded_response(%{empty_response() | content: bytes(String.repeat("x", 63))},
        BhttpKnownLength),
      4,
      1),
    hex("3f")))
  assert(equals(part(encoded_response(%{empty_response() | content: bytes(String.repeat("x", 64))},
        BhttpKnownLength),
      4,
      2),
    hex("4040")))
  assert(equals(part(encoded_response(%{empty_response() |
          content: bytes(String.repeat("x", 16384))
        },
        BhttpKnownLength),
      4,
      4),
    hex("80004000")))
end

test("one MiB complete wire cap and exact output cap are enforced without truncation") do
  let limits = default_bhttp_limits()
  let complete = append(hex("0140c8"), hex(String.repeat("00", 1048573)))
  assert(Bytes.length(complete) == 1048576)
  assert(response(complete).status == 200)
  assert(response_error(append(complete, hex("00")), limits) == BhttpInputTooLarge)
  let value = %{empty_response() | content: bytes("payload")}
  let wire = encoded_response(value, BhttpKnownLength)
  assert(Result.is_ok(encode_response(value,
    BhttpKnownLength,
    %{limits | wire_bytes: Bytes.length(wire)})))
  assert(case encode_response(value,
    BhttpKnownLength,
    %{limits | wire_bytes: Bytes.length(wire) - 1}) do
    Err(error) -> error == BhttpOutputTooLarge
    Ok(_) -> false
  end)
  assert(response_error(wire, %{limits | wire_bytes: Bytes.length(wire) - 1}) == BhttpInputTooLarge)
end
