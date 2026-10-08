from Privacy.Bhttp import (
  BhttpField,
  BhttpRequest,
  BhttpResponse,
  bhttp_decode_request,
  bhttp_decode_response,
  bhttp_encode_request,
  bhttp_encode_response
)
from Privacy.OhttpWire import (
  OhttpKeyConfig,
  ohttp_key_config_decode,
  ohttp_key_config_encode,
  ohttp_keys_encode,
  ohttp_padded_length,
  ohttp_request_message,
  ohttp_response_message
)

fn hex(text :: String) -> Bytes!String do
  case Bytes.from_hex(text) do
    Err(_) -> Err("bad hex in test")
    Ok(value)
  end
end

fn text(bytes :: Bytes) -> String!String do
  case Bytes.to_utf8(bytes) do
    Err(_) -> Err("not UTF-8")
    Ok(value)
  end
end

fn slice(input :: Bytes, offset :: Int, length :: Int) -> Bytes!String do
  case Bytes.slice(input, offset, length) do
    Err(_) -> Err("slice failed")
    Ok(value)
  end
end

fn repeated(value :: Int, length :: Int) -> Bytes!String do
  case Bytes.repeat(value, length) do
    Err(_) -> Err("repeat failed")
    Ok(bytes)
  end
end

fn join(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts,
    Ok(Bytes.empty()),
    fn acc, part -> case acc do
      Err(error)
      Ok(bytes) -> case Bytes.concat(bytes, part) do
        Err(_) -> Err("concat failed")
        Ok(value)
      end
    end end)
end

fn refused<T>(result :: Result<T, String>) -> Bool do
  case result do
    Ok(_) -> false
    Err(_) -> true
  end
end

fn refused_with<T>(result :: Result<T, String>, expected :: String) -> Bool do
  case result do
    Ok(_) -> false
    Err(error) -> error == expected
  end
end

fn replaced(input :: Bytes, offset :: Int, value :: Int) -> Bytes!String do
  let head = case Bytes.slice(input, 0, offset) do
    Err(_) -> Err("slice failed")
    Ok(bytes)
  end?
  let tail = case Bytes.slice(input, offset + 1, Bytes.length(input) - offset - 1) do
    Err(_) -> Err("slice failed")
    Ok(bytes)
  end?
  let middle = case Bytes.from_list([value]) do
    Err(_) -> Err("byte failed")
    Ok(bytes)
  end?
  join([head, middle, tail])
end

fn flipped(input :: Bytes, offset :: Int) -> Bytes!String do
  let old = case Bytes.get(input, offset) do
    Err(_) -> Err("get failed")
    Ok(value)
  end?
  replaced(input, offset, (old + 1) % 256)
end

fn gateway_pair() -> X25519KeyPair!String do
  case Crypto.x25519_from_seed(hex("3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a")?) do
    Err(_) -> Err("gateway key failed")
    Ok(pair)
  end
end

# RFC 9292 section 5.1, Figure 8 (known length).
fn rfc_request() -> Bytes!String do
  hex("0003474554056874747073000a2f68656c6c6f2e747874406c0a757365722d6167656e74346375726c2f372e31362e33206c69626375726c2f372e31362e33204f70656e53534c2f302e392e376c207a6c69622f312e322e3304686f73740f7777772e6578616d706c652e636f6d0f6163636570742d6c616e677561676506656e2c206d690000")
end

fn bhttp_proof() -> Bool!String do
  let figure8 = rfc_request()?
  let request = bhttp_decode_request(figure8)?
  assert(request.method == "GET")
  assert(request.scheme == "https")
  assert(request.authority == "")
  assert(request.path == "/hello.txt")
  assert(List.map(request.fields, fn field -> field.name end) == [
      "user-agent",
      "host",
      "accept-language"
    ])
  assert(List.get(request.fields, 1).value == "www.example.com")
  assert(Bytes.length(request.content) == 0)
  # The same bytes back: the two closing zeros are the empty content and the
  # empty trailer section.
  assert(Bytes.secure_equals(bhttp_encode_request(request, Bytes.length(figure8))?, figure8))
  # Truncated after the path (RFC 9458 Appendix A's request) is the same as
  # empty sections.
  let minimal = bhttp_decode_request(hex("00034745540568747470730b6578616d706c652e636f6d012f")?)?
  assert(minimal.authority == "example.com"
    && minimal.path == "/"
    && List.length(minimal.fields) == 0)
  # RFC 9292 Figure 13: a response with content and a trailer section.
  let figure13 = bhttp_decode_response(hex("0140c8001d5468697320636f6e74656e7420636f6e7461696e732043524c462e0d0a0d07747261696c65720474657874")?)?
  assert(figure13.status == 200)
  assert(text(figure13.content)? == "This content contains CRLF.\r\n")
  assert(bhttp_decode_response(hex("0140c8")?)?.status == 200)
  # An informational response before the final one is skipped.
  assert(bhttp_decode_response(hex("0140670040c800")?)?.status == 200)
  # Invalid messages: another framing, non-zero padding, a pseudo-field, an
  # uppercase name, a section that runs past the end, no final status.
  assert(refused(bhttp_decode_request(hex("02034745540568747470730b6578616d706c652e636f6d012f")?)))
  assert(refused(bhttp_decode_request(join([figure8, hex("0001")?])?)))
  assert(refused(bhttp_decode_request(hex("0004504f535405687474707300012f09073a73746174757300")?)))
  assert(refused(bhttp_decode_request(hex("0004504f535405687474707300012f070548454c4c4f00")?)))
  assert(refused(bhttp_decode_request(hex("0004504f535405687474707300012f0a0268690161")?)))
  assert(refused(bhttp_decode_response(hex("014067")?)))
  assert(refused(bhttp_decode_response(hex("0142580000")?)))
  # A padded response keeps its meaning.
  let response = BhttpResponse { status: 404, fields: [], content: Bytes.from_utf8("gone") }
  let padded = bhttp_encode_response(response, 1024)?
  assert(Bytes.length(padded) == 1024)
  let decoded = bhttp_decode_response(padded)?
  assert(decoded.status == 404 && text(decoded.content)? == "gone")
  let with_field = BhttpRequest {
    method: "POST",
    scheme: "https",
    authority: "",
    path: "/v1/mailbox/fetch",
    fields: [BhttpField { name: "accept", value: "application/octet-stream" }],
    content: Bytes.from_utf8("FET")
  }
  let round = bhttp_decode_request(bhttp_encode_request(with_field, 0)?)?
  assert(round.path == "/v1/mailbox/fetch"
    && List.get(round.fields, 0).value == "application/octet-stream")
  Ok(true)
end

test("binary HTTP reads and writes the RFC 9292 known-length examples") do
  case bhttp_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn key_config_proof() -> Bool!String do
  # RFC 9458 Appendix A: one X25519 key offering AES-128-GCM and ChaCha20-Poly1305.
  let rfc = ohttp_key_config_decode(hex("01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500080001000100010003")?)?
  assert(rfc.key_id == 1)
  let pair = gateway_pair()?
  assert(Bytes.secure_equals(rfc.public_key, pair.public_key.bytes))
  # Morse's configuration offers only HKDF-SHA256 with ChaCha20-Poly1305.
  let encoded = ohttp_key_config_encode(rfc)?
  assert(Bytes.to_hex(encoded) == "01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155000400010003")
  let list = ohttp_keys_encode([rfc, OhttpKeyConfig { key_id: 7, public_key: rfc.public_key }])?
  assert(Bytes.length(list) == 2 * (2 + 41))
  assert(Bytes.to_hex(slice(list, 0, 2)?) == "0029")
  # A configuration without the suite, with another KEM, or cut short.
  assert(refused_with(ohttp_key_config_decode(hex("01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155000400010001")?),
    "ohttp_key_config_unsupported"))
  assert(refused(ohttp_key_config_decode(hex("01001031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155000400010003")?)))
  assert(refused(ohttp_key_config_decode(hex("01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e7981550004000100")?)))
  Ok(true)
end

test("key configurations follow RFC 9458 section 3.1") do
  case key_config_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn padding_proof() -> Bool!String do
  # Requests pad to at least 256 bytes and a power of two, so a username's
  # length doesn't show; responses to at least 1 KiB, then powers of two,
  # then 64 KiB steps.
  let short = ohttp_request_message("POST", "/v1/devices/resolve", Bytes.from_utf8("al"))?
  let long = ohttp_request_message("POST", "/v1/devices/resolve", repeated(97, 100)?)?
  assert(Bytes.length(short) == 256 && Bytes.length(long) == 256)
  assert(Bytes.length(ohttp_response_message(404, Bytes.empty())?) == 1024)
  assert(Bytes.length(ohttp_response_message(200, repeated(1, 1500)?)?) == 2048)
  assert(ohttp_padded_length(65536, 1024) == 65536)
  assert(ohttp_padded_length(65537, 1024) == 131072)
  assert(ohttp_padded_length(524960, 1024) == 589824)
  assert(Bytes.length(ohttp_response_message(200, repeated(1, 524949)?)?) == 589824)
  Ok(true)
end

test("messages are padded to size buckets") do
  case padding_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
