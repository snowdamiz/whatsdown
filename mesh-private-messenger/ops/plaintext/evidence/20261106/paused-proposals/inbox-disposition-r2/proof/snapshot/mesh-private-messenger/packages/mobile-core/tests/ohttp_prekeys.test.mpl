from Mobile.OhttpPrekeys import fetch_ohttp_prekey
from Mobile.OhttpPins import MobileOhttpPins, decode_ohttp_pins
from Ohttp.BinaryHttp import decode_request, encode_response
from Ohttp.Keys import OhttpKeyConfig, encode_key_config
from Ohttp.Policy import admit_prekey_claim_request, prekey_claim_response
from Ohttp.Types import BhttpFraming, BhttpField, default_bhttp_limits
from Transparency.Config import decode_security_config, encode_security_config

fn bytes(text :: String) -> Bytes do
  Bytes.from_utf8(text)
end

fn fixture_pair() -> X25519KeyPair!String do
  case Crypto.x25519_from_seed(Bytes.from_hex("ef0106ca50fd40bd29f8e1cfb6079fd37b4052d3bf4ce20b616aff8dd2bd8c5f")?) do
    Err(_) -> Err("fixture key failed")
    Ok(value)
  end
end

fn pins() -> MobileOhttpPins!String do
  let network = bytes("2\n1\nhttps://core.example\nhttp://127.0.0.1:24457\nhttps://objects.example\nwss://stream.example/v1/mailbox/stream\n16")
  let security = decode_security_config(bytes(String.join([
      "1",
      String.repeat("11", 32),
      String.repeat("22", 32),
      String.repeat("33", 32),
      String.repeat("44", 32),
      "8"
    ],
    "\n")))?
  let pair = fixture_pair()?
  let key = encode_key_config(OhttpKeyConfig { key_id: 37, public_key: pair.public_key })?
  decode_ohttp_pins(bytes(String.join([
        "1",
        Bytes.to_hex(Crypto.sha256(network)),
        Bytes.to_hex(Crypto.sha256(encode_security_config(security)?)),
        "1",
        "required",
        "1",
        "2000 5000 " <> Bytes.to_base64(key)
      ],
      "\n")),
    network,
    security)
end

fn outer(status :: Int, body :: Bytes, media :: String, cache :: String) -> Response do
  HTTP.response_bytes_with_headers(status,
    body,
    Map.new()
      |> Map.put("Content-Type", media)
      |> Map.put("Cache-Control", cache))
end

fn exchange(request :: Request) -> Response!String do
  for name in ["cookie", "authorization", "x-forwarded-for", "x-account-id", "traceparent"] do
    assert(Request.header(request, name) == None)
  end
  assert(Request.header(request, "content-type") == Some("message/ohttp-req"))
  assert(Request.header(request, "accept") == Some("message/ohttp-res"))
  assert(Request.header(request, "cache-control") == Some("no-store"))
  let pair = fixture_pair()?
  let opened = case Ohttp.decapsulate_request(pair.private_key, 37, Request.body_bytes(request)) do
    Err(_) -> return Err("fixture request decryption failed")
    Ok(value) -> value
  end
  let limits = default_bhttp_limits()
  let inner = case decode_request(opened.plaintext, %{limits | content_bytes: 120}) do
    Err(_) -> return Err("fixture request decoding failed")
    Ok(value) -> value
  end
  let stamped = admit_prekey_claim_request(inner, "https://core.example", false)?
  let marker = Bytes.to_utf8(stamped)?
  if marker == "missing" do
    return Ok(HTTP.response_bytes(200, bytes(String.repeat("x", 48))))
  end
  if marker == "outer_big" do
    return Ok(outer(200, bytes(String.repeat("x", 1048577)), "message/ohttp-res", "no-store"))
  end
  if marker == "short" do
    return Ok(outer(200, bytes(String.repeat("x", 47)), "message/ohttp-res", "no-store"))
  end
  if marker == "slow" do
    Timer.sleep(250)
  end
  let response = prekey_claim_response(if marker == "inner_error" do
      503
    else
      200
    end,
    if marker == "max" do
      bytes(String.repeat("x", 19312))
    else
      stamped
    end)?
  let response = if marker == "inner_big" do
    %{response | content: bytes(String.repeat("x", 19313))}
  else if marker == "inner_fields" do
    %{response |
      fields: List.append(response.fields, BhttpField { name: bytes("x-extra"), value: bytes("x") })
    }
  else
    response
  end
  let plaintext = if marker == "malformed" do
    bytes("not binary HTTP")
  else
    case encode_response(response,
      if marker == "indeterminate" do
        BhttpIndeterminateLength
      else
        BhttpKnownLength
      end,
      limits) do
      Err(_) -> return Err("fixture response encoding failed")
      Ok(value) -> value
    end
  end
  let encrypted = if marker == "cross" do
    let other = case Ohttp.encapsulate_request(37, pair.public_key, bytes("another request")) do
      Err(_) -> return Err("fixture second request failed")
      Ok(value) -> value
    end
    let other_open = case Ohttp.decapsulate_request(pair.private_key, 37, other.wire) do
      Err(_) -> return Err("fixture second opening failed")
      Ok(value) -> value
    end
    Ohttp.encapsulate_response(other_open.response_context, plaintext)
  else
    Ohttp.encapsulate_response(opened.response_context, plaintext)
  end
  let encrypted = case encrypted do
    Err(_) -> return Err("fixture response encryption failed")
    Ok(value) -> value
  end
  if marker == "redirect" do
    # Following this redirect would produce a valid response for this exact
    # context. A generic failed redirect target cannot prove redirect refusal.
    return Ok(HTTP.response_bytes_with_headers(303,
      Bytes.empty(),
      Map.new()
        |> Map.put("Location",
          "http://127.0.0.1:24457/redirect-target?reply=" <> Bytes.to_hex(encrypted))))
  end
  if marker == "encoding" do
    return Ok(HTTP.response_bytes_with_headers(200,
      encrypted,
      Map.new()
        |> Map.put("Content-Type", "message/ohttp-res")
        |> Map.put("Cache-Control", "no-store")
        |> Map.put("Content-Encoding", "unsupported-proof-encoding")))
  end
  let encrypted = if marker == "tampered" do
    let changed = case Bytes.from_list([
      (Bytes.get(encrypted, Bytes.length(encrypted) - 1)? + 1) % 256
    ]) do
      Err(_) -> return Err("fixture mutation failed")
      Ok(value) -> value
    end
    Bytes.concat(Bytes.slice(encrypted, 0, Bytes.length(encrypted) - 1)?, changed)?
  else
    encrypted
  end
  let status = if marker == "outer_error" do
    503
  else
    200
  end
  let media = if marker == "media" do
    "application/octet-stream"
  else
    "message/ohttp-res"
  end
  let cache = if marker == "cache" do
    "public"
  else
    "no-store"
  end
  Ok(outer(status, encrypted, media, cache))
end

fn upstream(request :: Request) -> Response do
  case exchange(request) do
    Err(error) -> HTTP.response(500, error)
    Ok(value) -> value
  end
end

fn redirected(request :: Request) -> Response do
  let body = case Request.query(request, "reply") do
    None -> return HTTP.response(400, "missing fixture reply")
    Some(value) -> case Bytes.from_hex(value) do
      Err(_) -> return HTTP.response(400, "invalid fixture reply")
      Ok(raw) -> raw
    end
  end
  outer(200, body, "message/ohttp-res", "no-store")
end

actor gateway() do
  HTTP.router()
    |> HTTP.on_post("/v1/ohttp", upstream)
    |> HTTP.on_get("/redirect-target", redirected)
    |> HTTP.serve(24457)
end

fn successful() -> Bool!String do
  let configured = pins()?
  for marker in ["exact stamped bytes", "", "indeterminate", String.repeat("x", 120)] do
    let body = bytes(marker)
    assert(Bytes.secure_equals(fetch_ohttp_prekey(configured, body, U64.parse("2000")?, 1000)?,
      body))
  end
  assert(Bytes.length(fetch_ohttp_prekey(configured,
    bytes("max"),
    U64.parse("4999")?,
    1000)?) == 19312)
  Ok(true)
end

fn failures() -> Bool!String do
  let configured = pins()?
  let now = U64.parse("2000")?
  for marker in [
    "inner_error",
    "inner_big",
    "inner_fields",
    "malformed",
    "cross",
    "tampered",
    "missing",
    "redirect",
    "outer_big",
    "short",
    "media",
    "cache",
    "outer_error",
    "encoding"
  ] do
    assert(Result.is_err(fetch_ohttp_prekey(configured, bytes(marker), now, 1000)))
  end
  assert(Result.is_err(fetch_ohttp_prekey(configured, bytes("slow"), now, 10)))
  let unavailable = %{configured |
    network: %{configured.network | edge_origin: "http://127.0.0.1:24458"}
  }
  assert(Result.is_err(fetch_ohttp_prekey(unavailable, bytes("x"), now, 100)))
  Ok(true)
end

fn local_refusals() -> Bool!String do
  let configured = pins()?
  let now = U64.parse("2000")?
  for value in [-1, 0, 8001] do
    assert(Result.is_err(fetch_ohttp_prekey(configured, bytes("x"), now, value)))
  end
  for time in ["0", "1999", "5000", "18446744073709551615"] do
    assert(Result.is_err(fetch_ohttp_prekey(configured, bytes("x"), U64.parse(time)?, 1000)))
  end
  assert(Result.is_err(fetch_ohttp_prekey(%{configured | required: false, keys: []},
    bytes("x"),
    now,
    1000)))
  assert(Result.is_err(fetch_ohttp_prekey(configured, bytes(String.repeat("x", 121)), now, 1000)))
  for invalid in [
    "https://EDGE.example",
    "https://edge.example/",
    "https://edge.example?x=1",
    "https://user@edge.example",
    "http://external.example",
    "https://edge.example/path"
  ] do
    assert(Result.is_err(fetch_ohttp_prekey(%{configured |
        network: %{configured.network | edge_origin: invalid}
      },
      bytes("x"),
      now,
      1000)))
  end
  assert(Result.is_err(fetch_ohttp_prekey(%{configured |
      network: %{configured.network | development: false}
    },
    bytes("x"),
    now,
    1000)))
  Ok(true)
end

test("OHTTP prekey transport refuses invalid mode time bounds and origins before networking") do
  assert(local_refusals()?)
  Ok(nil)
end

test("OHTTP prekey transport preserves exact stamped bytes and authenticated bounded replies") do
  let _server = spawn(gateway)
  Timer.sleep(100)
  let result = successful()
  let refused = failures()
  Process.request_shutdown()
  Timer.sleep(50)
  assert(result?)
  assert(refused?)
  Ok(nil)
end
