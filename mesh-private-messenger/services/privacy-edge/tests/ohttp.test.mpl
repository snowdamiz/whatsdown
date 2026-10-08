from Api.Binary import relay_ohttp

fn token() -> String do
  "0123456789abcdef0123456789abcdef"
end

fn header(request :: Request, name :: String) -> Option<String> do
  case Request.header(request, name) do
    None -> Request.header(request, String.to_lower(name))
    Some(value)
  end
end

# A gateway that answers with its own opaque bytes, and only when the edge
# sent the body with its bearer and the OHTTP media type, and no client
# address or cookie.
# Its answer is a fixed "encapsulated response" the edge must pass back as is.

fn fake_gateway(request :: Request) -> Response do
  if header(request, "Authorization") != Some("Bearer " <> token())
    || header(request, "Content-Type") != Some("message/ohttp-req")
    || header(request, "X-Forwarded-For") != None
    || header(request, "Cookie") != None do
    HTTP.response(401, "")
  else if Bytes.get(Request.body_bytes(request), 0) != Ok(1) do
    HTTP.response(422, "")
  else
    case Bytes.concat(Crypto.sha256(Request.body_bytes(request)), Bytes.from_utf8("answer")) do
      Err(_) -> HTTP.response(500, "")
      Ok(body) -> HTTP.response_bytes(200, body)
    end
  end
end

actor fake_core() do
  HTTP.router()
    |> HTTP.on_post("/internal/v1/ohttp", fake_gateway)
    |> HTTP.serve(18995)
end

fn bytes(result :: Result<Bytes, String>) -> Bytes!String do
  case result do
    Err(_) -> Err("bytes failed")
    Ok(value)
  end
end

fn relayed() -> Bool!String do
  # An encapsulated request is ciphertext to the edge: it forwards the exact
  # bytes and hands back the exact answer, holding no key to open either.
  let random = case Crypto.random_bytes(300) do
    Err(_) -> Err("random failed")
    Ok(value)
  end?
  let first = case Bytes.from_list([1]) do
    Err(_) -> Err("byte failed")
    Ok(value)
  end?
  let encapsulated = bytes(Bytes.concat(first, random))?
  let result = relay_ohttp(encapsulated, "http://127.0.0.1:18995", token())?
  assert(result.status == 200)
  let expected = bytes(Bytes.concat(Crypto.sha256(encapsulated), Bytes.from_utf8("answer")))?
  assert(Bytes.secure_equals(result.body, expected))
  # A request the gateway can't open comes back as its bare status; one too
  # short or too long to be an encapsulated request doesn't leave the edge.
  let other_key = bytes(Bytes.concat(Crypto.sha256(random), random))?
  assert(relay_ohttp(other_key, "http://127.0.0.1:18995", token())?.status == 422)
  assert(relay_ohttp(Bytes.from_utf8("short"), "http://127.0.0.1:18995", token())?.status == 400)
  let oversized = case Bytes.repeat(1, 65592) do
    Err(_) -> Err("repeat failed")
    Ok(value)
  end?
  assert(relay_ohttp(oversized, "http://127.0.0.1:18995", token())?.status == 400)
  assert(relay_ohttp(encapsulated, "http://127.0.0.1:1", token())?.status == 502)
  Ok(true)
end

test("the edge relays encapsulated bytes it cannot read, and returns the answer unchanged") do
  let _server = spawn(fake_core)
  Timer.sleep(100)
  case relayed() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
  Process.request_shutdown()
  Timer.sleep(50)
end
