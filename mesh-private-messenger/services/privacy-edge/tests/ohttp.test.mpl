from Api.Ohttp import prepare_ohttp, ohttp_relay_target, forward_ohttp

fn body(size :: Int, value :: String) -> Bytes do
  Bytes.from_utf8(String.repeat(value, size))
end

test("OHTTP outer admission preserves opaque bytes with strict media and wire bounds") do
  let input = body(55, "x")
  let accepted = prepare_ohttp(input, "message/ohttp-req", "")
  assert(accepted.status == 200)
  assert(Bytes.secure_equals(accepted.body, input))
  assert(prepare_ohttp(input, "message/ohttp-req", "identity").status == 200)
  assert(prepare_ohttp(input, "application/octet-stream", "").status == 415)
  assert(prepare_ohttp(input, "message/ohttp-req; charset=utf-8", "").status == 415)
  assert(prepare_ohttp(input, "message/ohttp-req", "gzip").status == 415)
  assert(prepare_ohttp(Bytes.empty(), "message/ohttp-req", "").status == 400)
  assert(prepare_ohttp(body(54, "x"), "message/ohttp-req", "").status == 400)
  assert(prepare_ohttp(body(1048576, "x"), "message/ohttp-req", "").status == 200)
  let oversized = prepare_ohttp(body(1048577, "x"), "message/ohttp-req", "")
  assert(oversized.status == 413)
  assert(Bytes.length(oversized.body) == 0)
end

fn targets() -> Bool!String do
  assert(ohttp_relay_target("http://delivery.internal",
    false)? == "http://delivery.internal/internal/v1/ohttp")
  assert(ohttp_relay_target("https://gateway.test",
    false)? == "https://gateway.test/internal/v1/ohttp")
  assert(ohttp_relay_target("http://127.0.0.1:24453",
    true)? == "http://127.0.0.1:24453/internal/v1/ohttp")
  assert(ohttp_relay_target("http://[::1]:24453", true)? == "http://[::1]:24453/internal/v1/ohttp")
  assert(Result.is_err(ohttp_relay_target("http://127.0.0.1:24453", false)))
  assert(Result.is_err(ohttp_relay_target("http://attacker.test", true)))
  assert(Result.is_err(ohttp_relay_target("http://delivery.internal:80", false)))
  assert(Result.is_err(ohttp_relay_target("https://gateway.test/", false)))
  assert(Result.is_err(ohttp_relay_target("https://gateway.test/other", false)))
  assert(Result.is_err(ohttp_relay_target("https://gateway.test?target=evil", false)))
  assert(Result.is_err(ohttp_relay_target("https://gateway.test#trace", false)))
  assert(Result.is_err(ohttp_relay_target("https://user:secret@gateway.test", false)))
  Ok(true)
end

test("OHTTP relay selects only a fixed path under canonical configured origins") do
  let result = targets()
  case result do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn reply(status :: Int, content :: Bytes, media :: String, cache :: String) -> Response do
  HTTP.response_bytes_with_headers(status,
    content,
    Map.new()
      |> Map.put("Content-Type", media)
      |> Map.put("Cache-Control", cache)
      |> Map.put("Set-Cookie", "private-diagnostic")
      |> Map.put("X-Request-ID", "private-diagnostic")
      |> Map.put("Location", "http://127.0.0.1:24453/redirect-target"))
end

fn upstream(request :: Request) -> Response do
  if Request.header(request, "authorization") != Some("Bearer 0123456789abcdef0123456789abcdef")
    || Request.header(request, "content-type") != Some("message/ohttp-req")
    || Request.header(request, "accept") != Some("message/ohttp-res")
    || Request.header(request, "cache-control") != Some("no-store")
    || Request.header(request, "cookie") != None
    || Request.header(request, "x-forwarded-for") != None
    || Request.header(request, "x-account-id") != None
    || Request.header(request, "traceparent") != None do
    return HTTP.response(401, "private diagnostic")
  end
  let input = Request.body_bytes(request)
  if Bytes.secure_equals(input, body(55, "r")) do
    return reply(307, body(48, "z"), "message/ohttp-res", "no-store")
  end
  if Bytes.secure_equals(input, body(55, "b")) do
    return reply(200, body(48, "z"), "text/plain", "no-store")
  end
  if Bytes.secure_equals(input, body(55, "e")) do
    return reply(429, Bytes.from_utf8("private diagnostic"), "text/plain", "no-store")
  end
  if Bytes.secure_equals(input, body(55, "o")) do
    return reply(200, body(1048577, "z"), "message/ohttp-res", "no-store")
  end
  if Bytes.secure_equals(input, body(55, "c")) do
    return reply(200, body(48, "z"), "message/ohttp-res", "public")
  end
  if Bytes.secure_equals(input, body(55, "s")) do
    return reply(200, body(47, "z"), "message/ohttp-res", "no-store")
  end
  if Bytes.secure_equals(input, body(55, "n")) do
    return HTTP.response_bytes(200, body(48, "z"))
  end
  if Bytes.length(input) == 1048576 do
    return reply(200, input, "message/ohttp-res", "no-store")
  end
  reply(200, body(48, "z"), "message/ohttp-res", "no-store")
end

fn redirected(_request :: Request) -> Response do
  reply(200, body(48, "z"), "message/ohttp-res", "no-store")
end

actor gateway() do
  HTTP.router()
    |> HTTP.on_post("/internal/v1/ohttp", upstream)
    |> HTTP.on_post("/redirect-target", redirected)
    |> HTTP.serve(24453)
end

fn local_exchange() -> Bool!String do
  let origin = "http://127.0.0.1:24453"
  let token = "0123456789abcdef0123456789abcdef"
  let value = forward_ohttp(body(55, "a"), "message/ohttp-req", "", origin, token, true)?
  assert(value.status == 200)
  assert(Bytes.secure_equals(value.body, body(48, "z")))
  let large = forward_ohttp(body(1048576, "x"), "message/ohttp-req", "", origin, token, true)?
  assert(large.status == 200)
  assert(Bytes.secure_equals(large.body, body(1048576, "x")))
  let redirected_result = forward_ohttp(body(55, "r"),
    "message/ohttp-req",
    "",
    origin,
    token,
    true)?
  assert(redirected_result.status == 502)
  assert(Bytes.length(redirected_result.body) == 0)
  assert(forward_ohttp(body(55, "b"), "message/ohttp-req", "", origin, token, true)?.status == 502)
  assert(forward_ohttp(body(55, "o"), "message/ohttp-req", "", origin, token, true)?.status == 502)
  assert(forward_ohttp(body(55, "c"), "message/ohttp-req", "", origin, token, true)?.status == 502)
  assert(forward_ohttp(body(55, "s"), "message/ohttp-req", "", origin, token, true)?.status == 502)
  assert(forward_ohttp(body(55, "n"), "message/ohttp-req", "", origin, token, true)?.status == 502)
  let failed = forward_ohttp(body(55, "e"), "message/ohttp-req", "", origin, token, true)?
  assert(failed.status == 429)
  assert(Bytes.length(failed.body) == 0)
  assert(forward_ohttp(body(54, "a"), "message/ohttp-req", "", origin, token, true)?.status == 400)
  assert(forward_ohttp(body(55, "a"),
    "message/ohttp-req",
    "",
    origin,
    "short",
    true)?.status == 503)
  assert(forward_ohttp(body(55, "a"), "message/ohttp-req", "", origin, token, false)?.status == 503)
  Ok(true)
end

test("OHTTP relay uses real bounded HTTP with sanitized headers and no redirect or plaintext error") do
  let _server = spawn(gateway)
  Timer.sleep(100)
  let result = local_exchange()
  Process.request_shutdown()
  Timer.sleep(50)
  case result do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
