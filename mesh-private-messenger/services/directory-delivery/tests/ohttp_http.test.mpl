from Api.Router import build_router
from Api.OhttpHttp import validate_ohttp_gateway_config
from Runtime.Registry import start_registry
from Ohttp.BinaryHttp import encode_request, decode_response
from Ohttp.LookupPolicy import OhttpLookupOperation, lookup_request
from Ohttp.Types import BhttpFraming, default_bhttp_limits

actor gateway_http() do
  HTTP.serve(build_router(), Env.get_int("MORSE_OHTTP_HTTP_TEST_PORT", 24694))
end

fn exchange_http(body :: Bytes, token :: String, media :: String) -> HttpResponse!String do
  let relay = Env.get("MORSE_OHTTP_HTTP_RELAY_URL", "")
  Http.build(:post,
    if relay == "" do
      "http://127.0.0.1:"
        <> Int.to_string(Env.get_int("MORSE_OHTTP_HTTP_TEST_PORT", 24694))
        <> "/internal/v1/ohttp"
    else
      relay <> "/v1/ohttp"
    end)
    |> Http.header("Content-Type", media)
    |> Http.header("Authorization", token)
    |> Http.header("Cookie", "caller-cookie=must-not-cross-relay")
    |> Http.header("X-Forwarded-For", "192.0.2.18")
    |> Http.header("X-Account-Id", "must-not-cross-relay")
    |> Http.header("Traceparent", "must-not-cross-relay")
    |> Http.body_bytes(body)
    |> Http.timeout(5000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(1048576)
    |> Http.send()
end

fn proof() -> Result<(), String> do
  let expectation = Env.get("MORSE_OHTTP_HTTP_EXPECT", "on")
  let validated = validate_ohttp_gateway_config()
  assert(Result.is_ok(validated) == (expectation == "on" || expectation == "off"))
  let url = Env.get("MESSENGER_OHTTP_TEST_DATABASE_URL", "")
  if url == "" do
    return Err("owned OHTTP HTTP database required")
  end
  let pool = Pool.open(url, 1, 2, 5000)?
  start_registry(pool)
  let _server = spawn(gateway_http)
  Timer.sleep(100)
  let token = "Bearer " <> Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", "")
  let dummy = Bytes.from_utf8(String.repeat("x", 55))
  if expectation != "on" do
    # A configured key id reaches the private-key checks as well as parsing.
    let known = Bytes.concat(Bytes.from_hex(if expectation == "invalid-second" do
        "17"
      else
        "11"
      end)?,
      Bytes.from_utf8(String.repeat("x", 54)))?
    let response = exchange_http(known, token, "message/ohttp-req")?
    assert(response.status == if expectation == "off" do
        404
      else
        503
      end)
    assert(Bytes.length(response.body_bytes) == 0)
    Pool.close(pool)
    return Ok(nil)
  end
  let refused = exchange_http(dummy,
    "Bearer wrong-credential-which-is-long-enough",
    "message/ohttp-req")?
  # The public relay uses its own credential, so this gets as far as the
  # gateway's unknown-key rejection even with an invalid caller credential.
  assert(refused.status == if Env.get("MORSE_OHTTP_HTTP_RELAY_URL", "") == "" do
      401
    else
      400
    end
    && Bytes.length(refused.body_bytes) == 0)
  let refused = exchange_http(dummy, token, "application/octet-stream")?
  assert(refused.status == 415 && Bytes.length(refused.body_bytes) == 0)
  # The public Mesh HTTP server refuses this size before dispatch. The Worker
  # adapter separately returns 413; this native boundary closes the connection.
  assert(Result.is_err(exchange_http(Bytes.from_utf8(String.repeat("x", 1048577)),
    token,
    "message/ohttp-req")))
  let refused = exchange_http(dummy, token, "message/ohttp-req")?
  assert(refused.status == 400 && Bytes.length(refused.body_bytes) == 0)
  for key_id in if Env.get("MORSE_OHTTP_HTTP_ROTATION", "off") == "on" do
    [17, 23]
  else
    [17]
  end do
    let key = case Crypto.x25519_from_seed(Bytes.from_hex(if key_id == 17 do
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    else
      "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    end)?) do
      Err(_) -> return Err("fixture key")
      Ok(value) -> value
    end
    let query = lookup_request("https://core.example",
      false,
      OhttpDirectoryLookup(2),
      Bytes.empty())?
    let inner = case encode_request(query, BhttpKnownLength, default_bhttp_limits()) do
      Err(_) -> return Err("fixture request encoding")
      Ok(value) -> value
    end
    let outgoing = case Ohttp.encapsulate_request(key_id, key.public_key, inner) do
      Err(_) -> return Err("fixture encryption")
      Ok(value) -> value
    end
    if Env.get("MORSE_OHTTP_HTTP_ROTATION", "off") == "on" do
      # Both ids are configured. Relabeling a ciphertext must not retry the key
      # under which it was actually encrypted.
      let suffix = case Bytes.slice(outgoing.wire, 1, Bytes.length(outgoing.wire) - 1) do
        Err(_) -> return Err("fixture ciphertext slice")
        Ok(value) -> value
      end
      let changed = Bytes.concat(Bytes.from_hex(if key_id == 17 do
          "17"
        else
          "11"
        end)?,
        suffix)?
      let refused = exchange_http(changed, token, "message/ohttp-req")?
      assert(refused.status == 400 && Bytes.length(refused.body_bytes) == 0)
    end
    let response = exchange_http(outgoing.wire, token, "message/ohttp-req")?
    assert(response.status == 200)
    assert(Map.get(response.headers, "content-type") == "message/ohttp-res")
    assert(Map.get(response.headers, "cache-control") == "no-store")
    let plaintext = case Ohttp.decapsulate_response(outgoing.response_context,
      response.body_bytes) do
      Err(_) -> return Err("fixture response authentication")
      Ok(value) -> value
    end
    let inner_response = case decode_response(plaintext, default_bhttp_limits()) do
      Err(_) -> return Err("fixture response decoding")
      Ok(value) -> value
    end
    assert(inner_response.status == 404)
    assert(Bytes.secure_equals(inner_response.content,
      Bytes.from_utf8("transparency_v2_not_active")))
  end
  Pool.close(pool)
  Ok(nil)
end

test("configured gateway authenticates the actual HTTP route and encrypts fixed target results") do
  let result = proof()
  Process.request_shutdown()
  Timer.sleep(50)
  case result do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> println("m3-ohttp-http:passed")
  end
end
