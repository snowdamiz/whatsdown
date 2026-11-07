from Mobile.PushNetwork import (
  native_push_intent,
  native_push_complete_with_endpoint,
  native_push_send
)
from MobileCore import create_account_export, erase_account_export
from Mobile.Profile import load_profile
from Mobile.PushState import load_push_state
from Mobile.Codec import mobile_byte
from Storage.Keys import platform_key
from Storage.Blobs import load_blob
from Transport.Packet import decode_client_profile
from Push.Binding import (
  decode_push_bind,
  decode_push_unbind,
  push_bind_signing_bytes,
  push_unbind_signing_bytes
)
from Tests.PushNetworkSupport import fields, intent, complete, config
from Tests.Support import database_path

fn network(port :: Int) -> Bool do
  let origin = "http://127.0.0.1:" <> Int.to_string(port)
  Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
    Bytes.from_utf8("2\n1\n"
      <> origin
      <> "\n"
      <> origin
      <> "\n"
      <> origin
      <> "\nws://127.0.0.1:"
      <> Int.to_string(port)
      <> "/v1/mailbox/stream\n1"))
end

fn replace_account(path :: String) -> Result<(), String> do
  erase_account_export(Bytes.from_utf8(path))?
  create_account_export(fields([Bytes.from_utf8(path), Bytes.from_utf8("replacement")])?)?
  Ok(nil)
end

fn provider_reply(path :: String, mode :: Int) -> Response!String do
  if mode == 8 do
    native_push_intent(intent(path, 2)?)?
    nil
  else if mode == 9 do
    replace_account(path)?
  end
  Ok(HTTP.response(200, "{\"data\":{\"expoPushToken\":\"ExpoPushToken[native-boundary]\"}}"))
end

fn received(request :: Request, path :: String, mode :: Int, bind :: Bool) -> Response!String do
  if Request.header(request, "content-type") != Some("application/octet-stream")
    || Request.header(request, "cache-control") != Some("no-store")
    || Request.header(request, "authorization") != None
    || Request.header(request, "cookie") != None do
    return Ok(HTTP.response(400, "invalid headers"))
  end
  let body = Request.body_bytes(request)
  let profile = decode_client_profile(load_profile(path)?)?
  let signed = if bind do
    push_bind_signing_bytes(decode_push_bind(body)?)?
  else
    push_unbind_signing_bytes(decode_push_unbind(body)?)?
  end
  let signature = if bind do
    decode_push_bind(body)?.signature
  else
    decode_push_unbind(body)?.signature
  end
  let mailbox = if bind do
    decode_push_bind(body)?.mailbox_token_hash
  else
    decode_push_unbind(body)?.mailbox_token_hash
  end
  if !Bytes.secure_equals(mailbox, Crypto.sha256(profile.entry.mailbox_token)) do
    return Err("wrong push mailbox")
  end
  case Crypto.verify(SigningPublicKey { bytes: profile.credential.signing_public_key },
    signed,
    Signature { bytes: signature }) do
    Ok(true) -> nil
    _ -> return Err("invalid push signature")
  end
  let label = path
    <> if bind do
      ".bind"
    else
      ".unbind"
    end
  let previous = case File.read(label) do
    Err(_) -> ""
    Ok(value) -> value
  end
  let digest = Bytes.to_hex(Crypto.sha256(body))
  if previous != "" && previous != digest do
    return Err("push retry changed its wire")
  end
  File.write(label, digest)?
  if mode == 1 && previous == "" do
    return Ok(HTTP.response(503, ""))
  end
  if mode == 2 do
    return Ok(HTTP.response_with_headers(307, "", Map.put(Map.new(), "Location", "/untrusted")))
  end
  if mode == 3 do
    return Ok(HTTP.response(201, String.repeat("x", 1025)))
  end
  if mode == 4 do
    return Ok(HTTP.response(201, "unexpected body"))
  end
  if mode == 5 do
    native_push_intent(intent(path, 2)?)?
  end
  if mode == 6 do
    replace_account(path)?
  end
  if mode == 7 && !network(20599) do
    return Err("test config replacement failed")
  end
  if mode == 10 && !bind && previous == "" do
    return Ok(HTTP.response(403, ""))
  end
  if mode == 11 do
    return Ok(HTTP.response(200, ""))
  end
  if mode == 12 do
    Timer.sleep(9000)
  end
  Ok(HTTP.response(if bind do
      201
    else
      200
    end,
    ""))
end

fn http_result(result :: Response!String) -> Response do
  case result do
    Err(error) -> HTTP.response(500, error)
    Ok(value) -> value
  end
end

actor peer(port :: Int, path :: String, mode :: Int) do
  HTTP.router()
    |> HTTP.on_post("/provider", fn(_) -> http_result(provider_reply(path, mode)) end)
    |> HTTP.on_put("/v1/push/bind", fn(input) -> http_result(received(input, path, mode, true)) end)
    |> HTTP.on_post("/v1/push/unbind",
      fn(input) -> http_result(received(input, path, mode, false)) end)
    |> HTTP.on_put("/untrusted",
      fn(_) do
        File.write(path <> ".redirected", "bad")
        HTTP.response(201, "")
      end)
    |> HTTP.serve(port)
end

fn run_case(mode :: Int) -> Result<(), String> do
  let port = 20572 + mode
  let path = database_path("native_push_network")?
  config(port)?
  let original = create_account_export(fields([Bytes.from_utf8(path), Bytes.from_utf8("alice")])?)?
  let _server = spawn(peer, port, path, mode)
  Timer.sleep(100)
  let endpoint = "http://127.0.0.1:" <> Int.to_string(port) <> "/provider"
  let permission = native_push_intent(intent(path, 1)?)?
  let prime = native_push_complete_with_endpoint(complete(path, permission, 0)?, endpoint)?
  if mode == 8 || mode == 9 do
    assert(Result.is_err(native_push_complete_with_endpoint(complete(path, prime, 0)?, endpoint)))
    assert(!File.exists(path <> ".bind"))
    if mode == 8 do
      assert(Bytes.get(native_push_intent(intent(path, 0)?)?, 4)? == 5)
    else
      assert(!Bytes.secure_equals(load_profile(path)?, original))
      assert(Result.is_err(load_blob(path, "push-binding/v1")))
    end
  else
    let bind = native_push_complete_with_endpoint(complete(path, prime, 0)?, endpoint)?
    assert(Bytes.length(bind) == 50 && Bytes.get(bind, 0)? == 2 && Bytes.get(bind, 4)? == 3)
    let before = load_blob(path, "push-binding/v1")?
    let bad = Bytes.concat(Bytes.slice(bind, 0, 49)?,
      mobile_byte(if Bytes.get(bind, 49)? == 0 do
        1
      else
        0
      end)?)?
    assert(Result.is_err(native_push_send(fields([Bytes.from_utf8(path), bad])?)))
    assert(!File.exists(path <> ".bind"))
    let result = native_push_send(fields([Bytes.from_utf8(path), bind])?)
    assert(File.exists(path <> ".bind"))
    if mode == 0 || mode == 10 do
      let enabled = result?
      assert(Bytes.length(enabled) == 19 && Bytes.get(enabled, 18)? == 1)
      assert(Result.is_err(native_push_send(fields([Bytes.from_utf8(path), bind])?)))
      let clear = native_push_intent(intent(path, 2)?)?
      let unbind = native_push_complete_with_endpoint(complete(path, clear, 1)?, endpoint)?
      assert(Bytes.get(unbind, 4)? == 4)
      if mode == 10 do
        assert(Result.is_err(native_push_send(fields([Bytes.from_utf8(path), unbind])?)))
        assert(Bytes.secure_equals(native_push_intent(intent(path, 0)?)?, unbind))
      end
      let final_clear = native_push_send(fields([Bytes.from_utf8(path), unbind])?)?
      assert(Bytes.get(final_clear, 4)? == 5)
      let disabled = native_push_complete_with_endpoint(complete(path, final_clear, 0)?, endpoint)?
      assert(Bytes.get(disabled, 18)? == 0)
    else
      assert(Result.is_err(result))
      if mode == 5 do
        assert(Bytes.get(native_push_intent(intent(path, 0)?)?, 4)? == 5)
      else if mode == 6 do
        assert(!Bytes.secure_equals(load_profile(path)?, original))
        assert(Result.is_err(load_blob(path, "push-binding/v1")))
      else
        assert(Bytes.secure_equals(load_blob(path, "push-binding/v1")?, before))
        if mode == 1 do
          # Reopening the operation reloads the exact durable signed request.
          let recovered = native_push_intent(intent(path, 0)?)?
          assert(Bytes.secure_equals(recovered, bind))
          assert(Bytes.get(native_push_send(fields([Bytes.from_utf8(path), recovered])?)?,
            18)? == 1)
        end
        if mode == 12 do
          Timer.sleep(1200)
          assert(Bytes.secure_equals(load_blob(path, "push-binding/v1")?, before))
        end
      end
    end
    assert(!File.exists(path <> ".redirected"))
  end
  erase_account_export(Bytes.from_utf8(path))?
  for suffix in [".bind", ".unbind", ".redirected"] do
    if File.exists(path <> suffix) do
      File.delete(path <> suffix)?
    end
  end
  Ok(nil)
end

fn proof() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  for mode in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12] do
    println("push mode " <> Int.to_string(mode))
    run_case(mode)?
  end
  Ok(nil)
end

test("native push owns bounded bind and unbind HTTP, exact recovery, and stale response fences") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
