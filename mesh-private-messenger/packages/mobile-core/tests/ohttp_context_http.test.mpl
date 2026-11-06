from Mobile.OhttpContext import capture_native_ohttp_context, fetch_guarded_ohttp_prekey
from Mobile.Account import create_account
from Mobile.Types import MobileAccountRequest
from Mobile.Codec import mobile_join, mobile_vector, current_time
from Tests.Support import database_path
from Ohttp.Keys import OhttpKeyConfig, encode_key_config
from Ohttp.BinaryHttp import decode_request, encode_response
from Ohttp.Policy import admit_prekey_claim_request, prekey_claim_response
from Ohttp.Types import BhttpFraming, default_bhttp_limits
from Transparency.Config import decode_security_config, encode_security_config
from Storage.Blobs import load_blob
from Storage.Keys import platform_key, local_context, open_local, seal_local
from Storage.AccountGuard import load_account_basis, commit_account_changes
from Storage.Records import store_updated_blobs

fn bytes(value :: String) -> Bytes do
  Bytes.from_utf8(value)
end

fn network() -> Bytes do
  bytes("2\n1\nhttps://core.example\nhttp://127.0.0.1:24467\nhttps://objects.example\nwss://stream.example/v1/mailbox/stream\n16")
end

fn security() -> Bytes do
  bytes("1\n"
    <> String.repeat("11", 32)
    <> "\n"
    <> String.repeat("22", 32)
    <> "\n"
    <> String.repeat("33", 32)
    <> "\n31e1f05a740102751261153ed490fd94a675258c3b8e30b373beaabfba281550\n8")
end

fn pair() -> X25519KeyPair!String do
  case Crypto.x25519_from_seed(Bytes.from_hex("ef0106ca50fd40bd29f8e1cfb6079fd37b4052d3bf4ce20b616aff8dd2bd8c5f")?) do
    Err(_) -> Err("fixture key")
    Ok(value)
  end
end

fn install(finish :: U64, overlap :: Bool) -> Result<(), String> do
  let first = encode_key_config(OhttpKeyConfig { key_id: 37, public_key: pair()?.public_key })?
  let second = case Crypto.x25519_from_seed(bytes(String.repeat("y", 32))) do
    Err(_) -> return Err("fixture second key")
    Ok(value) -> value
  end
  let other = encode_key_config(OhttpKeyConfig { key_id: 38, public_key: second.public_key })?
  let canonical = encode_security_config(decode_security_config(security())?)?
  let companion = bytes("1\n"
    <> Bytes.to_hex(Crypto.sha256(network()))
    <> "\n"
    <> Bytes.to_hex(Crypto.sha256(canonical))
    <> "\n1\nrequired\n"
    <> (if overlap do
      "2"
    else
      "1"
    end)
    <> "\n0 "
    <> U64.to_string(finish)
    <> " "
    <> Bytes.to_base64(first)
    <> (if overlap do
      "\n0 18446744073709551615 " <> Bytes.to_base64(other)
    else
      ""
    end))
  assert(Test.set_push_token(bytes("messenger/network/v1"), network()))
  assert(Test.set_push_token(bytes("messenger/config/v1"), security()))
  assert(Test.set_push_token(bytes("messenger/ohttp/v1"), companion))
  Ok(nil)
end

fn created() -> String!String do
  let path = database_path("ohttp-http-context")?
  create_account(MobileAccountRequest { database_path: bytes(path), username: bytes("alice") })?
  Ok(path)
end

fn profile(path :: String) -> Bytes!String do
  load_blob(path, "profile/v1")
end

fn fence(path :: String) -> Bytes!String do
  load_blob(path, "ohttp-revision/v1")
end

fn exchange(request :: Request, control :: String) -> Response!String do
  let calls = case File.read(control <> ".calls") do
    Err(_) -> 0
    Ok(value) -> Option.unwrap_or(String.to_int(value), 0)
  end
  File.write(control <> ".calls", Int.to_string(calls + 1))?
  let private_key = pair()?.private_key
  let opened = case Ohttp.decapsulate_request(private_key, 37, Request.body_bytes(request)) do
    Err(_) -> return Err("request did not use selected key37")
    Ok(value) -> value
  end
  let limits = default_bhttp_limits()
  let inner = case decode_request(opened.plaintext, %{limits | content_bytes: 120}) do
    Err(_) -> return Err("fixture request encoding invalid")
    Ok(value) -> value
  end
  let marker = Bytes.to_utf8(admit_prekey_claim_request(inner, "https://core.example", false)?)?
  let path = File.read(control <> ".path")?
  if marker == "network" do
    assert(Test.set_push_token(bytes("messenger/network/v1"), bytes("changed network")))
  else if marker == "security" do
    assert(Test.set_push_token(bytes("messenger/config/v1"), bytes("changed security")))
  else if marker == "companion" do
    assert(Test.set_push_token(bytes("messenger/ohttp/v1"), bytes("changed companion")))
  else if marker == "profile" || marker == "failure_profile" do
    store_updated_blobs(path,
      ["profile/v1"],
      [Bytes.from_hex(File.read(control <> ".replacement")?)?])?
  else if marker == "fence" || marker == "failure_fence" do
    let before = load_account_basis(path, ["ohttp-revision/v1"])?
    let key = platform_key()?
    let clear = open_local(List.get(before.records, 0), key, local_context("ohttp-revision/v1")?)?
    let next = seal_local(clear, key, local_context("ohttp-revision/v1")?)?
    commit_account_changes(path, before, ["ohttp-revision/v1"], [next], [])?
    File.write(control <> ".winner", Bytes.to_hex(next))?
  else if marker == "expiry" do
    Timer.sleep(1500)
  end
  if marker == "transport_error" || String.starts_with(marker, "failure_") do
    return Ok(HTTP.response(503, "owned outer failure"))
  end
  let response = prekey_claim_response(200, bytes(marker))?
  let plaintext = case encode_response(response, BhttpKnownLength, limits) do
    Err(_) -> return Err("fixture response encoding failed")
    Ok(value) -> value
  end
  let reply = case Ohttp.encapsulate_response(opened.response_context, plaintext) do
    Err(_) -> return Err("fixture response")
    Ok(value) -> value
  end
  Ok(HTTP.response_bytes_with_headers(200,
    reply,
    Map.new()
      |> Map.put("Content-Type", "message/ohttp-res")
      |> Map.put("Cache-Control", "no-store")))
end

actor gateway(control :: String) do
  HTTP.router()
    |> HTTP.on_post("/v1/ohttp",
      fn(request) do
        case exchange(request, control) do
          Err(error) -> HTTP.response(500, error)
          Ok(value) -> value
        end
      end)
    |> HTTP.serve(24467)
end

fn scenarios(control :: String) -> Bool!String do
  let maximum = U64.parse("18446744073709551615")?
  install(maximum, false)?
  let replacement_path = created()?
  let replacement = profile(replacement_path)?
  File.write(control <> ".replacement", Bytes.to_hex(replacement))?
  for marker in [
    "ok",
    "transport_error",
    "network",
    "security",
    "companion",
    "profile",
    "fence",
    "failure_profile",
    "failure_fence"
  ] do
    install(maximum, false)?
    let path = created()?
    let original = profile(path)?
    let context = capture_native_ohttp_context(path, original)?
    let old_fence = fence(path)?
    File.write(control <> ".path", path)?
    let result = fetch_guarded_ohttp_prekey(path, context, bytes(marker), 3000)
    if marker == "ok" do
      assert(Bytes.secure_equals(result?, bytes(marker)))
    else if marker == "transport_error" do
      assert(case result do
        Err("ohttp_prekey_transport_failed") -> true
        _ -> false
      end)
    else
      assert(case result do
        Err("account_state_changed") -> true
        _ -> false
      end)
    end
    if marker == "profile" || marker == "failure_profile" do
      assert(Bytes.secure_equals(profile(path)?, replacement))
      assert(Bytes.secure_equals(fence(path)?, old_fence))
    else if marker == "fence" || marker == "failure_fence" do
      assert(Bytes.to_hex(fence(path)?) == File.read(control <> ".winner")?)
      assert(!Bytes.secure_equals(fence(path)?, old_fence))
      assert(Bytes.secure_equals(profile(path)?, original))
    end
  end
  # No request is sent when raw config changes after fence capture.
  install(maximum, false)?
  let path = created()?
  let context = capture_native_ohttp_context(path, profile(path)?)?
  let calls = File.read(control <> ".calls")?
  assert(Test.set_push_token(bytes("messenger/ohttp/v1"), bytes("changed before HTTP")))
  assert(Result.is_err(fetch_guarded_ohttp_prekey(path, context, bytes("must not send"), 3000)))
  assert(File.read(control <> ".calls")? == calls)
  # A copied ordinary context cannot steer unconfigured origins/keys or omit
  # the fence basis. The actual server request counter must remain unchanged.
  install(maximum, false)?
  let tamper_path = created()?
  let valid = capture_native_ohttp_context(tamper_path, profile(tamper_path)?)?
  let chosen = case valid.selected_key do
    None -> return Err("fixture selected key")
    Some(value) -> value
  end
  let other_pair = case Crypto.x25519_from_seed(bytes(String.repeat("z", 32))) do
    Err(_) -> return Err("fixture other key")
    Ok(value) -> value
  end
  let other = %{chosen | config: OhttpKeyConfig { key_id: 37, public_key: other_pair.public_key }}
  let requests = File.read(control <> ".calls")?
  for altered in [
    %{valid |
      pins: %{valid.pins |
        network: %{valid.pins.network | core_origin: "https://other-core.example"}
      }
    },
    %{valid |
      pins: %{valid.pins | network: %{valid.pins.network | edge_origin: "http://127.0.0.1:24468"}}
    },
    %{valid | selected_key: Some(other)},
    %{valid | basis: %{valid.basis | labels: [], records: []}},
    %{valid | pins: %{valid.pins | identity: bytes(String.repeat("q", 32))}}
  ] do
    assert(case fetch_guarded_ohttp_prekey(tamper_path, altered, bytes("must-not-leak"), 3000) do
      Err("invalid_ohttp_context") -> true
      _ -> false
    end)
    assert(File.read(control <> ".calls")? == requests)
  end
  # Key38 remains valid, but the response was encrypted to the used key37 context.
  let finish = U64.add(current_time()?, U64.parse("1000")?)?
  install(finish, true)?
  let expiry_path = created()?
  let expired = capture_native_ohttp_context(expiry_path, profile(expiry_path)?)?
  File.write(control <> ".path", expiry_path)?
  assert(case fetch_guarded_ohttp_prekey(expiry_path, expired, bytes("expiry"), 3000) do
    Err("ohttp_key_expired") -> true
    _ -> false
  end)
  Ok(true)
end

fn http_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let control = database_path("ohttp-http-control")?
  let _server = spawn(gateway, control)
  Timer.sleep(100)
  let result = scenarios(control)
  Process.request_shutdown()
  Timer.sleep(50)
  result
end

test("real OHTTP completion preserves account/config/fence winners on both success and HTTP failure") do
  case http_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> do
      assert(value)
      println("m3-context-http:passed")
    end
  end
end
