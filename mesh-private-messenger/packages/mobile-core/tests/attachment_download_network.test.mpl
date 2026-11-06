from Mobile.Attachments import prepare_attachment, seal_attachment_chunk, decode_reference
from Mobile.CreditAttachmentNative import native_attachment_fetch_chunk
from Mobile.CreditState import pack_credit_parts
from Mobile.Types import MobileAttachmentPrepareRequest, MobileAttachmentChunkRequest
from Mobile.Codec import mobile_write_u32
from MobileCore import create_account_export, erase_account_export
from Tests.GroupLifecycleWire import group_vectors, output_list
from Tests.Support import database_path, repeated

fn configured(port :: Int, development :: Bool) -> Bool do
  Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
    Bytes.from_utf8("1\n"
      <> (if development do
        "1"
      else
        "0"
      end)
      <> "\nhttp://127.0.0.1:18086\nhttp://127.0.0.1:18087\nhttp://127.0.0.1:"
      <> Int.to_string(port)
      <> "\nws://127.0.0.1:18090/v1/mailbox/stream"))
end

fn fixture_response(value :: Bytes!String) -> Response do
  case value do
    Err(_) -> HTTP.response(500, "fixture bytes")
    Ok(wire) -> HTTP.response_bytes(200, wire)
  end
end

fn matches_fixture(value :: Bytes!String) -> Plaintext<Bool> do
  case value do
    Ok(bytes) -> Bytes.secure_equals(bytes, Bytes.from_utf8("x"))
    Err(_) -> false
  end
end

fn reply(input :: Request,
  path :: String,
  capability :: String,
  wire :: Bytes,
  mode :: Int) -> Response do
  if Request.header(input, "x-object-capability") != Some(capability)
    || Request.header(input, "content-type") != Some("application/octet-stream")
    || Request.header(input, "cache-control") != Some("no-store")
    || Request.header(input, "authorization") != None
    || Request.header(input, "cookie") != None
    || Bytes.length(Request.body_bytes(input)) != 0 do
    return HTTP.response(400, "unexpected request authority")
  end
  case File.write(path <> ".requested", "1") do
    Err(_) -> return HTTP.response(500, "fixture marker")
    Ok(_) -> nil
  end
  if mode == 1 do
    return fixture_response(Bytes.concat(wire, Bytes.from_utf8("x")))
  end
  if mode == 2 do
    return fixture_response(repeated(1, 65577))
  end
  if mode == 3 do
    return HTTP.response_with_headers(307, "", Map.put(Map.new(), "Location", "/untrusted"))
  end
  if mode == 4 || mode == 6 do
    case erase_account_export(Bytes.from_utf8(path)) do
      Err(_) -> return HTTP.response(500, "fixture erase")
      Ok(_) -> nil
    end
    if mode == 6 do
      let input = case group_vectors([Bytes.from_utf8(path), Bytes.from_utf8("replacement")]) do
        Err(_) -> return HTTP.response(500, "fixture profile")
        Ok(value) -> value
      end
      case create_account_export(input) do
        Err(_) -> return HTTP.response(500, "fixture replacement")
        Ok(_) -> nil
      end
    end
  end
  if mode == 5 do
    configured(22199, true)
  end
  HTTP.response_bytes(200, wire)
end

actor peer(port :: Int,
  route :: String,
  path :: String,
  capability :: String,
  wire :: Bytes,
  mode :: Int) do
  HTTP.router()
    |> HTTP.on_get(route, fn(input) -> reply(input, path, capability, wire, mode) end)
    |> HTTP.on_get("/untrusted", fn(_) -> HTTP.response(500, "redirect followed") end)
    |> HTTP.serve(port)
end

fn run_case(mode :: Int) -> Unit!String do
  let path = database_path("attachment_download_network")?
  create_account_export(group_vectors([Bytes.from_utf8(path), Bytes.from_utf8("downloads")])?)?
  let material = output_list(prepare_attachment(MobileAttachmentPrepareRequest {
    database_path: path,
    filename: Bytes.from_utf8("file.bin"),
    mime_type: Bytes.from_utf8("application/octet-stream"),
    plaintext_size: 1,
    difficulty: 1
  })?)?
  let reference = List.head(material)
  let decoded = decode_reference(reference)?
  let wire = seal_attachment_chunk(MobileAttachmentChunkRequest {
    database_path: path,
    reference: reference,
    index: 0,
    payload: Bytes.from_utf8("x")
  })?
  let port = 22160 + mode
  let _server = spawn(peer,
    port,
    "/v1/objects/#{Bytes.to_hex(decoded.object_id)}/parts/1",
    path,
    Bytes.to_hex(decoded.download_capability),
    wire,
    mode)
  Timer.sleep(40)
  assert(configured(port, mode != 7))
  let request = pack_credit_parts([
    Bytes.from_utf8(path),
    reference,
    mobile_write_u32(if mode == 8 do
      1
    else
      0
    end)?
  ])?
  let result = native_attachment_fetch_chunk(request)
  if mode == 0 do
    assert(declassify(matches_fixture(result),
      "test-only comparison of the authenticated native download with the known one-byte synthetic fixture"))
  else
    assert(declassify(Result.is_err(result),
      "test-only rejection of synthetic native download fixture; no response bytes or error payload disclosed"))
  end
  if mode == 7 || mode == 8 do
    assert(!File.exists(path <> ".requested"))
  else
    assert(File.exists(path <> ".requested"))
  end
  erase_account_export(Bytes.from_utf8(path))?
  if File.exists(path <> ".requested") do
    File.delete(path <> ".requested")?
  end
  Ok(nil)
end

fn proof() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  for mode in 0..9 do
    run_case(mode)?
  end
  Ok(nil)
end

test("native legacy download derives object authority and rejects unsafe transport or changed profile") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
