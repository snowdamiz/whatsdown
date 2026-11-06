from Mobile.AttachmentRecipients import attachment_authorization
from Mobile.Profile import load_profile
from Transport.Packet import decode_client_profile
from Tests.GroupConsistencySupport import account_fixture, signed_transparency_view
from Tests.GroupLifecycleSupport import install_signed_transparency
from Transparency.Merkle import leaf_hash
from Mobile.AttachmentUpload import native_attachment_upload, native_attachment_discard
from Mobile.Attachments import open_attachment_chunk
from Mobile.CreditState import pack_credit_parts, unpack_credit_parts
from Mobile.Types import MobileAttachmentChunkRequest
from Mobile.Codec import current_time
from MobileCore import create_account_export, erase_account_export
from Objects.Grant import (
  decode_grant,
  verify_grant,
  decode_complete,
  decode_delete,
  encode_grant_response,
  ObjectGrantResponse
)
from Tests.GroupLifecycleWire import group_vectors, output_list
from Tests.Support import database_path, repeated

fn exact(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "synthetic public attachment upload fixture equality only; no application disclosure")
end

fn opened_equals(result :: Result<Plaintext<Bytes>, String>,
  expected :: Bytes) -> Plaintext<Bool> do
  case result do
    Ok(value) -> Bytes.secure_equals(value, expected)
    Err(_) -> false
  end
end

fn configured(port :: Int) -> Bool do
  Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
    Bytes.from_utf8("2\n1\nhttp://127.0.0.1:18086\nhttp://127.0.0.1:18087\nhttp://127.0.0.1:"
      <> Int.to_string(port)
      <> "\nws://127.0.0.1:18090/v1/mailbox/stream\n1"))
end

fn bytes_at(path :: String) -> Bytes!String do
  Bytes.from_base64(File.read(path)?)
end

fn mark(path :: String, value :: Bytes) -> Unit!String do
  File.write(path, Bytes.to_base64(value))
end

fn route(input :: Request, path :: String, mode :: Int, step :: Int) -> Response!String do
  if Request.header(input, "content-type") != Some("application/octet-stream")
    || Request.header(input, "cache-control") != Some("no-store")
    || Request.header(input, "authorization") != None
    || Request.header(input, "cookie") != None do
    return Ok(HTTP.response(400, "unexpected headers"))
  end
  let body = Request.body_bytes(input)
  if step >= 1 && step <= 3 do
    let index = case Request.param(input, "index") do
      None -> return Err("missing index")
      Some(value) -> value
    end
    mark(path <> ".part" <> index, body)?
  end
  mark(path <> ".step#{step}", body)?
  if step == 0 do
    assert(Request.header(input, "x-object-capability") == None)
    assert(verify_grant(body, current_time()?, U64.parse("300000")?, U64.parse("604800000")?, 1)?)
    if mode == 1 do
      return Ok(HTTP.response_with_headers(307, "", Map.put(Map.new(), "Location", "/untrusted")))
    end
    if mode == 2 do
      return Ok(HTTP.response_bytes(201, repeated(1, 37)?))
    end
    let grant = decode_grant(body)?
    let object_id = if mode == 3 do
      repeated(9, 32)?
    else
      grant.object_id
    end
    return Ok(HTTP.response_bytes(201,
      encode_grant_response(ObjectGrantResponse { object_id: object_id })?))
  end
  let grant = decode_grant(bytes_at(path <> ".step0")?)?
  if step == 4 || step == 5 do
    assert(Request.header(input, "x-object-capability") == None)
    let control = if step == 4 do
      decode_complete(body)?
    else
      decode_delete(body)?
    end
    assert(Bytes.secure_equals(control.object_id, grant.object_id))
    assert(Bytes.secure_equals(control.capability, grant.upload_capability))
    if step == 4 && mode == 6 do
      return Ok(HTTP.response(503, ""))
    end
    if step == 5 && mode == 10 do
      return Ok(HTTP.response(503, ""))
    end
    return Ok(HTTP.response(if step == 4 do
        200
      else
        204
      end,
      ""))
  end
  assert(Request.header(input,
    "x-object-capability") == Some(Bytes.to_hex(grant.upload_capability)))
  assert(Bytes.length(body) >= 41 && Bytes.length(body) <= 65576)
  if step == 2 && mode == 4 do
    return Ok(HTTP.response(413, ""))
  end
  if step == 2 && mode == 5 do
    return Ok(HTTP.response(200, "unexpected"))
  end
  if step == 2 && mode == 7 do
    erase_account_export(Bytes.from_utf8(path))?
  end
  if step == 2 && mode == 8 do
    configured(22399)
  end
  Ok(HTTP.response(200, ""))
end

fn reply(input :: Request, path :: String, mode :: Int, step :: Int) -> Response do
  case route(input, path, mode, step) do
    Err(error) -> HTTP.response(500, error)
    Ok(value) -> value
  end
end

actor peer(port :: Int, path :: String, mode :: Int) do
  HTTP.router()
    |> HTTP.on_post("/v1/attachments/grant", fn(input) -> reply(input, path, mode, 0) end)
    |> HTTP.on_put("/v1/objects/:id/parts/:index",
      fn(input) do
        let step = if Request.param(input, "index") == Some("0") do
          1
        else if Request.param(input, "index") == Some("1") do
          2
        else
          3
        end
        reply(input, path, mode, step)
      end)
    |> HTTP.on_post("/v1/attachments/complete", fn(input) -> reply(input, path, mode, 4) end)
    |> HTTP.on_post("/v1/attachments/delete", fn(input) -> reply(input, path, mode, 5) end)
    |> HTTP.on_get("/untrusted", fn(_) -> HTTP.response(500, "redirect followed") end)
    |> HTTP.serve(port)
end

fn run_case(mode :: Int) -> Unit!String do
  let account = account_fixture("attachment_upload_network", "uploads")?
  let path = account.path
  let view = signed_transparency_view([leaf_hash(account.device_set)?])?
  assert(install_signed_transparency(path, view, account.device_set)?)
  let port = 22200 + mode
  let _server = spawn(peer, port, path, mode)
  Timer.sleep(40)
  assert(configured(port))
  let profile = load_profile(path)?
  let authorization = attachment_authorization(path,
    profile,
    4,
    decode_client_profile(profile)?.account_id)?
  let plaintext = repeated(37,
    if mode == 11 do
      16777216
    else if mode == 12 do
      16777217
    else
      65537
    end)?
  let request = pack_credit_parts([
    Bytes.from_utf8(path),
    Bytes.from_utf8("file.bin"),
    Bytes.from_utf8("application/octet-stream"),
    plaintext,
    authorization
  ])?
  let result = native_attachment_upload(request)
  if mode == 0 || mode == 9 || mode == 10 || mode == 11 do
    let output = output_list(result?)?
    assert(List.length(output) == 3 && Bytes.length(List.get(output, 1)) == 32)
    let reference = List.head(output)
    let chunks = if mode == 11 do
      256
    else
      2
    end
    for index in 0..chunks do
      let opened = open_attachment_chunk(MobileAttachmentChunkRequest {
        database_path: path,
        reference: reference,
        index: index,
        payload: bytes_at(path <> ".part#{index + 1}")?
      })
      assert(exact(opened_equals(opened,
        Bytes.slice(plaintext,
          index * 65536,
          if index == 0 || mode == 11 do
            65536
          else
            1
          end)?)))
    end
    assert(File.exists(path <> ".step4"))
    let ticket = List.get(output, 2)
    if mode == 9 do
      let tampered = Bytes.concat(ticket, Bytes.from_utf8("x"))?
      assert(Result.is_err(native_attachment_discard(pack_credit_parts([
        Bytes.from_utf8(path),
        tampered
      ])?)))
      assert(!File.exists(path <> ".step5"))
      erase_account_export(Bytes.from_utf8(path))?
      create_account_export(group_vectors([
        Bytes.from_utf8(path),
        Bytes.from_utf8("replacement")
      ])?)?
      assert(Result.is_err(native_attachment_discard(pack_credit_parts([
        Bytes.from_utf8(path),
        ticket
      ])?)))
      assert(!File.exists(path <> ".step5"))
    else
      let discarded = native_attachment_discard(pack_credit_parts([Bytes.from_utf8(path), ticket])?)
      if mode == 0 || mode == 11 do
        assert(Bytes.length(discarded?) == 0)
      else
        assert(Result.is_err(discarded))
      end
      assert(File.exists(path <> ".step5"))
    end
  else
    assert(Result.is_err(result))
    assert(!File.exists(path <> ".step4") || mode == 6)
    if mode >= 1 && mode <= 6 do
      assert(File.exists(path <> ".step5"))
    end
    if mode == 12 do
      assert(!File.exists(path <> ".step0"))
    end
    if mode == 7 || mode == 8 do
      assert(!File.exists(path <> ".step5"))
    end
  end
  erase_account_export(Bytes.from_utf8(path))?
  for step in 0..6 do
    if File.exists(path <> ".step#{step}") do
      File.delete(path <> ".step#{step}")?
    end
  end
  for index in 0..257 do
    if File.exists(path <> ".part#{index}") do
      File.delete(path <> ".part#{index}")?
    end
  end
  Ok(nil)
end

fn proof() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  for mode in 0..13 do
    run_case(mode)?
  end
  Ok(nil)
end

test("native free uploads own capabilities, encrypt bounded chunks and fence discard authority") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
