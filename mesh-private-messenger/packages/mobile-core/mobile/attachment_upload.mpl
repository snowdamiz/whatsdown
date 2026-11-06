from Mobile.AttachmentRecipients import require_padded_attachment_authorization

##! Free files retain their existing16MiB in-memory limit. Mesh owns all object
##! HTTP and returns only a message reference and an opaque discard ticket.
##! Paid resumable staging is deliberately a separate journaled protocol.

from Mobile.Attachments import prepare_attachment, seal_attachment_chunk
from Mobile.Codec import (
  mobile_reader,
  take_fixed,
  take_vector,
  mobile_read_u32,
  mobile_utf8,
  mobile_finish,
  encode_output_list
)
from Mobile.CreditState import pack_credit_parts, unpack_credit_parts
from Mobile.NetworkPins import MobileNetworkPins, native_network_pins
from Mobile.Profile import load_profile
from Mobile.Types import MobileAttachmentPrepareRequest, MobileAttachmentChunkRequest
from Objects.Grant import decode_grant_response, decode_delete
from Storage.Keys import platform_key, seal_local, open_local, local_context

struct UploadInput do
  path :: String
  filename :: Bytes
  mime :: Bytes
  plaintext :: Bytes
  authorization :: Bytes
end

fn parsed_upload(input :: Bytes) -> UploadInput!String do
  let state = mobile_reader(input, 16830000, "invalid_attachment_upload")?
  let count = take_fixed(state, 4)?
  if mobile_read_u32(count.value)? != 5 do
    return Err("invalid_attachment_upload")
  end
  let path = take_vector(count.state, 4096)?
  let filename = take_vector(path.state, 255)?
  let mime = take_vector(filename.state, 127)?
  let plaintext = take_vector(mime.state, 16777216)?
  let authorization = take_vector(plaintext.state, 40000)?
  mobile_finish(authorization.state, "invalid_attachment_upload")?
  if Bytes.length(path.value) == 0
    || Bytes.length(mime.value) == 0
    || Bytes.length(plaintext.value) == 0 do
    return Err("invalid_attachment_upload")
  end
  Ok(UploadInput {
    path: mobile_utf8(path.value, "invalid_attachment_upload")?,
    filename: filename.value,
    mime: mime.value,
    plaintext: plaintext.value,
    authorization: authorization.value
  })
end

fn fence(path :: String, before :: Bytes, pins :: MobileNetworkPins) -> Unit!String do
  if !Bytes.secure_equals(load_profile(path)?, before) do
    return Err("attachment_profile_changed")
  end
  let current = native_network_pins()?
  if current.object_origin != pins.object_origin
    || current.object_work_difficulty != pins.object_work_difficulty do
    return Err("attachment_configuration_changed")
  end
  Ok(nil)
end

# The response limit is checked by the HTTP runtime before buffering. Grant
# replies are exactly36 bytes and must name this object's native random ID.
fn object_http(pins :: MobileNetworkPins,
  mode :: Int,
  object_id :: Bytes,
  capability :: Bytes,
  index :: Int,
  body :: Bytes) -> Bytes!String do
  let part = mode == 1
  let route = if part do
    "/v1/objects/#{Bytes.to_hex(object_id)}/parts/#{index}"
  else if mode == 0 do
    "/v1/attachments/grant"
  else if mode == 2 do
    "/v1/attachments/complete"
  else
    "/v1/attachments/delete"
  end
  let request = Http.build(if part do
      :put
    else
      :post
    end,
    pins.object_origin <> route)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Cache-Control", "no-store")
    |> Http.timeout(12000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(if mode == 0 do
      36
    else
      1
    end)
  let authorized = if part do
    Http.header(request, "X-Object-Capability", Bytes.to_hex(capability))
  else
    request
  end
  let response = case Http.send(Http.body_bytes(authorized, body)) do
    Err(_) -> return Err("attachment_transport_unavailable")
    Ok(value) -> value
  end
  let statuses = if mode == 0 || mode == 1 do
    [200, 201]
  else if mode == 2 do
    [200]
  else
    [204, 404]
  end
  if !List.contains(statuses, response.status) do
    return Err("attachment_http_" <> Int.to_string(response.status))
  end
  if mode == 0 do
    if !Bytes.secure_equals(decode_grant_response(response.body_bytes)?.object_id, object_id) do
      return Err("invalid_attachment_grant_reply")
    end
  else if Bytes.length(response.body_bytes) != 0 do
    return Err("invalid_attachment_reply")
  end
  Ok(response.body_bytes)
end

fn upload_parts(request :: UploadInput,
  before :: Bytes,
  pins :: MobileNetworkPins,
  material :: List<Bytes>) -> Unit!String do
  let reference = List.get(material, 0)
  let object_id = List.get(material, 1)
  let capability = List.get(material, 2)
  require_padded_attachment_authorization(request.path, request.authorization)?
  fence(request.path, before, pins)?
  object_http(pins, 0, object_id, capability, 0, List.get(material, 3))?
  require_padded_attachment_authorization(request.path, request.authorization)?
  fence(request.path, before, pins)?
  object_http(pins, 1, object_id, capability, 0, List.get(material, 6))?
  let count = (Bytes.length(request.plaintext) + 65535) / 65536
  for index in 0..count do
    require_padded_attachment_authorization(request.path, request.authorization)?
    fence(request.path, before, pins)?
    let length = if index + 1 == count do
      Bytes.length(request.plaintext) - index * 65536
    else
      65536
    end
    let wire = seal_attachment_chunk(MobileAttachmentChunkRequest {
      database_path: request.path,
      reference: reference,
      index: index,
      payload: Bytes.slice(request.plaintext, index * 65536, length)?
    })?
    require_padded_attachment_authorization(request.path, request.authorization)?
    fence(request.path, before, pins)?
    object_http(pins, 1, object_id, capability, index + 1, wire)?
  end
  require_padded_attachment_authorization(request.path, request.authorization)?
  fence(request.path, before, pins)?
  object_http(pins, 2, object_id, capability, 0, List.get(material, 4))?
  fence(request.path, before, pins)
end

fn discard_context(path :: String) -> Bytes!String do
  local_context("attachment-discard/v1/" <> Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(path))))
end

pub fn native_attachment_upload(input :: Bytes) -> Bytes!String do
  let request = parsed_upload(input)?
  let pins = native_network_pins()?
  let before = load_profile(request.path)?
  require_padded_attachment_authorization(request.path, request.authorization)?
  let prepared = prepare_attachment(MobileAttachmentPrepareRequest {
    database_path: request.path,
    filename: request.filename,
    mime_type: request.mime,
    plaintext_size: Bytes.length(request.plaintext),
    difficulty: pins.object_work_difficulty
  })?
  if Bytes.length(prepared) < 8 || mobile_read_u32(Bytes.slice(prepared, 0, 4)?)? != 4 do
    return Err("invalid_attachment_upload")
  end
  let material = unpack_credit_parts(Bytes.slice(prepared, 4, Bytes.length(prepared) - 4)?,
    7,
    1024)?
  if List.length(material) != 7 do
    return Err("invalid_attachment_upload")
  end
  # Prepare the bounded opaque cleanup authority before creating a remote object.
  let wrapping = platform_key()?
  let ticket = seal_local(pack_credit_parts([
      Crypto.sha256(before),
      Bytes.from_utf8(pins.object_origin),
      List.get(material, 5)
    ])?,
    wrapping,
    discard_context(request.path)?)?
  case upload_parts(request, before, pins, material) do
    Err(error) -> do
      # A failed upload is best-effort deleted only while its original local
      # identity and build destination are still valid. Remote expiry is fallback.
      if Result.is_ok(fence(request.path, before, pins)) do
        object_http(pins, 3, List.get(material, 1), List.get(material, 2), 0, List.get(material, 5))
      end
      Err(error)
    end
    Ok(_) -> encode_output_list([List.get(material, 0), List.get(material, 1), ticket])
  end
end

pub fn native_attachment_discard(input :: Bytes) -> Bytes!String do
  if Bytes.length(input) > 8300 do
    return Err("invalid_attachment_discard")
  end
  let parts = unpack_credit_parts(input, 2, 4096)?
  if List.length(parts) != 2 || Bytes.length(List.head(parts)) == 0 do
    return Err("invalid_attachment_discard")
  end
  let path = mobile_utf8(List.head(parts), "invalid_attachment_discard")?
  let pins = native_network_pins()?
  let before = load_profile(path)?
  let wrapping = platform_key()?
  let ticket = unpack_credit_parts(open_local(List.get(parts, 1),
      wrapping,
      discard_context(path)?)?,
    3,
    2048)?
  if List.length(ticket) != 3
    || !Bytes.secure_equals(List.head(ticket), Crypto.sha256(before))
    || mobile_utf8(List.get(ticket, 1), "invalid_attachment_discard")? != pins.object_origin do
    return Err("invalid_attachment_discard")
  end
  let control = decode_delete(List.get(ticket, 2))?
  fence(path, before, pins)?
  object_http(pins, 3, control.object_id, control.capability, 0, List.get(ticket, 2))?
  fence(path, before, pins)?
  Ok(Bytes.empty())
end
