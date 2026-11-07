##! Bounded paid-object HTTP through immutable native issuer configuration.

from Mobile.NativeIssuerTls import issuer_tls_request, issuer_tls_request_with_frame
from Mobile.NetworkPins import MobileNetworkPins
from Transparency.Config import SecurityConfig

pub struct AttachmentHttpResponse do
  status :: Int
  body :: Bytes
end

# Download helpers preserve actual status without exposing decoded error bodies.
# Only the captured, authenticated origins and capabilities choose the request.
fn attachment_download_request(origin :: String,
  route :: String,
  object_id :: Bytes,
  capability :: Bytes,
  index :: Int) -> Int!String do
  if origin == "-"
    || Bytes.length(object_id) != 32
    || Bytes.length(capability) != 32
    || index < 1
    || index > 8192 do
    return Err("invalid_paid_attachment")
  end
  Ok(Http.build(:get, origin <> route)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Cache-Control", "no-store")
    |> Http.header("X-Object-Capability", Bytes.to_hex(capability))
    |> Http.timeout(12000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(65576))
end

pub fn legacy_attachment_download_response(pins :: MobileNetworkPins,
  object_id :: Bytes,
  capability :: Bytes,
  index :: Int) -> AttachmentHttpResponse!String do
  let route = "/v1/objects/#{Bytes.to_hex(object_id)}/parts/#{index}"
  let request = attachment_download_request(pins.object_origin,
    route,
    object_id,
    capability,
    index)?
  case Http.send(request) do
    Err(_) -> Err("attachment_transport_unavailable")
    Ok(response) -> Ok(AttachmentHttpResponse {
      status: response.status,
      body: response.body_bytes
    })
  end
end

pub fn issuer_attachment_download_response_with_frame(config :: SecurityConfig,
  captured_tls_frame :: Bytes,
  object_id :: Bytes,
  capability :: Bytes,
  index :: Int) -> AttachmentHttpResponse!String do
  let route = "/v2/objects/#{Bytes.to_hex(object_id)}/parts/#{index}"
  let request = attachment_download_request(config.issuer_origin,
    route,
    object_id,
    capability,
    index)?
  let authorized = issuer_tls_request_with_frame(request, config.issuer_origin, captured_tls_frame)?
  case Http.send(authorized) do
    Err(_) -> Err("paid_attachment_transport_unavailable")
    Ok(response) -> Ok(AttachmentHttpResponse {
      status: response.status,
      body: response.body_bytes
    })
  end
end

# mode0=grant,1=part PUT,2=complete,3=delete,4=part GET. Callers derive all
# material from the authenticated journal/reference, never from a JS URL.
pub fn attachment_http(config :: SecurityConfig,
  mode :: Int,
  object_id :: Bytes,
  capability :: Bytes,
  index :: Int,
  body :: Bytes) -> AttachmentHttpResponse!String do
  let part = mode == 1 || mode == 4
  if config.issuer_origin == "-"
    || mode < 0
    || mode > 4
    || (part
      && (Bytes.length(object_id) != 32
        || Bytes.length(capability) != 32
        || index < 0
        || index > 8192))
    || (mode == 0 && (Bytes.length(body) < 1 || Bytes.length(body) > 88355))
    || (mode == 1 && (Bytes.length(body) < 1 || Bytes.length(body) > 65576))
    || ((mode == 2 || mode == 3) && Bytes.length(body) != 68)
    || (mode == 4 && Bytes.length(body) != 0) do
    return Err("invalid_paid_attachment")
  end
  let route = if part do
    "/v2/objects/#{Bytes.to_hex(object_id)}/parts/#{index}"
  else if mode == 0 do
    "/v1/attachments/paid-grant"
  else if mode == 2 do
    "/v2/attachments/complete"
  else
    "/v2/attachments/delete"
  end
  let maximum = if mode == 0 do
    462
  else if mode == 4 do
    65576
  else
    1
  end
  let method = if mode == 4 do
    :get
  else if mode == 1 do
    :put
  else
    :post
  end
  let request = Http.build(method, config.issuer_origin <> route)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Cache-Control", "no-store")
    |> Http.timeout(12000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(maximum)
  let authorized = if part do
    Http.header(request, "X-Object-Capability", Bytes.to_hex(capability))
  else
    request
  end
  let payload = if mode == 4 do
    authorized
  else
    Http.body_bytes(authorized, body)
  end
  let response = case Http.send(issuer_tls_request(payload, config.issuer_origin)?) do
    Err(_) -> return Err("paid_attachment_transport_unavailable")
    Ok(value) -> value
  end
  let statuses = if mode == 0 || mode == 1 do
    [200, 201]
  else if mode == 2 do
    [200, 202]
  else if mode == 3 do
    [202, 204]
  else
    [200]
  end
  if !List.contains(statuses, response.status) do
    return Err("paid_attachment_http_" <> Int.to_string(response.status))
  end
  if mode != 0 && mode != 4 && Bytes.length(response.body_bytes) != 0 do
    return Err("invalid_paid_attachment_reply")
  end
  Ok(AttachmentHttpResponse { status: response.status, body: response.body_bytes })
end
