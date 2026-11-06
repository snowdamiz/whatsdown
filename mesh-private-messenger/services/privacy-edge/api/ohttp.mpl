##! Opaque OHTTP relay transport. No decryption, inner parsing or work admission.
from Api.Binary import EdgeResult
from Privacy.Edge import internal_delivery_authorization

fn empty(status :: Int) -> EdgeResult do
  EdgeResult { status: status, body: Bytes.empty() }
end

fn header(headers :: Map<String, String>, name :: String) -> String do
  if Map.has_key(headers, name) do
    Map.get(headers, name)
  else
    ""
  end
end

pub fn prepare_ohttp(body :: Bytes,
  content_type :: String,
  content_encoding :: String) -> EdgeResult do
  if content_type != "message/ohttp-req"
    || (content_encoding != "" && content_encoding != "identity") do
    empty(415)
  else if Bytes.length(body) > 1048576 do
    empty(413)
  else if Bytes.length(body) < 55 do
    empty(400)
  else
    EdgeResult { status: 200, body: body }
  end
end

pub fn ohttp_relay_target(origin :: String, development :: Bool) -> String!String do
  if String.length(origin) < 8
    || String.length(origin) > 2048
    || !Regex.is_match(~r/^[\x21-\x7e]+$/, origin)
    || String.contains(origin, "\\")
    || String.contains(origin, "@")
    || String.contains(origin, "?")
    || String.contains(origin, "#") do
    return Err("ohttp_invalid_gateway_origin")
  end
  let canonical = case Http.url_origin(origin) do
    Err(_) -> return Err("ohttp_invalid_gateway_origin")
    Ok(value) -> value
  end
  if canonical != origin do
    return Err("ohttp_invalid_gateway_origin")
  end
  if !String.starts_with(origin, "https://")
    && origin != "http://delivery.internal"
    && !(development
      && Regex.is_match(~r/^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:[1-9][0-9]{0,4})?$/,
        origin)) do
    return Err("ohttp_invalid_gateway_origin")
  end
  Ok(origin <> "/internal/v1/ohttp")
end

## Only explicitly supplied ciphertext and server configuration cross this API.
## Caller cookies, identity, forwarding and tracing headers are never accepted.
pub fn forward_ohttp(body :: Bytes,
  content_type :: String,
  content_encoding :: String,
  internal_origin :: String,
  internal_token :: String,
  development :: Bool) -> EdgeResult!String do
  let prepared = prepare_ohttp(body, content_type, content_encoding)
  if prepared.status != 200 do
    return Ok(prepared)
  end
  let target = case ohttp_relay_target(internal_origin, development) do
    Err(_) -> return Ok(empty(503))
    Ok(value) -> value
  end
  let authorization = case internal_delivery_authorization(internal_token) do
    Err(_) -> return Ok(empty(503))
    Ok(value) -> value
  end
  let response = case Http.build(:post, target)
    |> Http.header("Content-Type", "message/ohttp-req")
    |> Http.header("Accept", "message/ohttp-res")
    |> Http.header("Cache-Control", "no-store")
    |> Http.header("Authorization", authorization)
    |> Http.body_bytes(prepared.body)
    |> Http.timeout(5000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(1048576)
    |> Http.send() do
    Err(_) -> return Ok(empty(502))
    Ok(value) -> value
  end
  if response.status != 200 do
    return Ok(empty(if response.status >= 400 && response.status <= 599 do
      response.status
    else
      502
    end))
  end
  let encoding = header(response.headers, "content-encoding")
  if header(response.headers, "content-type") != "message/ohttp-res"
    || header(response.headers, "cache-control") != "no-store"
    || (encoding != "" && encoding != "identity")
    || Bytes.length(response.body_bytes) < 48
    || Bytes.length(response.body_bytes) > 1048576 do
    return Ok(empty(502))
  end
  Ok(EdgeResult { status: 200, body: response.body_bytes })
end

fn enabled(name :: String) -> Bool!String do
  case Env.get(name, "off") do
    "off" -> Ok(false)
    "on" -> Ok(true)
    _ -> Err("invalid_ohttp_relay_configuration")
  end
end

pub fn validate_ohttp_relay_config() -> Result<(), String> do
  if !enabled("MORSE_OHTTP")? do
    return Ok(nil)
  end
  ohttp_relay_target(Env.get("MESSENGER_DELIVERY_INTERNAL_URL", ""),
    enabled("MESSENGER_OHTTP_DEVELOPMENT")?)?
  internal_delivery_authorization(Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", ""))?
  Ok(nil)
end

fn request_header(request :: Request, name :: String) -> String do
  case Request.header(request, name) do
    None -> ""
    Some(value) -> value
  end
end

fn response(result :: EdgeResult) -> Response do
  let headers = Map.put(Map.new(), "Cache-Control", "no-store")
  if result.status == 200 do
    HTTP.response_bytes_with_headers(200,
      result.body,
      Map.put(headers, "Content-Type", "message/ohttp-res"))
  else
    HTTP.response_bytes_with_headers(result.status, Bytes.empty(), headers)
  end
end

## The client supplies ciphertext and media metadata only. All upstream
## destinations and credentials come from this relay's own configuration.
pub fn handle_ohttp(request :: Request) -> Response do
  case enabled("MORSE_OHTTP") do
    Err(_) -> return response(empty(503))
    Ok(false) -> return response(empty(404))
    Ok(true) -> nil
  end
  let development = case enabled("MESSENGER_OHTTP_DEVELOPMENT") do
    Err(_) -> return response(empty(503))
    Ok(value) -> value
  end
  response(case forward_ohttp(Request.body_bytes(request),
    request_header(request, "content-type"),
    request_header(request, "content-encoding"),
    Env.get("MESSENGER_DELIVERY_INTERNAL_URL", ""),
    Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", ""),
    development) do
    Err(_) -> empty(502)
    Ok(value) -> value
  end)
end
