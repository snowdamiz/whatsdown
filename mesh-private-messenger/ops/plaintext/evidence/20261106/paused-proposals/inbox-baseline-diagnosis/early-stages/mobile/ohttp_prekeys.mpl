##! Bounded prekey transport for decoded release-owned OHTTP pins.
##! The native caller must guard account/configuration/revision around this call.
from Mobile.OhttpPins import MobileOhttpPins, select_ohttp_key
from Ohttp.BinaryHttp import encode_request, decode_response
from Ohttp.Policy import prekey_claim_request, open_prekey_claim_response
from Ohttp.Types import BhttpFraming, default_bhttp_limits

fn edge_target(origin :: String, development :: Bool) -> String!String do
  if String.length(origin) < 8
    || String.length(origin) > 2048
    || !Regex.is_match(~r/^[\x21-\x7e]+$/, origin)
    || String.contains(origin, "\\")
    || String.contains(origin, "@")
    || String.contains(origin, "?")
    || String.contains(origin, "#") do
    return Err("ohttp_invalid_edge_origin")
  end
  let canonical = case Http.url_origin(origin) do
    Err(_) -> return Err("ohttp_invalid_edge_origin")
    Ok(value) -> value
  end
  if canonical != origin
    || (!String.starts_with(origin, "https://")
      && !(development
        && Regex.is_match(~r/^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:[1-9][0-9]{0,4})?$/,
          origin))) do
    return Err("ohttp_invalid_edge_origin")
  end
  Ok(origin <> "/v1/ohttp")
end

fn header(headers :: Map<String, String>, name :: String) -> String do
  if Map.has_key(headers, name) do
    Map.get(headers, name)
  else
    ""
  end
end

## No direct fallback or retry is permitted here. Stamping and reservation
## remain at the existing caller/admission boundary, outside this transport.
pub fn fetch_ohttp_prekey(pins :: MobileOhttpPins,
  stamped :: Bytes,
  now :: U64,
  timeout :: Int) -> Bytes!String do
  if !pins.required do
    return Err("ohttp_required")
  end
  if timeout < 1 || timeout > 8000 do
    return Err("ohttp_invalid_timeout")
  end
  let selected = case select_ohttp_key(pins, now)? do
    None -> return Err("ohttp_required")
    Some(value) -> value
  end
  let target = edge_target(pins.network.edge_origin, pins.network.development)?
  let request = prekey_claim_request(pins.network.core_origin, pins.network.development, stamped)?
  let limits = default_bhttp_limits()
  let plaintext = case encode_request(request, BhttpKnownLength, %{limits | content_bytes: 120}) do
    Err(_) -> return Err("ohttp_prekey_request_invalid")
    Ok(value) -> value
  end
  let outgoing = case Ohttp.encapsulate_request(selected.key_id, selected.public_key, plaintext) do
    Err(_) -> return Err("ohttp_prekey_encryption_failed")
    Ok(value) -> value
  end
  let response = case Http.build(:post, target)
    |> Http.header("Content-Type", "message/ohttp-req")
    |> Http.header("Accept", "message/ohttp-res")
    |> Http.header("Cache-Control", "no-store")
    |> Http.body_bytes(outgoing.wire)
    |> Http.timeout(timeout)
    |> Http.max_response_bytes(1048576)
    |> Http.max_redirects(0)
    |> Http.send() do
    Err(_) -> return Err("ohttp_prekey_transport_failed")
    Ok(value) -> value
  end
  let encoding = header(response.headers, "content-encoding")
  if response.status != 200
    || header(response.headers, "content-type") != "message/ohttp-res"
    || header(response.headers, "cache-control") != "no-store"
    || (encoding != "" && encoding != "identity")
    || Bytes.length(response.body_bytes) < 48
    || Bytes.length(response.body_bytes) > 1048576 do
    return Err("ohttp_prekey_transport_failed")
  end
  let plaintext = case Ohttp.decapsulate_response(outgoing.response_context, response.body_bytes) do
    Err(_) -> return Err("ohttp_prekey_response_authentication_failed")
    Ok(value) -> value
  end
  let inner = case decode_response(plaintext, %{limits | content_bytes: 19312}) do
    Err(_) -> return Err("ohttp_prekey_response_invalid")
    Ok(value) -> value
  end
  open_prekey_claim_response(inner)
end
