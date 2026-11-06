from Api.Binary import EdgeResult
from Credits.PostageBox import decode_sealed_postage_batch
from Credits.PostageReply import is_sealed_postage_reply
from Credits.PostagePolicy import decode_postage_policy
from Privacy.Edge import (
  decode_stamped_request,
  verify_request_stamp,
  internal_delivery_authorization
)

fn empty(status :: Int) -> EdgeResult do
  EdgeResult { status: status, body: Bytes.empty() }
end

# The edge knows neither recipient nor price. The one padded credit box and all
# deliveries stay encrypted; separate endpoint labels bind their work stamps.
pub fn prepare_postage(body :: Bytes,
  now :: U64,
  maximum_future :: U64,
  difficulty :: Int,
  recovery :: Bool) -> EdgeResult do
  let (stamp, batch) = case decode_stamped_request(body, 541865) do
    Err(_) -> return empty(400)
    Ok(value) -> value
  end
  if Result.is_err(decode_sealed_postage_batch(batch)) do
    return empty(400)
  end
  let label = if recovery do
    "mesh-msg/v1/work/postage/reconcile"
  else
    "mesh-msg/v1/work/postage"
  end
  case verify_request_stamp(label, batch, stamp, now, maximum_future, difficulty) do
    Err(_) -> empty(400)
    Ok(false) -> empty(429)
    Ok(true) -> EdgeResult { status: 200, body: batch }
  end
end

pub fn forward_postage(body :: Bytes,
  internal_url :: String,
  internal_token :: String,
  recovery :: Bool) -> EdgeResult!String do
  if Result.is_err(decode_sealed_postage_batch(body)) do
    return Ok(empty(400))
  end
  if String.length(internal_url) == 0 do
    return Ok(empty(503))
  end
  let authorization = case internal_delivery_authorization(internal_token) do
    Err(_) -> return Ok(empty(503))
    Ok(value) -> value
  end
  let path = if recovery do
    "/internal/credits/postage/reconcile"
  else
    "/internal/credits/postage"
  end
  let result = Http.build(:post, internal_url <> path)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Accept", "application/octet-stream")
    |> Http.header("Authorization", authorization)
    |> Http.body_bytes(body)
    |> Http.timeout(30000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(564)
    |> Http.send()
  let response = case result do
    Err(_) -> return Ok(empty(502))
    Ok(value) -> value
  end
  if response.status == 200 || (!recovery && response.status == 201) do
    if is_sealed_postage_reply(response.body_bytes) do
      Ok(EdgeResult { status: response.status, body: response.body_bytes })
    else
      Ok(empty(502))
    end
  else if List.contains([400, 403, 409, 425, 429, 503], response.status) do
    Ok(empty(response.status))
  else
    Ok(empty(502))
  end
end

# Owner-signed public policy publication follows the registration boundary.
# Its 8-byte acknowledgement is not a witnessed admission or credit receipt.
pub fn forward_postage_policy(body :: Bytes, internal_url :: String) -> EdgeResult!String do
  if Result.is_err(decode_postage_policy(body)) do
    return Ok(empty(400))
  end
  if String.length(internal_url) == 0 do
    return Ok(empty(503))
  end
  let result = Http.build(:post, internal_url <> "/v1/credits/postage-policy")
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.body_bytes(body)
    |> Http.timeout(30000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(512)
    |> Http.send()
  let response = case result do
    Err(_) -> return Ok(empty(502))
    Ok(value) -> value
  end
  if response.status == 200 || response.status == 201 do
    if Bytes.length(response.body_bytes) != 8 do
      return Ok(empty(502))
    end
    let revision = case Bytes.read_u64_be(response.body_bytes, 0) do
      Err(_) -> return Ok(empty(502))
      Ok(value) -> value
    end
    if revision == U64.parse("0")? do
      Ok(empty(502))
    else
      Ok(EdgeResult { status: response.status, body: response.body_bytes })
    end
  else if List.contains([400, 403, 409, 429, 503], response.status) do
    Ok(empty(response.status))
  else
    Ok(empty(502))
  end
end
