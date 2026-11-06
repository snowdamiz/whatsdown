from Transparency.RpcTransport import require_rpc_current
# All proof requests use only a pinned/cached directory origin. They carry no
# account identifiers, follow no redirects and have per-response byte limits.
pub fn anchor_proof_origin(origin :: String) -> String!String do
  let canonical = Http.url_origin(origin)?
  if (origin != canonical && origin != canonical <> "/")
    || (!String.starts_with(origin, "https://")
      && !String.starts_with(origin, "http://127.0.0.1:")) do
    Err("invalid_anchor_origin")
  else
    Ok(canonical)
  end
end

pub fn fetch_anchor_proof(origin :: String,
  route :: String,
  body :: Bytes,
  maximum :: Int,
  require_current :: Fun() -> Result<(), String>) -> Result<(String, Bytes), String> do
  let origin = anchor_proof_origin(origin)?
  require_rpc_current(require_current)?
  let sent = (Http.build(:post, origin <> route)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.body_bytes(body)
    |> Http.timeout(3000)
    |> Http.max_response_bytes(maximum)
    |> Http.max_redirects(0)
    |> Http.send())
  require_rpc_current(require_current)?
  let response = case sent do
    Err(_) -> return Ok(("proof_unavailable", Bytes.empty()))
    Ok(value) -> value
  end
  if response.status == 200 do
    Ok(("received", response.body_bytes))
  else if response.status >= 500 || response.status == 408 || response.status == 429 do
    Ok(("proof_unavailable", response.body_bytes))
  else
    Ok(("mismatch", response.body_bytes))
  end
end
