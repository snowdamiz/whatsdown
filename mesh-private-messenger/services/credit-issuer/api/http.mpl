from Api.Lightning import lightning_quote_response, lightning_issue_response
from Api.Purchases import quote_response, issue_response, IssuerResult
from Privacy.Edge import internal_delivery_authorized
from Runtime.Config import open_storage_key
from Runtime.KeySync import issuer_now
from Runtime.Registry import issuer_state

fn respond(value :: IssuerResult) -> Response do
  HTTP.response_bytes_with_headers(value.status,
    value.body,
    Map.new()
      |> Map.put("Content-Type", "application/octet-stream")
      |> Map.put("Cache-Control", "no-store"))
end

fn purchase(request :: Request, operation :: String) -> Response do
  let state = issuer_state()
  let config = state.config
  if !internal_delivery_authorized(Request.header(request, "authorization"),
    config.purchase_token) do
    return respond(IssuerResult { status: 401, body: Bytes.empty() })
  end
  let now = case issuer_now() do
    Ok(value) -> value
    Err(_) -> return respond(IssuerResult { status: 503, body: Bytes.empty() })
  end
  let open_key = fn() do open_storage_key(config.key_directory) end
  if operation == "lightning/quote" || operation == "lightning/issue" do
    return case config.lightning do
      None -> respond(IssuerResult { status: 503, body: Bytes.empty() })
      Some(policy) -> respond(if operation == "lightning/quote" do
        lightning_quote_response(state.pool, policy, Request.body_bytes(request), open_key, now)
      else
        lightning_issue_response(state.pool, policy, Request.body_bytes(request), open_key, now)
      end)
    end
  end
  respond(if operation == "quote" do
    quote_response(state.pool, config.policy, Request.body_bytes(request), open_key, now)
  else
    issue_response(state.pool, config.policy, Request.body_bytes(request), open_key, now)
  end)
end

pub fn handle_quote(request :: Request) -> Response do
  purchase(request, "quote")
end

pub fn handle_issue(request :: Request) -> Response do
  purchase(request, "issue")
end

pub fn handle_health(_request :: Request) -> Response do
  HTTP.response(200, "ok")
end

pub fn handle_lightning_quote(request :: Request) -> Response do
  purchase(request, "lightning/quote")
end

pub fn handle_lightning_issue(request :: Request) -> Response do
  purchase(request, "lightning/issue")
end
