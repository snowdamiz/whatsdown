from Api.Binary import EdgeResult, forward_submission, prepare_submission
from Privacy.Edge import internal_delivery_token
from Api.Credits import forward_credit
from Api.Postage import prepare_postage, forward_postage, forward_postage_policy
from Api.Ohttp import handle_ohttp, validate_ohttp_relay_config

fn fatal(message :: String) do
  io_eprintln(message)
  Process.exit(1)
end

fn respond(result :: EdgeResult) -> Response do
  HTTP.response_bytes(result.status, result.body)
end

fn current_time() -> U64!String do
  U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn handle_health(_request :: Request) -> Response do
  HTTP.response(200, "ok")
end

fn credit_request(request :: Request, operation :: String) -> Response do
  let upstream = if operation == "issuer"
    || operation == "retention"
    || operation == "signup"
    || operation == "signup-policy"
    || operation == "reconcile" do
    Env.get("MESSENGER_DELIVERY_INTERNAL_URL", "")
  else
    Env.get("MESSENGER_CREDIT_ISSUER_INTERNAL_URL", "")
  end
  let result = case forward_credit(operation,
    Request.body_bytes(request),
    upstream,
    Env.get("MESSENGER_CREDIT_PURCHASE_INTERNAL_TOKEN", "")) do
    Ok(value) -> value
    Err(_) -> EdgeResult { status: 502, body: Bytes.empty() }
  end
  HTTP.response_bytes_with_headers(result.status,
    result.body,
    Map.new()
      |> Map.put("Content-Type", "application/octet-stream")
      |> Map.put("Cache-Control", "no-store"))
end

fn handle_credit_issuer(request :: Request) -> Response do
  credit_request(request, "issuer")
end

fn handle_credit_quote(request :: Request) -> Response do
  credit_request(request, "quote")
end

fn handle_credit_issue(request :: Request) -> Response do
  credit_request(request, "issue")
end

fn handle_lightning_quote(request :: Request) -> Response do
  credit_request(request, "lightning/quote")
end

fn handle_lightning_issue(request :: Request) -> Response do
  credit_request(request, "lightning/issue")
end

fn handle_credit_retention(request :: Request) -> Response do
  credit_request(request, "retention")
end

fn handle_credit_signup(request :: Request) -> Response do
  credit_request(request, "signup")
end

fn handle_credit_signup_policy(request :: Request) -> Response do
  credit_request(request, "signup-policy")
end

fn handle_credit_recovery(request :: Request) -> Response do
  credit_request(request, "reconcile")
end

fn postage_response(result :: EdgeResult) -> Response do
  HTTP.response_bytes_with_headers(result.status,
    result.body,
    Map.new()
      |> Map.put("Content-Type", "application/octet-stream")
      |> Map.put("Cache-Control", "no-store"))
end

fn postage_request(request :: Request, recovery :: Bool) -> Response do
  let now = case current_time() do
    Err(_) -> return postage_response(EdgeResult { status: 503, body: Bytes.empty() })
    Ok(value) -> value
  end
  let future = case U64.parse("300000") do
    Err(_) -> return postage_response(EdgeResult { status: 503, body: Bytes.empty() })
    Ok(value) -> value
  end
  let admitted = prepare_postage(Request.body_bytes(request),
    now,
    future,
    Env.get_int("MESSENGER_ABUSE_DIFFICULTY", 16),
    recovery)
  if admitted.status != 200 do
    return postage_response(admitted)
  end
  postage_response(case forward_postage(admitted.body,
    Env.get("MESSENGER_DELIVERY_INTERNAL_URL", ""),
    Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", ""),
    recovery) do
    Err(_) -> EdgeResult { status: 502, body: Bytes.empty() }
    Ok(value) -> value
  end)
end

fn handle_credit_postage(request :: Request) -> Response do
  postage_request(request, false)
end

fn handle_credit_postage_reconcile(request :: Request) -> Response do
  postage_request(request, true)
end

fn handle_postage_policy(request :: Request) -> Response do
  postage_response(case forward_postage_policy(Request.body_bytes(request),
    Env.get("MESSENGER_DELIVERY_INTERNAL_URL", "")) do
    Err(_) -> EdgeResult { status: 502, body: Bytes.empty() }
    Ok(value) -> value
  end)
end

fn handle_submit(request :: Request) -> Response do
  case current_time() do
    Err(_) -> HTTP.response(500, "")
    Ok(now) -> case U64.parse("300000") do
      Err(_) -> HTTP.response(500, "")
      Ok(maximum_future) -> do
        let difficulty = Env.get_int("MESSENGER_ABUSE_DIFFICULTY", 16)
        let prepared = prepare_submission(Request.body_bytes(request),
          now,
          maximum_future,
          difficulty)
        if prepared.status != 200 do
          respond(prepared)
        else
          case forward_submission(prepared.body,
            Env.get("MESSENGER_DELIVERY_INTERNAL_URL", ""),
            Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", "")) do
            Err(_) -> HTTP.response(503, "")
            Ok(forwarded) -> respond(forwarded)
          end
        end
      end
    end
  end
end

fn main() do
  Process.install_shutdown_signals()
  case validate_ohttp_relay_config() do
    Err(_) -> fatal("privacy-edge OHTTP configuration failed")
    Ok(_) -> nil
  end
  let port = Env.get_int("MESSENGER_PRIVACY_EDGE_PORT", 18087)
  let difficulty = Env.get_int("MESSENGER_ABUSE_DIFFICULTY", 16)
  let internal_url = Env.get("MESSENGER_DELIVERY_INTERNAL_URL", "")
  case internal_delivery_token(Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", "")) do
    Err(error) -> fatal("privacy-edge configuration failed: #{error}")
    Ok(_) -> if port <= 0 || port > 65535 do
      fatal("MESSENGER_PRIVACY_EDGE_PORT must be between 1 and 65535")
    else if difficulty < 1 || difficulty > 24 do
      fatal("MESSENGER_ABUSE_DIFFICULTY must be between 1 and 24")
    else if String.length(internal_url) == 0 do
      fatal("MESSENGER_DELIVERY_INTERNAL_URL is required")
    else
      println("privacy-edge listening on :#{port}")
      HTTP.serve_on(HTTP.router()
          |> HTTP.on_get("/health", handle_health)
          |> HTTP.on_post("/v1/ohttp", handle_ohttp)
          |> HTTP.on_post("/v1/credits/issuer", handle_credit_issuer)
          |> HTTP.on_post("/v1/credits/quote", handle_credit_quote)
          |> HTTP.on_post("/v1/credits/issue", handle_credit_issue)
          |> HTTP.on_post("/v1/credits/lightning/quote", handle_lightning_quote)
          |> HTTP.on_post("/v1/credits/lightning/issue", handle_lightning_issue)
          |> HTTP.on_post("/v1/credits/retention", handle_credit_retention)
          |> HTTP.on_post("/v1/credits/signup", handle_credit_signup)
          |> HTTP.on_post("/v1/credits/signup-policy", handle_credit_signup_policy)
          |> HTTP.on_post("/v1/credits/reconcile", handle_credit_recovery)
          |> HTTP.on_post("/v1/credits/postage", handle_credit_postage)
          |> HTTP.on_post("/v1/credits/postage/reconcile", handle_credit_postage_reconcile)
          |> HTTP.on_post("/v1/credits/postage-policy", handle_postage_policy)
          |> HTTP.on_post("/v1/envelopes/batch", handle_submit),
        Env.get("MESSENGER_BIND_ADDRESS", "::"),
        port)
      if !Process.shutdown_requested() do
        fatal("privacy-edge HTTP server failed")
      else
        nil
      end
    end
  end
end
