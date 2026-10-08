from Api.Binary import (
  EdgeResult,
  forward_quote,
  forward_to_issuer,
  relay_ohttp,
  submit_envelope,
  submit_paid
)
from Privacy.Edge import internal_delivery_token

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

fn handle_submit(request :: Request) -> Response do
  case current_time() do
    Err(_) -> HTTP.response(500, "")
    Ok(now) -> case U64.parse("300000") do
      Err(_) -> HTTP.response(500, "")
      Ok(maximum_future) -> case submit_envelope(Request.body_bytes(request),
        now,
        maximum_future,
        Env.get_int("MESSENGER_ABUSE_DIFFICULTY", 16),
        Env.get("MESSENGER_DELIVERY_INTERNAL_URL", ""),
        Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", "")) do
        Err(_) -> HTTP.response(503, "")
        Ok(result) -> respond(result)
      end
    end
  end
end

fn handle_mailbox_retention(request :: Request) -> Response do
  case submit_paid(Request.body_bytes(request),
    2,
    "/internal/v1/mailbox/retention",
    Env.get("MESSENGER_DELIVERY_INTERNAL_URL", ""),
    Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", "")) do
    Err(_) -> HTTP.response(503, "")
    Ok(result) -> respond(result)
  end
end

fn handle_credit_quote(request :: Request) -> Response do
  case (current_time(), U64.parse("300000")) do
    (Ok(now), Ok(maximum_future)) -> respond(forward_quote(Request.body_bytes(request),
      now,
      maximum_future,
      Env.get_int("MESSENGER_ABUSE_DIFFICULTY", 16),
      Env.get("MORSE_CREDIT_ISSUER_URL", "")))
    _ -> HTTP.response(500, "")
  end
end

# Encapsulated requests pass through to the gateway; its 200 is an
# encapsulated response, any other status one the gateway couldn't open.

fn handle_ohttp(request :: Request) -> Response do
  case relay_ohttp(Request.body_bytes(request),
    Env.get("MESSENGER_DELIVERY_INTERNAL_URL", ""),
    Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", "")) do
    Err(_) -> HTTP.response(503, "")
    Ok(result) -> if result.status == 200 do
      HTTP.response_bytes_with_headers(200,
        result.body,
        Map.put(Map.put(Map.new(), "Content-Type", "message/ohttp-res"),
          "Cache-Control",
          "no-store"))
    else
      HTTP.response_bytes(result.status, Bytes.empty())
    end
  end
end

fn handle_credit_issue(request :: Request) -> Response do
  respond(forward_to_issuer(Env.get("MORSE_CREDIT_ISSUER_URL", ""),
    "/v1/credits/issue",
    Request.body_bytes(request)))
end

fn main() do
  Process.install_shutdown_signals()
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
      HTTP.serve(HTTP.router()
          |> HTTP.on_get("/health", handle_health)
          |> HTTP.on_post("/v1/envelopes/batch", handle_submit)
          |> HTTP.on_post("/v1/mailbox/retention", handle_mailbox_retention)
          |> HTTP.on_post("/v1/ohttp", handle_ohttp)
          |> HTTP.on_post("/v1/credits/quote", handle_credit_quote)
          |> HTTP.on_post("/v1/credits/issue", handle_credit_issue),
        port)
      if !Process.shutdown_requested() do
        fatal("privacy-edge HTTP server failed")
      else
        nil
      end
    end
  end
end
