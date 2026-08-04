from Api.Binary import EdgeResult, prepare_submission

fn fatal(message :: String) do
  io_eprintln(message)
  Process.exit(1)
end

fn respond(result :: EdgeResult) -> Response do
  HTTP.response_bytes(result.status, result.body)
end

fn current_time() -> U64 ! String do
  U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn handle_health(_request :: Request) -> Response do
  HTTP.response(200, "ok")
end

fn handle_submit(request :: Request) -> Response do
  case current_time() do
    Err( _) -> HTTP.response(500, "")
    Ok( now) -> case U64.parse("300000") do
      Err( _) -> HTTP.response(500, "")
      Ok( maximum_future) -> do
        let difficulty = Env.get_int("MESSENGER_ABUSE_DIFFICULTY", 16)
        let prepared = prepare_submission(Request.body_bytes(request),
        now,
        maximum_future,
        difficulty)
        if prepared.status != 200 do
          respond(prepared)
        else
          case Http.build(:post,
          Env.get("MESSENGER_DELIVERY_INTERNAL_URL", "") <> "/internal/v1/envelopes/sealed")
            |> Http.header("Content-Type", "application/octet-stream")
            |> Http.body_bytes(prepared.body)
            |> Http.timeout(5000)
            |> Http.max_response_bytes(1024)
            |> Http.send() do
            Err( _) -> HTTP.response(502, "")
            Ok( forwarded) -> HTTP.response_bytes(forwarded.status, forwarded.body_bytes)
          end
        end
      end
    end
  end
end

fn main() do
  Process.install_shutdown_signals()
  let port = Env.get_int("MESSENGER_PRIVACY_EDGE_PORT", 18087)
  let difficulty = Env.get_int("MESSENGER_ABUSE_DIFFICULTY", 16)
  let internal_url = Env.get("MESSENGER_DELIVERY_INTERNAL_URL", "")
  if port <= 0 || port > 65535 do
    fatal("MESSENGER_PRIVACY_EDGE_PORT must be between 1 and 65535")
  else if difficulty < 1 || difficulty > 24 do
    fatal("MESSENGER_ABUSE_DIFFICULTY must be between 1 and 24")
  else if String.length(internal_url) == 0 do
    fatal("MESSENGER_DELIVERY_INTERNAL_URL is required")
  else
    println("privacy-edge listening on :#{port}")
    HTTP.serve(HTTP.router()
      |> HTTP.on_get("/health", handle_health)
      |> HTTP.on_post("/v1/envelopes/batch", handle_submit),
    port)
    if !Process.shutdown_requested() do
      fatal("privacy-edge HTTP server failed")
    else
      nil
    end
  end
end
