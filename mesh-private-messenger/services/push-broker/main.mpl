import RuntimeJobs
from Broker.Expo import BrokerOutcome
from Broker.Queue import initialize, transaction_in_progress
from Broker.Service import run_scheduled, accept_durable_with_key, access_token, broker_private_key, internal_token, outcome_status, provider_url, start_worker

fn fatal(message :: String) do
  io_eprintln(message)
  Process.exit(1)
end

fn configured_url() -> String!String do
  provider_url(Env.get("MESSENGER_EXPO_PUSH_URL", "https://exp.host/--/api/v2/push/send"))
end

fn configured_token() -> String!String do
  case access_token(Env.get("MESSENGER_EXPO_ACCESS_TOKEN", "")) do
    Err(error)
    Ok(None) -> Ok("")
    Ok(Some(value)) -> Ok(value)
  end
end

fn configured_internal_token() -> String!String do
  internal_token(Env.get("MESSENGER_PUSH_BROKER_INTERNAL_TOKEN", ""))
end

fn configured_queue_path() -> String!String do
  let path = Env.get("MESSENGER_PUSH_BROKER_DATABASE_URL", "")
  if String.length(path) > 4096 || !(String.starts_with(path, "postgres://") || String.starts_with(path,
    "postgresql://")) do
    Err("invalid broker database URL")
  else
    Ok(path)
  end
end

fn validate_config() -> Result<(), String> do
  let _private_key = broker_private_key()?
  let _url = configured_url()?
  let _token = configured_token()?
  let _internal_token = configured_internal_token()?
  initialize(configured_queue_path()?)?
  Ok(nil)
end

fn accept_configured(input :: Bytes) -> BrokerOutcome!String do
  let private_key = broker_private_key()?
  Ok(accept_durable_with_key(configured_queue_path()?,
    input,
    private_key,
    DateTime.to_unix_ms(DateTime.utc_now())))
end

fn handle_health(_request :: Request) -> Response do
  HTTP.response(200, "ok")
end

fn handle_push(request :: Request) -> Response do
  case configured_internal_token() do
    Err(_) -> HTTP.response(503, "")
    Ok(secret) -> do
      let permitted = RuntimeJobs.internal_request_authorized(request, secret)
      if !permitted do
        HTTP.response(401, "")
      else
        case accept_configured(Request.body_bytes(request)) do
          Err(_) -> HTTP.response(503, "")
          Ok(outcome) -> HTTP.response(outcome_status(outcome), "")
        end
      end
    end
  end
end

fn serve(port :: Int) -> Result<(), String> do
  let path = configured_queue_path()?
  let token = configured_token()?
  start_worker(path, token)
  if RuntimeJobs.enabled() do
    println("push-broker listening on :#{port} with scheduled jobs")
  else
    println("push-broker listening on :#{port} with one worker")
  end
  HTTP.serve(HTTP.router()
      |> HTTP.on_get("/health", handle_health)
      |> HTTP.on_post("/internal/v1/jobs/push", handle_jobs)
      |> HTTP.on_post("/internal/v1/push", handle_push),
    port)
  if Process.shutdown_requested() do
    Ok(nil)
  else
    Err("HTTP server failed")
  end
end

fn main() do
  Process.install_shutdown_signals()
  let port = Env.get_int("MESSENGER_PUSH_BROKER_PORT", 18088)
  case validate_config() do
    Err(error) -> fatal("push-broker configuration failed: #{error}")
    Ok(_) -> if port <= 0 || port > 65535 do
      fatal("MESSENGER_PUSH_BROKER_PORT must be between 1 and 65535")
    else
      case serve(port) do
        Err(error) -> fatal("push-broker startup failed: #{error}")
        Ok(_) -> nil
      end
    end
  end
end

fn handle_jobs(request :: Request) -> Response do
  if !RuntimeJobs.internal_request_authorized(request,
    Env.get("MESSENGER_PUSH_BROKER_INTERNAL_TOKEN", "")) do
    HTTP.response(401, "")
  else
    case configured_queue_path() do
      Err(_) -> HTTP.response(503, "")
      Ok(path) -> case transaction_in_progress(path, Request.body(request)) do
        Err(_) -> HTTP.response(503, "")
        Ok(true) -> HTTP.response(202, "")
        Ok(false) -> case configured_token() do
          Err(_) -> HTTP.response(503, "")
          Ok(token) -> case run_scheduled(path, token) do
            Err(_) -> HTTP.response(503, "")
            Ok(due) -> HTTP.response(200, Int.to_string(due))
          end
        end
      end
    end
  end
end
