from Broker.Expo import BrokerOutcome
from Broker.Queue import initialize
from Broker.Service import accept_durable, access_token, authorized, broker_seed, internal_token, outcome_status, provider_url, start_worker

fn fatal(message :: String) do
  io_eprintln(message)
  Process.exit(1)
end

fn configured_seed() -> Bytes ! String do
  broker_seed(Env.get("MESSENGER_PUSH_BROKER_SEED_HEX", ""))
end

fn configured_url() -> String ! String do
  provider_url(Env.get("MESSENGER_EXPO_PUSH_URL", "https://exp.host/--/api/v2/push/send"))
end

fn configured_token() -> String ! String do
  case access_token(Env.get("MESSENGER_EXPO_ACCESS_TOKEN", "")) do
    Err( error) -> Err(error)
    Ok( None) -> Ok("")
    Ok( Some( value)) -> Ok(value)
  end
end

fn configured_internal_token() -> String ! String do
  internal_token(Env.get("MESSENGER_PUSH_BROKER_INTERNAL_TOKEN", ""))
end

fn configured_queue_path() -> String ! String do
  let path = Env.get("MESSENGER_PUSH_BROKER_DB_PATH", "push-broker.db")
  if String.length(path) == 0 || String.length(path) > 4096 || path == ":memory:" do
    Err("invalid broker queue path")
  else
    Ok(path)
  end
end

fn validate_config() -> Result <(), String > do
  let _seed = configured_seed() ?
  let _url = configured_url() ?
  let _token = configured_token() ?
  let _internal_token = configured_internal_token() ?
  initialize(configured_queue_path() ?) ?
  Ok(nil)
end

fn accept_configured(input :: Bytes) -> BrokerOutcome ! String do
  Ok(accept_durable(configured_queue_path() ?,
  input,
  configured_seed() ?,
  DateTime.to_unix_ms(DateTime.utc_now())))
end

fn handle_health(_request :: Request) -> Response do
  HTTP.response(200, "ok")
end

fn handle_push(request :: Request) -> Response do
  case configured_internal_token() do
    Err( _) -> HTTP.response(503, "")
    Ok( secret) -> do
      let permitted = case Request.header(request, "Authorization") do
        None -> false
        Some( value) -> authorized(Some(value), secret)
      end
      if !permitted do
        HTTP.response(401, "")
      else
        case accept_configured(Request.body_bytes(request)) do
          Err( _) -> HTTP.response(503, "")
          Ok( outcome) -> HTTP.response(outcome_status(outcome), "")
        end
      end
    end
  end
end

fn serve(port :: Int) -> Result <(), String > do
  let path = configured_queue_path() ?
  let seed = configured_seed() ?
  let token = configured_token() ?
  start_worker(path, seed, token)
  println("push-broker listening on :#{port} with one worker")
  let _ = HTTP.serve(HTTP.router()
    |> HTTP.on_get("/health", handle_health)
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
    Err( error) -> fatal("push-broker configuration failed: #{error}")
    Ok( _) -> if port <= 0 || port > 65535 do
      fatal("MESSENGER_PUSH_BROKER_PORT must be between 1 and 65535")
    else
      case serve(port) do
        Err( error) -> fatal("push-broker startup failed: #{error}")
        Ok( _) -> nil
      end
    end
  end
end
