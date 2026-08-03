from Broker.Expo import BrokerOutcome
from Broker.Service import access_token, broker_seed, deliver, outcome_status, provider_url

fn configured_seed() -> Bytes ! String do
  broker_seed(Env.get("MESSENGER_PUSH_BROKER_SEED_HEX", ""))
end

fn configured_url() -> String ! String do
  provider_url(Env.get("MESSENGER_EXPO_PUSH_URL", "https://exp.host/--/api/v2/push/send"))
end

fn configured_token() -> Option < String > ! String do
  access_token(Env.get("MESSENGER_EXPO_ACCESS_TOKEN", ""))
end

fn validate_config() -> Result <(), String > do
  let _seed = configured_seed() ?
  let _url = configured_url() ?
  let _token = configured_token() ?
  Ok(nil)
end

fn deliver_configured(input :: Bytes) -> BrokerOutcome ! String do
  Ok(deliver(input, configured_seed() ?, configured_url() ?, configured_token() ?))
end

fn handle_health(_request :: Request) -> Response do
  HTTP.response(200, "ok")
end

fn handle_push(request :: Request) -> Response do
  case deliver_configured(Request.body_bytes(request)) do
    Err( _) -> HTTP.response(503, "")
    Ok( outcome) -> HTTP.response(outcome_status(outcome), "")
  end
end

fn main() do
  Process.install_shutdown_signals()
  let port = Env.get_int("MESSENGER_PUSH_BROKER_PORT", 18088)
  case validate_config() do
    Err( error) -> println("push-broker configuration failed: #{error}")
    Ok( _) -> if port <= 0 || port > 65535 do
      println("MESSENGER_PUSH_BROKER_PORT must be between 1 and 65535")
    else
      println("push-broker listening on :#{port}")
      let _ = HTTP.serve(HTTP.router()
        |> HTTP.on_get("/health", handle_health)
        |> HTTP.on_post("/internal/v1/push", handle_push),
      port)
      nil
    end
  end
end
