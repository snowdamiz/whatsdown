from Api.Http import (
  handle_quote,
  handle_issue,
  handle_health,
  handle_lightning_quote,
  handle_lightning_issue
)
from Runtime.Config import configured_server, open_storage_key
from Runtime.Registry import start_registry
from Runtime.KeySync import start_key_synchronizer
from Runtime.TreasuryControl import validate_treasury_startup, start_treasury_worker
from Runtime.TreasuryOperator import run_treasury_operator
from Runtime.LightningControl import start_lightning_worker
from Runtime.BtcConversion import run_btc_conversion_operator

fn fatal(message :: String) do
  io_eprintln(message)
  Process.exit(1)
end

fn main() do
  Process.install_shutdown_signals()
  let config = case configured_server() do
    Ok(value) -> value
    Err(_) -> do
      fatal("credit issuer configuration is invalid")
      return
    end
  end
  if config.policy.enabled do
    case open_storage_key(config.key_directory) do
      Ok(key) -> Secret.destroy(key)
      Err(_) -> do
        fatal("credit issuer storage key is unavailable")
        return
      end
    end
  end
  let pool = case Pool.open(config.database_url, 1, 4, 5000) do
    Ok(value) -> value
    Err(_) -> do
      fatal("credit issuer database is unavailable")
      return
    end
  end
  let args = Env.args()
  if List.length(args) > 1 do
    let result = if List.get(args, 1) == "btc-conversion" do
      run_btc_conversion_operator(pool, config, args)
    else
      run_treasury_operator(pool, config, args)
    end
    Pool.close(pool)
    case result do
      Ok(value) -> println(value)
      Err(_) -> fatal("credit treasury command failed")
    end
    return
  end
  case validate_treasury_startup(pool, config) do
    Ok(_) -> nil
    Err(_) -> do
      Pool.close(pool)
      fatal("credit treasury keys are unavailable or do not match configured pins")
      return
    end
  end
  start_registry(pool, config)
  start_key_synchronizer(pool, config)
  start_treasury_worker(pool, config)
  start_lightning_worker(pool, config)
  HTTP.serve(HTTP.router()
      |> HTTP.on_get("/health", handle_health)
      |> HTTP.on_post("/internal/v1/credits/quote", handle_quote)
      |> HTTP.on_post("/internal/v1/credits/issue", handle_issue)
      |> HTTP.on_post("/internal/v1/credits/lightning/quote", handle_lightning_quote)
      |> HTTP.on_post("/internal/v1/credits/lightning/issue", handle_lightning_issue),
    config.port)
  Pool.close(pool)
  if !Process.shutdown_requested() do
    fatal("credit issuer HTTP server failed")
  end
end
