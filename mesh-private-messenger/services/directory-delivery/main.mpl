from Api.Router import build_router
from Api.Binary import validate_delivery_config, validate_transparency_config
from Runtime.Registry import start_registry
from Runtime.Workers import start_workers

fn serve(pool :: PoolHandle, port :: Int) do
  let _ = start_registry(pool)
  case start_workers(2, 250) do
    Err( error) -> println("worker startup failed: #{error}")
    Ok( count) -> do
      println("directory-delivery listening on :#{port} with #{count} workers")
      HTTP.serve(build_router(), port)
    end
  end
  Pool.close(pool)
end

fn main() do
  Process.install_shutdown_signals()
  let url = Env.get("MESSENGER_DATABASE_URL",
  "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let port = Env.get_int("MESSENGER_PORT", 18086)
  case validate_transparency_config() do
    Err( error) -> println("transparency configuration failed: #{error}")
    Ok( _) -> case validate_delivery_config() do
      Err( error) -> println("delivery configuration failed: #{error}")
      Ok( _) -> if port <= 0 || port > 65535 do
        println("MESSENGER_PORT must be between 1 and 65535")
      else
        case Pool.open(url, 1, 4, 5000) do
          Err( error) -> println("database connection failed: #{error}")
          Ok( pool) -> serve(pool, port)
        end
      end
    end
  end
end
