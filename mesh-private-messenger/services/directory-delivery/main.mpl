from Api.Router import build_router
from Api.Binary import validate_delivery_config, validate_transparency_config
from Privacy.Edge import internal_delivery_token
from Runtime.Registry import start_registry
from Runtime.Workers import start_workers
from Runtime.MailboxStream import start_mailbox_stream

fn fatal(message :: String) do
  io_eprintln(message)
  Process.exit(1)
end

fn serve(pool :: PoolHandle, port :: Int, stream_port :: Int) do
  let _ = start_registry(pool)
  start_mailbox_stream(stream_port)
  case start_workers(2, 250) do
    Err(error) -> do
      Pool.close(pool)
      fatal("worker startup failed: #{error}")
    end
    Ok(count) -> do
      println("directory-delivery listening on :#{port} with #{count} workers")
      HTTP.serve(build_router(), port)
      Pool.close(pool)
      if !Process.shutdown_requested() do
        fatal("directory-delivery HTTP server failed")
      else
        nil
      end
    end
  end
end

fn main() do
  Process.install_shutdown_signals()
  let url = Env.get("MESSENGER_DATABASE_URL",
  "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let port = Env.get_int("MESSENGER_PORT", 18086)
  let stream_port = Env.get_int("MESSENGER_STREAM_PORT", 18090)
  let difficulty = Env.get_int("MESSENGER_ABUSE_DIFFICULTY", 16)
  if difficulty < 1 || difficulty > 24 do
    fatal("MESSENGER_ABUSE_DIFFICULTY must be between 1 and 24")
  else
    nil
  end
  case internal_delivery_token(Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", "")) do
    Err(error) -> fatal("ingress configuration failed: #{error}")
    Ok(_) -> case validate_transparency_config() do
      Err(error) -> fatal("transparency configuration failed: #{error}")
      Ok(_) -> case validate_delivery_config() do
        Err(error) -> fatal("delivery configuration failed: #{error}")
        Ok(_) -> if port <= 0 || port > 65535 || stream_port <= 0 || stream_port > 65535 || stream_port == port do
          fatal("HTTP and stream ports must be distinct and between 1 and 65535")
        else
          case Pool.open(url, 1, 4, 5000) do
            Err(error) -> fatal("database connection failed: #{error}")
            Ok(pool) -> serve(pool, port, stream_port)
          end
        end
      end
    end
  end
end
