from Api.Router import build_router
from Runtime.Registry import start_registry

fn serve(pool :: PoolHandle, port :: Int) do
  let _ = start_registry(pool)
  println("directory-delivery listening on :#{port}")
  HTTP.serve(build_router(), port)
end

fn main() do
  let url = Env.get("MESSENGER_DATABASE_URL",
  "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let port = Env.get_int("MESSENGER_PORT", 18086)
  if port <= 0 || port > 65535 do
    println("MESSENGER_PORT must be between 1 and 65535")
  else
    case Pool.open(url, 1, 4, 5000) do
      Err( error) -> println("database connection failed: #{error}")
      Ok( pool) -> serve(pool, port)
    end
  end
end
