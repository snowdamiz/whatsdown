from Command import parse_command
from Operations import run_action

fn execute() -> String!String do
  let (action, limit) = parse_command(Env.args())?
  let url = Env.get("MESSENGER_DATABASE_URL", "")
  if url == "" do
    return Err("MESSENGER_DATABASE_URL is required")
  end
  let pool = Pool.open(url, 1, 2, 5000)?
  let result = run_action(pool, action, limit, Env.get("MESSENGER_SECURITY_CONFIG", ""))
  Pool.close(pool)
  result
end

fn main() do
  case execute() do
    Err(error) -> do
      io_eprintln(error)
      Process.exit(1)
    end
    Ok(value) -> println(value)
  end
end
