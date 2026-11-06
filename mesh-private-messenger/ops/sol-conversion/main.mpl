from Runtime.SolConversionConfig import parse_sol_conversion_operator
from Runtime.SolConversionNetwork import (
  SolConversionConfig,
  refresh_unsigned_weekly_sol_conversion,
  prepare_weekly_sol_conversion,
  commit_weekly_sol_conversion,
  submit_weekly_sol_conversion,
  reconcile_weekly_sol_conversion
)
from Storage.SolConversion import load_sol_conversion, StoredSolConversion

fn small(value :: String) -> Int!String do
  case String.to_int(value) do
    Some(v) -> Ok(v)
    None -> Err("invalid_conversion_argument")
  end
end

fn dispatch(pool :: PoolHandle,
  config :: SolConversionConfig,
  args :: List<String>) -> StoredSolConversion!String do
  let action = List.get(args, 2)
  if action == "prepare" && List.length(args) == 6 do
    let saved = prepare_weekly_sol_conversion(pool,
      config,
      U64.parse(List.get(args, 3))?,
      small(List.get(args, 4))?)?
    File.write(List.get(args, 5), Bytes.to_base64(saved.plan.message))?
    Ok(saved)
  else if action == "refresh-unsigned" && List.length(args) == 5 do
    let saved = refresh_unsigned_weekly_sol_conversion(pool,
      config,
      Bytes.from_hex(List.get(args, 3))?)?
    File.write(List.get(args, 4), Bytes.to_base64(saved.plan.message))?
    Ok(saved)
  else if action == "commit" && List.length(args) == 6 do
    let raw = File.read(List.get(args, 5))?
    if Bytes.length(Bytes.from_utf8(raw)) > 2048 do
      return Err("conversion_packet_size")
    end
    commit_weekly_sol_conversion(pool,
      config,
      Bytes.from_hex(List.get(args, 3))?,
      small(List.get(args, 4))?,
      Bytes.from_base64(raw)?)
  else if (action == "submit" || action == "reconcile" || action == "status")
    && List.length(args) == 4 do
    let id = Bytes.from_hex(List.get(args, 3))?
    if action == "submit" do
      submit_weekly_sol_conversion(pool, config, id)
    else if action == "reconcile" do
      reconcile_weekly_sol_conversion(pool, config, id)
    else
      Repo.transaction(pool,
        fn(conn :: borrow PgConn) do load_sol_conversion(conn, config.profile, id) end)
    end
  else
    Err("conversion_usage")
  end
end

fn execute() -> Result<(), String> do
  let args = Env.args()
  if List.length(args) < 4 do
    return Err("conversion_usage")
  end
  let config = parse_sol_conversion_operator(File.read(List.get(args, 1))?)?
  let pool = Pool.open(config.database_url, 1, 4, 5000)?
  let result = dispatch(pool, config.worker, args)
  Pool.close(pool)
  let saved = result?
  println("{\"intent_id\":"
    <> Json.encode_string(Bytes.to_hex(saved.plan.intent_id))
    <> ",\"attempt\":"
    <> Int.to_string(saved.ordinal)
    <> ",\"state\":"
    <> Int.to_string(saved.state)
    <> "}")
  Ok(nil)
end

fn main() do
  case execute() do
    Ok(_) -> nil
    Err(_) -> do
      io_eprintln("SOL conversion command failed; exact pending state is preserved")
      Process.exit(1)
    end
  end
end
