from Monitor.Command import MonitorCommand, parse_monitor_command

fn proof() -> Bool!String do
  let command = parse_monitor_command(["mesh-cli", "monitor", "--log", "morse-main"])?
  assert(command.log_name == "morse-main" && !command.once && command.port == 18100)
  let once = parse_monitor_command([
    "mesh-cli",
    "monitor",
    "--once",
    "--port",
    "18101",
    "--log",
    "morse-canary"
  ])?
  assert(once.once && once.port == 18101 && once.log_name == "morse-canary")
  for args in [
    ["mesh-cli", "monitor"],
    ["mesh-cli", "monitor", "--log", "morse-main", "--log", "morse-canary"],
    ["mesh-cli", "monitor", "--log", "morse-main", "--once", "--once"],
    ["mesh-cli", "monitor", "--log", "morse-main", "--port", "018100"],
    ["mesh-cli", "monitor", "--log", "morse-main", "--port", "0"],
    ["mesh-cli", "monitor", "--log", "morse-main", "--port", "65536"],
    ["mesh-cli", "monitor", "--log", "../log"],
    ["mesh-cli", "monitor", "--log", "morse-main", "extra"]
  ] do
    case parse_monitor_command(args) do
      Err(_) -> nil
      Ok(_) -> assert(false)
    end
  end
  Ok(true)
end

test("monitor CLI requires an explicit log and rejects ambiguous or repeated options") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
