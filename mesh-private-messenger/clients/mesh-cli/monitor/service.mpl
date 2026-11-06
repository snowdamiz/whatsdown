from Monitor.Command import MonitorCommand, parse_monitor_command
from Monitor.Config import MonitorConfig, configured_monitor
from Monitor.Run import run_monitor_once
from Monitor.State import load_monitor_state
from Monitor.Status import serve_monitor_status

fn wait_for_poll(remaining :: Int) do
  if remaining > 0 && !Process.shutdown_requested() do
    Timer.sleep(250)
    wait_for_poll(remaining - 250)
  end
end

actor monitor_worker(config :: MonitorConfig) do
  while !Process.shutdown_requested() do
    case run_monitor_once(config, DateTime.to_unix_ms(DateTime.utc_now())) do
      Err(error) -> io_eprintln("monitor failed: #{error}")
      Ok(report) -> println(report)
    end
    wait_for_poll(15000)
  end
end

pub fn run_monitor_command(args :: List<String>) -> Int!String do
  let command = parse_monitor_command(args)?
  let config = configured_monitor(command.log_name)?
  load_monitor_state(config.path, config.identity)?
  if command.once do
    let report = run_monitor_once(config, DateTime.to_unix_ms(DateTime.utc_now()))?
    println(report)
    let healthy = Json.as_bool(Json.object_get(Json.parse(report)?, "healthy")?)?
    Ok(if healthy do
      0
    else
      2
    end)
  else
    Process.install_shutdown_signals()
    let _worker = spawn(monitor_worker, config)
    serve_monitor_status(config, command.port)
    Ok(0)
  end
end
