##! morse-monitor: follows a Morse transparency log's anchor ring on Solana,
##! checks every anchored checkpoint against the one before it and against
##! the directory, files fork proofs with relays, and serves a status page.
##! See README.md for the checks, the flags and how to run it.
##!
##! Exit codes: 0 stopped cleanly (or --once found nothing), 1 configuration
##! or state error, 2 --once found an inconsistency (a P0 finding).

from Monitor.Flags import MonitorConfig, monitor_config_parse
from Monitor.Cycle import monitor_cycle, monitor_p0_count
from Monitor.Status import monitor_serve
from Monitor.Store import monitor_store_open

fn now_ms() -> Int do
  DateTime.to_unix_ms(DateTime.utc_now())
end

fn cycle(config :: MonitorConfig) do
  case monitor_cycle(config, now_ms()) do
    Err(reason) -> io_eprintln("morse-monitor: cycle failed: #{reason}")
    Ok(_) -> nil
  end
end

fn wait(remaining_ms :: Int) do
  if remaining_ms > 0 && !Process.shutdown_requested() do
    Timer.sleep(1000)
    wait(remaining_ms - 1000)
  end
end

fn watch(config :: MonitorConfig) -> Int!String do
  cycle(config)
  if Process.shutdown_requested() do
    Ok(0)
  else
    wait(config.interval_ms)
    watch(config)
  end
end

fn run() -> Int!String do
  let config = monitor_config_parse(List.drop(Env.args(), 1))?
  # Creates the state (and checks it opens) before anything reads it.
  Sqlite.close(monitor_store_open(config.state_path)?)
  if config.once do
    monitor_cycle(config, now_ms())?
    if monitor_p0_count(config)? > 0 do
      Ok(2)
    else
      Ok(0)
    end
  else
    Process.install_shutdown_signals()
    if config.listen > 0 do
      monitor_serve(config.listen, config.state_path)
    end
    println("morse-monitor watching #{config.log_name} every #{config.interval_ms / 1000} s")
    watch(config)
  end
end

fn main() do
  case run() do
    Err(error) -> do
      io_eprintln("morse-monitor: #{error}")
      Process.exit(1)
    end
    Ok(0) -> nil
    Ok(code) -> Process.exit(code)
  end
end
