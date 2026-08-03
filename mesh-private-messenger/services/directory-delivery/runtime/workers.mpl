from Storage.Outbox import finish_outbox, lease_outbox
from Storage.Retention import purge_envelopes
from Runtime.Registry import get_pool
from Runtime.PushDispatch import dispatch_push

fn process_outbox_once(pool :: PoolHandle, owner :: String) -> Bool ! String do
  let events = lease_outbox(pool, owner, 1, 30) ?
  if List.length(events) == 0 do
    Ok(false)
  else
    let event = List.head(events)
    finish_outbox(pool,
    event,
    owner,
    dispatch_push(pool, event, Env.get("MESSENGER_LOCAL_FAKE_PUSH_AVAILABLE", "true") != "false") ?) ?
    Ok(true)
  end
end

fn outbox_loop(owner :: String, polling_ms :: Int) do
  if Process.shutdown_requested() do
    nil
  else
    case process_outbox_once(get_pool(), owner) do
      Err( _) -> println("outbox worker failed")
      Ok( _) -> nil
    end
    Timer.sleep(polling_ms)
    outbox_loop(owner, polling_ms)
  end
end

actor outbox_worker(owner :: String, polling_ms :: Int) do
  outbox_loop(owner, polling_ms)
end

fn run_retention() do
  case purge_envelopes(get_pool(), 3600, 128) do
    Err( _) -> println("retention worker failed")
    Ok( _) -> nil
  end
end

fn retention_loop(interval_ms :: Int, elapsed_ms :: Int) do
  if Process.shutdown_requested() do
    nil
  else
    let next_elapsed = if elapsed_ms >= interval_ms do
      run_retention()
      0
    else
      elapsed_ms
    end
    Timer.sleep(250)
    retention_loop(interval_ms, next_elapsed + 250)
  end
end

actor retention_worker(interval_ms :: Int) do
  retention_loop(interval_ms, interval_ms)
end

fn start_outbox_workers(count :: Int, polling_ms :: Int, index :: Int) -> Int ! String do
  if index >= count do
    Ok(count)
  else
    case Crypto.random_bytes(16) do
      Err( _) -> Err("worker identity generation failed")
      Ok( random) -> do
        let owner = "outbox-#{Bytes.to_hex(random)}"
        spawn(outbox_worker, owner, polling_ms)
        start_outbox_workers(count, polling_ms, index + 1)
      end
    end
  end
end

pub fn start_workers(outbox_count :: Int, polling_ms :: Int) -> Int ! String do
  if outbox_count <= 0 || outbox_count > 16 || polling_ms < 10 || polling_ms > 60000 do
    Err("invalid worker configuration")
  else
    let count = start_outbox_workers(outbox_count, polling_ms, 0) ?
    spawn(retention_worker, 60000)
    Ok(count + 1)
  end
end
