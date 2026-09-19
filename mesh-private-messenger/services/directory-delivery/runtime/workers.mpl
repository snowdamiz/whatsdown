from Storage.Outbox import finish_outbox, lease_outbox
from Storage.Retention import purge_envelopes
from Runtime.Registry import get_pool
from Runtime.PushDispatch import dispatch_configured_push
from Runtime.MailboxStream import wake_mailbox
import RuntimeJobs

pub fn transaction_in_progress(pool :: PoolHandle, id :: String) -> Bool ! String do
  Repo.transaction(pool, fn (conn :: borrow PgConn) -> RuntimeJobs.in_progress(conn, id) end)
end

pub fn next_work_at(pool :: PoolHandle) -> Int ! String do
  RuntimeJobs.due_time(Pool.query(pool,
  "SELECT COALESCE(min(due), 0)::text AS due FROM (SELECT floor(extract(epoch FROM CASE WHEN status = 'leased' THEN lease_expires_at ELSE available_at END) * 1000)::bigint AS due FROM messenger_outbox_events WHERE completed_at IS NULL UNION ALL SELECT LEAST(expiration_ms, COALESCE(floor(extract(epoch FROM acknowledged_at) * 1000)::bigint + 3600000, expiration_ms)) AS due FROM messenger_envelopes) AS deadlines",
  []) ?)
end

fn drain_outbox(pool :: PoolHandle, owner :: String, remaining :: Int) -> Result <(), String > do
  if remaining <= 0 do
    Ok(nil)
  else if process_outbox_once(pool, owner) ? do
    drain_outbox(pool, owner, remaining - 1)
  else
    Ok(nil)
  end
end

pub fn run_scheduled(pool :: PoolHandle) -> Int ! String do
  let random = case Crypto.random_bytes(16) do
    Err( _) -> Err("worker identity generation failed")
    Ok( value) -> Ok(value)
  end ?
  drain_outbox(pool, "scheduled-" <> Bytes.to_hex(random), 4) ?
  let _ = purge_envelopes(pool, 3600, 128) ?
  next_work_at(pool)
end

fn process_outbox_once(pool :: PoolHandle, owner :: String) -> Bool ! String do
  let events = lease_outbox(pool, owner, 1, 30) ?
  if List.length(events) == 0 do
    Ok(false)
  else
    let event = List.head(events)
    wake_mailbox(event.mailbox_token_hash)
    finish_outbox(pool, event, owner, dispatch_configured_push(pool, event) ?) ?
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
  if RuntimeJobs.enabled() do
    Ok(0)
  else if outbox_count <= 0 || outbox_count > 16 || polling_ms < 10 || polling_ms > 60000 do
    Err("invalid worker configuration")
  else
    let count = start_outbox_workers(outbox_count, polling_ms, 0) ?
    spawn(retention_worker, 60000)
    Ok(count + 1)
  end
end
