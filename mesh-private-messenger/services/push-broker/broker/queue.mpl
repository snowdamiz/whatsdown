from Broker.Expo import prepare_expo_request
from Push.Token import decode_push_wake

pub type EnqueueOutcome do
  QueueAccepted

  QueueCoalesced
end deriving(Eq, Debug)

pub struct QueueJob do
  wake_hash :: String
  request_hash :: String
  sealed_request :: Bytes
  state :: String
  ticket_id :: String
  attempts :: Int
end

fn configure(database :: SqliteConn) -> Result <(), String > do
  let _ = Sqlite.execute(database, "PRAGMA busy_timeout = 5000", []) ?
  let _ = Sqlite.execute(database, "PRAGMA foreign_keys = ON", []) ?
  let _ = Sqlite.execute(database, "PRAGMA synchronous = FULL", []) ?
  Ok(nil)
end

fn schema(database :: SqliteConn) -> Result <(), String > do
  let _ = Sqlite.execute(database, "PRAGMA journal_mode = WAL", []) ?
  let _ = Sqlite.execute(database,
  "CREATE TABLE IF NOT EXISTS broker_jobs (wake_hash TEXT PRIMARY KEY CHECK(length(wake_hash) = 64), request_hash TEXT NOT NULL CHECK(length(request_hash) = 64), sealed_request TEXT NOT NULL CHECK(length(sealed_request) BETWEEN 1 AND 828), state TEXT NOT NULL CHECK(state IN ('pending', 'retry_send', 'receipt', 'retry_receipt', 'terminal')), ticket_id TEXT NOT NULL DEFAULT '' CHECK(length(ticket_id) <= 256), attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0), next_attempt_ms INTEGER NOT NULL CHECK(next_attempt_ms >= 0), updated_ms INTEGER NOT NULL CHECK(updated_ms >= 0)) STRICT",
  []) ?
  let _ = Sqlite.execute(database,
  "CREATE INDEX IF NOT EXISTS broker_jobs_due ON broker_jobs (state, next_attempt_ms)",
  []) ?
  let _ = Sqlite.execute(database,
  "CREATE TRIGGER IF NOT EXISTS broker_jobs_capacity BEFORE INSERT ON broker_jobs WHEN (SELECT count(*) FROM broker_jobs) >= 100000 AND NOT EXISTS (SELECT 1 FROM broker_jobs WHERE wake_hash = NEW.wake_hash) BEGIN SELECT RAISE(ABORT, 'broker queue full'); END",
  []) ?
  Ok(nil)
end

fn initialize_open(database :: SqliteConn) -> Result <(), String > do
  configure(database) ?
  schema(database)
end

pub fn initialize(path :: String) -> Result <(), String > do
  if String.length(path) == 0 || String.length(path) > 4096 || path == ":memory:" do
    Err("invalid broker queue path")
  else
    case Sqlite.open(path) do
      Err( _) -> Err("broker queue unavailable")
      Ok( database) -> case initialize_open(database) do
        Err( _) -> do
          Sqlite.close(database)
          Err("broker queue unavailable")
        end
        Ok( _) -> do
          Sqlite.close(database)
          Ok(nil)
        end
      end
    end
  end
end

pub fn enqueue(path :: String, input :: Bytes, broker_private_seed :: Bytes, now_ms :: Int) -> Result < EnqueueOutcome, String > do
  if now_ms < 0 do
    Err("invalid broker time")
  else
    case Sqlite.open(path) do
      Err( _) -> Err("broker queue unavailable")
      Ok( database) -> do
        let result = case configure(database) do
          Err( error) -> Err(error)
          Ok( _) -> case prepare_expo_request(input, broker_private_seed) do
            Err( error) -> Err(error)
            Ok( _) -> case decode_push_wake(input) do
              Err( error) -> Err(error)
              Ok( wake) -> do
                let wake_hash = Bytes.to_hex(wake.wake_token_hash)
                let request_hash = Bytes.to_hex(Crypto.sha256(input))
                case Sqlite.execute(database,
                "INSERT INTO broker_jobs (wake_hash, request_hash, sealed_request, state, ticket_id, attempts, next_attempt_ms, updated_ms) VALUES (?, ?, ?, 'pending', '', 0, ?, ?) ON CONFLICT(wake_hash) DO UPDATE SET request_hash = excluded.request_hash, sealed_request = excluded.sealed_request, state = 'pending', ticket_id = '', attempts = 0, next_attempt_ms = excluded.next_attempt_ms, updated_ms = excluded.updated_ms WHERE broker_jobs.request_hash <> excluded.request_hash",
                [wake_hash, request_hash, Bytes.to_base64(input), Int.to_string(now_ms), Int.to_string(now_ms)]) do
                  Err( error) -> Err(error)
                  Ok( changed) -> if changed == 0 do
                    Ok(QueueCoalesced)
                  else
                    Ok(QueueAccepted)
                  end
                end
              end
            end
          end
        end
        Sqlite.close(database)
        case result do
          Err( _) -> Err("broker queue unavailable")
          Ok( outcome) -> Ok(outcome)
        end
      end
    end
  end
end

fn decode_job(row :: Map < String, String >) -> Result < QueueJob, String > do
  let wake_hash = Map.get(row, "wake_hash")
  let request_hash = Map.get(row, "request_hash")
  let sealed_request = Bytes.from_base64(Map.get(row, "sealed_request")) ?
  let state = Map.get(row, "state")
  let ticket_id = Map.get(row, "ticket_id")
  let attempts = case String.to_int(Map.get(row, "attempts")) do
    None -> Err("invalid broker queue state")
    Some( value) -> Ok(value)
  end ?
  if String.length(wake_hash) != 64 || String.length(request_hash) != 64 || Bytes.length(sealed_request) == 0 || Bytes.length(sealed_request) > 621 || Bytes.to_hex(Crypto.sha256(sealed_request)) != request_hash || attempts < 0 do
    Err("invalid broker queue state")
  else
    Ok(QueueJob {
      wake_hash : wake_hash,
      request_hash : request_hash,
      sealed_request : sealed_request,
      state : state,
      ticket_id : ticket_id,
      attempts : attempts
    })
  end
end

pub fn next_job(path :: String, now_ms :: Int) -> Result < Option < QueueJob >, String > do
  if now_ms < 0 do
    Err("invalid broker time")
  else
    case Sqlite.open(path) do
      Err( _) -> Err("broker queue unavailable")
      Ok( database) -> do
        let result = case configure(database) do
          Err( error) -> Err(error)
          Ok( _) -> case Sqlite.query(database,
          "SELECT wake_hash, request_hash, sealed_request, state, ticket_id, attempts FROM broker_jobs WHERE state IN ('pending', 'retry_send', 'receipt', 'retry_receipt') AND next_attempt_ms <= ? ORDER BY next_attempt_ms, updated_ms, wake_hash LIMIT 1",
          [Int.to_string(now_ms)]) do
            Err( error) -> Err(error)
            Ok( rows) -> if List.length(rows) == 0 do
              Ok(None)
            else if List.length(rows) == 1 do
              case decode_job(List.head(rows)) do
                Err( error) -> Err(error)
                Ok( job) -> Ok(Some(job))
              end
            else
              Err("invalid broker queue state")
            end
          end
        end
        Sqlite.close(database)
        case result do
          Err( _) -> Err("broker queue unavailable")
          Ok( job) -> Ok(job)
        end
      end
    end
  end
end

fn update_exact(path :: String,
sql :: String,
wake_hash :: String,
request_hash :: String,
values :: List < String >) -> Result <(), String > do
  case Sqlite.open(path) do
    Err( _) -> Err("broker queue unavailable")
    Ok( database) -> do
      let configured = configure(database)
      let result = case configured do
        Err( error) -> Err(error)
        Ok( _) -> Sqlite.execute(database, sql, List.concat(values, [wake_hash, request_hash]))
      end
      Sqlite.close(database)
      case result do
        Err( _) -> Err("broker queue unavailable")
        Ok( changed) -> if changed == 1 do
          Ok(nil)
        else
          Err("stale broker queue job")
        end
      end
    end
  end
end

pub fn mark_terminal(path :: String, wake_hash :: String, request_hash :: String, now_ms :: Int) -> Result <(), String > do
  update_exact(path,
  "UPDATE broker_jobs SET state = 'terminal', ticket_id = '', updated_ms = ? WHERE wake_hash = ? AND request_hash = ?",
  wake_hash,
  request_hash,
  [Int.to_string(now_ms)])
end

pub fn record_ticket(path :: String, job :: QueueJob, ticket_id :: String, now_ms :: Int) -> Result <(), String > do
  if String.length(ticket_id) == 0 || String.length(ticket_id) > 256 || now_ms < 0 || String.contains(ticket_id,
  "\r") || String.contains(ticket_id, "\n") do
    Err("invalid Expo ticket")
  else
    update_exact(path,
    "UPDATE broker_jobs SET state = 'receipt', ticket_id = ?, attempts = 0, next_attempt_ms = ?, updated_ms = ? WHERE wake_hash = ? AND request_hash = ? AND state IN ('pending', 'retry_send')",
    job.wake_hash,
    job.request_hash,
    [ticket_id, Int.to_string(now_ms + 900000), Int.to_string(now_ms)])
  end
end

fn bounded_delay(remaining :: Int, delay_ms :: Int) -> Int do
  if remaining <= 0 || delay_ms >= 900000 do
    delay_ms
  else if delay_ms > 450000 do
    900000
  else
    bounded_delay(remaining - 1, delay_ms * 2)
  end
end

pub fn retry_delay_ms(attempts :: Int) -> Int do
  if attempts <= 0 do
    1000
  else if attempts >= 30 do
    900000
  else
    bounded_delay(attempts, 1000)
  end
end

pub fn retry_job(path :: String, job :: QueueJob, now_ms :: Int) -> Result <(), String > do
  if now_ms < 0 || job.attempts < 0 do
    Err("invalid broker retry")
  else
    let state = if job.state == "pending" || job.state == "retry_send" do
      "retry_send"
    else if job.state == "receipt" || job.state == "retry_receipt" do
      "retry_receipt"
    else
      ""
    end
    if String.length(state) == 0 do
      Err("invalid broker retry state")
    else
      let attempts = if job.attempts >= 30 do
        30
      else
        job.attempts + 1
      end
      update_exact(path,
      "UPDATE broker_jobs SET state = ?, attempts = ?, next_attempt_ms = ?, updated_ms = ? WHERE wake_hash = ? AND request_hash = ? AND state IN ('pending', 'retry_send', 'receipt', 'retry_receipt')",
      job.wake_hash,
      job.request_hash,
      [state, Int.to_string(attempts), Int.to_string(now_ms + retry_delay_ms(job.attempts)), Int.to_string(now_ms)])
    end
  end
end

pub fn complete_job(path :: String, job :: QueueJob, now_ms :: Int) -> Result <(), String > do
  update_exact(path,
  "UPDATE broker_jobs SET state = 'terminal', ticket_id = '', updated_ms = ? WHERE wake_hash = ? AND request_hash = ? AND state IN ('receipt', 'retry_receipt')",
  job.wake_hash,
  job.request_hash,
  [Int.to_string(now_ms)])
end

pub fn tombstone_cutoff_ms(now_ms :: Int) -> Int do
  if now_ms <= 604800000 do
    0
  else
    now_ms - 604800000
  end
end

pub fn purge_tombstones(path :: String, older_than_ms :: Int, limit :: Int) -> Int ! String do
  if older_than_ms < 0 || limit <= 0 || limit > 1000 do
    Err("invalid tombstone purge")
  else
    case Sqlite.open(path) do
      Err( _) -> Err("broker queue unavailable")
      Ok( database) -> do
        let result = case configure(database) do
          Err( error) -> Err(error)
          Ok( _) -> Sqlite.execute(database,
          "DELETE FROM broker_jobs WHERE wake_hash IN (SELECT wake_hash FROM broker_jobs WHERE state = 'terminal' AND updated_ms < ? ORDER BY updated_ms, wake_hash LIMIT ?)",
          [Int.to_string(older_than_ms), Int.to_string(limit)])
        end
        Sqlite.close(database)
        case result do
          Err( _) -> Err("broker queue unavailable")
          Ok( changed) -> Ok(changed)
        end
      end
    end
  end
end
