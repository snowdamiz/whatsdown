from Broker.Expo import prepare_expo_request_with_key
from Push.Token import decode_push_wake
import RuntimeJobs

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

fn configure(database :: borrow PgConn) -> Result <(), String > do
  let _ = Pg.execute(database, "SET statement_timeout = '10s'", []) ?
  Ok(nil)
end

fn schema(database :: borrow PgConn) -> Result <(), String > do
  let _ = Pg.execute(database,
  "CREATE TABLE IF NOT EXISTS broker_jobs (wake_hash TEXT PRIMARY KEY CHECK(length(wake_hash) = 64), request_hash TEXT NOT NULL CHECK(length(request_hash) = 64), sealed_request TEXT NOT NULL CHECK(length(sealed_request) BETWEEN 1 AND 828), state TEXT NOT NULL CHECK(state IN ('pending', 'retry_send', 'receipt', 'retry_receipt', 'terminal')), ticket_id TEXT NOT NULL DEFAULT '' CHECK(length(ticket_id) <= 256), attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0), next_attempt_ms BIGINT NOT NULL CHECK(next_attempt_ms >= 0), updated_ms BIGINT NOT NULL CHECK(updated_ms >= 0))",
  []) ?
  let _ = Pg.execute(database,
  "CREATE INDEX IF NOT EXISTS broker_jobs_due ON broker_jobs (state, next_attempt_ms)",
  []) ?
  let _ = Pg.execute(database,
  "CREATE OR REPLACE FUNCTION messenger_broker_capacity() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(1835365487); IF (SELECT count(*) FROM broker_jobs) >= 100000 AND NOT EXISTS (SELECT 1 FROM broker_jobs WHERE wake_hash = NEW.wake_hash) THEN RAISE EXCEPTION 'broker queue full'; END IF; RETURN NEW; END; $$",
  []) ?
  let _ = Pg.execute(database,
  "CREATE OR REPLACE TRIGGER broker_jobs_capacity BEFORE INSERT ON broker_jobs FOR EACH ROW EXECUTE FUNCTION messenger_broker_capacity()",
  []) ?
  Ok(nil)
end

fn initialize_open(database :: borrow PgConn) -> Result <(), String > do
  configure(database) ?
  schema(database)
end

pub fn initialize(path :: String) -> Result <(), String > do
  if String.length(path) == 0 || String.length(path) > 4096 || path == ":memory:" do
    Err("invalid broker queue path")
  else
    case Pg.connect(path) do
      Err(_) -> Err("broker queue unavailable")
      Ok(database) -> case initialize_open(database) do
        Err(_) -> do
          Pg.close(database)
          Err("broker queue unavailable")
        end
        Ok(_) -> do
          Pg.close(database)
          Ok(nil)
        end
      end
    end
  end
end

fn enqueue_open(database :: borrow PgConn, input :: Bytes, now_ms :: Int) -> EnqueueOutcome ! String do
  configure(database) ?
  Pg.begin(database) ?
  let wake = decode_push_wake(input) ?
  let wake_hash = Bytes.to_hex(wake.wake_token_hash)
  let request_hash = Bytes.to_hex(Crypto.sha256(input))
  let changed = Pg.execute(database,
  "INSERT INTO broker_jobs (wake_hash, request_hash, sealed_request, state, ticket_id, attempts, next_attempt_ms, updated_ms) VALUES ($1, $2, $3, 'pending', '', 0, $4, $5) ON CONFLICT(wake_hash) DO UPDATE SET request_hash = excluded.request_hash, sealed_request = excluded.sealed_request, state = 'pending', ticket_id = '', attempts = 0, next_attempt_ms = excluded.next_attempt_ms, updated_ms = excluded.updated_ms WHERE broker_jobs.request_hash <> excluded.request_hash",
  [wake_hash, request_hash, Bytes.to_base64(input), Int.to_string(now_ms), Int.to_string(now_ms)]) ?
  if changed > 0 do
    RuntimeJobs.notify(database, "push") ?
  end
  Pg.commit(database) ?
  if changed == 0 do
    Ok(QueueCoalesced)
  else
    Ok(QueueAccepted)
  end
end

fn enqueue_prepared(path :: String, input :: Bytes, now_ms :: Int) -> EnqueueOutcome ! String do
  let database = Pg.connect(path) ?
  case enqueue_open(database, input, now_ms) do
    Err(_) -> do
      let _ = Pg.rollback(database)
      Pg.close(database)
      Err("broker queue unavailable")
    end
    Ok(outcome) -> do
      Pg.close(database)
      Ok(outcome)
    end
  end
end

pub fn transaction_in_progress(path :: String, id :: String) -> Bool ! String do
  let database = Pg.connect(path) ?
  let result = RuntimeJobs.in_progress(database, id)
  Pg.close(database)
  result
end

pub fn next_work_at(path :: String) -> Int ! String do
  let database = Pg.connect(path) ?
  let rows = Pg.query(database,
  "SELECT COALESCE(min(CASE WHEN state = 'terminal' THEN updated_ms + 604800001 ELSE next_attempt_ms END), 0)::text AS due FROM broker_jobs",
  [])
  Pg.close(database)
  RuntimeJobs.due_time(rows ?)
end

pub fn enqueue_with_key(path :: String,
input :: Bytes,
broker_private_key :: borrow X25519PrivateKey,
now_ms :: Int) -> Result < EnqueueOutcome, String > do
  if now_ms < 0 do
    Err("invalid broker time")
  else
    case prepare_expo_request_with_key(input, broker_private_key) do
      Err(_) -> Err("broker queue unavailable")
      Ok(_) -> enqueue_prepared(path, input, now_ms)
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
    Some(value) -> Ok(value)
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
    case Pg.connect(path) do
      Err(_) -> Err("broker queue unavailable")
      Ok(database) -> do
        let result = case configure(database) do
          Err(error) -> Err(error)
          Ok(_) -> case Pg.query(database,
          "SELECT wake_hash, request_hash, sealed_request, state, ticket_id, attempts FROM broker_jobs WHERE state IN ('pending', 'retry_send', 'receipt', 'retry_receipt') AND next_attempt_ms <= $1 ORDER BY next_attempt_ms, updated_ms, wake_hash LIMIT 1",
          [Int.to_string(now_ms)]) do
            Err(error) -> Err(error)
            Ok([]) -> Ok(None)
            Ok([row]) -> case decode_job(row) do
              Err(error) -> Err(error)
              Ok(job) -> Ok(Some(job))
            end
            Ok(_) -> Err("invalid broker queue state")
          end
        end
        Pg.close(database)
        case result do
          Err(_) -> Err("broker queue unavailable")
          Ok(job) -> Ok(job)
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
  case Pg.connect(path) do
    Err(_) -> Err("broker queue unavailable")
    Ok(database) -> do
      let configured = configure(database)
      let result = case configured do
        Err(error) -> Err(error)
        Ok(_) -> Pg.execute(database, sql, List.concat(values, [wake_hash, request_hash]))
      end
      Pg.close(database)
      case result do
        Err(_) -> Err("broker queue unavailable")
        Ok(changed) -> if changed == 1 do
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
  "UPDATE broker_jobs SET state = 'terminal', ticket_id = '', updated_ms = $1 WHERE wake_hash = $2 AND request_hash = $3",
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
    "UPDATE broker_jobs SET state = 'receipt', ticket_id = $1, attempts = 0, next_attempt_ms = $2, updated_ms = $3 WHERE wake_hash = $4 AND request_hash = $5 AND state IN ('pending', 'retry_send')",
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
      "UPDATE broker_jobs SET state = $1, attempts = $2, next_attempt_ms = $3, updated_ms = $4 WHERE wake_hash = $5 AND request_hash = $6 AND state IN ('pending', 'retry_send', 'receipt', 'retry_receipt')",
      job.wake_hash,
      job.request_hash,
      [state, Int.to_string(attempts), Int.to_string(now_ms + retry_delay_ms(job.attempts)), Int.to_string(now_ms)])
    end
  end
end

pub fn complete_job(path :: String, job :: QueueJob, now_ms :: Int) -> Result <(), String > do
  update_exact(path,
  "UPDATE broker_jobs SET state = 'terminal', ticket_id = '', updated_ms = $1 WHERE wake_hash = $2 AND request_hash = $3 AND state IN ('receipt', 'retry_receipt')",
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
    case Pg.connect(path) do
      Err(_) -> Err("broker queue unavailable")
      Ok(database) -> do
        let result = case configure(database) do
          Err(error) -> Err(error)
          Ok(_) -> Pg.execute(database,
          "DELETE FROM broker_jobs WHERE wake_hash IN (SELECT wake_hash FROM broker_jobs WHERE state = 'terminal' AND updated_ms < $1 ORDER BY updated_ms, wake_hash LIMIT $2)",
          [Int.to_string(older_than_ms), Int.to_string(limit)])
        end
        Pg.close(database)
        case result do
          Err(_) -> Err("broker queue unavailable")
          Ok(changed) -> Ok(changed)
        end
      end
    end
  end
end
