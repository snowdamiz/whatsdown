from Broker.Expo import BrokerOutcome, classify_expo_receipt, parse_expo_ticket, prepare_expo_request_with_key, receipt_message
from Broker.Queue import EnqueueOutcome, QueueJob, complete_job, enqueue_with_key, mark_terminal, next_job, purge_tombstones, record_ticket, retry_job, tombstone_cutoff_ms
from Broker.Queue import next_work_at
import RuntimeJobs

fn drain_due(path :: String,
  private_key :: borrow X25519PrivateKey,
  token :: String,
  remaining :: Int) -> Result<(), String> do
  if remaining <= 0 do
    Ok(nil)
  else if process_once_with_key(path, private_key, token, DateTime.to_unix_ms(DateTime.utc_now()))? do
    drain_due(path, private_key, token, remaining - 1)
  else
    Ok(nil)
  end
end

pub fn run_scheduled(path :: String, token :: String) -> Int!String do
  let private_key = broker_private_key()?
  drain_due(path, private_key, token, 4)?
  purge_tombstones(path, tombstone_cutoff_ms(DateTime.to_unix_ms(DateTime.utc_now())), 256)?
  next_work_at(path)
end

pub fn expo_send_url() -> String do
  "https://exp.host/--/api/v2/push/send"
end

pub fn expo_receipts_url() -> String do
  "https://exp.host/--/api/v2/push/getReceipts"
end

pub fn broker_private_key() -> X25519PrivateKey!String do
  let material = case Env.get_secret_hex("MESSENGER_PUSH_BROKER_SEED_HEX") do
    Err(_) -> Err("invalid broker seed")
    Ok(value)
  end?
  case Crypto.x25519_from_secret(material) do
    Err(_) -> Err("invalid broker seed")
    Ok(pair) -> Ok(pair.private_key)
  end
end

pub fn provider_url(value :: String) -> String!String do
  if value != expo_send_url() do
    Err("invalid Expo provider URL")
  else
    Ok(value)
  end
end

pub fn access_token(value :: String) -> Option<String>!String do
  if String.length(value) == 0 do
    Ok(None)
  else if String.length(value) > 2048 || String.trim(value) != value || String.contains(value, "\r") || String.contains(value,
    "\n") do
    Err("invalid Expo access token")
  else
    Ok(Some(value))
  end
end

pub fn internal_token(value :: String) -> String!String do
  if String.length(value) < 32 || String.length(value) > 256 || String.trim(value) != value || String.contains(value,
    "\r") || String.contains(value, "\n") do
    Err("invalid internal broker token")
  else
    Ok(value)
  end
end

pub fn authorized(header :: Option<String>, secret :: String) -> Bool do
  case header do
    None -> false
    Some(value) -> Bytes.secure_equals(Crypto.sha256(Bytes.from_utf8(value)),
      Crypto.sha256(Bytes.from_utf8("Bearer " <> secret)))
  end
end

pub fn prepare_delivery_with_key(input :: Bytes, broker_private_key :: borrow X25519PrivateKey) -> Result<String, BrokerOutcome> do
  if Bytes.length(input) == 0 || Bytes.length(input) > 621 do
    Err(Permanent)
  else
    case prepare_expo_request_with_key(input, broker_private_key) do
      Err(_) -> Err(Permanent)
      Ok(message)
    end
  end
end

pub fn send_ticket_with_key(input :: Bytes,
  broker_private_key :: borrow X25519PrivateKey,
  token :: String) -> Result<String, BrokerOutcome> do
  case prepare_delivery_with_key(input, broker_private_key) do
    Err(outcome)
    Ok(message) -> do
      let request = Http.build(:post, expo_send_url())
        |> Http.header("Content-Type", "application/json")
        |> Http.body(message)
        |> Http.timeout(5000)
        |> Http.max_response_bytes(65536)
      let authorized_request = if String.length(token) == 0 do
        request
      else
        Http.header(request, "Authorization", "Bearer " <> token)
      end
      case Http.send(authorized_request) do
        Err(_) -> Err(Retryable)
        Ok(response) -> parse_expo_ticket(response.status, response.body_bytes)
      end
    end
  end
end

pub fn check_receipt(ticket_id :: String, token :: String) -> BrokerOutcome do
  let request = Http.build(:post, expo_receipts_url())
    |> Http.header("Content-Type", "application/json")
    |> Http.body(receipt_message(ticket_id))
    |> Http.timeout(5000)
    |> Http.max_response_bytes(65536)
  let authorized_request = if String.length(token) == 0 do
    request
  else
    Http.header(request, "Authorization", "Bearer " <> token)
  end
  case Http.send(authorized_request) do
    Err(_) -> Retryable
    Ok(response) -> classify_expo_receipt(response.status, response.body_bytes, ticket_id)
  end
end

pub fn accept_durable_with_key(path :: String,
  input :: Bytes,
  broker_private_key :: borrow X25519PrivateKey,
  now_ms :: Int) -> BrokerOutcome do
  case prepare_delivery_with_key(input, broker_private_key) do
    Err(outcome) -> outcome
    Ok(_) -> case enqueue_with_key(path, input, broker_private_key, now_ms) do
      Err(_) -> Retryable
      Ok(QueueAccepted) -> Delivered
      Ok(QueueCoalesced) -> Delivered
    end
  end
end

fn process_send_with_key(path :: String,
  job :: QueueJob,
  broker_private_key :: borrow X25519PrivateKey,
  token :: String,
  now_ms :: Int) -> Result<(), String> do
  case send_ticket_with_key(job.sealed_request, broker_private_key, token) do
    Ok(ticket_id) -> record_ticket(path, job, ticket_id, now_ms)
    Err(Delivered) -> Err("invalid Expo send state")
    Err(Permanent) -> mark_terminal(path, job.wake_hash, job.request_hash, now_ms)
    Err(Retryable) -> retry_job(path, job, now_ms)
  end
end

fn process_receipt(path :: String, job :: QueueJob, token :: String, now_ms :: Int) -> Result<(), String> do
  case check_receipt(job.ticket_id, token) do
    Delivered -> complete_job(path, job, now_ms)
    Permanent -> mark_terminal(path, job.wake_hash, job.request_hash, now_ms)
    Retryable -> retry_job(path, job, now_ms)
  end
end

pub fn process_once_with_key(path :: String,
  broker_private_key :: borrow X25519PrivateKey,
  token :: String,
  now_ms :: Int) -> Bool!String do
  case next_job(path, now_ms)? do
    None -> Ok(false)
    Some(job) -> if job.state == "pending" || job.state == "retry_send" do
      process_send_with_key(path, job, broker_private_key, token, now_ms)?
      Ok(true)
    else if job.state == "receipt" || job.state == "retry_receipt" do
      process_receipt(path, job, token, now_ms)?
      Ok(true)
    else
      Err("invalid broker queue state")
    end
  end
end

fn worker_loop(path :: String,
  broker_private_key :: borrow X25519PrivateKey,
  token :: String,
  last_purge_ms :: Int) do
  if Process.shutdown_requested() do
    nil
  else
    let now_ms = DateTime.to_unix_ms(DateTime.utc_now())
    let next_purge_ms = if now_ms - last_purge_ms >= 60000 do
      case purge_tombstones(path, tombstone_cutoff_ms(now_ms), 256) do
        Err(_) -> println("push tombstone purge failed")
        Ok(_) -> nil
      end
      now_ms
    else
      last_purge_ms
    end
    case process_once_with_key(path, broker_private_key, token, now_ms) do
      Err(_) -> println("push worker failed")
      Ok(_) -> nil
    end
    Timer.sleep(250)
    worker_loop(path, broker_private_key, token, next_purge_ms)
  end
end

fn run_worker(path :: String, token :: String) -> Result<(), String> do
  let private_key = broker_private_key()?
  worker_loop(path, private_key, token, 0)
  Ok(nil)
end

actor push_worker(path :: String, token :: String) do
  case run_worker(path, token) do
    Err(_) -> println("push worker key configuration failed")
    Ok(_) -> nil
  end
end

pub fn start_worker(path :: String, token :: String) do
  if !RuntimeJobs.enabled() do
    spawn(push_worker, path, token)
  end
  nil
end

pub fn outcome_status(outcome :: BrokerOutcome) -> Int do
  case outcome do
    Delivered -> 204
    Permanent -> 422
    Retryable -> 503
  end
end
