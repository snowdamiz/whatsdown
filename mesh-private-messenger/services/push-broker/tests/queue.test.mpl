from Broker.Queue import EnqueueOutcome, complete_job, enqueue, initialize, mark_terminal, next_job, purge_tombstones, record_ticket, retry_delay_ms, retry_job, tombstone_cutoff_ms
from Push.Token import PushWakeRequest, encode_push_wake, seal_provider_token

fn seed(value :: Int) -> Bytes ! String do
  case Bytes.repeat(value, 32) do
    Err( _) -> Err("seed allocation failed")
    Ok( output) -> Ok(output)
  end
end

fn queue_proof() -> Bool ! String do
  let random = case Crypto.random_bytes(8) do
    Err( _) -> Err("random path failed")
    Ok( value) -> Ok(value)
  end ?
  let suffix = Bytes.to_hex(random)
  let path = "/tmp/mesh-push-broker-#{suffix}.db"
  let private_seed = seed(13) ?
  let broker = case Crypto.x25519_from_seed(private_seed) do
    Err( _) -> Err("broker key failed")
    Ok( output) -> Ok(output)
  end ?
  initialize(path) ?
  let first_sealed = seal_provider_token(Bytes.from_utf8("ExpoPushToken[first-queue-token]"),
  broker.public_key) ?
  let first = encode_push_wake(PushWakeRequest {
    version : 1,
    wake_token_hash : Crypto.sha256(Bytes.from_utf8("queue-wake")),
    provider : 1,
    sealed_provider_token : first_sealed
  }) ?
  let first_accepted = case enqueue(path, first, private_seed, 1000) ? do
    QueueAccepted -> true
    QueueCoalesced -> false
  end
  assert(first_accepted)
  let duplicate_coalesced = case enqueue(path, first, private_seed, 1001) ? do
    QueueAccepted -> false
    QueueCoalesced -> true
  end
  assert(duplicate_coalesced)
  let job = case next_job(path, 1001) ? do
    None -> Err("queued wake was missing")
    Some( value) -> Ok(value)
  end ?
  assert(Bytes.secure_equals(job.sealed_request, first))
  mark_terminal(path, job.wake_hash, job.request_hash, 1002) ?
  let terminal_coalesced = case enqueue(path, first, private_seed, 1003) ? do
    QueueAccepted -> false
    QueueCoalesced -> true
  end
  assert(terminal_coalesced)
  case next_job(path, 1003) ? do
    None -> nil
    Some( _) -> assert(false)
  end
  let changed_broker = case Crypto.x25519_from_seed(private_seed) do
    Err( _) -> Err("broker key failed")
    Ok( output) -> Ok(output)
  end ?
  let changed_sealed = seal_provider_token(Bytes.from_utf8("ExpoPushToken[changed-queue-token]"),
  changed_broker.public_key) ?
  let changed = encode_push_wake(PushWakeRequest {
    version : 1,
    wake_token_hash : Crypto.sha256(Bytes.from_utf8("queue-wake")),
    provider : 1,
    sealed_provider_token : changed_sealed
  }) ?
  let changed_accepted = case enqueue(path, changed, private_seed, 1004) ? do
    QueueAccepted -> true
    QueueCoalesced -> false
  end
  assert(changed_accepted)
  let changed_job = case next_job(path, 1004) ? do
    None -> Err("changed binding was not queued")
    Some( value) -> Ok(value)
  end ?
  assert(Bytes.secure_equals(changed_job.sealed_request, changed))
  record_ticket(path, changed_job, "ticket-queued", 1005) ?
  case next_job(path, 901004) ? do
    None -> nil
    Some( _) -> assert(false)
  end
  let receipt_job = case next_job(path, 901005) ? do
    None -> Err("receipt was not scheduled")
    Some( value) -> Ok(value)
  end ?
  assert(receipt_job.state == "receipt")
  assert(receipt_job.ticket_id == "ticket-queued")
  retry_job(path, receipt_job, 901005) ?
  case next_job(path, 902004) ? do
    None -> nil
    Some( _) -> assert(false)
  end
  let retry = case next_job(path, 902005) ? do
    None -> Err("receipt retry was not scheduled")
    Some( value) -> Ok(value)
  end ?
  assert(retry.state == "retry_receipt")
  assert(retry.attempts == 1)
  assert(retry_delay_ms(0) == 1000)
  assert(retry_delay_ms(30) == 900000)
  complete_job(path, retry, 902006) ?
  case next_job(path, 902006) ? do
    None -> nil
    Some( _) -> assert(false)
  end
  case enqueue(path, changed, private_seed, 902006) ? do
    QueueAccepted -> assert(false)
    QueueCoalesced -> nil
  end
  case enqueue(path, first, private_seed, 902007) ? do
    QueueAccepted -> nil
    QueueCoalesced -> assert(false)
  end
  let final_job = case next_job(path, 902007) ? do
    None -> Err("changed binding did not reset delivered tombstone")
    Some( value) -> Ok(value)
  end ?
  mark_terminal(path, final_job.wake_hash, final_job.request_hash, 902008) ?
  assert(tombstone_cutoff_ms(604800123) == 123)
  assert(purge_tombstones(path, 902009, 1) ? == 1)
  case enqueue(path, first, private_seed, 902010) ? do
    QueueAccepted -> nil
    QueueCoalesced -> assert(false)
  end
  Ok(true)
end

test("durable queue coalesces wakes and resets a tombstone only for a changed binding") do
  case queue_proof() do
    Err( _) -> assert(false)
    Ok( value) -> assert(value)
  end
end
