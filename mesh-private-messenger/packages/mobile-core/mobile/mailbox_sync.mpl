from Mobile.Account import mailbox_fetch
from Mobile.Codec import current_time, mobile_utf8, mobile_join, mobile_write_u16, mobile_byte
from Mobile.HistoryExpiry import expire_direct_history
from Mobile.GroupHistoryExpiry import expire_group_history
from Mobile.Inbox import process_delivery_batch
from Mobile.NetworkPins import native_network_pins
from Mobile.Profile import load_profile
from Mobile.Types import MobileBatchRequest
from Protocol.MailboxWire import decode_delivery_batch, decode_mailbox_fetch, decode_mailbox_ack

pub struct MailboxSyncOutcome do
  batches :: Int
  received :: Int
  acknowledged :: Int
  pending :: Bool
  more :: Bool
end

fn current(path :: String, identity :: Bytes, origin :: String) -> Bool do
  let pins = case native_network_pins() do
    Err(_) -> return false
    Ok(value) -> value
  end
  let profile = case load_profile(path) do
    Err(_) -> return false
    Ok(value) -> value
  end
  pins.core_origin == origin && Bytes.secure_equals(Crypto.sha256(profile), identity)
end

fn remaining(started :: Int) -> Int!String do
  let elapsed = Monotonic.elapsed(started, Monotonic.now_nanos())?
  Ok(12000 - elapsed / 1000000)
end

fn post(origin :: String,
  route :: String,
  body :: Bytes,
  maximum :: Int,
  started :: Int) -> Bytes!String do
  let budget = remaining(started)?
  if budget <= 0 do
    return Err("mailbox_transport_budget_exhausted")
  end
  let timeout = if budget < 8000 do
    budget
  else
    8000
  end
  let response = case Http.build(:post, origin <> route)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Cache-Control", "no-store")
    |> Http.body_bytes(body)
    |> Http.timeout(timeout)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(maximum)
    |> Http.send() do
    Err(_) -> return Err("mailbox_transport_unavailable")
    Ok(value) -> value
  end
  if response.status != 200 do
    return Err("mailbox_http_" <> Int.to_string(response.status))
  end
  Ok(response.body_bytes)
end

fn receive_pass(path :: String,
  identity :: Bytes,
  origin :: String,
  started :: Int,
  prior :: Option<U64>,
  progress :: MailboxSyncOutcome) -> MailboxSyncOutcome!String do
  if progress.batches >= 16 || remaining(started)? <= 0 do
    return Ok(%{progress | more: true})
  end
  if !current(path, identity, origin) do
    return Err("mailbox_sync_identity_changed")
  end
  let request = mailbox_fetch(path)?
  let fetch = case decode_mailbox_fetch(request) do
    Err(_) -> return Err("invalid_mailbox_fetch")
    Ok(value) -> value
  end
  let encoded = post(origin, "/v1/mailbox/fetch", request, 524949, started)?
  if !current(path, identity, origin) do
    return Err("mailbox_sync_identity_changed")
  end
  let deliveries = case decode_delivery_batch(encoded) do
    Err(_) -> return Err("invalid_delivery_batch")
    Ok(value) -> value
  end
  let acknowledged = process_delivery_batch(MobileBatchRequest {
    database_path: path,
    batch: encoded
  })?
  let done = if Bytes.length(acknowledged) == 0 do
    0
  else
    let ack = case decode_mailbox_ack(acknowledged) do
      Err(_) -> return Err("invalid_mailbox_ack")
      Ok(value) -> value
    end
    if !current(path, identity, origin) do
      return Err("mailbox_sync_identity_changed")
    end
    let response = post(origin, "/v1/mailbox/ack", acknowledged, 4096, started)?
    if Bytes.length(response) != 0 do
      return Err("invalid_mailbox_ack_response")
    end
    if !current(path, identity, origin) do
      return Err("mailbox_sync_identity_changed")
    end
    List.length(ack.envelope_ids)
  end
  let delivered = List.length(deliveries)
  let next = MailboxSyncOutcome {
    batches: progress.batches + 1,
    received: progress.received + delivered,
    acknowledged: progress.acknowledged + done,
    pending: progress.pending || done < delivered,
    more: false
  }
  let stalled = case prior do
    None -> false
    Some(value) -> done == 0 && U64.compare(value, fetch.after_sequence) == 0
  end
  if delivered == 0 || stalled do
    Ok(next)
  else
    receive_pass(path, identity, origin, started, Some(fetch.after_sequence), next)
  end
end

## No caller URL, request bytes, signatures or wire batches cross this boundary.
## Failed acknowledgement remains safe to retry: inbox processing is durable
## before submission and redelivery produces an acknowledgement of the same IDs.
pub fn synchronize_mailbox(database_path :: String) -> MailboxSyncOutcome!String do
  let expiry_now = current_time()?
  expire_direct_history(database_path, expiry_now)?
  expire_group_history(database_path, expiry_now)?
  let pins = native_network_pins()?
  let identity = Crypto.sha256(load_profile(database_path)?)
  receive_pass(database_path,
    identity,
    pins.core_origin,
    Monotonic.now_nanos(),
    None,
    MailboxSyncOutcome { batches: 0, received: 0, acknowledged: 0, pending: false, more: false })
end

pub fn native_mailbox_synchronize(input :: Bytes) -> Bytes!String do
  if Bytes.length(input) == 0
    || Bytes.length(input) > 4096
    || List.any(Bytes.to_list(input), fn(value) -> value == 0 end) do
    return Err("invalid_database_path")
  end
  let outcome = synchronize_mailbox(mobile_utf8(input, "invalid_database_path")?)?
  mobile_join([
      mobile_byte(1)?,
      Bytes.from_utf8("MSY"),
      mobile_write_u16(outcome.batches)?,
      mobile_write_u16(outcome.received)?,
      mobile_write_u16(outcome.acknowledged)?,
      mobile_byte(if outcome.pending do
        1
      else
        0
      end)?,
      mobile_byte(if outcome.more do
        1
      else
        0
      end)?
    ],
    0,
    Bytes.empty())
end
