from Runtime.FakePushProvider import generic_push_payload, send_local_fake_push
from Push.Token import PushWakeRequest, encode_push_wake
from Storage.Outbox import OutboxEvent, PushResult
from Storage.Push import ProviderPushBinding, find_push_binding_for_mailbox

pub fn broker_status(status :: Int) -> PushResult do
  if status == 204 do
    PushDelivered
  else if status == 422 do
    PushPermanent("provider_rejected")
  else if status == 503 do
    PushRetryable("provider_retryable")
  else
    PushRetryable("broker_invalid_response")
  end
end

pub fn broker_authorization(value :: String) -> String ! String do
  if String.length(value) < 32 || String.length(value) > 256 || String.trim(value) != value || String.contains(value,
  "\r") || String.contains(value, "\n") do
    Err("invalid broker credential")
  else
    Ok("Bearer " <> value)
  end
end

pub fn broker_wake_request(binding :: ProviderPushBinding, event_id :: String) -> Bytes ! String do
  let material = case Bytes.concat(binding.wake_token_hash,
  Bytes.from_utf8("mesh-msg/v1/push-event/" <> event_id)) do
    Err( _) -> Err("wake allocation failed")
    Ok( value) -> Ok(value)
  end ?
  encode_push_wake(PushWakeRequest {
    version : 1,
    wake_token_hash : Crypto.sha256(material),
    provider : binding.provider,
    sealed_provider_token : binding.provider_token_ciphertext
  })
end

fn send_broker_push(binding :: ProviderPushBinding,
event_id :: String,
broker_url :: String,
authorization :: String) -> PushResult do
  let wake = broker_wake_request(binding, event_id)
  case wake do
    Err( _) -> PushPermanent("invalid_provider_request")
    Ok( body) -> case Http.build(:post, broker_url)
      |> Http.header("Content-Type", "application/octet-stream")
      |> Http.header("Authorization", authorization)
      |> Http.body_bytes(body)
      |> Http.timeout(5000)
      |> Http.max_response_bytes(1024)
      |> Http.send() do
      Err( _) -> PushRetryable("broker_unavailable")
      Ok( response) -> broker_status(response.status)
    end
  end
end

pub fn dispatch_push(pool :: PoolHandle, event :: OutboxEvent, local_fake_available :: Bool) -> PushResult ! String do
  case find_push_binding_for_mailbox(pool, event.mailbox_token_hash) ? do
    None -> Ok(PushDelivered)
    Some( binding) -> Ok(send_local_fake_push(binding, generic_push_payload(), local_fake_available))
  end
end

pub fn dispatch_broker_push(pool :: PoolHandle,
event :: OutboxEvent,
broker_url :: String,
broker_token :: String) -> PushResult ! String do
  case find_push_binding_for_mailbox(pool, event.mailbox_token_hash) ? do
    None -> Ok(PushDelivered)
    Some( binding) -> if String.length(broker_url) == 0 do
      Ok(PushRetryable("broker_unconfigured"))
    else
      case broker_authorization(broker_token) do
        Err( _) -> Ok(PushRetryable("broker_auth_unconfigured"))
        Ok( authorization) -> Ok(send_broker_push(binding,
        event.event_id,
        broker_url,
        authorization))
      end
    end
  end
end

pub fn dispatch_configured_push(pool :: PoolHandle, event :: OutboxEvent) -> PushResult ! String do
  let mode = Env.get("MESSENGER_PUSH_MODE", "disabled")
  if mode == "local-fake" do
    dispatch_push(pool, event, Env.get("MESSENGER_LOCAL_FAKE_PUSH_AVAILABLE", "true") != "false")
  else if mode == "broker" do
    dispatch_broker_push(pool,
    event,
    Env.get("MESSENGER_PUSH_BROKER_URL", ""),
    Env.get("MESSENGER_PUSH_BROKER_INTERNAL_TOKEN", ""))
  else
    case find_push_binding_for_mailbox(pool, event.mailbox_token_hash) ? do
      None -> Ok(PushDelivered)
      Some( _) -> Ok(PushRetryable("push_disabled"))
    end
  end
end
