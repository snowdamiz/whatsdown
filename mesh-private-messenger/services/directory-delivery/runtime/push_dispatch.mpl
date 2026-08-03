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

fn send_broker_push(binding :: ProviderPushBinding, broker_url :: String) -> PushResult do
  let wake = encode_push_wake(PushWakeRequest {
    version : 1,
    wake_token_hash : binding.wake_token_hash,
    provider : binding.provider,
    sealed_provider_token : binding.provider_token_ciphertext
  })
  case wake do
    Err( _) -> PushPermanent("invalid_provider_request")
    Ok( body) -> case Http.build(:post, broker_url)
      |> Http.header("Content-Type", "application/octet-stream")
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

pub fn dispatch_broker_push(pool :: PoolHandle, event :: OutboxEvent, broker_url :: String) -> PushResult ! String do
  case find_push_binding_for_mailbox(pool, event.mailbox_token_hash) ? do
    None -> Ok(PushDelivered)
    Some( binding) -> if String.length(broker_url) == 0 do
      Ok(PushRetryable("broker_unconfigured"))
    else
      Ok(send_broker_push(binding, broker_url))
    end
  end
end

pub fn dispatch_configured_push(pool :: PoolHandle, event :: OutboxEvent) -> PushResult ! String do
  let mode = Env.get("MESSENGER_PUSH_MODE", "disabled")
  if mode == "local-fake" do
    dispatch_push(pool, event, Env.get("MESSENGER_LOCAL_FAKE_PUSH_AVAILABLE", "true") != "false")
  else if mode == "broker" do
    dispatch_broker_push(pool, event, Env.get("MESSENGER_PUSH_BROKER_URL", ""))
  else
    case find_push_binding_for_mailbox(pool, event.mailbox_token_hash) ? do
      None -> Ok(PushDelivered)
      Some( _) -> Ok(PushRetryable("push_disabled"))
    end
  end
end
