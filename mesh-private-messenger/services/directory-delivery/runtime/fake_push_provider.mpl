from Storage.Outbox import PushResult
from Storage.Push import ProviderPushBinding

pub struct GenericPushPayload do
  body :: String
  kind :: String
end

pub fn generic_push_payload() -> GenericPushPayload do
  GenericPushPayload { body: "New encrypted activity", kind: "encrypted-wakeup" }
end

pub fn send_local_fake_push(binding :: ProviderPushBinding,
  payload :: GenericPushPayload,
  available :: Bool) -> PushResult do
  if Bytes.length(binding.wake_token_hash) != 32 || binding.provider <= 0 || Bytes.length(binding.provider_token_ciphertext) < 17 || payload.body != "New encrypted activity" || payload.kind != "encrypted-wakeup" do
    PushPermanent("invalid_provider_request")
  else if available do
    PushDelivered
  else
    PushRetryable("provider_unavailable")
  end
end
