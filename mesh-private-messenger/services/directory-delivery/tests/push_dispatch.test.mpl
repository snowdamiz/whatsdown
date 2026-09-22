from Runtime.PushDispatch import broker_authorization, broker_wake_request
from Storage.Push import ProviderPushBinding
from Push.Token import decode_push_wake, seal_provider_token

fn distinct_delivery_wakes() -> Bool ! String do
  let broker = case Crypto.x25519_from_seed(Crypto.sha256(Bytes.from_utf8("test-broker"))) do
    Err(_) -> Err("test key failed")
    Ok(value) -> Ok(value)
  end ?
  let binding = ProviderPushBinding {
    wake_token_hash : Crypto.sha256(Bytes.from_utf8("device-binding")),
    provider : 1,
    provider_token_ciphertext : seal_provider_token(Bytes.from_utf8("ExpoPushToken[test-device]"),
    broker.public_key) ?
  }
  let first = broker_wake_request(binding, "event-one") ?
  assert(Bytes.to_hex(first) == Bytes.to_hex(broker_wake_request(binding, "event-one") ?))
  let second = broker_wake_request(binding, "event-two") ?
  assert(Bytes.to_hex(first) != Bytes.to_hex(second))
  assert(Bytes.to_hex((decode_push_wake(first) ?).wake_token_hash) != Bytes.to_hex(binding.wake_token_hash))
  assert(Bytes.to_hex((decode_push_wake(second) ?).sealed_provider_token) == Bytes.to_hex(binding.provider_token_ciphertext))
  Ok(true)
end

test("later messages wake the same device while retries keep a stable deduplication key") do
  case distinct_delivery_wakes() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end

test("directory push dispatch requires a safe broker bearer credential") do
  let secret = "0123456789abcdef0123456789abcdef"
  case broker_authorization(secret) do
    Err(_) -> assert(false)
    Ok(value) -> assert(value == "Bearer " <> secret)
  end
  case broker_authorization("") do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
  case broker_authorization("0123456789abcdef0123456789abc\n") do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
end
