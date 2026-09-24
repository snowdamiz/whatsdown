from Broker.Expo import BrokerOutcome, classify_expo_receipt, classify_expo_response, expo_message, parse_expo_ticket, prepare_expo_request_with_key, receipt_message
from Broker.Service import access_token, authorized, expo_receipts_url, expo_send_url, internal_token, outcome_status, prepare_delivery_with_key, provider_url
from Push.Token import PushWakeRequest, encode_push_wake, seal_provider_token

fn seed(value :: Int) -> Bytes!String do
  case Bytes.repeat(value, 32) do
    Err(_) -> Err("seed allocation failed")
    Ok(output)
  end
end

fn is_retryable(value :: BrokerOutcome) -> Bool do
  case value do
    Retryable -> true
    _ -> false
  end
end

fn is_permanent(value :: BrokerOutcome) -> Bool do
  case value do
    Permanent -> true
    _ -> false
  end
end

fn generic_payload() -> Bool!String do
  let message = expo_message(Bytes.from_utf8("ExponentPushToken[opaque-device-token]"))?
  assert(message == "{\"to\":\"ExponentPushToken[opaque-device-token]\",\"contentAvailable\":true,\"priority\":\"normal\",\"data\":{\"kind\":\"encrypted-wakeup\"}}")
  Ok(true)
end

fn opened_payload() -> Bool!String do
  let broker_seed = seed(7)?
  let broker = case Crypto.x25519_from_seed(broker_seed) do
    Err(_) -> Err("broker key failed")
    Ok(output)
  end?
  let token = Bytes.from_utf8("ExpoPushToken[broker-only-token]")
  let sealed = seal_provider_token(token, broker.public_key)?
  let wake = encode_push_wake(PushWakeRequest {
    version: 1,
    wake_token_hash: Crypto.sha256(Bytes.from_utf8("wake")),
    provider: 1,
    sealed_provider_token: sealed
  })?
  assert(prepare_expo_request_with_key(wake, broker.private_key)? == expo_message(token)?)
  Ok(true)
end

test("broker opens the sealed provider token from a canonical wake request") do
  case opened_payload() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end

test("Expo success ticket is delivered") do
  case classify_expo_response(200,
    Bytes.from_utf8("{\"data\":{\"status\":\"ok\",\"id\":\"ticket-1\"}}")) do
    Delivered -> assert(true)
    _ -> assert(false)
  end
end

test("Expo single-item ticket array is delivered") do
  case classify_expo_response(201,
    Bytes.from_utf8("{\"data\":[{\"status\":\"ok\",\"id\":\"ticket-2\"}]}")) do
    Delivered -> assert(true)
    _ -> assert(false)
  end
end

test("Expo send responses retain the ticket id for receipt polling") do
  case parse_expo_ticket(200,
    Bytes.from_utf8("{\"data\":{\"status\":\"ok\",\"id\":\"ticket-retained\"}}")) do
    Err(_) -> assert(false)
    Ok(id) -> assert(id == "ticket-retained")
  end
  case parse_expo_ticket(200,
    Bytes.from_utf8("{\"data\":{\"status\":\"error\",\"details\":{\"error\":\"DeviceNotRegistered\"}}}")) do
    Err(Permanent) -> assert(true)
    _ -> assert(false)
  end
end

test("Expo receipts decide delivery and terminal device state") do
  assert(receipt_message("ticket-retained") == "{\"ids\":[\"ticket-retained\"]}")
  let delivered = Bytes.from_utf8("{\"data\":{\"ticket-retained\":{\"status\":\"ok\"}}}")
  case classify_expo_receipt(200, delivered, "ticket-retained") do
    Delivered -> assert(true)
    _ -> assert(false)
  end
  let unregistered = Bytes.from_utf8("{\"data\":{\"ticket-retained\":{\"status\":\"error\",\"details\":{\"error\":\"DeviceNotRegistered\"}}}}")
  case classify_expo_receipt(200, unregistered, "ticket-retained") do
    Permanent -> assert(true)
    _ -> assert(false)
  end
  let credentials = Bytes.from_utf8("{\"data\":{\"ticket-retained\":{\"status\":\"error\",\"details\":{\"error\":\"InvalidCredentials\"}}}}")
  assert(is_retryable(classify_expo_receipt(200, credentials, "ticket-retained")))
  assert(is_retryable(classify_expo_receipt(200,
    Bytes.from_utf8("{\"data\":{}}"),
    "ticket-retained")))
end

test("Expo rejects an unregistered device permanently") do
  let body = Bytes.from_utf8("{\"data\":{\"status\":\"error\",\"message\":\"not registered\",\"details\":{\"error\":\"DeviceNotRegistered\"}}}")
  case classify_expo_response(200, body) do
    Permanent -> assert(true)
    _ -> assert(false)
  end
end

test("Expo message rate errors are retryable") do
  let body = Bytes.from_utf8("{\"data\":[{\"status\":\"error\",\"message\":\"slow down\",\"details\":{\"error\":\"MessageRateExceeded\"}}]}")
  case classify_expo_response(200, body) do
    Retryable -> assert(true)
    _ -> assert(false)
  end
end

test("Expo unknown and credential ticket errors remain retryable") do
  let unknown = Bytes.from_utf8("{\"data\":{\"status\":\"error\",\"message\":\"new provider error\",\"details\":{\"error\":\"FutureProviderError\"}}}")
  let credentials = Bytes.from_utf8("{\"data\":{\"status\":\"error\",\"message\":\"credentials\",\"details\":{\"error\":\"InvalidCredentials\"}}}")
  assert(is_retryable(classify_expo_response(200, unknown)))
  assert(is_retryable(classify_expo_response(200, credentials)))
end

test("Expo HTTP failures distinguish retryable outages from permanent requests") do
  assert(is_retryable(classify_expo_response(302, Bytes.empty())))
  assert(is_retryable(classify_expo_response(429, Bytes.empty())))
  assert(is_retryable(classify_expo_response(500, Bytes.empty())))
  assert(is_retryable(classify_expo_response(503, Bytes.empty())))
  assert(is_permanent(classify_expo_response(400, Bytes.empty())))
  assert(is_retryable(classify_expo_response(401, Bytes.empty())))
end

test("Expo payload contains only generic encrypted activity") do
  case generic_payload() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end

test("broker outcomes map to the internal delivery contract") do
  assert(outcome_status(Delivered) == 204)
  assert(outcome_status(Permanent) == 422)
  assert(outcome_status(Retryable) == 503)
end

test("broker configuration rejects unsafe external provider settings") do
  assert(expo_send_url() == "https://exp.host/--/api/v2/push/send")
  assert(expo_receipts_url() == "https://exp.host/--/api/v2/push/getReceipts")
  case provider_url("https://exp.host/--/api/v2/push/send") do
    Err(_) -> assert(false)
    Ok(value) -> assert(value == "https://exp.host/--/api/v2/push/send")
  end
  case provider_url("http://exp.host/push") do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
  case provider_url("https://attacker.example/push") do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
  case access_token("") do
    Err(_) -> assert(false)
    Ok(None) -> assert(true)
    Ok(Some(_)) -> assert(false)
  end
  case access_token("token\r\ninjected") do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
end

test("broker requires an exact internal bearer credential") do
  let secret = "0123456789abcdef0123456789abcdef"
  case internal_token(secret) do
    Err(_) -> assert(false)
    Ok(validated) -> do
      assert(authorized(Some("Bearer " <> validated), validated))
      assert(!authorized(None, validated))
      assert(!authorized(Some("Bearer wrong"), validated))
    end
  end
  case internal_token("") do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
end

fn invalid_delivery_proof() -> Bool!String do
  let broker = case Crypto.x25519_from_seed(seed(3)?) do
    Err(_) -> Err("broker key failed")
    Ok(output)
  end?
  case prepare_delivery_with_key(Bytes.empty(), broker.private_key) do
    Err(Permanent) -> assert(true)
    _ -> assert(false)
  end
  case Bytes.repeat(0, 622) do
    Err(_) -> assert(false)
    Ok(oversized) -> case prepare_delivery_with_key(oversized, broker.private_key) do
      Err(Permanent) -> assert(true)
      _ -> assert(false)
    end
  end
  case prepare_delivery_with_key(Bytes.from_utf8("not-a-canonical-wake"), broker.private_key) do
    Err(Permanent) -> assert(true)
    _ -> assert(false)
  end
  Ok(true)
end

test("broker rejects empty, oversized, and malformed internal push bodies") do
  case invalid_delivery_proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end
