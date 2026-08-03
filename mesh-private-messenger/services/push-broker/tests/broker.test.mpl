from Broker.Expo import BrokerOutcome, classify_expo_response, expo_message, prepare_expo_request
from Broker.Service import access_token, broker_seed, outcome_status, prepare_delivery, provider_url
from Push.Token import PushWakeRequest, encode_push_wake, seal_provider_token

fn seed(value :: Int) -> Bytes ! String do
  case Bytes.repeat(value, 32) do
    Err( _) -> Err("seed allocation failed")
    Ok( output) -> Ok(output)
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

fn generic_payload() -> Bool ! String do
  let message = expo_message(Bytes.from_utf8("ExponentPushToken[opaque-device-token]")) ?
  assert(message == "{\"to\":\"ExponentPushToken[opaque-device-token]\",\"body\":\"New encrypted activity\",\"data\":{\"kind\":\"encrypted-wakeup\"}}")
  Ok(true)
end

fn opened_payload() -> Bool ! String do
  let broker_seed = seed(7) ?
  let broker = case Crypto.x25519_from_seed(broker_seed) do
    Err( _) -> Err("broker key failed")
    Ok( output) -> Ok(output)
  end ?
  let token = Bytes.from_utf8("ExpoPushToken[broker-only-token]")
  let wake = encode_push_wake(PushWakeRequest {
    version : 1,
    wake_token_hash : Crypto.sha256(Bytes.from_utf8("wake")),
    provider : 1,
    sealed_provider_token : seal_provider_token(token, broker.public_key) ?
  }) ?
  assert(prepare_expo_request(wake, broker_seed) ? == expo_message(token) ?)
  Ok(true)
end

test("broker opens the sealed provider token from a canonical wake request") do
  case opened_payload() do
    Err( _) -> assert(false)
    Ok( value) -> assert(value)
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

test("Expo HTTP failures distinguish retryable outages from permanent requests") do
  assert(is_retryable(classify_expo_response(302, Bytes.empty())))
  assert(is_retryable(classify_expo_response(429, Bytes.empty())))
  assert(is_retryable(classify_expo_response(500, Bytes.empty())))
  assert(is_retryable(classify_expo_response(503, Bytes.empty())))
  assert(is_permanent(classify_expo_response(400, Bytes.empty())))
  assert(is_permanent(classify_expo_response(401, Bytes.empty())))
end

test("Expo payload contains only generic encrypted activity") do
  case generic_payload() do
    Err( _) -> assert(false)
    Ok( value) -> assert(value)
  end
end

test("broker outcomes map to the internal delivery contract") do
  assert(outcome_status(Delivered) == 204)
  assert(outcome_status(Permanent) == 422)
  assert(outcome_status(Retryable) == 503)
end

test("broker configuration rejects unsafe external provider settings") do
  let valid_seed = case seed(9) do
    Err( _) -> ""
    Ok( value) -> Bytes.to_hex(value)
  end
  case broker_seed(valid_seed) do
    Err( _) -> assert(false)
    Ok( value) -> assert(Bytes.length(value) == 32)
  end
  case broker_seed("") do
    Err( _) -> assert(true)
    Ok( _) -> assert(false)
  end
  case provider_url("https://exp.host/--/api/v2/push/send") do
    Err( _) -> assert(false)
    Ok( value) -> assert(value == "https://exp.host/--/api/v2/push/send")
  end
  case provider_url("http://exp.host/push") do
    Err( _) -> assert(true)
    Ok( _) -> assert(false)
  end
  case access_token("") do
    Err( _) -> assert(false)
    Ok( None) -> assert(true)
    Ok( Some( _)) -> assert(false)
  end
  case access_token("token\r\ninjected") do
    Err( _) -> assert(true)
    Ok( _) -> assert(false)
  end
end

test("broker rejects empty, oversized, and malformed internal push bodies") do
  case seed(3) do
    Err( _) -> assert(false)
    Ok( private_seed) -> do
      case prepare_delivery(Bytes.empty(), private_seed) do
        Err( Permanent) -> assert(true)
        _ -> assert(false)
      end
      case Bytes.repeat(0, 622) do
        Err( _) -> assert(false)
        Ok( oversized) -> case prepare_delivery(oversized, private_seed) do
          Err( Permanent) -> assert(true)
          _ -> assert(false)
        end
      end
      case prepare_delivery(Bytes.from_utf8("not-a-canonical-wake"), private_seed) do
        Err( Permanent) -> assert(true)
        _ -> assert(false)
      end
    end
  end
end
