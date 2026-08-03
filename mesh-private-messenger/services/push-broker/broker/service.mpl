from Broker.Expo import BrokerOutcome, classify_expo_response, prepare_expo_request

pub fn broker_seed(encoded :: String) -> Bytes ! String do
  case Bytes.from_hex(encoded) do
    Err( _) -> Err("invalid broker seed")
    Ok( value) -> if Bytes.length(value) == 32 do
      Ok(value)
    else
      Err("invalid broker seed")
    end
  end
end

pub fn provider_url(value :: String) -> String ! String do
  if String.length(value) == 0 || String.length(value) > 2048 || !String.starts_with(value,
  "https://") || String.contains(value, "\r") || String.contains(value, "\n") || String.contains(value,
  " ") do
    Err("invalid Expo provider URL")
  else
    Ok(value)
  end
end

pub fn access_token(value :: String) -> Option < String > ! String do
  if String.length(value) == 0 do
    Ok(None)
  else if String.length(value) > 2048 || String.trim(value) != value || String.contains(value, "\r") || String.contains(value,
  "\n") do
    Err("invalid Expo access token")
  else
    Ok(Some(value))
  end
end

pub fn prepare_delivery(input :: Bytes, broker_private_seed :: Bytes) -> Result < String, BrokerOutcome > do
  if Bytes.length(input) == 0 || Bytes.length(input) > 621 do
    Err(Permanent)
  else
    case prepare_expo_request(input, broker_private_seed) do
      Err( _) -> Err(Permanent)
      Ok( message) -> Ok(message)
    end
  end
end

pub fn deliver(input :: Bytes,
broker_private_seed :: Bytes,
url :: String,
token :: Option < String >) -> BrokerOutcome do
  case prepare_delivery(input, broker_private_seed) do
    Err( outcome) -> outcome
    Ok( message) -> do
      let request = Http.build(:post, url)
        |> Http.header("Content-Type", "application/json")
        |> Http.body(message)
        |> Http.timeout(5000)
        |> Http.max_response_bytes(65536)
      let authorized = case token do
        None -> request
        Some( value) -> Http.header(request, "Authorization", "Bearer " <> value)
      end
      case Http.send(authorized) do
        Err( _) -> Retryable
        Ok( response) -> classify_expo_response(response.status, response.body_bytes)
      end
    end
  end
end

pub fn outcome_status(outcome :: BrokerOutcome) -> Int do
  case outcome do
    Delivered -> 204
    Permanent -> 422
    Retryable -> 503
  end
end
