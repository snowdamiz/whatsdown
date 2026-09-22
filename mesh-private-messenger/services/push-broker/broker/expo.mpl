from Push.Token import decode_push_wake, open_provider_token_with_key

pub type BrokerOutcome do
  Delivered

  Retryable

  Permanent
end deriving(Eq, Debug)

pub fn expo_message(token :: Bytes) -> String ! String do
  let value = case Bytes.to_utf8(token) do
    Err(_) -> Err("invalid provider token")
    Ok(output) -> Ok(output)
  end ?
  Ok("{\"to\":" <> Json.encode_string(value) <> ",\"contentAvailable\":true,\"priority\":\"normal\",\"data\":{\"kind\":\"encrypted-wakeup\"}}")
end

pub fn prepare_expo_request_with_key(input :: Bytes, broker_private_key :: borrow X25519PrivateKey) -> String ! String do
  if Bytes.length(input) > 621 do
    Err("invalid push request")
  else
    let wake = case decode_push_wake(input) do
      Err(_) -> Err("invalid push request")
      Ok(output) -> Ok(output)
    end ?
    let token = case open_provider_token_with_key(wake.sealed_provider_token, broker_private_key) do
      Err(_) -> Err("invalid push request")
      Ok(output) -> Ok(output)
    end ?
    expo_message(token)
  end
end

fn error_ticket_outcome(ticket :: Json) -> BrokerOutcome do
  case Json.object_get(ticket, "details") do
    Err(_) -> Retryable
    Ok(details) -> case Json.object_get(details, "error") do
      Err(_) -> Retryable
      Ok(error) -> case Json.as_string(error) do
        Err(_) -> Retryable
        Ok(code) -> if code == "DeviceNotRegistered" do
          Permanent
        else
          Retryable
        end
      end
    end
  end
end

fn ticket_result(ticket :: Json) -> Result < String, BrokerOutcome > do
  case Json.object_get(ticket, "status") do
    Err(_) -> Err(Retryable)
    Ok(status) -> case Json.as_string(status) do
      Err(_) -> Err(Retryable)
      Ok(value) -> if value == "error" do
        Err(error_ticket_outcome(ticket))
      else if value == "ok" do
        case Json.object_get(ticket, "id") do
          Err(_) -> Err(Retryable)
          Ok(id) -> case Json.as_string(id) do
            Err(_) -> Err(Retryable)
            Ok(ticket_id) -> if String.length(ticket_id) > 0 && String.length(ticket_id) <= 256 do
              Ok(ticket_id)
            else
              Err(Retryable)
            end
          end
        end
      else
        Err(Retryable)
      end
    end
  end
end

fn data_ticket(data :: Json) -> Result < String, BrokerOutcome > do
  case Json.object_get(data, "status") do
    Ok(_) -> ticket_result(data)
    Err(_) -> case Json.array_length(data) do
      Err(_) -> Err(Retryable)
      Ok(count) -> if count != 1 do
        Err(Retryable)
      else
        case Json.array_get(data, 0) do
          Err(_) -> Err(Retryable)
          Ok(ticket) -> ticket_result(ticket)
        end
      end
    end
  end
end

fn response_ticket(body :: Bytes) -> Result < String, BrokerOutcome > do
  case Bytes.to_utf8(body) do
    Err(_) -> Err(Retryable)
    Ok(encoded) -> case Json.parse(encoded) do
      Err(_) -> Err(Retryable)
      Ok(root) -> case Json.object_get(root, "data") do
        Err(_) -> Err(Retryable)
        Ok(data) -> data_ticket(data)
      end
    end
  end
end

pub fn parse_expo_ticket(status :: Int, body :: Bytes) -> Result < String, BrokerOutcome > do
  if status >= 200 && status <= 299 do
    response_ticket(body)
  else if status == 429 || status >= 500 do
    Err(Retryable)
  else if status == 400 do
    Err(Permanent)
  else
    Err(Retryable)
  end
end

pub fn classify_expo_response(status :: Int, body :: Bytes) -> BrokerOutcome do
  case parse_expo_ticket(status, body) do
    Err(outcome) -> outcome
    Ok(_) -> Delivered
  end
end

pub fn receipt_message(ticket_id :: String) -> String do
  "{\"ids\":[" <> Json.encode_string(ticket_id) <> "]}"
end

fn receipt_ticket_outcome(ticket :: Json) -> BrokerOutcome do
  case Json.object_get(ticket, "status") do
    Err(_) -> Retryable
    Ok(status) -> case Json.as_string(status) do
      Err(_) -> Retryable
      Ok(value) -> if value == "ok" do
        Delivered
      else if value == "error" do
        error_ticket_outcome(ticket)
      else
        Retryable
      end
    end
  end
end

fn receipt_response_outcome(body :: Bytes, ticket_id :: String) -> BrokerOutcome do
  case Bytes.to_utf8(body) do
    Err(_) -> Retryable
    Ok(encoded) -> case Json.parse(encoded) do
      Err(_) -> Retryable
      Ok(root) -> case Json.object_get(root, "data") do
        Err(_) -> Retryable
        Ok(data) -> case Json.object_get(data, ticket_id) do
          Err(_) -> Retryable
          Ok(ticket) -> receipt_ticket_outcome(ticket)
        end
      end
    end
  end
end

pub fn classify_expo_receipt(status :: Int, body :: Bytes, ticket_id :: String) -> BrokerOutcome do
  if status >= 200 && status <= 299 do
    receipt_response_outcome(body, ticket_id)
  else if status == 400 do
    Permanent
  else
    Retryable
  end
end
