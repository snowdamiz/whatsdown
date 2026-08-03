from Push.Token import decode_push_wake, open_provider_token

pub type BrokerOutcome do
  Delivered

  Retryable

  Permanent
end deriving(Eq, Debug)

pub fn expo_message(token :: Bytes) -> String ! String do
  let value = case Bytes.to_utf8(token) do
    Err( _) -> Err("invalid provider token")
    Ok( output) -> Ok(output)
  end ?
  Ok("{\"to\":" <> Json.encode_string(value) <> ",\"body\":\"New encrypted activity\",\"data\":{\"kind\":\"encrypted-wakeup\"}}")
end

pub fn prepare_expo_request(input :: Bytes, broker_private_seed :: Bytes) -> String ! String do
  if Bytes.length(input) > 621 do
    Err("invalid push request")
  else
    let wake = case decode_push_wake(input) do
      Err( _) -> Err("invalid push request")
      Ok( output) -> Ok(output)
    end ?
    let token = case open_provider_token(wake.sealed_provider_token, broker_private_seed) do
      Err( _) -> Err("invalid push request")
      Ok( output) -> Ok(output)
    end ?
    expo_message(token)
  end
end

fn error_ticket_outcome(ticket :: Json) -> BrokerOutcome do
  case Json.object_get(ticket, "details") do
    Err( _) -> Permanent
    Ok( details) -> case Json.object_get(details, "error") do
      Err( _) -> Permanent
      Ok( error) -> case Json.as_string(error) do
        Err( _) -> Permanent
        Ok( code) -> if code == "MessageRateExceeded" do
          Retryable
        else
          Permanent
        end
      end
    end
  end
end

fn ticket_outcome(ticket :: Json) -> BrokerOutcome do
  case Json.object_get(ticket, "status") do
    Err( _) -> Retryable
    Ok( status) -> case Json.as_string(status) do
      Err( _) -> Retryable
      Ok( value) -> if value == "error" do
        error_ticket_outcome(ticket)
      else if value == "ok" do
        case Json.object_get(ticket, "id") do
          Err( _) -> Retryable
          Ok( id) -> case Json.as_string(id) do
            Err( _) -> Retryable
            Ok( ticket_id) -> if String.length(ticket_id) > 0 && String.length(ticket_id) <= 256 do
              Delivered
            else
              Retryable
            end
          end
        end
      else
        Retryable
      end
    end
  end
end

fn data_outcome(data :: Json) -> BrokerOutcome do
  case Json.object_get(data, "status") do
    Ok( _) -> ticket_outcome(data)
    Err( _) -> case Json.array_length(data) do
      Err( _) -> Retryable
      Ok( count) -> if count != 1 do
        Retryable
      else
        case Json.array_get(data, 0) do
          Err( _) -> Retryable
          Ok( ticket) -> ticket_outcome(ticket)
        end
      end
    end
  end
end

fn response_outcome(body :: Bytes) -> BrokerOutcome do
  case Bytes.to_utf8(body) do
    Err( _) -> Retryable
    Ok( encoded) -> case Json.parse(encoded) do
      Err( _) -> Retryable
      Ok( root) -> case Json.object_get(root, "data") do
        Err( _) -> Retryable
        Ok( data) -> data_outcome(data)
      end
    end
  end
end

pub fn classify_expo_response(status :: Int, body :: Bytes) -> BrokerOutcome do
  if status >= 200 && status <= 299 do
    response_outcome(body)
  else if status == 429 || status >= 500 do
    Retryable
  else if status >= 400 && status <= 499 do
    Permanent
  else
    Retryable
  end
end
