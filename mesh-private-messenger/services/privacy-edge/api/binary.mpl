from Privacy.Edge import internal_delivery_authorization, sealed_delivery_bytes, verify_submission

pub struct EdgeResult do
  status :: Int
  body :: Bytes
end

fn response(status :: Int, body :: Bytes) -> EdgeResult do
  EdgeResult {
    status: status,
    body: body
  }
end

pub fn prepare_submission(body :: Bytes, now :: U64, maximum_future :: U64, difficulty :: Int) -> EdgeResult do
  case verify_submission(body, now, maximum_future, difficulty) do
    Err(_) -> response(400, Bytes.empty())
    Ok(false) -> response(429, Bytes.empty())
    Ok(true) -> case sealed_delivery_bytes(body) do
      Err(_) -> response(400, Bytes.empty())
      Ok(sealed) -> response(200, sealed)
    end
  end
end

pub fn forward_submission(body :: Bytes, internal_url :: String, internal_token :: String) -> EdgeResult!String do
  let authorization = internal_delivery_authorization(internal_token)?
  case Http.build(:post, internal_url <> "/internal/v1/envelopes/sealed")
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Authorization", authorization)
    |> Http.body_bytes(body)
    |> Http.timeout(5000)
    |> Http.max_response_bytes(1024)
    |> Http.send() do
    Err(_) -> Ok(response(502, Bytes.empty()))
    Ok(forwarded) -> Ok(response(forwarded.status, forwarded.body_bytes))
  end
end
