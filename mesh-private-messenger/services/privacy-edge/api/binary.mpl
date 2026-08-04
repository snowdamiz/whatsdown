from Privacy.Edge import sealed_delivery_bytes, verify_submission

pub struct EdgeResult do
  status :: Int
  body :: Bytes
end

fn response(status :: Int, body :: Bytes) -> EdgeResult do
  EdgeResult {
    status : status,
    body : body
  }
end

pub fn prepare_submission(body :: Bytes, now :: U64, maximum_future :: U64, difficulty :: Int) -> EdgeResult do
  case verify_submission(body, now, maximum_future, difficulty) do
    Err( _) -> response(400, Bytes.empty())
    Ok( false) -> response(429, Bytes.empty())
    Ok( true) -> case sealed_delivery_bytes(body) do
      Err( _) -> response(400, Bytes.empty())
      Ok( sealed) -> response(200, sealed)
    end
  end
end
