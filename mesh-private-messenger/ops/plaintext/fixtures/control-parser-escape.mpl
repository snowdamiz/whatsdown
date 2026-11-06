from Mobile.Requests import parse_fanout_control_request
fn alternate(input :: Bytes) -> Int!String do
  let control = parse_fanout_control_request(input)?
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), control.body))
end
fn main() do nil end
