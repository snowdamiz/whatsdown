from Mobile.Requests import (
  parse_store_request,
  parse_fanout_targets_request,
  parse_triple_payload_request
)

fn storage_alias(input :: Bytes) -> Int!String do
  let value = parse_store_request(input)?
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), value.envelope))
end

fn fanout_alias(input :: Bytes) -> Int!String do
  let value = parse_fanout_targets_request(input)?
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), value.local_device_set))
end

fn triple_alias(input :: Bytes) -> Int!String do
  let value = parse_triple_payload_request(input)?
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), value.second))
end

fn main() do
  nil
end
