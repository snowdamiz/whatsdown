from Groups.GroupPayload import decode_group_payload
from MobileCore import receive_initial_export

fn body_selected_effect(input :: Bytes) -> Int!String do
  let value = decode_group_payload(input)?
  if Bytes.length(value.body) > 0 do
    Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8("constant")))
  else
    Ok(0)
  end
end

fn unrelated_private_caller(flag :: Plaintext<Bool>, input :: Bytes) -> Int!String do
  if flag do
    let _ = decode_group_payload(input)?
    Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8("constant")))
  else
    Ok(0)
  end
end

fn native_display_called_from_mesh(input :: Bytes) -> Int!String do
  let body = receive_initial_export(input)?
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), body))
end

fn main() do nil end
