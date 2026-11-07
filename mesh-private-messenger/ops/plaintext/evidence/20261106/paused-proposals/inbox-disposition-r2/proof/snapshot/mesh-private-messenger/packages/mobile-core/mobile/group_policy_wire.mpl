from Mobile.Codec import (
  mobile_byte,
  mobile_append,
  mobile_write_u32,
  mobile_read_byte,
  mobile_read_u32
)

pub fn group_policy_label(group :: Bytes) -> String!String do
  if Bytes.length(group) != 32 do
    Err("invalid_group_id")
  else
    Ok("group-disappearing/v1/#{Bytes.to_hex(group)}")
  end
end

pub fn encode_group_policy(seconds :: Int) -> Bytes!String do
  if seconds < 0 || seconds > 2592000 do
    Err("invalid_group_policy")
  else
    mobile_append(mobile_byte(1)?, mobile_write_u32(seconds)?)
  end
end

pub fn decode_group_policy(value :: Bytes) -> Int!String do
  if Bytes.length(value) != 5 || mobile_read_byte(Bytes.slice(value, 0, 1)?)? != 1 do
    Err("invalid_group_policy")
  else
    let seconds = mobile_read_u32(Bytes.slice(value, 1, 4)?)?
    let _ = encode_group_policy(seconds)?
    Ok(seconds)
  end
end
