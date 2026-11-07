from Groups.GroupCodec import (
  group_join,
  group_byte,
  group_vector,
  group_wire_start,
  group_wire_u8,
  group_wire_fixed,
  group_wire_vector,
  group_wire_end
)
from Groups.Mls import GroupError

# GMS version 5 authenticates this framing inside the sender's ciphertext.
pub struct GroupPayload do
  kind :: Int
  body :: Plaintext<Bytes>
  hint :: Bytes
  recipient_account :: Bytes
  recipient_device :: Bytes
end

fn valid_fields(kind :: Int, body :: Bytes, hint :: Bytes, account :: Bytes, device :: Bytes) -> Bool do
  if kind == 1 do
    Bytes.length(body) <= 65237
      && (Bytes.length(hint) == 0 || Bytes.length(hint) == 40)
      && Bytes.length(account) == 0
      && Bytes.length(device) == 0
  else
    kind == 5
      && Bytes.length(body) <= 2987
      && Bytes.length(hint) == 0
      && Bytes.length(account) == 32
      && Bytes.length(device) == 16
  end
end

fn encode(value :: GroupPayload) -> Bytes!GroupError do
  if !valid_fields(value.kind, value.body, value.hint, value.recipient_account, value.recipient_device) do
    return Err(InvalidGroup)
  end
  let route = if value.kind == 1 do
    group_vector(value.hint)?
  else
    group_join([value.recipient_account, value.recipient_device], 0, Bytes.empty())?
  end
  group_join([
      group_byte(1)?,
      Bytes.from_utf8("GAP"),
      group_byte(value.kind)?,
      route,
      group_vector(value.body)?
    ],
    0,
    Bytes.empty())
end

fn decode(input :: Bytes, maximum_body :: Int) -> GroupPayload!GroupError do
  let kind = group_wire_u8(group_wire_start(input, 65290, "GAP")?)?
  let (state, hint, account, device) = if kind.value == 1 do
    let hint = group_wire_vector(kind.state, 40)?
    (hint.state, hint.value, Bytes.empty(), Bytes.empty())
  else if kind.value == 5 do
    let account = group_wire_fixed(kind.state, 32)?
    let device = group_wire_fixed(account.state, 16)?
    (device.state, Bytes.empty(), account.value, device.value)
  else
    return Err(InvalidGroup)
  end
  let body = group_wire_vector(state,
    if kind.value == 1 do
      maximum_body
    else
      2987
    end)?
  group_wire_end(body.state)?
  if !valid_fields(kind.value, body.value, hint, account, device) do
    return Err(InvalidGroup)
  end
  Ok(GroupPayload {
    kind: kind.value,
    body: body.value,
    hint: hint,
    recipient_account: account,
    recipient_device: device
  })
end

pub fn encode_group_payload(value :: GroupPayload) -> Plaintext<Bytes>!String do
  let encoded = encode(value)
  if declassify(Result.is_err(encoded),
    "group payload framing releases only bounded encoding success or refusal before encryption; body hints recipient identifiers exact sizes and error payloads remain private") do
    Err("invalid_group_payload")
  else
    Ok(Result.unwrap_or(encoded, Bytes.empty()))
  end
end

fn decode_at_limit(input :: Bytes, maximum_body :: Int) -> GroupPayload!String do
  case decode(input, maximum_body) do
    Err(_) -> Err("invalid_group_payload")
    Ok(value)
  end
end


pub fn decode_group_payload(input :: Bytes) -> GroupPayload!String do
  decode_at_limit(input, 65237)
end

# GAP2 shares the canonical GAP1 parser with a smaller application body budget.
pub fn decode_expiring_group_payload(input :: Bytes) -> GroupPayload!String do
  decode_at_limit(input, 65225)
end
