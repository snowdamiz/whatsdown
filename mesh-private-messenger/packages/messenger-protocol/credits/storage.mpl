from Credits.Token import PendingCredit
from Credits.Wire import (
  CreditToken,
  encode_token_input,
  decode_token_input,
  encode_token_request,
  decode_token_request,
  encode_credit_token,
  decode_credit_token
)

# The caller's local-data context binds account, device, purchase/token record
# and snapshot version. The inner resource seal preserves that identity while
# selecting its own type purpose and the required empty session identifier.
fn state_context(local_context :: Bytes) -> Bytes!String do
  if Bytes.length(local_context) != 123
    || Bytes.to_hex(Bytes.slice(local_context, 113, 2)?) != "000e" do
    return Err("invalid_credit_storage_context")
  end
  let prefix = Bytes.concat(Bytes.slice(local_context, 0, 49)?,
    Bytes.from_hex(String.repeat("00", 32))?)?
  let suffix = Bytes.concat(Bytes.slice(local_context, 81, 32)?,
    Bytes.concat(Bytes.from_hex("0013")?, Bytes.slice(local_context, 115, 8)?)?)?
  Bytes.concat(prefix, suffix)
end

fn seal_bytes(value :: Bytes,
  wrapping :: borrow StorageKey,
  local_context :: Bytes) -> Bytes!String do
  case StorageKey.seal_bytes(value, wrapping, local_context) do
    Err(_) -> Err("credit_storage_seal_failed")
    Ok(blob)
  end
end

fn open_bytes(blob :: Bytes,
  wrapping :: borrow StorageKey,
  local_context :: Bytes) -> Bytes!String do
  case StorageKey.unseal_bytes(blob, wrapping, local_context) do
    Err(_) -> Err("credit_storage_open_failed")
    Ok(value)
  end
end

# Persist the returned ciphertext atomically before sending this issuance
# request. The inverse never enters public Bytes; the outer seal also hides and
# authenticates the nonce, request and all metadata linking this pending token.
pub fn seal_pending_credit(pending :: consume PendingCredit,
  wrapping :: borrow StorageKey,
  local_context :: Bytes) -> Bytes!String do
  let input = encode_token_input(pending.input)?
  let request = encode_token_request(pending.request)?
  if pending.request.truncated_key_id != Bytes.get(pending.input.token_key_id, 31)? do
    return Err("invalid_pending_credit")
  end
  let state_blob = case BlindRsaBlindingState.seal_for_storage(pending.state,
    wrapping,
    state_context(local_context)?) do
    Err(_) -> return Err("credit_state_seal_failed")
    Ok(blob) -> blob
  end
  if Bytes.length(state_blob) < 1 || Bytes.length(state_blob) > 4096 do
    return Err("invalid_credit_state_blob")
  end
  let length = case Bytes.write_u32_be(U64.parse(Int.to_string(Bytes.length(state_blob)))?) do
    Err(_) -> return Err("invalid_credit_state_blob")
    Ok(value) -> value
  end
  let body = Bytes.concat(Bytes.concat(Bytes.from_hex("0143504e")?, input)?,
    Bytes.concat(request, Bytes.concat(length, state_blob)?)?)?
  seal_bytes(body, wrapping, local_context)
end

pub fn open_pending_credit(snapshot :: Bytes,
  wrapping :: borrow StorageKey,
  local_context :: Bytes) -> PendingCredit!String do
  let context = state_context(local_context)?
  let body = open_bytes(snapshot, wrapping, local_context)?
  if Bytes.length(body) < 366
    || Bytes.length(body) > 4461
    || Bytes.to_hex(Bytes.slice(body, 0, 4)?) != "0143504e" do
    return Err("invalid_pending_credit")
  end
  let state_length = case Bytes.read_u32_be(body, 361) do
    Err(_) -> return Err("invalid_credit_state_blob")
    Ok(value) -> U64.to_int(value)?
  end
  if state_length < 1 || state_length > 4096 || Bytes.length(body) != 365 + state_length do
    return Err("invalid_credit_state_blob")
  end
  let input = decode_token_input(Bytes.slice(body, 4, 98)?)?
  let request = decode_token_request(Bytes.slice(body, 102, 259)?)?
  if request.truncated_key_id != Bytes.get(input.token_key_id, 31)? do
    return Err("invalid_pending_credit")
  end
  let state = case BlindRsaBlindingState.unseal_from_storage(Bytes.slice(body, 365, state_length)?,
    wrapping,
    context) do
    Err(_) -> return Err("credit_state_open_failed")
    Ok(value) -> value
  end
  Ok(PendingCredit { input: input, request: request, state: state })
end

pub fn seal_credit_token(token :: CreditToken,
  wrapping :: borrow StorageKey,
  local_context :: Bytes) -> Bytes!String do
  seal_bytes(Bytes.concat(Bytes.from_hex("0143544b")?, encode_credit_token(token)?)?,
    wrapping,
    local_context)
end

pub fn open_credit_token(blob :: Bytes,
  wrapping :: borrow StorageKey,
  local_context :: Bytes) -> CreditToken!String do
  let body = open_bytes(blob, wrapping, local_context)?
  if Bytes.length(body) != 358 || Bytes.to_hex(Bytes.slice(body, 0, 4)?) != "0143544b" do
    return Err("invalid_stored_credit")
  end
  decode_credit_token(Bytes.slice(body, 4, 354)?)
end
