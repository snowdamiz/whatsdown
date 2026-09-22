from Push.Binding import PushBindRequest, decode_push_bind, encode_push_bind
from Push.Token import PushWakeRequest, decode_push_wake, encode_push_wake, open_provider_token_with_key, seal_provider_token

fn seed(value :: Int) -> Bytes ! String do
  case Bytes.repeat(value, 32) do
    Err(_) -> Err("seed allocation failed")
    Ok(output) -> Ok(output)
  end
end

fn empty_signature() -> Bytes ! String do
  case Bytes.repeat(0, 64) do
    Err(_) -> Err("signature allocation failed")
    Ok(output) -> Ok(output)
  end
end

fn tamper_last_byte(input :: Bytes) -> Bytes ! String do
  let length = Bytes.length(input)
  let last = case Bytes.get(input, length - 1) do
    Err(_) -> Err("token wire missing")
    Ok(output) -> Ok(output)
  end ?
  let prefix = case Bytes.slice(input, 0, length - 1) do
    Err(_) -> Err("token wire missing")
    Ok(output) -> Ok(output)
  end ?
  let replacement = if last == 120 do
    Bytes.from_utf8("y")
  else
    Bytes.from_utf8("x")
  end
  case Bytes.concat(prefix, replacement) do
    Err(_) -> Err("token tamper failed")
    Ok(output) -> Ok(output)
  end
end

fn append_trailing_byte(input :: Bytes) -> Bytes ! String do
  case Bytes.concat(input, Bytes.from_utf8("x")) do
    Err(_) -> Err("wake tamper failed")
    Ok(output) -> Ok(output)
  end
end

fn proof() -> Bool ! String do
  let broker_seed = seed(7) ?
  let broker = case Crypto.x25519_from_seed(broker_seed) do
    Err(_) -> Err("broker key failed")
    Ok(output) -> Ok(output)
  end ?
  let token = Bytes.from_utf8("ExponentPushToken[opaque-device-token]")
  let sealed = seal_provider_token(token, broker.public_key) ?
  assert(Bytes.length(sealed) <= 580)
  assert(Bytes.secure_equals(open_provider_token_with_key(sealed, broker.private_key) ?, token))
  case open_provider_token_with_key(tamper_last_byte(sealed) ?, broker.private_key) do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
  case seal_provider_token(Bytes.from_utf8("not-a-provider-token"), broker.public_key) do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
  let wake = PushWakeRequest {
    version : 1,
    wake_token_hash : Crypto.sha256(Bytes.from_utf8("wake")),
    provider : 1,
    sealed_provider_token : sealed
  }
  let wake_wire = encode_push_wake(wake) ?
  let opened_wake = decode_push_wake(wake_wire) ?
  assert(Bytes.secure_equals(opened_wake.wake_token_hash, wake.wake_token_hash))
  assert(opened_wake.provider == 1)
  assert(Bytes.secure_equals(opened_wake.sealed_provider_token, sealed))
  case decode_push_wake(append_trailing_byte(wake_wire) ?) do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
  let binding = PushBindRequest {
    mailbox_token_hash : seed(1) ?,
    wake_token_hash : seed(2) ?,
    revision : U64.parse("1") ?,
    provider : 1,
    provider_token_ciphertext : sealed,
    signature : empty_signature() ?
  }
  let binding_wire = encode_push_bind(binding) ?
  assert(Bytes.secure_equals(decode_push_bind(binding_wire) ?.provider_token_ciphertext, sealed))
  case encode_push_bind(% {binding | provider_token_ciphertext : seed(8) ? }) do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
  Ok(true)
end

test("push broker alone opens canonical provider tokens") do
  case proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end
