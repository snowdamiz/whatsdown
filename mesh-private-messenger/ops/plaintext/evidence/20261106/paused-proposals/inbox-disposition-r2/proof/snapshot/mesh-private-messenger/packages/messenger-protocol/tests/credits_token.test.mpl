from Credits.Issuer import CreditIssuerKey
from Credits.Token import (
  PendingCredit,
  blind_credit,
  sign_credit_request,
  finalize_credit,
  verify_credit_token,
  verify_credit_frame
)
from Credits.Wire import CreditFrame, encode_credit_token, decode_credit_token

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn round_trip() -> Bool!String do
  let signer = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("test RSA generation failed")
    Ok(value) -> value
  end
  let public = case Crypto.blind_rsa_public(signer) do
    Err(_) -> return Err("test RSA public key failed")
    Ok(value) -> value
  end
  let now = wide(10 * 2592000 + 1000)?
  let key = CreditIssuerKey {
    quote_public_key: Bytes.from_hex(String.repeat("11", 32))?,
    epoch: wide(10)?,
    purpose: 0,
    spki: public.bytes
  }
  let service_key = Bytes.from_hex(String.repeat("ab", 32))?
  let pending = blind_credit(key, service_key, now)?
  let first_request = pending.request
  let response = sign_credit_request(signer, key, pending.request)?
  let token = finalize_credit(key, pending, response)?
  assert(verify_credit_token(key, token, service_key, now, 0)?)
  let persisted = decode_credit_token(encode_credit_token(token)?)?
  assert(verify_credit_token(key, persisted, service_key, now, 0)?)
  assert(!verify_credit_token(key, token, service_key, now, 1)?)
  assert(!verify_credit_token(key, token, Bytes.from_hex(String.repeat("cd", 32))?, now, 0)?)
  assert(!verify_credit_token(key, token, service_key, wide(12 * 2592000)?, 0)?)
  assert(!verify_credit_token(key,
    %{token | input: %{token.input | nonce: Bytes.from_hex(String.repeat("00", 32))?}},
    service_key,
    now,
    0)?)
  assert(!verify_credit_token(key,
    %{token | authenticator: Bytes.from_hex(String.repeat("00", 256))?},
    service_key,
    now,
    0)?)
  assert(Result.is_err(sign_credit_request(signer, key, %{first_request | truncated_key_id: -1})))
  let pending_second = blind_credit(key, service_key, now)?
  let second_response = sign_credit_request(signer, key, pending_second.request)?
  let second = finalize_credit(key, pending_second, second_response)?
  let payload = Bytes.from_utf8("paid attachment allocation")
  let frame = CreditFrame { binding: Crypto.sha256(payload), tokens: [token, second] }
  let spends = verify_credit_frame(frame, payload, 2, [key], service_key, now, 0)?
  assert(List.length(spends) == 2)
  assert(List.head(spends).epoch == key.epoch)
  assert(List.head(spends).retain_until == wide(12 * 2592000 + 604800)?)
  assert(Result.is_err(verify_credit_frame(frame, payload, 2, [], service_key, now, 0)))
  assert(Result.is_err(verify_credit_frame(frame, payload, 2, [key, key], service_key, now, 0)))
  assert(Result.is_err(verify_credit_frame(%{frame |
      tokens: [token, %{second | authenticator: Bytes.from_hex(String.repeat("00", 256))?}]
    },
    payload,
    2,
    [key],
    service_key,
    now,
    0)))
  # Restoring the inverse after the issuing process restarts must finalize the
  # exact same input. Only the public storage API can preserve this resource.
  let recoverable = blind_credit(key, service_key, now)?
  let wrapping = case StorageKey.ephemeral() do
    Err(_) -> return Err("test storage key failed")
    Ok(value) -> value
  end
  let context = Bytes.from_hex("01"
    <> String.repeat("00", 80)
    <> String.repeat("11", 32)
    <> "00130000000000000001")?
  let sealed = case BlindRsaBlindingState.seal_for_storage(recoverable.state, wrapping, context) do
    Err(_) -> return Err("test blinding state seal failed")
    Ok(value) -> value
  end
  let recovered_input = recoverable.input
  let recovered_request = recoverable.request
  Secret.destroy(recoverable.state)
  let restored = case BlindRsaBlindingState.unseal_from_storage(sealed, wrapping, context) do
    Err(_) -> return Err("test blinding state open failed")
    Ok(value) -> value
  end
  let recovered = PendingCredit {
    input: recovered_input,
    request: recovered_request,
    state: restored
  }
  let recovered_response = sign_credit_request(signer, key, recovered.request)?
  assert(verify_credit_token(key,
    finalize_credit(key, recovered, recovered_response)?,
    service_key,
    now,
    0)?)
  Ok(true)
end

test("Morse issues, restores, finalizes and verifies credits through the public Mesh BR1 API") do
  case round_trip() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
