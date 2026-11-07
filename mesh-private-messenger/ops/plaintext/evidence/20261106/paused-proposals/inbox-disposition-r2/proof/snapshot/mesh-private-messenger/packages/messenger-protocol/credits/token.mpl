from Credits.Issuer import CreditIssuerKey, issuer_public_key, issuer_key_id
from Credits.Policy import issuer_epoch_accepted, spent_retention_until
from Credits.Wire import (
  CreditTokenInput,
  CreditTokenRequest,
  CreditToken,
  CreditFrame,
  credit_challenge,
  encode_token_input,
  encode_token_request,
  encode_credit_token,
  check_credit_frame
)

pub struct PendingCredit do
  input :: CreditTokenInput
  request :: CreditTokenRequest
  state :: BlindRsaBlindingState
end

pub struct CreditSpend do
  nullifier :: Bytes
  epoch :: U64
  retain_until :: U64
end

# Issuer keys passed here must already be admitted by Credits.Issuer. Every
# client token gets independent entropy; the shared challenge contains no quote.
pub fn blind_credit(key :: CreditIssuerKey,
  service_key :: Bytes,
  now_seconds :: U64) -> PendingCredit!String do
  let public = issuer_public_key(key)?
  if !issuer_epoch_accepted(key.epoch, now_seconds)? do
    return Err("inactive_credit_issuer")
  end
  let nonce = case Crypto.random_bytes(32) do
    Err(_) -> return Err("credit_entropy_unavailable")
    Ok(value) -> value
  end
  let key_id = issuer_key_id(key)?
  let input = CreditTokenInput {
    nonce: nonce,
    challenge_digest: Crypto.sha256(credit_challenge(service_key, key.purpose)?),
    token_key_id: key_id
  }
  let blinded = case Crypto.blind_rsa_blind(public, encode_token_input(input)?) do
    Err(_) -> return Err("credit_blind_failed")
    Ok(value) -> value
  end
  Ok(PendingCredit {
    input: input,
    request: CreditTokenRequest {
      truncated_key_id: Bytes.get(key_id, 31)?,
      blinded_message: blinded.blinded
    },
    state: blinded.state
  })
end

# Payment authorization and durable quote/batch idempotency precede this call.
# The private key must be the exact issuer key selected for that paid quote.
pub fn sign_credit_request(secret :: borrow BlindRsaSecretKey,
  key :: CreditIssuerKey,
  request :: CreditTokenRequest) -> Bytes!String do
  encode_token_request(request)?
  let expected = issuer_key_id(key)?
  let public = case Crypto.blind_rsa_public(secret) do
    Err(_) -> return Err("credit_signing_unavailable")
    Ok(value) -> value
  end
  if !Bytes.secure_equals(public.bytes, key.spki)
    || request.truncated_key_id != Bytes.get(expected, 31)? do
    return Err("credit_signing_key_mismatch")
  end
  case Crypto.blind_rsa_sign(secret, request.blinded_message) do
    Err(_) -> Err("credit_signing_failed")
    Ok(signature)
  end
end

pub fn finalize_credit(key :: CreditIssuerKey,
  pending :: consume PendingCredit,
  response :: Bytes) -> CreditToken!String do
  let public = issuer_public_key(key)?
  let expected = issuer_key_id(key)?
  let input = pending.input
  encode_token_request(pending.request)?
  if !Bytes.secure_equals(pending.input.token_key_id, expected)
    || pending.request.truncated_key_id != Bytes.get(expected, 31)? do
    return Err("credit_finalization_key_mismatch")
  end
  let signature = case Crypto.blind_rsa_finalize(public,
    encode_token_input(pending.input)?,
    response,
    pending.state) do
    Err(_) -> return Err("credit_finalization_failed")
    Ok(value) -> value
  end
  Ok(CreditToken { input: input, authenticator: signature })
end

pub fn verify_credit_token(key :: CreditIssuerKey,
  token :: CreditToken,
  service_key :: Bytes,
  now_seconds :: U64,
  purpose :: Int) -> Bool!String do
  let public = issuer_public_key(key)?
  encode_credit_token(token)?
  if key.purpose != purpose
    || !issuer_epoch_accepted(key.epoch, now_seconds)?
    || !Bytes.secure_equals(token.input.token_key_id, issuer_key_id(key)?)
    || !Bytes.secure_equals(token.input.challenge_digest,
      Crypto.sha256(credit_challenge(service_key, purpose)?)) do
    return Ok(false)
  end
  case Crypto.blind_rsa_verify(public, encode_token_input(token.input)?, token.authenticator) do
    Err(_) -> Ok(false)
    Ok(valid)
  end
end

fn select_key(keys :: List<CreditIssuerKey>, key_id :: Bytes) -> CreditIssuerKey!String do
  if List.length(keys) == 0 do
    Err("unknown_credit_issuer")
  else if Bytes.secure_equals(Crypto.sha256(List.head(keys).spki), key_id) do
    Ok(List.head(keys))
  else
    select_key(List.tail(keys), key_id)
  end
end

# One result covers the entire frame. The core must insert every returned
# nullifier and create the entitlement/hold in ONE transaction. This function
# does not spend tokens and never substitutes a per-edge cache for that ledger.
pub fn verify_credit_frame(frame :: CreditFrame,
  request_body :: Bytes,
  expected_credits :: Int,
  admitted_keys :: List<CreditIssuerKey>,
  service_key :: Bytes,
  now_seconds :: U64,
  purpose :: Int) -> List<CreditSpend>!String do
  let nullifiers = check_credit_frame(frame, request_body, expected_credits)?
  let count = List.length(admitted_keys)
  if count < 1 || count > 2 do
    return Err("invalid_credit_issuer_cache")
  end
  for index in 0..count do
    let key = List.get(admitted_keys, index)
    issuer_public_key(key)?
    if key.purpose != purpose || !issuer_epoch_accepted(key.epoch, now_seconds)? do
      return Err("inactive_credit_issuer")
    end
    for earlier in 0..index do
      let other = List.get(admitted_keys, earlier)
      if other.epoch == key.epoch || Bytes.secure_equals(other.spki, key.spki) do
        return Err("invalid_credit_issuer_cache")
      end
    end
  end
  let spends = for index in 0..List.length(frame.tokens) do
    let token = List.get(frame.tokens, index)
    let key = select_key(admitted_keys, token.input.token_key_id)?
    if !verify_credit_token(key, token, service_key, now_seconds, purpose)? do
      return Err("invalid_credit_token")
    end
    CreditSpend {
      nullifier: List.get(nullifiers, index),
      epoch: key.epoch,
      retain_until: spent_retention_until(key.epoch)?
    }
  end
  Ok(spends)
end
