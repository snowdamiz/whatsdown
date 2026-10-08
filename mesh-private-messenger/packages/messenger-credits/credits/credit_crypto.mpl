##! Credit token cryptography over `Crypto.BlindRsa` (profile BR1,
##! RSABSSA-SHA384-PSS-Deterministic, RFC 9474 and RFC 9578). A separate package
##! from messenger-protocol, so only the services and clients that handle
##! tokens need a Mesh release with BR1.

from Credits.IssuerKey import IssuerKey
from Credits.CreditToken import (
  credits_challenge_digest,
  credits_decode_token,
  credits_token_input,
  credits_token_key_id
)

fn public_key(spki :: Bytes) -> BlindRsaPublicKey!String do
  case Crypto.blind_rsa_public_from_spki(spki) do
    Err(_) -> Err("invalid credit issuer key")
    Ok(value)
  end
end

## RSA only: the token names this key and its authenticator verifies over the
## token input, whatever challenge the input carries.

pub fn credits_verify_authenticator(spki :: Bytes, token :: Bytes) -> Bool!String do
  let value = credits_decode_token(token)?
  if !Bytes.secure_equals(value.token_key_id, credits_token_key_id(spki)) do
    Ok(false)
  else
    let key = public_key(spki)?
    let input = credits_token_input(value.nonce, value.challenge_digest, value.token_key_id)?
    case Crypto.blind_rsa_verify(key, input, value.authenticator) do
      Ok(valid)
      Err(_) -> Ok(false)
    end
  end
end

## A Morse credit: a type-2 token for this logged issuer key, carrying the
## issuer's Morse challenge (protocol/credits-v1.md), whose authenticator
## verifies. Checking the key is logged, current and unrevoked is the caller's.

pub fn credits_verify_token(key :: IssuerKey, token :: Bytes) -> Bool!String do
  let value = credits_decode_token(token)?
  if !Bytes.secure_equals(value.challenge_digest, credits_challenge_digest(key.issuer_name)?) do
    Ok(false)
  else
    credits_verify_authenticator(key.spki, token)
  end
end

## Fresh token inputs for a key: a random 32-byte nonce each.

pub fn credits_new_inputs(key :: IssuerKey, count :: Int) -> List<Bytes>!String do
  let digest = credits_challenge_digest(key.issuer_name)?
  let key_id = credits_token_key_id(key.spki)
  let inputs = for _index in 0..count do
    let nonce = case Crypto.random_bytes(32) do
      Err(_) -> Err("credit nonce generation failed")
      Ok(value)
    end?
    credits_token_input(nonce, digest, key_id)?
  end
  Ok(inputs)
end

fn finalized(key :: BlindRsaPublicKey,
  input :: Bytes,
  signature :: Bytes,
  state :: consume BlindRsaBlindingState) -> Bytes!String do
  case Crypto.blind_rsa_finalize(key, input, signature, state) do
    Err(_) -> Err("credit signature does not verify")
    Ok(authenticator) -> case Bytes.concat(input, authenticator) do
      Err(_) -> Err("credit token allocation failed")
      Ok(token)
    end
  end
end

# Each level blinds one input and keeps its blinding state on the stack (a
# state is affine: no list can hold it), the deepest level makes the one
# exchange, and each level finalizes its own token on the way back.

fn blind_from(key :: BlindRsaPublicKey,
  inputs :: List<Bytes>,
  index :: Int,
  blinded :: List<Bytes>,
  exchange :: Fun(List<Bytes>) -> List<Bytes>!String) -> (List<Bytes>, List<Bytes>)!String do
  if index >= List.length(inputs) do
    let signatures = exchange(blinded)?
    if List.length(signatures) != List.length(inputs) do
      Err("the issuer answered a different number of signatures")
    else
      Ok((signatures, List.new()))
    end
  else
    let input = List.get(inputs, index)
    let value = case Crypto.blind_rsa_blind(key, input) do
      Err(_) -> Err("credit blinding failed")
      Ok(output)
    end?
    let request = value.blinded
    let (signatures, later) = blind_from(key,
      inputs,
      index + 1,
      List.append(blinded, request),
      exchange)?
    let token = finalized(key, input, List.get(signatures, index), value.state)?
    Ok((signatures, [token] ++ later))
  end
end

## Blinds every input for `key`, hands the blinded messages (in order) to
## `exchange` once, which returns the issuer's blind signatures in the same
## order, and returns the finished 354-byte tokens. Fails, keeping nothing,
## if any signature does not verify.

pub fn credits_blind_batch(key :: IssuerKey,
  inputs :: List<Bytes>,
  exchange :: Fun(List<Bytes>) -> List<Bytes>!String) -> List<Bytes>!String do
  let public = public_key(key.spki)?
  let (_signatures, tokens) = blind_from(public, inputs, 0, List.new(), exchange)?
  Ok(tokens)
end
