##! Test fixture for credits: a clean spent set and log, an issuer key
##! announced into the log, and tokens signed by it.

from Api.Binary import BinaryResult
from Api.CreditRoutes import credits_issuer_leaf_request
from Credits.CreditCrypto import credits_new_inputs
from Credits.IssuerKey import (
  IssuerKey,
  IssuerKeyRevocation,
  credits_encode_issuer_key,
  credits_encode_revocation,
  credits_issuer_key
)
from Storage.TransparencyWitnesses import transparency_seed_registry
from Tests.TransparencySupport import transparency_test_reset

pub fn credits_test_reset(pool :: PoolHandle) -> Result<(), String> do
  transparency_test_reset(pool)?
  Pool.execute(pool, "TRUNCATE credit_issuer_keys, credit_spent, credit_holds, credit_mode", [])?
  transparency_seed_registry(pool)?
  Ok(nil)
end

pub fn credits_test_public(issuer :: borrow BlindRsaSecretKey) -> Bytes!String do
  case Crypto.blind_rsa_public(issuer) do
    Err(_) -> Err("issuer public key failed")
    Ok(value) -> Ok(value.bytes)
  end
end

pub fn credits_test_issuer() -> BlindRsaSecretKey!String do
  case Crypto.blind_rsa_generate() do
    Err(_) -> Err("issuer key generation failed")
    Ok(value)
  end
end

## The key of `epoch` for `purpose` (1 live, 2 test) of credits.morseapp.io.

pub fn credits_test_key(issuer :: borrow BlindRsaSecretKey,
  purpose :: Int,
  epoch :: Int) -> IssuerKey!String do
  credits_issuer_key(purpose, "credits.morseapp.io", epoch, credits_test_public(issuer)?)
end

## Announces a key as the issuer would; the HTTP status the core answered.

pub fn credits_test_announce(pool :: PoolHandle, key :: IssuerKey) -> Int!String do
  Ok(credits_issuer_leaf_request(pool, credits_encode_issuer_key(key)?).status)
end

pub fn credits_test_revoke(pool :: PoolHandle, key :: IssuerKey) -> Int!String do
  Ok(credits_issuer_leaf_request(pool,
    credits_encode_revocation(IssuerKeyRevocation {
      purpose: key.purpose,
      issuer_name: key.issuer_name,
      epoch: key.epoch,
      token_key_id: Crypto.sha256(key.spki),
      revoked_at: DateTime.to_unix_ms(DateTime.utc_now())
    })?).status)
end

fn tokens_from(issuer :: borrow BlindRsaSecretKey,
  public :: BlindRsaPublicKey,
  inputs :: List<Bytes>,
  index :: Int,
  output :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(inputs) do
    Ok(output)
  else
    let input = List.get(inputs, index)
    let blinded = case Crypto.blind_rsa_blind(public, input) do
      Err(_) -> Err("blinding failed")
      Ok(value)
    end?
    let request = blinded.blinded
    let signature = case Crypto.blind_rsa_sign(issuer, request) do
      Err(_) -> Err("signing failed")
      Ok(value)
    end?
    let authenticator = case Crypto.blind_rsa_finalize(public, input, signature, blinded.state) do
      Err(_) -> Err("finalizing failed")
      Ok(value)
    end?
    tokens_from(issuer,
      public,
      inputs,
      index + 1,
      List.append(output, Bytes.concat(input, authenticator)?))
  end
end

## `count` fresh tokens of `key`, signed by `issuer` (its secret key).

pub fn credits_test_tokens(issuer :: borrow BlindRsaSecretKey,
  key :: IssuerKey,
  count :: Int) -> List<Bytes>!String do
  let public = case Crypto.blind_rsa_public_from_spki(key.spki) do
    Err(_) -> Err("issuer key invalid")
    Ok(value)
  end?
  tokens_from(issuer, public, credits_new_inputs(key, count)?, 0, List.new())
end

pub fn credits_test_count(pool :: PoolHandle, table :: String) -> Int!String do
  let rows = Pool.query_values(pool, "SELECT count(*)::text AS value FROM " <> table, [])?
  case rows do
    [row] -> case Map.get(row, "value") do
      Text(value) -> case String.to_int(value) do
        Some(parsed) -> Ok(parsed)
        None -> Err("count failed")
      end
      _ -> Err("count failed")
    end
    _ -> Err("count failed")
  end
end
