##! Signing keys: one blind RSA key per purpose and 30-day epoch (Unix-time
##! epochs, protocol/credits-v1.md), stored sealed and announced into the
##! transparency log before the issuer signs with it.
##!
##! A server has no durable Mesh `StorageKey` (only `ephemeral()`, and
##! `platform()` needs a host's secure store), so `BlindRsaSecretKey.
##! seal_for_storage` cannot persist a key across restarts. Keys are instead
##! generated offline (PKCS#8), HPKE-sealed to the issuer's key-wrapping key by
##! `credit-issuer provision-key`, and opened only in the issuer, from
##! MORSE_CREDIT_KEY_WRAPPING_SEED_HEX, straight into `SecretBytes`: a key is
##! never ordinary `Bytes` in either process.

from Credits.IssuerKey import (
  IssuerKeyRevocation,
  credits_encode_issuer_key,
  credits_encode_revocation,
  credits_epoch_at,
  credits_issuer_key,
  credits_purpose_code
)
from Issuer.Settings import IssuerSettings, issuer_purpose

pub struct IssuerKeyRow do
  key_id :: Bytes
  purpose :: String
  epoch :: Int
  spki :: Bytes
  sealed_key :: Bytes
  announced :: Bool
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid key row")
  end
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(output) -> Ok(output)
    _ -> Err("invalid key row")
  end
end

fn integer(value :: DbValue) -> Int!String do
  case String.to_int(text(value)?) do
    Some(output) -> Ok(output)
    None -> Err("invalid key row")
  end
end

fn wrap_info() -> Bytes do
  Bytes.from_utf8("morse-credits/v1/issuer-key-wrap")
end

fn wrap_aad(purpose :: String, epoch :: Int) -> Bytes!String do
  let code = Bytes.from_list([credits_purpose_code(purpose)?])
  let epoch_bytes = Bytes.write_u32_be(U64.parse(Int.to_string(epoch))?)
  case (code, epoch_bytes) do
    (Ok(left), Ok(right)) -> Bytes.concat(left, right)
    _ -> Err("invalid key epoch")
  end
end

fn crypto<T>(value :: Result<T, CryptoError>, message :: String) -> T!String do
  case value do
    Err(_) -> Err(message)
    Ok(output)
  end
end

## Opens a sealed key for `purpose` and `epoch` with the key-wrapping key.

pub fn issuer_open_key(sealed :: Bytes,
  wrapping :: borrow X25519PrivateKey,
  purpose :: String,
  epoch :: Int) -> BlindRsaSecretKey!String do
  let material = case Crypto.hpke_open_secret(wrapping,
    wrap_info(),
    wrap_aad(purpose, epoch)?,
    sealed) do
    Err(_) -> Err("sealed issuer key does not open")
    Ok(value)
  end?
  case Crypto.blind_rsa_from_secret(material) do
    Err(_) -> Err("sealed issuer key is not a BR1 key")
    Ok(key)
  end
end

## The issuer's key-wrapping key, from MORSE_CREDIT_KEY_WRAPPING_SEED_HEX.

pub fn issuer_wrapping_key() -> X25519PrivateKey!String do
  let material = case Env.get_secret_hex("MORSE_CREDIT_KEY_WRAPPING_SEED_HEX") do
    Err(_) -> Err("MORSE_CREDIT_KEY_WRAPPING_SEED_HEX is missing")
    Ok(value)
  end?
  case Crypto.x25519_from_secret(material) do
    Err(_) -> Err("MORSE_CREDIT_KEY_WRAPPING_SEED_HEX is not an X25519 key")
    Ok(pair) -> Ok(pair.private_key)
  end
end

## Seals a PKCS#8 key to the wrapping public key and records it for its
## purpose and epoch. Returns its token_key_id.

pub fn issuer_provision_key(pool :: PoolHandle,
  wrapping_public :: Bytes,
  pkcs8 :: consume SecretBytes,
  purpose :: String,
  epoch :: Int) -> Bytes!String do
  let sealed = crypto(Crypto.hpke_seal_secret(X25519PublicKey { bytes: wrapping_public },
      wrap_info(),
      wrap_aad(purpose, epoch)?,
      pkcs8),
    "the key-wrapping public key is invalid")?
  let key = case Crypto.blind_rsa_from_secret(pkcs8) do
    Err(_) -> Err("not an RSA-2048 PKCS#8 key")
    Ok(value)
  end?
  let public = crypto(Crypto.blind_rsa_public(key), "not a BR1 key")?
  credits_purpose_code(purpose)?
  if epoch < 0 || epoch > 4294967295 do
    return Err("invalid key epoch")
  end
  let key_id = Crypto.sha256(public.bytes)
  Pool.execute_values(pool,
    "INSERT INTO issuer_keys (key_id, purpose, epoch, spki, sealed_key) VALUES ($1, $2, $3::bigint, $4, $5)",
    [
      Binary(key_id),
      Text(purpose),
      Text(Int.to_string(epoch)),
      Binary(public.bytes),
      Binary(sealed)
    ])?
  Ok(key_id)
end

fn key_row(row :: Map<String, DbValue>) -> IssuerKeyRow!String do
  Ok(IssuerKeyRow {
    key_id: binary(Map.get(row, "key_id"))?,
    purpose: text(Map.get(row, "purpose"))?,
    epoch: integer(Map.get(row, "epoch"))?,
    spki: binary(Map.get(row, "spki"))?,
    sealed_key: binary(Map.get(row, "sealed_key"))?,
    announced: text(Map.get(row, "announced"))? == "true"
  })
end

fn unrevoked(pool :: PoolHandle, purpose :: String, epoch :: Int) -> Option<IssuerKeyRow>!String do
  let rows = Pool.query_values(pool,
    "SELECT key_id, purpose, epoch::text AS epoch, spki, sealed_key, (announced_at IS NOT NULL)::text AS announced FROM issuer_keys WHERE purpose = $1 AND epoch = $2::bigint AND revoked_at IS NULL",
    [Text(purpose), Text(Int.to_string(epoch))])?
  case rows do
    [row] -> Ok(Some(key_row(row)?))
    _ -> Ok(None)
  end
end

## The key to sign with now: this epoch's, announced and unrevoked.

pub fn issuer_signing_key(pool :: PoolHandle,
  purpose :: String,
  now_ms :: Int) -> Option<IssuerKeyRow>!String do
  case unrevoked(pool, purpose, credits_epoch_at(now_ms))? do
    Some(row) -> if row.announced do
      Ok(Some(row))
    else
      Ok(None)
    end
    None -> Ok(None)
  end
end

pub fn issuer_key_by_id(pool :: PoolHandle, key_id :: Bytes) -> Option<IssuerKeyRow>!String do
  let rows = Pool.query_values(pool,
    "SELECT key_id, purpose, epoch::text AS epoch, spki, sealed_key, (announced_at IS NOT NULL)::text AS announced FROM issuer_keys WHERE key_id = $1",
    [Binary(key_id)])?
  case rows do
    [row] -> Ok(Some(key_row(row)?))
    _ -> Ok(None)
  end
end

pub fn issuer_key_revoked(pool :: PoolHandle, key_id :: Bytes) -> Bool!String do
  let rows = Pool.query_values(pool,
    "SELECT 1 FROM issuer_keys WHERE key_id = $1 AND revoked_at IS NOT NULL",
    [Binary(key_id)])?
  Ok(List.length(rows) == 1)
end

## Posts a leaf to the directory's issuer route; the HTTP status.

pub fn issuer_post_leaf(settings :: IssuerSettings, leaf :: Bytes) -> Int!String do
  let answer = Http.build(:post, settings.directory_url <> "/internal/v1/credits/issuer-keys")
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Authorization", "Bearer " <> settings.directory_token)
    |> Http.body_bytes(leaf)
    |> Http.timeout(15000)
    |> Http.max_response_bytes(1024)
    |> Http.send()
  case answer do
    Err(error) -> Err("directory unreachable: #{error}")
    Ok(response) -> Ok(response.status)
  end
end

fn announce(pool :: PoolHandle, settings :: IssuerSettings, row :: IssuerKeyRow) -> Bool!String do
  let leaf = credits_encode_issuer_key(credits_issuer_key(credits_purpose_code(row.purpose)?,
    settings.issuer_name,
    row.epoch,
    row.spki)?)?
  let status = issuer_post_leaf(settings, leaf)?
  if status == 201 || status == 200 do
    Pool.execute_values(pool,
      "UPDATE issuer_keys SET announced_at = now() WHERE key_id = $1 AND announced_at IS NULL",
      [Binary(row.key_id)])?
    Ok(true)
  else
    Err("the directory refused issuer key epoch #{row.epoch} with #{status}")
  end
end

fn announce_epoch(pool :: PoolHandle, settings :: IssuerSettings, epoch :: Int) -> Int!String do
  case unrevoked(pool, issuer_purpose(settings), epoch)? do
    Some(row) -> if row.announced do
      Ok(0)
    else if announce(pool, settings, row)? do
      Ok(1)
    else
      Ok(0)
    end
    None -> Ok(0)
  end
end

## Rotation: announces this epoch's key and, once provisioned, the next one's
## (a key is valid from its epoch's start, so announcing early leaves no gap).
## Returns how many keys it announced.

pub fn issuer_announce_keys(pool :: PoolHandle,
  settings :: IssuerSettings,
  now_ms :: Int) -> Int!String do
  let epoch = credits_epoch_at(now_ms)
  Ok(announce_epoch(pool, settings, epoch)? + announce_epoch(pool, settings, epoch + 1)?)
end

## Whether this epoch's key is announced and the next epoch's provisioned.

pub fn issuer_key_health(pool :: PoolHandle,
  purpose :: String,
  now_ms :: Int) -> (Bool, Bool)!String do
  let epoch = credits_epoch_at(now_ms)
  let current = case unrevoked(pool, purpose, epoch)? do
    Some(row) -> row.announced
    None -> false
  end
  let next = case unrevoked(pool, purpose, epoch + 1)? do
    Some(_) -> true
    None -> false
  end
  Ok((current, next))
end

## Incident response: publishes a revocation leaf for the unrevoked key of
## `purpose` and `epoch`, then marks it revoked. A replacement key for the
## same epoch can then be provisioned and announced.

pub fn issuer_revoke_key(pool :: PoolHandle,
  settings :: IssuerSettings,
  purpose :: String,
  epoch :: Int,
  now_ms :: Int) -> Bytes!String do
  let row = case unrevoked(pool, purpose, epoch)? do
    None -> Err("no unrevoked #{purpose} key for epoch #{epoch}")
    Some(value) -> Ok(value)
  end?
  let leaf = credits_encode_revocation(IssuerKeyRevocation {
    purpose: credits_purpose_code(purpose)?,
    issuer_name: settings.issuer_name,
    epoch: epoch,
    token_key_id: row.key_id,
    revoked_at: now_ms
  })?
  let status = issuer_post_leaf(settings, leaf)?
  if status != 201 && status != 200 do
    return Err("the directory refused the revocation with #{status}")
  end
  Pool.execute_values(pool,
    "UPDATE issuer_keys SET revoked_at = now() WHERE key_id = $1",
    [Binary(row.key_id)])?
  Ok(row.key_id)
end
