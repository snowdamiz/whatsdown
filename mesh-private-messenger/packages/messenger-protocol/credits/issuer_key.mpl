##! Issuer keys in the transparency log (plan §6.10): a phone accepts a credit
##! key only when its leaf is in the log it verified, so the issuer cannot give
##! one user a key of their own.
##!
##! - `issuer-key-v1` leaf, IKY: `u8 1 ‖ "IKY" ‖ u8 purpose (1 live, 2 test) ‖
##!   vector32(issuer_name) ‖ u32 epoch ‖ u64 not_before_ms ‖ u64 not_after_ms ‖
##!   spki342`. Epoch e starts at e × 30 days (Unix time); its key is valid for
##!   two epochs, [start, start + 60 days): current, then previous.
##! - revocation leaf, IKR: `u8 1 ‖ "IKR" ‖ u8 purpose ‖ vector32(issuer_name) ‖
##!   u32 epoch ‖ token_key_id32 ‖ u64 revoked_at_ms`.
##! - CIK, the `GET /v1/credits/issuer-keys` answer: `u8 1 ‖ "CIK" ‖ u8 count
##!   (0–8) ‖ count × vector32(KTE v2)`, one evidence frame per key.

from Credits.CreditToken import credits_valid_host
from Transparency.Codec import (
  TcodecBytes,
  tcodec_done,
  tcodec_join,
  tcodec_start,
  tcodec_take_fixed,
  tcodec_take_u32,
  tcodec_take_u64,
  tcodec_take_u8,
  tcodec_take_vector,
  tcodec_u32,
  tcodec_u64,
  tcodec_u8,
  tcodec_vector
)
from Binary.Reader import BinaryReader

pub struct IssuerKey do
  purpose :: Int
  issuer_name :: String
  epoch :: Int
  not_before :: Int
  not_after :: Int
  spki :: Bytes
end

pub struct IssuerKeyRevocation do
  purpose :: Int
  issuer_name :: String
  epoch :: Int
  token_key_id :: Bytes
  revoked_at :: Int
end

pub fn credits_epoch_length() -> Int do
  2592000000
end

pub fn credits_epoch_at(now_ms :: Int) -> Int do
  now_ms / credits_epoch_length()
end

## 1 live, 2 test.

pub fn credits_purpose_name(purpose :: Int) -> String!String do
  case purpose do
    1 -> Ok("live")
    2 -> Ok("test")
    _ -> Err("unknown credit key purpose")
  end
end

pub fn credits_purpose_code(name :: String) -> Int!String do
  case name do
    "live" -> Ok(1)
    "test" -> Ok(2)
    _ -> Err("unknown credit key purpose")
  end
end

fn checked(value :: IssuerKey) -> IssuerKey!String do
  credits_purpose_name(value.purpose)?
  let start = value.epoch * credits_epoch_length()
  if !credits_valid_host(value.issuer_name)
    || value.epoch < 0
    || value.epoch > 4294967295
    || value.not_before != start
    || value.not_after != start + 2 * credits_epoch_length()
    || Bytes.length(value.spki) != 342 do
    Err("invalid issuer key")
  else
    Ok(value)
  end
end

## The key of `epoch`, with the validity window the epoch implies.

pub fn credits_issuer_key(purpose :: Int,
  issuer_name :: String,
  epoch :: Int,
  spki :: Bytes) -> IssuerKey!String do
  let start = epoch * credits_epoch_length()
  checked(IssuerKey {
    purpose: purpose,
    issuer_name: issuer_name,
    epoch: epoch,
    not_before: start,
    not_after: start + 2 * credits_epoch_length(),
    spki: spki
  })
end

pub fn credits_key_valid_at(value :: IssuerKey, now_ms :: Int) -> Bool do
  value.not_before <= now_ms && now_ms < value.not_after
end

fn header(magic :: String) -> Bytes!String do
  tcodec_join([tcodec_u8(1)?, Bytes.from_utf8(magic)])
end

pub fn credits_encode_issuer_key(value :: IssuerKey) -> Bytes!String do
  checked(value)?
  tcodec_join([
    header("IKY")?,
    tcodec_u8(value.purpose)?,
    tcodec_vector(Bytes.from_utf8(value.issuer_name))?,
    tcodec_u32(value.epoch)?,
    tcodec_u64(value.not_before)?,
    tcodec_u64(value.not_after)?,
    value.spki
  ])
end

fn name_from(state :: BinaryReader) -> TcodecBytes!String do
  tcodec_take_vector(state, 253)
end

fn key_from(input :: Bytes) -> IssuerKey!String do
  let purpose = tcodec_take_u8(tcodec_start(input, 628, 1, "IKY")?)?
  let name = name_from(purpose.state)?
  let epoch = tcodec_take_u32(name.state)?
  let not_before = tcodec_take_u64(epoch.state)?
  let not_after = tcodec_take_u64(not_before.state)?
  let spki = tcodec_take_fixed(not_after.state, 342)?
  tcodec_done(spki.state)?
  checked(IssuerKey {
    purpose: purpose.value,
    issuer_name: Bytes.to_utf8(name.value)?,
    epoch: epoch.value,
    not_before: not_before.value,
    not_after: not_after.value,
    spki: spki.value
  })
end

pub fn credits_decode_issuer_key(input :: Bytes) -> IssuerKey!String do
  case key_from(input) do
    Err(_) -> Err("invalid issuer key")
    Ok(value)
  end
end

fn checked_revocation(value :: IssuerKeyRevocation) -> IssuerKeyRevocation!String do
  credits_purpose_name(value.purpose)?
  if !credits_valid_host(value.issuer_name)
    || value.epoch < 0
    || value.epoch > 4294967295
    || Bytes.length(value.token_key_id) != 32
    || value.revoked_at < 0 do
    Err("invalid issuer key revocation")
  else
    Ok(value)
  end
end

pub fn credits_encode_revocation(value :: IssuerKeyRevocation) -> Bytes!String do
  checked_revocation(value)?
  tcodec_join([
    header("IKR")?,
    tcodec_u8(value.purpose)?,
    tcodec_vector(Bytes.from_utf8(value.issuer_name))?,
    tcodec_u32(value.epoch)?,
    value.token_key_id,
    tcodec_u64(value.revoked_at)?
  ])
end

fn revocation_from(input :: Bytes) -> IssuerKeyRevocation!String do
  let purpose = tcodec_take_u8(tcodec_start(input, 306, 1, "IKR")?)?
  let name = name_from(purpose.state)?
  let epoch = tcodec_take_u32(name.state)?
  let key_id = tcodec_take_fixed(epoch.state, 32)?
  let revoked_at = tcodec_take_u64(key_id.state)?
  tcodec_done(revoked_at.state)?
  checked_revocation(IssuerKeyRevocation {
    purpose: purpose.value,
    issuer_name: Bytes.to_utf8(name.value)?,
    epoch: epoch.value,
    token_key_id: key_id.value,
    revoked_at: revoked_at.value
  })
end

pub fn credits_decode_revocation(input :: Bytes) -> IssuerKeyRevocation!String do
  case revocation_from(input) do
    Err(_) -> Err("invalid issuer key revocation")
    Ok(value)
  end
end

## What a log leaf holds, by its first four bytes: 1 a device set, 2 an issuer
## key, 3 an issuer-key revocation, 0 anything else.

pub fn credits_leaf_kind(entry :: Bytes) -> Int do
  case Bytes.slice(entry, 0, 4) do
    Err(_) -> 0
    Ok(prefix) -> case Bytes.to_hex(prefix) do
      "01445653" -> 1
      "01494b59" -> 2
      "01494b52" -> 3
      _ -> 0
    end
  end
end

pub fn credits_encode_issuer_keys(evidence :: List<Bytes>) -> Bytes!String do
  if List.length(evidence) > 8 do
    Err("at most 8 issuer keys")
  else
    let parts = for value in evidence do
      tcodec_vector(value)?
    end
    tcodec_join([header("CIK")?, tcodec_u8(List.length(evidence))?] ++ parts)
  end
end

fn evidence_from(state :: BinaryReader,
  count :: Int,
  output :: List<Bytes>) -> (BinaryReader, List<Bytes>)!String do
  if List.length(output) >= count do
    Ok((state, output))
  else
    let value = tcodec_take_vector(state, 16777216)?
    evidence_from(value.state, count, List.append(output, value.value))
  end
end

fn listing_from(input :: Bytes) -> List<Bytes>!String do
  let count = tcodec_take_u8(tcodec_start(input, 134217728, 1, "CIK")?)?
  if count.value > 8 do
    Err("at most 8 issuer keys")
  else
    let (last, values) = evidence_from(count.state, count.value, List.new())?
    tcodec_done(last)?
    Ok(values)
  end
end

pub fn credits_decode_issuer_keys(input :: Bytes) -> List<Bytes>!String do
  case listing_from(input) do
    Err(_) -> Err("invalid issuer key listing")
    Ok(values)
  end
end
