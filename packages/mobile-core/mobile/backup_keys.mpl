from Backups.Protocol import BackupProfile, derive_backup_key
from Mobile.Codec import mobile_byte, mobile_join, mobile_wide, mobile_write_u64, mobile_zeroes
from Storage.Keys import context, pending_context

##! Mobile.BackupKeys: what a recovery code opens (`protocol/backup-wire-v1.md`,
##! version 2). The code is 32 random bytes the user holds. Everything else is
##! derived from it: where the backups are, the capabilities that reach them, and
##! the key that seals them, so a new device finds its backup from the code alone
##! and the store learns no account.

pub struct BackupSlot do
  object_id :: Bytes
  upload_capability :: Bytes
  download_capability :: Bytes
end

fn digest(parts :: List<Bytes>) -> Bytes!String do
  Ok(Crypto.sha256(mobile_join(parts, 0, Bytes.empty())?))
end

pub fn backup_locator(code :: Bytes) -> Bytes!String do
  if Bytes.length(code) != 32 do
    Err("invalid_backup_code")
  else
    digest([Bytes.from_utf8("mesh-msg/v2/backup-locator"), code])
  end
end

## One of the four objects a day may hold, `index` 0 through 3.

pub fn backup_slot(locator :: Bytes, day :: Int, index :: Int) -> BackupSlot!String do
  let position = mobile_join([
      mobile_write_u64(mobile_wide(Int.to_string(day))?)?,
      mobile_byte(index)?
    ],
    0,
    Bytes.empty())?
  Ok(BackupSlot {
    object_id: digest([Bytes.from_utf8("mesh-msg/v2/backup-object"), locator, position])?,
    upload_capability: digest([Bytes.from_utf8("mesh-msg/v2/backup-upload"), locator, position])?,
    download_capability: digest([
      Bytes.from_utf8("mesh-msg/v2/backup-download"),
      locator,
      position
    ])?
  })
end

## The sealing key: Argon2id under the version 1 profile, whose salt comes from
## the code, so nothing needs to be read before the key exists.

pub fn backup_content_key(code :: Bytes) -> SecretBytes!String do
  if Bytes.length(code) != 32 do
    return Err("invalid_backup_code")
  end
  let salt = case Bytes.slice(digest([Bytes.from_utf8("mesh-msg/v2/backup-salt"), code])?, 0, 16) do
    Err(_) -> Err("backup_key_failed")
    Ok(value)
  end?
  let secret = case Secret.from_bytes(code) do
    Err(_) -> Err("backup_key_failed")
    Ok(value)
  end?
  case derive_backup_key(secret,
    BackupProfile { version: 1, salt: salt, memory_kib: 65536, iterations: 3, parallelism: 1 }) do
    Err(_) -> Err("backup_key_failed")
    Ok(key)
  end
end

## The derived key kept on the device between calls, sealed under the platform
## key as purpose 5 with the label's hash as its object ID.

pub fn backup_seal_key(key :: borrow SecretBytes,
  wrapping_key :: borrow StorageKey,
  label :: String) -> Bytes!String do
  case Secret.seal_for_storage(key, wrapping_key, pending_context(label, 5)?) do
    Err(_) -> Err("backup_key_seal_failed")
    Ok(blob)
  end
end

pub fn backup_open_key(blob :: Bytes,
  wrapping_key :: borrow StorageKey,
  label :: String) -> SecretBytes!String do
  case Secret.unseal_from_storage(blob, wrapping_key, pending_context(label, 5)?) do
    Err(_) -> Err("backup_key_open_failed")
    Ok(key)
  end
end

## The key a backup seals the account key under: a storage key derived from
## the content key, so whoever holds the code can open it on a new device, and
## nothing else can. Purpose 6 (account authorization key), for the account,
## no device.

pub fn backup_account_key(key :: borrow SecretBytes) -> StorageKey!String do
  let material = case Crypto.hkdf_sha256(key,
    Bytes.from_utf8("mesh-msg/v2/backup-account-key"),
    Bytes.from_utf8("account authorization key"),
    32) do
    Err(_) -> Err("backup_key_failed")
    Ok(value)
  end?
  case StorageKey.from_secret(material, Bytes.from_utf8("morse/backup-account-key/v1")) do
    Err(_) -> Err("backup_key_failed")
    Ok(value)
  end
end

pub fn backup_account_context(account_id :: Bytes) -> Bytes!String do
  context(account_id, mobile_zeroes(16)?, "backup-account-key/v1", 6)
end
