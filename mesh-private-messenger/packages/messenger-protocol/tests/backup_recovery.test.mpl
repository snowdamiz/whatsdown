from Backups.Protocol import (
  BackupError,
  BackupManifest,
  create_backup_profile,
  derive_backup_key,
  generate_backup_id,
  seal_backup_manifest,
  seal_backup_chunk,
  profile_from_backup,
  open_backup_manifest,
  open_backup_chunk,
  verify_backup_snapshot
)
from Backups.Recovery import create_backup_recovery, open_backup_recovery

struct PreparedRecovery do
  code :: String
  manifest :: Bytes
  chunk :: Bytes
end

fn original_body() -> Bytes do
  Bytes.from_utf8("owned synthetic backup content; no active session or financial state")
end

fn prepare_backup() -> PreparedRecovery!BackupError do
  let (recovery, code) = create_backup_recovery()?
  let profile = create_backup_profile()?
  let key = derive_backup_key(recovery, profile)?
  Secret.destroy(recovery)
  let created = case U64.parse("1") do
    Err(_) -> return Err(InvalidManifest)
    Ok(value) -> value
  end
  let body = original_body()
  let manifest = BackupManifest {
    version: 1,
    backup_id: generate_backup_id()?,
    created_at: created,
    chunk_size: 65536,
    chunk_count: 1,
    plaintext_size: Bytes.length(body),
    snapshot_hash: Crypto.sha256(body)
  }
  let sealed_manifest = seal_backup_manifest(key, profile, manifest)?
  let chunk = seal_backup_chunk(key, manifest, 0, body)?
  Secret.destroy(key)
  Ok(PreparedRecovery { code: code, manifest: sealed_manifest, chunk: chunk })
end

fn restore_backup(saved :: PreparedRecovery, code :: String) -> Bytes!BackupError do
  let profile = profile_from_backup(saved.manifest)?
  let recovery = open_backup_recovery(code)?
  let key = derive_backup_key(recovery, profile)?
  Secret.destroy(recovery)
  let manifest = open_backup_manifest(key, saved.manifest)?
  let clear = open_backup_chunk(key, manifest, 0, saved.chunk)?
  Secret.destroy(key)
  if verify_backup_snapshot(manifest, clear) do
    Ok(clear)
  else
    Err(InvalidManifest)
  end
end

fn roundtrip() -> Bool!BackupError do
  let saved = prepare_backup()?
  let restored = restore_backup(saved, saved.code)?
  Ok(String.length(saved.code) == 85 && Bytes.secure_equals(restored, original_body()))
end

fn wrong_code() -> Bool!BackupError do
  let saved = prepare_backup()?
  let (other, other_code) = create_backup_recovery()?
  Secret.destroy(other)
  let refused = case restore_backup(saved, other_code) do
    Err(AuthenticationRejected) -> true
    _ -> false
  end
  let restored = restore_backup(saved, saved.code)?
  Ok(refused && Bytes.secure_equals(restored, original_body()))
end

fn malformed_code() -> Bool!BackupError do
  let (secret, code) = create_backup_recovery()?
  Secret.destroy(secret)
  let malformed = case open_backup_recovery(String.replace(code, "MRC1", "MRC2")) do
    Err(CryptoFailure(InvalidKey)) -> true
    _ -> false
  end
  let imported = open_backup_recovery(code)?
  Secret.destroy(imported)
  Ok(malformed)
end

test("D4 recovery code restores actual backup after original secrets are destroyed") do
  assert(case roundtrip() do
    Ok(true) -> true
    _ -> false
  end)
end

test("D4 a different valid recovery code fails manifest authentication and correct retry succeeds") do
  assert(case wrong_code() do
    Ok(true) -> true
    _ -> false
  end)
end

test("D4 malformed recovery code refuses through public Mesh and valid import still works") do
  assert(case malformed_code() do
    Ok(true) -> true
    _ -> false
  end)
end
