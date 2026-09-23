from Backups.Protocol import BackupError, BackupManifest, BackupProfile, create_backup_profile, derive_backup_key, generate_backup_id, generate_recovery_secret, open_backup_chunk, open_backup_manifest, profile_from_backup, seal_backup_chunk, seal_backup_manifest, verify_backup_snapshot

fn wide(value :: String) -> U64!BackupError do
  case U64.parse(value) do
    Err(_) -> Err(InvalidManifest)
    Ok(output)
  end
end

fn append(left :: Bytes, right :: Bytes) -> Bytes!BackupError do
  case Bytes.concat(left, right) do
    Err(_) -> Err(InvalidManifest)
    Ok(output)
  end
end

fn tamper_last_byte(input :: Bytes) -> Bytes!BackupError do
  let length = Bytes.length(input)
  let last = case Bytes.get(input, length - 1) do
    Err(_) -> Err(InvalidChunk)
    Ok(output)
  end?
  let prefix = case Bytes.slice(input, 0, length - 1) do
    Err(_) -> Err(InvalidChunk)
    Ok(output)
  end?
  let replacement = if last == 120 do
    Bytes.from_utf8("y")
  else
    Bytes.from_utf8("x")
  end
  case Bytes.concat(prefix, replacement) do
    Err(_) -> Err(InvalidChunk)
    Ok(output)
  end
end

fn backup_proof() -> Bool!BackupError do
  let recovery = generate_recovery_secret()?
  let profile = create_backup_profile()?
  let key = derive_backup_key(recovery, profile)?
  let backup_id = generate_backup_id()?
  let first = Bytes.from_utf8("0123456789abcdef")
  let second = Bytes.from_utf8("final")
  let plaintext = append(first, second)?
  let manifest = BackupManifest {
    version: 1,
    backup_id: backup_id,
    created_at: wide("4102444800000")?,
    chunk_size: 16,
    chunk_count: 2,
    plaintext_size: Bytes.length(plaintext),
    snapshot_hash: Crypto.sha256(plaintext)
  }
  let manifest_wire = seal_backup_manifest(key, profile, manifest)?
  let restored_profile = profile_from_backup(manifest_wire)?
  assert(restored_profile.version == 1)
  assert(restored_profile.memory_kib == 65536)
  assert(restored_profile.iterations == 3)
  assert(restored_profile.parallelism == 1)
  let restored_key = derive_backup_key(recovery, restored_profile)?
  let opened = open_backup_manifest(restored_key, manifest_wire)?
  assert(Bytes.secure_equals(opened.backup_id, backup_id))
  let first_wire = seal_backup_chunk(key, opened, 0, first)?
  let second_wire = seal_backup_chunk(key, opened, 1, second)?
  let opened_first = open_backup_chunk(restored_key, opened, 0, first_wire)?
  let opened_second = open_backup_chunk(restored_key, opened, 1, second_wire)?
  assert(Bytes.secure_equals(opened_first, first))
  assert(Bytes.secure_equals(opened_second, second))
  assert(verify_backup_snapshot(opened, append(opened_first, opened_second)?))
  assert(!verify_backup_snapshot(opened, append(plaintext, Bytes.from_utf8("x"))?))
  case seal_backup_chunk(key, opened, 1, Bytes.from_utf8("wrong-size")) do
    Err(InvalidChunkSize) -> assert(true)
    _ -> assert(false)
  end
  case open_backup_chunk(restored_key, opened, 1, first_wire) do
    Err(InvalidChunkIndex) -> assert(true)
    _ -> assert(false)
  end
  case open_backup_chunk(restored_key, opened, 1, tamper_last_byte(second_wire)?) do
    Err(AuthenticationRejected) -> assert(true)
    _ -> assert(false)
  end
  case open_backup_chunk(restored_key, opened, 1, append(second_wire, Bytes.from_utf8("x"))?) do
    Err(InvalidChunk) -> assert(true)
    _ -> assert(false)
  end
  case profile_from_backup(append(manifest_wire, Bytes.from_utf8("x"))?) do
    Err(InvalidManifest) -> assert(true)
    _ -> assert(false)
  end
  let weak_profile = BackupProfile {
    version: profile.version,
    salt: profile.salt,
    memory_kib: 8,
    iterations: profile.iterations,
    parallelism: profile.parallelism
  }
  case derive_backup_key(recovery, weak_profile) do
    Err(InvalidProfile) -> assert(true)
    Err(_) -> assert(false)
    Ok(unexpected) -> do
      Secret.destroy(unexpected)
      assert(false)
    end
  end
  let wrong_key = generate_recovery_secret()?
  case open_backup_manifest(wrong_key, manifest_wire) do
    Err(AuthenticationRejected) -> assert(true)
    _ -> assert(false)
  end
  Secret.destroy(wrong_key)
  Secret.destroy(restored_key)
  Secret.destroy(key)
  Secret.destroy(recovery)
  Ok(true)
end

test("versioned recovery profile seals an opaque bounded backup") do
  case backup_proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end
