from Binary.Reader import BinaryReader, finish, read_fixed, read_vector, reader

pub type BackupError do
  InvalidProfile

  InvalidManifest

  InvalidChunk

  InvalidChunkIndex

  InvalidChunkSize

  AuthenticationRejected

  CryptoFailure( error :: CryptoError)
end

pub struct BackupProfile do
  version :: Int
  salt :: Bytes
  memory_kib :: Int
  iterations :: Int
  parallelism :: Int
end

pub struct BackupManifest do
  version :: Int
  backup_id :: Bytes
  created_at :: U64
  chunk_size :: Int
  chunk_count :: Int
  plaintext_size :: Int
  snapshot_hash :: Bytes
end

struct SealedBackupManifest do
  profile :: BackupProfile
  backup_id :: Bytes
  nonce :: Bytes
  ciphertext :: Bytes
end

struct SealedBackupChunk do
  backup_id :: Bytes
  index :: Int
  nonce :: Bytes
  ciphertext :: Bytes
end

struct ReadBytes do
  state :: BinaryReader
  value :: Bytes
end

struct ReadInt do
  state :: BinaryReader
  value :: Int
end

struct ReadWide do
  state :: BinaryReader
  value :: U64
end

fn append(left :: Bytes, right :: Bytes) -> Bytes ! BackupError do
  case Bytes.concat(left, right) do
    Err( _) -> Err(InvalidManifest)
    Ok( output) -> Ok(output)
  end
end

fn join(parts :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! BackupError do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, append(output, List.get(parts, index)) ?)
  end
end

fn byte(value :: Int) -> Bytes ! BackupError do
  case Bytes.from_list([value]) do
    Err( _) -> Err(InvalidManifest)
    Ok( output) -> Ok(output)
  end
end

fn write_u32(value :: Int) -> Bytes ! BackupError do
  if value < 0 do
    Err(InvalidManifest)
  else
    let wide = case U64.parse(Int.to_string(value)) do
      Err( _) -> Err(InvalidManifest)
      Ok( output) -> Ok(output)
    end ?
    case Bytes.write_u32_be(wide) do
      Err( _) -> Err(InvalidManifest)
      Ok( output) -> Ok(output)
    end
  end
end

fn write_u64(value :: U64) -> Bytes ! BackupError do
  case Bytes.write_u64_be(value) do
    Err( _) -> Err(InvalidManifest)
    Ok( output) -> Ok(output)
  end
end

fn vector(value :: Bytes) -> Bytes ! BackupError do
  join([write_u32(Bytes.length(value)) ?, value], 0, Bytes.empty())
end

fn take_fixed(state :: BinaryReader, length :: Int) -> ReadBytes ! BackupError do
  case read_fixed(state, length) do
    Err( _) -> Err(InvalidManifest)
    Ok( ( next, value)) -> Ok(ReadBytes {
      state : next,
      value : value
    })
    Ok( _) -> Err(InvalidManifest)
  end
end

fn take_u8(state :: BinaryReader) -> ReadInt ! BackupError do
  let encoded = take_fixed(state, 1) ?
  case Bytes.get(encoded.value, 0) do
    Err( _) -> Err(InvalidManifest)
    Ok( value) -> Ok(ReadInt {
      state : encoded.state,
      value : value
    })
  end
end

fn take_u32(state :: BinaryReader) -> ReadInt ! BackupError do
  let encoded = take_fixed(state, 4) ?
  let wide = case Bytes.read_u32_be(encoded.value, 0) do
    Err( _) -> Err(InvalidManifest)
    Ok( output) -> Ok(output)
  end ?
  case U64.to_int(wide) do
    Err( _) -> Err(InvalidManifest)
    Ok( value) -> Ok(ReadInt {
      state : encoded.state,
      value : value
    })
  end
end

fn take_u64(state :: BinaryReader) -> ReadWide ! BackupError do
  let encoded = take_fixed(state, 8) ?
  case Bytes.read_u64_be(encoded.value, 0) do
    Err( _) -> Err(InvalidManifest)
    Ok( value) -> Ok(ReadWide {
      state : encoded.state,
      value : value
    })
  end
end

fn take_vector(state :: BinaryReader, maximum :: Int) -> ReadBytes ! BackupError do
  case read_vector(state, maximum) do
    Err( _) -> Err(InvalidManifest)
    Ok( ( next, value)) -> Ok(ReadBytes {
      state : next,
      value : value
    })
    Ok( _) -> Err(InvalidManifest)
  end
end

fn start(input :: Bytes, maximum :: Int, magic_value :: String) -> BinaryReader ! BackupError do
  if Bytes.length(input) > maximum do
    Err(InvalidManifest)
  else
    let initial = case reader(input, maximum) do
      Err( _) -> Err(InvalidManifest)
      Ok( output) -> Ok(output)
    end ?
    let version = take_u8(initial) ?
    let magic = take_fixed(version.state, 3) ?
    if version.value == 1 && Bytes.secure_equals(magic.value, Bytes.from_utf8(magic_value)) do
      Ok(magic.state)
    else
      Err(InvalidManifest)
    end
  end
end

fn done(state :: BinaryReader) -> Result <(), BackupError > do
  case finish(state) do
    Err( _) -> Err(InvalidManifest)
    Ok( _) -> Ok(nil)
  end
end

fn valid_profile(value :: BackupProfile) -> Result <(), BackupError > do
  # ponytail: one reviewed mobile profile; add a new version instead of mutable parameters.
  if value.version != 1 || Bytes.length(value.salt) != 16 || value.memory_kib != 65536 || value.iterations != 3 || value.parallelism != 1 do
    Err(InvalidProfile)
  else
    Ok(nil)
  end
end

fn encode_profile(value :: BackupProfile) -> Bytes ! BackupError do
  valid_profile(value) ?
  join([byte(value.version) ?, value.salt, write_u32(value.memory_kib) ?, write_u32(value.iterations) ?, byte(value.parallelism) ?],
  0,
  Bytes.empty())
end

fn decode_profile(state :: BinaryReader) -> Result <( BinaryReader, BackupProfile), BackupError > do
  let version = take_u8(state) ?
  let salt = take_fixed(version.state, 16) ?
  let memory = take_u32(salt.state) ?
  let iterations = take_u32(memory.state) ?
  let parallelism = take_u8(iterations.state) ?
  let value = BackupProfile {
    version : version.value,
    salt : salt.value,
    memory_kib : memory.value,
    iterations : iterations.value,
    parallelism : parallelism.value
  }
  valid_profile(value) ?
  Ok((parallelism.state, value))
end

fn validate_manifest(value :: BackupManifest) -> Result <(), BackupError > do
  if value.version != 1 || Bytes.length(value.backup_id) != 32 || Bytes.length(value.snapshot_hash) != 32 do
    Err(InvalidManifest)
  else if value.chunk_size <= 0 || value.chunk_size > 65536 || value.chunk_count <= 0 || value.chunk_count > 256 do
    Err(InvalidManifest)
  else
    let maximum = value.chunk_size * value.chunk_count
    let minimum = value.chunk_size * (value.chunk_count - 1)
    if value.plaintext_size <= minimum || value.plaintext_size > maximum do
      Err(InvalidManifest)
    else
      Ok(nil)
    end
  end
end

fn encode_manifest(value :: BackupManifest) -> Bytes ! BackupError do
  validate_manifest(value) ?
  join([byte(1) ?, Bytes.from_utf8("BMF"), value.backup_id, write_u64(value.created_at) ?, write_u32(value.chunk_size) ?, write_u32(value.chunk_count) ?, write_u32(value.plaintext_size) ?, value.snapshot_hash],
  0,
  Bytes.empty())
end

fn decode_manifest(input :: Bytes) -> BackupManifest ! BackupError do
  let backup_id = take_fixed(start(input, 88, "BMF") ?, 32) ?
  let created_at = take_u64(backup_id.state) ?
  let chunk_size = take_u32(created_at.state) ?
  let chunk_count = take_u32(chunk_size.state) ?
  let plaintext_size = take_u32(chunk_count.state) ?
  let snapshot_hash = take_fixed(plaintext_size.state, 32) ?
  done(snapshot_hash.state) ?
  let value = BackupManifest {
    version : 1,
    backup_id : backup_id.value,
    created_at : created_at.value,
    chunk_size : chunk_size.value,
    chunk_count : chunk_count.value,
    plaintext_size : plaintext_size.value,
    snapshot_hash : snapshot_hash.value
  }
  validate_manifest(value) ?
  Ok(value)
end

fn manifest_label() -> Bytes do
  Bytes.from_utf8("mesh-msg/v1/backup-manifest")
end

fn chunk_label() -> Bytes do
  Bytes.from_utf8("mesh-msg/v1/backup-chunk")
end

fn key_label() -> Bytes do
  Bytes.from_utf8("mesh-msg/v1/backup-key")
end

fn manifest_aad(profile :: BackupProfile, backup_id :: Bytes) -> Bytes ! BackupError do
  join([manifest_label(), encode_profile(profile) ?, backup_id], 0, Bytes.empty())
end

fn chunk_aad(manifest :: BackupManifest, index :: Int) -> Bytes ! BackupError do
  join([chunk_label(), Crypto.sha256(encode_manifest(manifest) ?), write_u32(index) ?],
  0,
  Bytes.empty())
end

fn nonce() -> Bytes ! BackupError do
  case Crypto.random_bytes(12) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( output) -> Ok(output)
  end
end

fn content_key(key :: borrow SecretBytes, backup_id :: Bytes, label :: Bytes) -> AeadKey ! BackupError do
  let material = case Crypto.hkdf_sha256(key, backup_id, label, 32) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( output) -> Ok(output)
  end ?
  case Crypto.aead_key(material) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( output) -> Ok(output)
  end
end

fn seal(key :: borrow AeadKey, nonce_value :: Bytes, aad :: Bytes, plaintext :: Bytes) -> Bytes ! BackupError do
  case Crypto.aead_seal(key, nonce_value, aad, plaintext) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( output) -> Ok(output)
  end
end

fn open(key :: borrow AeadKey, nonce_value :: Bytes, aad :: Bytes, ciphertext :: Bytes) -> Bytes ! BackupError do
  case Crypto.aead_open(key, nonce_value, aad, ciphertext) do
    Err( AuthenticationFailed) -> Err(AuthenticationRejected)
    Err( error) -> Err(CryptoFailure(error))
    Ok( output) -> Ok(output)
  end
end

fn encode_sealed_manifest(value :: SealedBackupManifest) -> Bytes ! BackupError do
  valid_profile(value.profile) ?
  if Bytes.length(value.backup_id) != 32 || Bytes.length(value.nonce) != 12 || Bytes.length(value.ciphertext) != 104 do
    Err(InvalidManifest)
  else
    join([byte(1) ?, Bytes.from_utf8("EBM"), encode_profile(value.profile) ?, value.backup_id, value.nonce, vector(value.ciphertext) ?],
    0,
    Bytes.empty())
  end
end

fn decode_sealed_manifest(input :: Bytes) -> SealedBackupManifest ! BackupError do
  let ( state, profile) = decode_profile(start(input, 182, "EBM") ?) ?
  let backup_id = take_fixed(state, 32) ?
  let nonce_value = take_fixed(backup_id.state, 12) ?
  let ciphertext = take_vector(nonce_value.state, 104) ?
  done(ciphertext.state) ?
  if Bytes.length(ciphertext.value) != 104 do
    Err(InvalidManifest)
  else
    Ok(SealedBackupManifest {
      profile : profile,
      backup_id : backup_id.value,
      nonce : nonce_value.value,
      ciphertext : ciphertext.value
    })
  end
end

fn expected_chunk_size(value :: BackupManifest, index :: Int) -> Int ! BackupError do
  validate_manifest(value) ?
  if index < 0 || index >= value.chunk_count do
    Err(InvalidChunkIndex)
  else if index == value.chunk_count - 1 do
    Ok(value.plaintext_size - ((value.chunk_count - 1) * value.chunk_size))
  else
    Ok(value.chunk_size)
  end
end

fn encode_chunk(value :: SealedBackupChunk) -> Bytes ! BackupError do
  if Bytes.length(value.backup_id) != 32 || value.index < 0 || value.index >= 256 || Bytes.length(value.nonce) != 12 || Bytes.length(value.ciphertext) < 17 || Bytes.length(value.ciphertext) > 65552 do
    Err(InvalidChunk)
  else
    join([byte(1) ?, Bytes.from_utf8("BCH"), value.backup_id, write_u32(value.index) ?, value.nonce, vector(value.ciphertext) ?],
    0,
    Bytes.empty())
  end
end

fn decode_chunk(input :: Bytes) -> SealedBackupChunk ! BackupError do
  let backup_id = take_fixed(start(input, 65608, "BCH") ?, 32) ?
  let index = take_u32(backup_id.state) ?
  let nonce_value = take_fixed(index.state, 12) ?
  let ciphertext = take_vector(nonce_value.state, 65552) ?
  done(ciphertext.state) ?
  if index.value >= 256 || Bytes.length(ciphertext.value) < 17 do
    Err(InvalidChunk)
  else
    Ok(SealedBackupChunk {
      backup_id : backup_id.value,
      index : index.value,
      nonce : nonce_value.value,
      ciphertext : ciphertext.value
    })
  end
end

pub fn generate_recovery_secret() -> SecretBytes ! BackupError do
  case Secret.random(32) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( output) -> Ok(output)
  end
end

pub fn create_backup_profile() -> BackupProfile ! BackupError do
  let salt = case Crypto.random_bytes(16) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( output) -> Ok(output)
  end ?
  Ok(BackupProfile {
    version : 1,
    salt : salt,
    memory_kib : 65536,
    iterations : 3,
    parallelism : 1
  })
end

pub fn derive_backup_key(recovery :: borrow SecretBytes, profile :: BackupProfile) -> SecretBytes ! BackupError do
  valid_profile(profile) ?
  let domain_salt = append(key_label(), profile.salt) ?
  case Crypto.argon2id(recovery,
  domain_salt,
  profile.memory_kib,
  profile.iterations,
  profile.parallelism,
  32) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( output) -> Ok(output)
  end
end

pub fn generate_backup_id() -> Bytes ! BackupError do
  case Crypto.random_bytes(32) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( output) -> Ok(output)
  end
end

pub fn seal_backup_manifest(key :: borrow SecretBytes,
profile :: BackupProfile,
manifest :: BackupManifest) -> Bytes ! BackupError do
  valid_profile(profile) ?
  let plaintext = encode_manifest(manifest) ?
  let nonce_value = nonce() ?
  let aead = content_key(key, manifest.backup_id, manifest_label()) ?
  let ciphertext = seal(aead, nonce_value, manifest_aad(profile, manifest.backup_id) ?, plaintext) ?
  encode_sealed_manifest(SealedBackupManifest {
    profile : profile,
    backup_id : manifest.backup_id,
    nonce : nonce_value,
    ciphertext : ciphertext
  })
end

pub fn profile_from_backup(input :: Bytes) -> BackupProfile ! BackupError do
  Ok(decode_sealed_manifest(input) ?.profile)
end

pub fn open_backup_manifest(key :: borrow SecretBytes, input :: Bytes) -> BackupManifest ! BackupError do
  let sealed = decode_sealed_manifest(input) ?
  let aead = content_key(key, sealed.backup_id, manifest_label()) ?
  let plaintext = open(aead,
  sealed.nonce,
  manifest_aad(sealed.profile, sealed.backup_id) ?,
  sealed.ciphertext) ?
  let manifest = decode_manifest(plaintext) ?
  if Bytes.secure_equals(manifest.backup_id, sealed.backup_id) do
    Ok(manifest)
  else
    Err(InvalidManifest)
  end
end

pub fn seal_backup_chunk(key :: borrow SecretBytes,
manifest :: BackupManifest,
index :: Int,
plaintext :: Bytes) -> Bytes ! BackupError do
  if Bytes.length(plaintext) != expected_chunk_size(manifest, index) ? do
    Err(InvalidChunkSize)
  else
    let nonce_value = nonce() ?
    let aead = content_key(key, manifest.backup_id, chunk_label()) ?
    let ciphertext = seal(aead, nonce_value, chunk_aad(manifest, index) ?, plaintext) ?
    encode_chunk(SealedBackupChunk {
      backup_id : manifest.backup_id,
      index : index,
      nonce : nonce_value,
      ciphertext : ciphertext
    })
  end
end

pub fn open_backup_chunk(key :: borrow SecretBytes,
manifest :: BackupManifest,
expected_index :: Int,
input :: Bytes) -> Bytes ! BackupError do
  let expected_size = expected_chunk_size(manifest, expected_index) ?
  let sealed = case decode_chunk(input) do
    Err( _) -> Err(InvalidChunk)
    Ok( output) -> Ok(output)
  end ?
  if !Bytes.secure_equals(sealed.backup_id, manifest.backup_id) do
    Err(InvalidChunk)
  else if sealed.index != expected_index do
    Err(InvalidChunkIndex)
  else if Bytes.length(sealed.ciphertext) != expected_size + 16 do
    Err(InvalidChunkSize)
  else
    let aead = content_key(key, manifest.backup_id, chunk_label()) ?
    let plaintext = open(aead,
    sealed.nonce,
    chunk_aad(manifest, expected_index) ?,
    sealed.ciphertext) ?
    if Bytes.length(plaintext) == expected_size do
      Ok(plaintext)
    else
      Err(InvalidChunkSize)
    end
  end
end

pub fn verify_backup_snapshot(manifest :: BackupManifest, plaintext :: Bytes) -> Bool do
  case validate_manifest(manifest) do
    Err( _) -> false
    Ok( _) -> Bytes.length(plaintext) == manifest.plaintext_size && Bytes.secure_equals(Crypto.sha256(plaintext),
    manifest.snapshot_hash)
  end
end
