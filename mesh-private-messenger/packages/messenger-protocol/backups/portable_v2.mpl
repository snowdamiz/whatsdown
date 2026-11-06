from Binary.Reader import BinaryReader
from Protocol.V1 import ProtocolError
from Protocol.WirePrimitives import (
  protocol_as_int,
  protocol_open,
  protocol_require_end,
  protocol_take_fixed,
  protocol_take_u16,
  protocol_take_u32,
  protocol_take_u64,
  protocol_take_vector,
  protocol_write_length,
  protocol_write_u16,
  protocol_write_u64
)
from Backups.Protocol import (
  BackupError,
  BackupManifest,
  BackupProfile,
  create_backup_profile,
  derive_backup_key,
  generate_backup_id,
  open_backup_chunk,
  open_backup_manifest,
  profile_from_backup,
  verify_backup_snapshot
)
from Backups.Recovery import create_backup_recovery, open_backup_recovery
from Backups.FileBundle import BackupFileBundle, decode_backup_file
from Backups.TextArchive import (
  BackupArchiveScope,
  BackupTextArchive,
  decode_text_archive,
  encode_text_archive
)

##! Inactive whole-archive protocol. A new export creates a new user-held code.
##! This does not authorize account recovery or import, or qualify native file IO.
pub struct PortableBackupV2Content do
  owner_account :: Bytes
  owner_authorization_key :: Bytes
  service_realm :: Bytes
  candidate_count :: Int
  omitted_timed :: Int
  omitted_unknown :: Int
  omitted_nontext :: Int
  omitted_empty :: Int
  attachment_messages :: Int
  scopes :: List<BackupArchiveScope>
end

pub struct PortableBackupV2Created do
  wire :: Bytes
  recovery_code :: String
end

pub type PortableBackupV2Error do
  PortableBackupV2Refused
end

impl From<ProtocolError> for PortableBackupV2Error do
  fn from(error :: ProtocolError) -> PortableBackupV2Error do
    PortableBackupV2Refused
  end
end

impl From<BackupError> for PortableBackupV2Error do
  fn from(error :: BackupError) -> PortableBackupV2Error do
    PortableBackupV2Refused
  end
end

# Closed schema admission, never a caller-provided validator or raw-payload seal mode.
type PortableV2Schema do
  PortableV2TextOnly
  PortableV2TextOrContent
end

struct PortableV2Prepared do
  payload :: Plaintext<Bytes>
  extent :: Int
end

struct PortableV2RestoreCandidate do
  payload :: Plaintext<Bytes>
  complete :: Bool
end

struct PortableV2Bundle do
  manifest :: Bytes
  profile :: BackupProfile
  backup_id :: Bytes
  chunks :: List<Bytes>
  plaintext_size :: Int
end

struct PortableV2ChunkRead do
  state :: BinaryReader
  chunks :: List<Bytes>
  plaintext_size :: Int
end

fn portable_v2_join(parts :: List<Bytes>, maximum :: Int) -> Bytes!PortableBackupV2Error do
  case Bytes.concat_many(parts, maximum) do
    Err(_) -> Err(PortableBackupV2Refused)
    Ok(value)
  end
end

# Unlike a generic list join, this fixed append preserves the two extent proofs.
fn portable_v2_append(left :: Bytes, right :: Bytes) -> Bytes!PortableBackupV2Error do
  case Bytes.concat(left, right) do
    Err(_) -> Err(PortableBackupV2Refused)
    Ok(value)
  end
end

fn portable_v2_slice(input :: Bytes, start :: Int, count :: Int) -> Bytes!PortableBackupV2Error do
  case Bytes.slice(input, start, count) do
    Err(_) -> Err(PortableBackupV2Refused)
    Ok(value)
  end
end

fn portable_v2_octet(input :: Bytes, index :: Int) -> Int!PortableBackupV2Error do
  case Bytes.get(input, index) do
    Err(_) -> Err(PortableBackupV2Refused)
    Ok(value)
  end
end

fn portable_v2_u32(input :: Bytes, index :: Int) -> Int!PortableBackupV2Error do
  let wide = case Bytes.read_u32_be(input, index) do
    Err(_) -> return Err(PortableBackupV2Refused)
    Ok(value) -> value
  end
  Ok(protocol_as_int(wide)?)
end

fn portable_v2_magic(version :: Int, name :: String) -> Bytes!PortableBackupV2Error do
  let prefix = case Bytes.from_list([version]) do
    Err(_) -> return Err(PortableBackupV2Refused)
    Ok(value) -> value
  end
  portable_v2_join([prefix, Bytes.from_utf8(name)], 4)
end

fn portable_v2_nonce() -> Bytes!PortableBackupV2Error do
  case Bytes.repeat(0, 12) do
    Err(_) -> Err(PortableBackupV2Refused)
    Ok(value)
  end
end

fn portable_v2_vector(input :: Bytes) -> Bytes!PortableBackupV2Error do
  portable_v2_join([protocol_write_length(Bytes.length(input))?, input], 65612)
end

fn portable_v2_profile_bytes(value :: BackupProfile) -> Bytes!PortableBackupV2Error do
  if value.version != 1
    || Bytes.length(value.salt) != 16
    || value.memory_kib != 65536
    || value.iterations != 3
    || value.parallelism != 1 do
    return Err(PortableBackupV2Refused)
  end
  let one = case Bytes.from_list([1]) do
    Err(_) -> return Err(PortableBackupV2Refused)
    Ok(value) -> value
  end
  portable_v2_join([one, value.salt, protocol_write_length(65536)?, protocol_write_length(3)?, one],
    26)
end

fn portable_v2_decode_profile(input :: Bytes) -> BackupProfile!PortableBackupV2Error do
  if Bytes.length(input) != 26
    || portable_v2_octet(input, 0)? != 1
    || portable_v2_u32(input, 17)? != 65536
    || portable_v2_u32(input, 21)? != 3
    || portable_v2_octet(input, 25)? != 1 do
    return Err(PortableBackupV2Refused)
  end
  Ok(BackupProfile {
    version: 1,
    salt: portable_v2_slice(input, 1, 16)?,
    memory_kib: 65536,
    iterations: 3,
    parallelism: 1
  })
end

fn portable_v2_manifest_aad(profile :: BackupProfile,
  backup_id :: Bytes) -> Bytes!PortableBackupV2Error do
  let version = case Bytes.from_list([2]) do
    Err(_) -> return Err(PortableBackupV2Refused)
    Ok(value) -> value
  end
  portable_v2_join([
      Bytes.from_utf8("mesh-msg/v2/backup-manifest"),
      version,
      portable_v2_profile_bytes(profile)?,
      backup_id
    ],
    86)
end

fn portable_v2_chunk_info(binding :: Bytes, index :: Int) -> Bytes!PortableBackupV2Error do
  portable_v2_join([
      Bytes.from_utf8("mesh-msg/v2/backup-chunk-key"),
      binding,
      protocol_write_length(index)?
    ],
    64)
end

fn portable_v2_chunk_aad(backup_id :: Bytes,
  binding :: Bytes,
  index :: Int) -> Bytes!PortableBackupV2Error do
  let version = case Bytes.from_list([2]) do
    Err(_) -> return Err(PortableBackupV2Refused)
    Ok(value) -> value
  end
  portable_v2_join([
      Bytes.from_utf8("mesh-msg/v2/backup-chunk"),
      version,
      backup_id,
      protocol_write_length(index)?,
      binding
    ],
    93)
end

fn portable_v2_key(master :: borrow SecretBytes,
  backup_id :: Bytes,
  info :: Bytes) -> AeadKey!PortableBackupV2Error do
  let material = case Crypto.hkdf_sha256(master, backup_id, info, 32) do
    Err(_) -> return Err(PortableBackupV2Refused)
    Ok(value) -> value
  end
  # aead_key consumes material on both outcomes; it never exposes the raw bytes.
  case Crypto.aead_key(material) do
    Err(_) -> Err(PortableBackupV2Refused)
    Ok(value)
  end
end

fn portable_v2_seal(master :: borrow SecretBytes,
  backup_id :: Bytes,
  info :: Bytes,
  aad :: Bytes,
  body :: Plaintext<Bytes>) -> Bytes!PortableBackupV2Error do
  let nonce = portable_v2_nonce()?
  let key = portable_v2_key(master, backup_id, info)?
  let raw = Crypto.aead_seal(key, nonce, aad, body)
  Secret.destroy(key)
  # Exactly the bounded primitive tag is observed. The raw error payload is ignored.
  case declassify_discriminant(raw,
    "portable backup reviews only bounded AEAD seal admission for fixed manifest or disclosed-size chunk bodies; ciphertext alone crosses encryption and plaintext, error payloads and prior private control remain private") do
    Err(_) -> Err(PortableBackupV2Refused)
    Ok(value)
  end
end

fn portable_v2_open(master :: borrow SecretBytes,
  backup_id :: Bytes,
  info :: Bytes,
  aad :: Bytes,
  ciphertext :: Bytes) -> Plaintext<Bytes>!PortableBackupV2Error do
  let nonce = portable_v2_nonce()?
  let key = portable_v2_key(master, backup_id, info)?
  let raw = Crypto.aead_open(key, nonce, aad, ciphertext)
  Secret.destroy(key)
  case raw do
    Err(_) -> Err(PortableBackupV2Refused)
    Ok(value) -> do
      let protected :: Plaintext<Bytes> = value
      Ok(protected)
    end
  end
end

# Private root-accepting seam. A caller cannot reuse a writer or seal under a code.
fn portable_v2_seal_chunk(master :: borrow SecretBytes,
  backup_id :: Bytes,
  manifest_binding :: Bytes,
  index :: Int,
  body :: Plaintext<Bytes>) -> Bytes!PortableBackupV2Error do
  let info = portable_v2_chunk_info(manifest_binding, index)?
  let aad = portable_v2_chunk_aad(backup_id, manifest_binding, index)?
  let ciphertext = portable_v2_seal(master, backup_id, info, aad, body)?
  portable_v2_join([
      portable_v2_magic(2, "BCH")?,
      backup_id,
      protocol_write_length(index)?,
      portable_v2_nonce()?,
      portable_v2_vector(ciphertext)?
    ],
    65608)
end

fn portable_v2_prepare(content :: Plaintext<PortableBackupV2Content>,
  backup_id :: Bytes,
  created_at :: U64) -> PortableV2Prepared do
  let raw = encode_text_archive(BackupTextArchive {
    backup_id: backup_id,
    owner_account: content.owner_account,
    owner_authorization_key: content.owner_authorization_key,
    service_realm: content.service_realm,
    created_at: created_at,
    candidate_count: content.candidate_count,
    omitted_timed: content.omitted_timed,
    omitted_unknown: content.omitted_unknown,
    omitted_nontext: content.omitted_nontext,
    omitted_empty: content.omitted_empty,
    attachment_messages: content.attachment_messages,
    scopes: content.scopes
  })
  case raw do
    Err(_) -> PortableV2Prepared { payload: Bytes.empty(), extent: 0 }
    Ok(payload) -> if Bytes.length(payload) >= 293 && Bytes.length(payload) <= 16777216 do
      PortableV2Prepared { payload: payload, extent: Bytes.length(payload) }
    else
      PortableV2Prepared { payload: Bytes.empty(), extent: 0 }
    end
  end
end

fn portable_v2_manifest_header(backup_id :: Bytes,
  created_at :: U64,
  extent :: Int) -> Bytes!PortableBackupV2Error do
  portable_v2_join([
      portable_v2_magic(2, "BMF")?,
      backup_id,
      protocol_write_u64(created_at)?,
      protocol_write_length(65536)?,
      protocol_write_length((extent + 65535) / 65536)?,
      protocol_write_length(extent)?
    ],
    56)
end

fn portable_v2_chunk_from_payload(master :: borrow SecretBytes,
  backup_id :: Bytes,
  binding :: Bytes,
  payload :: Plaintext<Bytes>,
  index :: Int,
  extent :: Int) -> Bytes!PortableBackupV2Error do
  let offset = index * 65536
  let count = if extent - offset > 65536 do
    65536
  else
    extent - offset
  end
  let raw = Bytes.slice(payload, offset, count)
  case declassify_discriminant(raw,
    "portable backup reviews only bounded chunk slice admission at public offsets and lengths derived from the disclosed extent; chunk bytes and error payload remain private") do
    Err(_) -> Err(PortableBackupV2Refused)
    Ok(body) -> portable_v2_seal_chunk(master, backup_id, binding, index, body)
  end
end

fn portable_v2_create_wire(master :: borrow SecretBytes,
  profile :: BackupProfile,
  backup_id :: Bytes,
  created_at :: U64,
  payload :: Plaintext<Bytes>,
  extent :: Int) -> Bytes!PortableBackupV2Error do
  # Public fixed header plus fixed-extent private digest; no private Result branch.
  let header = portable_v2_manifest_header(backup_id, created_at, extent)?
  let body = portable_v2_append(header, Crypto.sha256(payload))?
  let aad = portable_v2_manifest_aad(profile, backup_id)?
  let ciphertext = portable_v2_seal(master,
    backup_id,
    Bytes.from_utf8("mesh-msg/v2/backup-manifest-key"),
    aad,
    body)?
  let manifest = portable_v2_join([
      portable_v2_magic(2, "EBM")?,
      portable_v2_profile_bytes(profile)?,
      backup_id,
      portable_v2_nonce()?,
      portable_v2_vector(ciphertext)?
    ],
    182)?
  let binding = Crypto.sha256(manifest)
  let chunk_count = (extent + 65535) / 65536
  let chunks = for index in 0..chunk_count do
    portable_v2_vector(portable_v2_chunk_from_payload(master,
      backup_id,
      binding,
      payload,
      index,
      extent)?)?
  end
  portable_v2_join([
      portable_v2_magic(2, "MBF")?,
      portable_v2_vector(manifest)?,
      protocol_write_u16(chunk_count)?
    ]
      ++ chunks,
    16796864)
end

## Each successful export has a fresh code. Display once and require user acknowledgement;
## never log or persist it. Ordinary String/Bytes do not promise prompt erasure.
fn portable_v2_create_prepared(prepared :: PortableV2Prepared,
  backup_id :: Bytes,
  created_at :: U64) -> PortableBackupV2Created!PortableBackupV2Error do
  let extent = declassify(prepared.extent,
    "portable backup explicitly discloses only zero refusal or a bounded payload byte extent already derivable from its unpadded encrypted framing; payload records and hashes remain private")
  if extent < 293 || extent > 16777216 do
    return Err(PortableBackupV2Refused)
  end
  let profile = create_backup_profile()?
  let (root, code) = create_backup_recovery()?
  let derived = derive_backup_key(root, profile)
  Secret.destroy(root)
  let master = case derived do
    Err(_) -> return Err(PortableBackupV2Refused)
    Ok(value) -> value
  end
  let raw = portable_v2_create_wire(master,
    profile,
    backup_id,
    created_at,
    prepared.payload,
    extent)
  Secret.destroy(master)
  case raw do
    Err(_) -> Err(PortableBackupV2Refused)
    Ok(wire) -> Ok(PortableBackupV2Created { wire: wire, recovery_code: code })
  end
end

## The original public writer continues to admit canonical text archives only.
pub fn create_portable_backup_v2(content :: Plaintext<PortableBackupV2Content>,
  created_at :: U64) -> PortableBackupV2Created!PortableBackupV2Error do
  let backup_id = generate_backup_id()?
  portable_v2_create_prepared(portable_v2_prepare(content, backup_id, created_at),
    backup_id,
    created_at)
end

fn portable_v2_wrapper_profile(input :: Bytes) -> BackupProfile!PortableBackupV2Error do
  if Bytes.length(input) != 182
    || !Bytes.secure_equals(portable_v2_slice(input, 0, 4)?, portable_v2_magic(2, "EBM")?)
    || !Bytes.secure_equals(portable_v2_slice(input, 62, 12)?, portable_v2_nonce()?)
    || portable_v2_u32(input, 74)? != 104 do
    return Err(PortableBackupV2Refused)
  end
  portable_v2_decode_profile(portable_v2_slice(input, 4, 26)?)
end

fn portable_v2_chunk_shape(chunk :: Bytes,
  backup_id :: Bytes,
  index :: Int,
  count :: Int) -> Int!PortableBackupV2Error do
  let size = Bytes.length(chunk)
  if size < 73
    || size > 65608
    || !Bytes.secure_equals(portable_v2_slice(chunk, 0, 4)?, portable_v2_magic(2, "BCH")?)
    || !Bytes.secure_equals(portable_v2_slice(chunk, 4, 32)?, backup_id)
    || portable_v2_u32(chunk, 36)? != index
    || !Bytes.secure_equals(portable_v2_slice(chunk, 40, 12)?, portable_v2_nonce()?) do
    return Err(PortableBackupV2Refused)
  end
  let encrypted_size = portable_v2_u32(chunk, 52)?
  if encrypted_size < 17
    || encrypted_size > 65552
    || size != 56 + encrypted_size
    || (index < count - 1 && encrypted_size != 65552) do
    return Err(PortableBackupV2Refused)
  end
  Ok(encrypted_size - 16)
end

fn portable_v2_read_chunks(state :: BinaryReader,
  count :: Int,
  index :: Int,
  backup_id :: Bytes,
  size :: Int,
  output :: List<Bytes>) -> PortableV2ChunkRead!PortableBackupV2Error do
  if index >= count do
    return Ok(PortableV2ChunkRead {
      state: state,
      chunks: List.reverse(output),
      plaintext_size: size
    })
  end
  let chunk = protocol_take_vector(state, 65608)?
  let extent = portable_v2_chunk_shape(chunk.value, backup_id, index, count)?
  if size + extent > 16777216 do
    return Err(PortableBackupV2Refused)
  end
  portable_v2_read_chunks(chunk.state,
    count,
    index + 1,
    backup_id,
    size + extent,
    [chunk.value] ++ output)
end

fn portable_v2_decode_file(input :: Bytes) -> PortableV2Bundle!PortableBackupV2Error do
  let magic = protocol_take_fixed(protocol_open(input, 16796864)?, 4)?
  if !Bytes.secure_equals(magic.value, portable_v2_magic(2, "MBF")?) do
    return Err(PortableBackupV2Refused)
  end
  let manifest = protocol_take_vector(magic.state, 182)?
  # Validate complete canonical public E before count-dependent chunk copies/KDF.
  let profile = portable_v2_wrapper_profile(manifest.value)?
  let backup_id = portable_v2_slice(manifest.value, 30, 32)?
  let count = protocol_take_u16(manifest.state)?
  if count.value < 1 || count.value > 256 do
    return Err(PortableBackupV2Refused)
  end
  let parsed = portable_v2_read_chunks(count.state, count.value, 0, backup_id, 0, [])?
  protocol_require_end(parsed.state)?
  Ok(PortableV2Bundle {
    manifest: manifest.value,
    profile: profile,
    backup_id: backup_id,
    chunks: parsed.chunks,
    plaintext_size: parsed.plaintext_size
  })
end

fn portable_v2_decode_manifest(input :: Plaintext<Bytes>) -> BackupManifest!PortableBackupV2Error do
  if Bytes.length(input) != 88 do
    return Err(PortableBackupV2Refused)
  end
  let magic = protocol_take_fixed(protocol_open(input, 88)?, 4)?
  if !Bytes.secure_equals(magic.value, portable_v2_magic(2, "BMF")?) do
    return Err(PortableBackupV2Refused)
  end
  let backup_id = protocol_take_fixed(magic.state, 32)?
  let created_at = protocol_take_u64(backup_id.state)?
  let chunk_size = protocol_take_u32(created_at.state)?
  let chunk_count = protocol_take_u32(chunk_size.state)?
  let plaintext_size = protocol_take_u32(chunk_count.state)?
  let snapshot_hash = protocol_take_fixed(plaintext_size.state, 32)?
  protocol_require_end(snapshot_hash.state)?
  let size = protocol_as_int(plaintext_size.value)?
  let count = protocol_as_int(chunk_count.value)?
  if protocol_as_int(chunk_size.value)? != 65536
    || size < 293
    || size > 16777216
    || count != (size + 65535) / 65536
    || count < 1
    || count > 256 do
    return Err(PortableBackupV2Refused)
  end
  Ok(BackupManifest {
    version: 2,
    backup_id: backup_id.value,
    created_at: created_at.value,
    chunk_size: 65536,
    chunk_count: count,
    plaintext_size: size,
    snapshot_hash: snapshot_hash.value
  })
end

fn portable_v2_checked_text(manifest :: Plaintext<BackupManifest>,
  payload :: Plaintext<Bytes>) -> Plaintext<Bytes>!PortableBackupV2Error do
  let archive = decode_text_archive(payload)?
  if !Bytes.secure_equals(archive.backup_id, manifest.backup_id)
    || archive.created_at != manifest.created_at do
    Err(PortableBackupV2Refused)
  else
    Ok(payload)
  end
end

fn portable_v2_checked_content(manifest :: Plaintext<BackupManifest>,
  payload :: Plaintext<Bytes>) -> Plaintext<Bytes>!PortableBackupV2Error do
  let archive = decode_content_archive(payload)?
  if !Bytes.secure_equals(archive.backup_id, manifest.backup_id)
    || archive.created_at != manifest.created_at do
    Err(PortableBackupV2Refused)
  else
    Ok(payload)
  end
end

fn portable_v2_checked_payload(manifest :: Plaintext<BackupManifest>,
  payload :: Plaintext<Bytes>,
  schema :: PortableV2Schema) -> Plaintext<Bytes>!PortableBackupV2Error do
  if Bytes.length(payload) != manifest.plaintext_size
    || !Bytes.secure_equals(Crypto.sha256(payload), manifest.snapshot_hash) do
    return Err(PortableBackupV2Refused)
  end
  case schema do
    PortableV2TextOnly -> portable_v2_checked_text(manifest, payload)
    PortableV2TextOrContent -> do
      # Dispatch only after complete authenticated reconstruction and whole hash.
      # The payload magic selects one canonical schema, with no decoder fallback.
      let magic = portable_v2_slice(payload, 0, 4)?
      if Bytes.secure_equals(magic, portable_v2_magic(1, "MTA")?) do
        portable_v2_checked_text(manifest, payload)
      else if Bytes.secure_equals(magic, portable_v2_magic(1, "MCA")?) do
        portable_v2_checked_content(manifest, payload)
      else
        Err(PortableBackupV2Refused)
      end
    end
  end
end

fn portable_v2_read_raw(master :: borrow SecretBytes,
  bundle :: PortableV2Bundle,
  schema :: PortableV2Schema) -> Plaintext<Bytes>!PortableBackupV2Error do
  let encrypted = portable_v2_slice(bundle.manifest, 78, 104)?
  let body = portable_v2_open(master,
    bundle.backup_id,
    Bytes.from_utf8("mesh-msg/v2/backup-manifest-key"),
    portable_v2_manifest_aad(bundle.profile, bundle.backup_id)?,
    encrypted)?
  let manifest :: Plaintext<BackupManifest> = portable_v2_decode_manifest(body)?
  if !Bytes.secure_equals(manifest.backup_id, bundle.backup_id)
    || manifest.plaintext_size != bundle.plaintext_size
    || manifest.chunk_count != List.length(bundle.chunks) do
    return Err(PortableBackupV2Refused)
  end
  let binding = Crypto.sha256(bundle.manifest)
  let parts = for index in 0..List.length(bundle.chunks) do
    let chunk = List.get(bundle.chunks, index)
    let opened = portable_v2_open(master,
      bundle.backup_id,
      portable_v2_chunk_info(binding, index)?,
      portable_v2_chunk_aad(bundle.backup_id, binding, index)?,
      portable_v2_slice(chunk, 56, Bytes.length(chunk) - 56)?)?
    if Bytes.length(opened) != Bytes.length(chunk) - 72 do
      return Err(PortableBackupV2Refused)
    end
    opened
  end
  portable_v2_checked_payload(manifest, portable_v2_join(parts, 16777216)?, schema)
end

fn portable_v2_read_v1_raw(master :: borrow SecretBytes,
  bundle :: BackupFileBundle) -> Plaintext<Bytes>!PortableBackupV2Error do
  let manifest :: Plaintext<BackupManifest> = open_backup_manifest(master, bundle.manifest)?
  if manifest.chunk_count != List.length(bundle.chunks) do
    return Err(PortableBackupV2Refused)
  end
  let parts = for index in 0..List.length(bundle.chunks) do
    let opened :: Plaintext<Bytes> = open_backup_chunk(master,
      manifest,
      index,
      List.get(bundle.chunks, index))?
    opened
  end
  let payload = portable_v2_join(parts, 16777216)?
  if !verify_backup_snapshot(manifest, payload) do
    return Err(PortableBackupV2Refused)
  end
  portable_v2_checked_payload(manifest, payload, PortableV2TextOnly)
end

fn portable_v2_master_from_code(code :: String,
  profile :: BackupProfile) -> SecretBytes!PortableBackupV2Error do
  let root = open_backup_recovery(code)?
  let derived = derive_backup_key(root, profile)
  Secret.destroy(root)
  case derived do
    Err(_) -> Err(PortableBackupV2Refused)
    Ok(value)
  end
end

fn portable_v2_restore_candidate(raw :: Result<Plaintext<Bytes>, PortableBackupV2Error>) -> PortableV2RestoreCandidate do
  case raw do
    Err(_) -> PortableV2RestoreCandidate { payload: Bytes.empty(), complete: false }
    Ok(payload) -> PortableV2RestoreCandidate { payload: payload, complete: true }
  end
end

fn portable_v2_finish_restore(raw :: Result<Plaintext<Bytes>, PortableBackupV2Error>) -> Plaintext<Bytes>!PortableBackupV2Error do
  let candidate = portable_v2_restore_candidate(raw)
  # Bind the observed status to this same authenticated canonical nonempty payload.
  let closed = if candidate.complete
    && Bytes.length(candidate.payload) >= 293
    && Bytes.length(candidate.payload) <= 16777216 do
    0
  else
    1
  end
  let outcome = declassify(closed,
    "portable backup exposes only complete restore validity after all authenticated chunks and snapshot hash checks; no plaintext, hash, stage, error payload or partial archive is disclosed")
  if outcome == 0 do
    Ok(candidate.payload)
  else
    Err(PortableBackupV2Refused)
  end
end

fn portable_v2_restore_v1(code :: String,
  wire :: Bytes) -> Plaintext<Bytes>!PortableBackupV2Error do
  let bundle = decode_backup_file(wire)?
  let profile = profile_from_backup(bundle.manifest)?
  let master = portable_v2_master_from_code(code, profile)?
  let raw = portable_v2_read_v1_raw(master, bundle)
  Secret.destroy(master)
  portable_v2_finish_restore(raw)
end

fn portable_v2_restore_v2(code :: String,
  wire :: Bytes,
  schema :: PortableV2Schema) -> Plaintext<Bytes>!PortableBackupV2Error do
  let bundle = portable_v2_decode_file(wire)?
  let master = portable_v2_master_from_code(code, bundle.profile)?
  let raw = portable_v2_read_raw(master, bundle, schema)
  Secret.destroy(master)
  portable_v2_finish_restore(raw)
end

pub fn restore_portable_backup(recovery_code :: String,
  wire :: Bytes) -> Plaintext<Bytes>!PortableBackupV2Error do
  let magic = portable_v2_slice(wire, 0, 4)?
  if Bytes.secure_equals(magic, portable_v2_magic(1, "MBF")?) do
    portable_v2_restore_v1(recovery_code, wire)
  else if Bytes.secure_equals(magic, portable_v2_magic(2, "MBF")?) do
    portable_v2_restore_v2(recovery_code, wire, PortableV2TextOnly)
  else
    Err(PortableBackupV2Refused)
  end
end

from Backups.ContentArchive import (
  BackupAttachmentPolicy,
  BackupContentArchive,
  BackupContentScope,
  decode_content_archive,
  encode_content_archive
)

# Typed content payload; no caller-chosen ID, encryption root, schema validator or writer.
pub struct PortableBackupContentArchive do
  policy :: BackupAttachmentPolicy
  owner_account :: Bytes
  owner_authorization_key :: Bytes
  service_realm :: Bytes
  candidate_count :: Int
  omitted_timed :: Int
  omitted_unknown :: Int
  omitted_nontext :: Int
  omitted_empty :: Int
  attachment_messages :: Int
  scopes :: List<BackupContentScope>
end

fn portable_v2_prepare_content(content :: Plaintext<PortableBackupContentArchive>,
  backup_id :: Bytes,
  created_at :: U64) -> PortableV2Prepared do
  let raw = encode_content_archive(BackupContentArchive {
    policy: content.policy,
    backup_id: backup_id,
    owner_account: content.owner_account,
    owner_authorization_key: content.owner_authorization_key,
    service_realm: content.service_realm,
    created_at: created_at,
    candidate_count: content.candidate_count,
    omitted_timed: content.omitted_timed,
    omitted_unknown: content.omitted_unknown,
    omitted_nontext: content.omitted_nontext,
    omitted_empty: content.omitted_empty,
    attachment_messages: content.attachment_messages,
    scopes: content.scopes
  })
  case raw do
    Err(_) -> PortableV2Prepared { payload: Bytes.empty(), extent: 0 }
    Ok(payload) -> if Bytes.length(payload) >= 319 && Bytes.length(payload) <= 16777216 do
      PortableV2Prepared { payload: payload, extent: Bytes.length(payload) }
    else
      PortableV2Prepared { payload: Bytes.empty(), extent: 0 }
    end
  end
end

## Fresh one-use code and ID, canonical typed MCA1 payload, unchanged MBF2 encryption.
## This does not authorize the current account, source history, restore or native IO.
pub fn create_portable_content_backup_v2(content :: Plaintext<PortableBackupContentArchive>,
  created_at :: U64) -> PortableBackupV2Created!PortableBackupV2Error do
  let backup_id = generate_backup_id()?
  portable_v2_create_prepared(portable_v2_prepare_content(content, backup_id, created_at),
    backup_id,
    created_at)
end

## Complete authenticated canonical payload only. MBF1 remains text-only; MBF2
## admits exactly MTA1 or MCA1. Returned bytes and all embedded metadata stay protected.
pub fn restore_portable_archive(recovery_code :: String,
  wire :: Bytes) -> Plaintext<Bytes>!PortableBackupV2Error do
  let magic = portable_v2_slice(wire, 0, 4)?
  if Bytes.secure_equals(magic, portable_v2_magic(1, "MBF")?) do
    portable_v2_restore_v1(recovery_code, wire)
  else if Bytes.secure_equals(magic, portable_v2_magic(2, "MBF")?) do
    portable_v2_restore_v2(recovery_code, wire, PortableV2TextOrContent)
  else
    Err(PortableBackupV2Refused)
  end
end
