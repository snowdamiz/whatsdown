##! Backup custody and trust captured by whole operations, never caller tokens.
from Storage.FanoutCommit import FanoutSnapshot
from Storage.AccountGuard import (
  AccountBasis,
  load_account_basis_bounded_with_key,
  require_account_basis_bounded_with_key
)
from Storage.Keys import platform_key, local_context, context, open_local, open_signing, open_x25519
from Transport.Packet import ClientProfile, decode_client_profile, encode_client_profile
from Protocol.V1 import AccountIdentity, DeviceCredential
from Identity.Device import verify_device_credential
from Prekeys.Bundle import verify_prekey_bundle
from Mobile.DeviceSet import verified_device_set
from Mobile.Codec import current_time
from Mobile.Platform import decode_native_security_config
from Mobile.Transparency import (
  BackupCapturedTransparencyInputs,
  backup_transparency_proof_label,
  verify_backup_captured_transparency,
  transparency_device_set_label,
  canonical_transparency_checkpoint
)
from Transparency.Config import SecurityConfig
from Mobile.OhttpContext import (
  NativeOhttpContext,
  capture_native_ohttp_context_bounded_with_key,
  require_ohttp_completion_time
)

pub struct D4BackupAuthority do
  sources :: FanoutSnapshot
  context :: NativeOhttpContext
  profile :: ClientProfile
  public_profile :: Bytes
  config :: SecurityConfig
  captured_at :: U64
  fresh_through :: U64
  service_realm :: Bytes
end

fn backup_minimum(left :: U64, right :: U64) -> U64 do
  if U64.compare(left, right) < 0 do
    left
  else
    right
  end
end

fn backup_authority_bounds(original :: FanoutSnapshot) -> Result<(), String> do
  if List.length(original.bases) == 0 || List.length(original.bases) > 8 do
    return Err("invalid_backup_snapshot")
  end
  for basis in original.bases do
    if List.length(basis.labels) > 64
      || List.length(basis.labels) != List.length(basis.records)
      || List.any(basis.records, fn(value) -> Bytes.length(value) > 33554432 end) do
      return Err("backup_source_limit")
    end
  end
  let labels = List.reduce(original.bases,
    0,
    fn(total, basis) -> total + List.length(basis.labels) end)
  let extent = List.reduce(original.bases,
    Bytes.length(List.head(original.bases).profile),
    fn(total, basis) do total
      + List.reduce(basis.records, 0, fn(size, value) -> size + Bytes.length(value) end) end)
  if labels > 192 || extent > 33554432 do
    Err("backup_source_limit")
  else
    Ok(nil)
  end
end

fn backup_captured_blob(original :: FanoutSnapshot, label :: String) -> Bytes!String do
  for basis in original.bases do
    for index in 0..List.length(basis.labels) do
      if List.get(basis.labels, index) == label do
        return Ok(List.get(basis.records, index))
      end
    end
  end
  Err("backup_source_not_captured")
end

fn backup_open_captured(original :: FanoutSnapshot,
  label :: String,
  key :: borrow StorageKey) -> Bytes!String do
  let blob = backup_captured_blob(original, label)?
  if Bytes.length(blob) == 0 do
    return Err("backup_source_missing")
  end
  open_local(blob, key, local_context(label)?)
end

fn backup_credential_valid(account :: AccountIdentity,
  credential :: DeviceCredential,
  now :: U64) -> Bool do
  case verify_device_credential(account, credential, now, account.directory_sequence) do
    Ok(valid) -> valid
    Err(_) -> false
  end
end

fn backup_bundle_valid(profile :: ClientProfile, account :: AccountIdentity, now :: U64) -> Bool do
  case verify_prekey_bundle(account, profile.bundle, 1, now, account.directory_sequence) do
    Ok(valid) -> valid
    Err(_) -> false
  end
end

fn backup_active_profile(local :: ClientProfile,
  wire :: Bytes,
  now :: U64) -> ClientProfile!String do
  let devices = verified_device_set(wire)?
  if devices.value.username != local.username
    || !Bytes.secure_equals(devices.account.account_id, local.account_id)
    || !Bytes.secure_equals(devices.value.account_identity, local.entry.account_identity)
    || !backup_credential_valid(local.account, local.credential, now)
    || !backup_bundle_valid(local, local.account, now) do
    return Err("backup_custody_invalid")
  end
  # Expired profiles remain account members for other features, but cannot
  # authorize a new archive. Only the actual current active entry is eligible.
  for member in devices.profiles do
    if Bytes.secure_equals(member.device_id, local.device_id) do
      if !Bytes.secure_equals(member.credential.signing_public_key,
        local.credential.signing_public_key)
        || !Bytes.secure_equals(member.credential.dh_public_key, local.credential.dh_public_key)
        || !backup_credential_valid(devices.account, member.credential, now)
        || !backup_bundle_valid(member, devices.account, now) do
        return Err("backup_custody_invalid")
      end
      return Ok(member)
    end
  end
  Err("backup_custody_invalid")
end

fn backup_owned_keys_match(profile :: ClientProfile,
  original :: FanoutSnapshot,
  key :: borrow StorageKey) -> Result<(), String> do
  let signing_blob = backup_captured_blob(original, "device-signing-key/v1")?
  let identity_blob = backup_captured_blob(original, "device-identity-key/v1")?
  let signing_context = context(profile.account_id, profile.device_id, "device-signing-key/v1", 7)?
  let identity_context = context(profile.account_id,
    profile.device_id,
    "device-identity-key/v1",
    8)?
  let challenge = Bytes.concat(Bytes.from_utf8("morse-backup-custody/v1\n"),
    Crypto.sha256(profile.encoded))?
  let signing = open_signing(signing_blob, key, signing_context)?
  let signing_matches = case Crypto.sign(signing, challenge) do
    Err(_) -> false
    Ok(signature) -> case Crypto.verify(SigningPublicKey {
        bytes: profile.credential.signing_public_key
      },
      challenge,
      signature) do
      Err(_) -> false
      Ok(valid) -> valid
    end
  end
  Secret.destroy(signing)
  if !signing_matches do
    return Err("backup_custody_invalid")
  end
  let identity = open_x25519(identity_blob, key, identity_context)?
  let identity_matches = case Crypto.x25519_public(identity) do
    Err(_) -> false
    Ok(public_key) -> Bytes.secure_equals(public_key.bytes, profile.credential.dh_public_key)
  end
  Secret.destroy(identity)
  if !identity_matches do
    Err("backup_custody_invalid")
  else
    Ok(nil)
  end
end

fn capture_backup_with_key(path :: String,
  expected_profile :: Bytes,
  initial :: AccountBasis,
  key :: borrow StorageKey) -> D4BackupAuthority!String do
  if Bytes.length(initial.profile) > 40000 do
    return Err("invalid_profile")
  end
  let public_profile = open_local(initial.profile, key, local_context("profile/v1")?)?
  let profile = decode_client_profile(public_profile)?
  if !Bytes.secure_equals(public_profile, expected_profile)
    || !Bytes.secure_equals(encode_client_profile(profile.entry,
        profile.account_id,
        profile.device_id)?,
      public_profile) do
    return Err("account_state_changed")
  end
  # Existing revision setup is completed before the fixed authority capture.
  let native = capture_native_ohttp_context_bounded_with_key(path, initial.profile, key)?
  let config = decode_native_security_config(native.security_frame)?
  let captured_at = current_time()?
  require_ohttp_completion_time(native.started_at, native.selected_key, captured_at)?
  let set_label = transparency_device_set_label(profile.account_id)
  let labels = [
    "device-signing-key/v1",
    "device-identity-key/v1",
    "ohttp-revision/v1",
    set_label,
    "transparency-checkpoint/v1",
    "transparency-view/v1",
    "transparency-view-chunk/v1/0",
    "transparency-view-chunk/v1/1",
    "transparency-view-chunk/v1/2",
    "transparency-witnesses/v2",
    "transparency-origin/v1"
  ]
  let original = capture_backup_snapshot_with_key(path,
    FanoutSnapshot { bases: [initial, native.basis] },
    labels,
    key)?
  backup_authority_bounds(original)?
  let cache = backup_open_captured(original, set_label, key)?
  let shared = backup_open_captured(original, "transparency-checkpoint/v1", key)?
  let proof_label = backup_transparency_proof_label(cache, shared)?
  let sources = if proof_label == "" do
    original
  else
    capture_backup_snapshot_with_key(path, original, [proof_label], key)?
  end
  backup_authority_bounds(sources)?
  let proof = if proof_label == "" do
    Bytes.empty()
  else
    let blob = backup_captured_blob(sources, proof_label)?
    if Bytes.length(blob) == 0 do
      Bytes.empty()
    else
      open_local(blob, key, local_context(proof_label)?)?
    end
  end
  let verified = verify_backup_captured_transparency(BackupCapturedTransparencyInputs {
      device_set_cache: cache,
      shared_checkpoint: shared,
      view_manifest: backup_open_captured(sources, "transparency-view/v1", key)?,
      view_chunks: for index in 0..3 do
        backup_open_captured(sources, "transparency-view-chunk/v1/#{Int.to_string(index)}", key)?
      end,
      witnesses: if canonical_transparency_checkpoint(shared)?.version == 1 do
        Bytes.empty()
      else
        backup_open_captured(sources, "transparency-witnesses/v2", key)?
      end,
      proof_label: proof_label,
      proof: proof
    },
    config,
    captured_at)?
  let member = backup_active_profile(profile, verified.verified.device_set, captured_at)?
  backup_owned_keys_match(profile, sources, key)?
  let origin = Bytes.to_utf8(backup_open_captured(sources, "transparency-origin/v1", key)?)?
  if origin != native.pins.network.core_origin do
    return Err("transparency_origin_mismatch")
  end
  let membership_deadline = backup_minimum(backup_minimum(profile.credential.expires_at,
      profile.bundle.expires_at),
    backup_minimum(member.credential.expires_at, member.bundle.expires_at))
  let trust_deadline = backup_minimum(verified.fresh_through, membership_deadline)
  let fresh_through = case native.selected_key do
    None -> trust_deadline
    Some(selected) -> backup_minimum(trust_deadline,
      U64.subtract(selected.not_after_ms, U64.parse("1")?)?)
  end
  let service_realm = case Bytes.concat_many([
      Bytes.from_utf8("morse-backup-service-realm/v1\n"),
      Bytes.from_utf8(native.pins.network.core_origin),
      config.service_public_key
    ],
    4096) do
    Err(_) -> return Err("invalid_backup_service_identity")
    Ok(value) -> Crypto.sha256(value)
  end
  let authority = D4BackupAuthority {
    sources: sources,
    context: native,
    profile: profile,
    public_profile: public_profile,
    config: config,
    captured_at: captured_at,
    fresh_through: fresh_through,
    service_realm: service_realm
  }
  # Recheck the exact originals after all cryptographic preparation.
  backup_capture_fence(path, key, BackupAuthorityFence(authority))?
  Ok(authority)
end

pub fn capture_backup_authority(path :: String,
  expected_profile :: Bytes) -> D4BackupAuthority!String do
  let key = platform_key()?
  let result = capture_backup_authority_with_key(path, expected_profile, key)
  Secret.destroy(key)
  result
end

## Internal whole-operation borrow; this key is obtained by the whole operation.
pub fn capture_backup_authority_with_key(path :: String,
  expected_profile :: Bytes,
  key :: borrow StorageKey) -> D4BackupAuthority!String do
  if String.length(path) < 1
    || String.length(path) > 4096
    || Bytes.length(expected_profile) < 1
    || Bytes.length(expected_profile) > 36134 do
    return Err("invalid_backup_request")
  end
  let initial = load_account_basis_bounded_with_key(path, key, [], 40000, 33554432, 33554432)?
  capture_backup_with_key(path, expected_profile, initial, key)
end

fn require_backup_frame(selector :: String, expected :: Bytes) -> Result<(), String> do
  case Host.push_get_token(Bytes.from_utf8(selector)) do
    Err(_) -> Err("account_state_changed")
    Ok(current) -> if Bytes.secure_equals(current, expected) do
      Ok(nil)
    else
      Err("account_state_changed")
    end
  end
end

## Supplied writer only: exact original ciphertexts, raw native frames, real time.
## Existing bounded keyed index lookup is allowed; payload crypto and reloads are not.
pub fn require_backup_authority_current(database :: SqliteConn,
  authority :: D4BackupAuthority) -> Result<(), String> do
  let key = platform_key()?
  let result = require_backup_authority_current_with_key(database, authority, key)
  Secret.destroy(key)
  result
end

pub fn require_backup_authority_current_with_key(database :: SqliteConn,
  authority :: D4BackupAuthority,
  key :: borrow StorageKey) -> Result<(), String> do
  require_backup_sources_current_with_key(database, authority.sources, key)?
  require_account_basis_bounded_with_key(database,
    key,
    authority.context.basis,
    40000,
    1024,
    41024)?
  require_backup_frame("messenger/network/v1", authority.context.network_frame)?
  require_backup_frame("messenger/config/v1", authority.context.security_frame)?
  require_backup_frame("messenger/ohttp/v1", authority.context.companion_frame)?
  let now = current_time()?
  require_ohttp_completion_time(authority.context.started_at, authority.context.selected_key, now)?
  if U64.compare(now, authority.captured_at) < 0 do
    Err("backup_clock_rollback")
  else if U64.compare(now, authority.fresh_through) > 0 do
    Err("backup_authority_expired")
  else
    Ok(nil)
  end
end

struct D4BackupBasisRow do
  label :: String
  ciphertext :: Bytes
end

fn backup_snapshot_bytes(original :: FanoutSnapshot) -> Int do
  List.reduce(original.bases,
    Bytes.length(List.head(original.bases).profile),
    fn(total, basis) do total
      + List.reduce(basis.records, 0, fn(size, value) -> size + Bytes.length(value) end) end)
end

fn backup_distinct_row(rows :: List<D4BackupBasisRow>,
  row :: D4BackupBasisRow,
  index :: Int) -> List<D4BackupBasisRow>!String do
  if index >= List.length(rows) do
    return Ok(List.append(rows, row))
  end
  let previous = List.get(rows, index)
  if previous.label == row.label do
    if !Bytes.secure_equals(previous.ciphertext, row.ciphertext) do
      Err("account_state_changed")
    else
      Ok(rows)
    end
  else
    backup_distinct_row(rows, row, index + 1)
  end
end

fn backup_distinct_rows(input :: List<D4BackupBasisRow>,
  index :: Int,
  rows :: List<D4BackupBasisRow>) -> List<D4BackupBasisRow>!String do
  if index >= List.length(input) do
    return Ok(rows)
  end
  let row = List.get(input, index)
  if String.length(row.label) < 1 || String.length(row.label) > 256 || row.label == "profile/v1" do
    return Err("invalid_backup_snapshot")
  end
  backup_distinct_rows(input, index + 1, backup_distinct_row(rows, row, 0)?)
end

fn backup_pack_rows(profile :: Bytes,
  rows :: List<D4BackupBasisRow>,
  offset :: Int,
  bases :: List<AccountBasis>) -> List<AccountBasis> do
  if offset >= List.length(rows) do
    bases
  else
    let chunk = List.take(List.drop(rows, offset), 64)
    backup_pack_rows(profile,
      rows,
      offset + 64,
      List.append(bases,
        AccountBasis {
          profile: profile,
          labels: List.map(chunk, fn(row) -> row.label end),
          records: List.map(chunk, fn(row) -> row.ciphertext end)
        }))
  end
end

# Pure conjunction normalization: identical original label/ciphertext guards
# are one condition; conflicting originals refuse. No original value is reloaded.
fn backup_normalize_snapshot(original :: FanoutSnapshot) -> FanoutSnapshot!String do
  backup_authority_bounds(original)?
  let profile = List.head(original.bases).profile
  let input = List.flatten(for basis in original.bases do
    if !Bytes.secure_equals(basis.profile, profile) do
      return Err("account_state_changed")
    end
    for index in 0..List.length(basis.labels) do
      D4BackupBasisRow {
        label: List.get(basis.labels, index),
        ciphertext: List.get(basis.records, index)
      }
    end
  end)
  let rows = backup_distinct_rows(input, 0, [])?
  let bases = if List.length(rows) == 0 do
    [AccountBasis { profile: profile, labels: [], records: [] }]
  else
    backup_pack_rows(profile, rows, 0, [])
  end
  Ok(FanoutSnapshot { bases: bases })
end

fn backup_capture_chunks(path :: String,
  original :: FanoutSnapshot,
  labels :: List<String>,
  offset :: Int,
  key :: borrow StorageKey) -> FanoutSnapshot!String do
  if offset >= List.length(labels) do
    return Ok(original)
  end
  let profile = List.head(original.bases).profile
  let remaining = 33554432 - backup_snapshot_bytes(original)
  let captured = load_account_basis_bounded_with_key(path,
    key,
    List.take(List.drop(labels, offset), 64),
    40000,
    remaining,
    Bytes.length(profile) + remaining)?
  if !Bytes.secure_equals(captured.profile, profile) do
    return Err("account_state_changed")
  end
  let next = backup_normalize_snapshot(FanoutSnapshot {
    bases: List.append(original.bases, captured)
  })?
  backup_capture_chunks(path, next, labels, offset + 64, key)
end

## Internal read evidence only. Whole operations supply their own earlier capture.
pub fn capture_backup_snapshot(path :: String,
  original :: FanoutSnapshot,
  labels :: List<String>) -> FanoutSnapshot!String do
  let key = platform_key()?
  let result = capture_backup_snapshot_with_key(path, original, labels, key)
  Secret.destroy(key)
  result
end

pub fn capture_backup_snapshot_with_key(path :: String,
  original :: FanoutSnapshot,
  labels :: List<String>,
  key :: borrow StorageKey) -> FanoutSnapshot!String do
  let before = backup_normalize_snapshot(original)?
  let old_labels = List.flatten(for basis in before.bases do
    basis.labels
  end)
  let new_labels = List.filter(labels, fn(label) -> !List.contains(old_labels, label) end)
  if List.length(old_labels) + List.length(new_labels) > 192 do
    return Err("backup_source_limit")
  end
  for index in 0..List.length(labels) do
    let label = List.get(labels, index)
    if label == "profile/v1"
      || String.length(label) < 1
      || String.length(label) > 256
      || List.contains(List.take(labels, index), label) do
      return Err("invalid_backup_snapshot")
    end
  end
  let captured = backup_capture_chunks(path, before, new_labels, 0, key)?
  backup_capture_fence(path, key, BackupSourcesFence(captured))?
  Ok(captured)
end

## Supplied writer, bounded SQL admission/comparison; never materializes a winner.
pub fn require_backup_sources_current(database :: SqliteConn,
  original :: FanoutSnapshot) -> Result<(), String> do
  let key = platform_key()?
  let result = require_backup_sources_current_with_key(database, original, key)
  Secret.destroy(key)
  result
end

pub fn require_backup_sources_current_with_key(database :: SqliteConn,
  original :: FanoutSnapshot,
  key :: borrow StorageKey) -> Result<(), String> do
  backup_authority_bounds(original)?
  for basis in original.bases do
    require_account_basis_bounded_with_key(database, key, basis, 40000, 33554432, 33554432)?
  end
  Ok(nil)
end

type D4BackupCaptureFence do
  BackupSourcesFence(sources :: FanoutSnapshot)
  BackupAuthorityFence(authority :: D4BackupAuthority)
end

fn backup_capture_fence_on(database :: SqliteConn,
  key :: borrow StorageKey,
  fence :: D4BackupCaptureFence) -> Result<(), String> do
  case fence do
    BackupSourcesFence(sources) -> require_backup_sources_current_with_key(database, sources, key)
    BackupAuthorityFence(authority) -> require_backup_authority_current_with_key(database,
      authority,
      key)
  end
end

# Direct borrowed-key call: affine resources are never captured by a closure.
# One connection, BEGIN IMMEDIATE before comparisons, cleanup on every result.
fn backup_capture_fence(path :: String,
  key :: borrow StorageKey,
  fence :: D4BackupCaptureFence) -> Result<(), String> do
  let database = case Sqlite.open(path) do
    Err(_) -> return Err("database_open_failed")
    Ok(value) -> value
  end
  let started = case Sqlite.execute(database, "PRAGMA busy_timeout = 1000", []) do
    Err(error)
    Ok(_) -> Sqlite.execute(database, "BEGIN IMMEDIATE", [])
  end
  let result = case started do
    Err(_) -> Err("database_write_failed")
    Ok(_) -> case backup_capture_fence_on(database, key, fence) do
      Err(error)
      Ok(_) -> case Sqlite.commit(database) do
        Err(_) -> Err("database_write_failed")
        Ok(_) -> Ok(nil)
      end
    end
  end
  case result do
    Err(_) -> do
      Sqlite.rollback(database)
      nil
    end
    Ok(_) -> nil
  end
  Sqlite.close(database)
  result
end
