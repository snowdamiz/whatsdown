from Tests.BackupArchiveFixture import D4CoreFixture, d4_core_fixture, d4_core_cleanup
from Storage.BackupArchiveCommit import require_backup_archive_snapshot
from Storage.Records import with_record_transaction, store_updated_blobs
from Storage.Blobs import load_blob
from Transport.Packet import decode_client_profile

fn d4_original_source_guard() -> Result<(), String> do
  let f = d4_core_fixture()?
  let valid = with_record_transaction(f.path,
    fn(database) do require_backup_archive_snapshot(database,
      f.original,
      f.account_id,
      f.archive_id) end)
  assert(Result.is_ok(valid))
  # This is an original ciphertext mutation, not a second capture/new basis.
  let winner = Bytes.from_utf8("concurrent winning source ciphertext")
  store_updated_blobs(f.path, [f.source_label], [winner])?
  let refused = with_record_transaction(f.path,
    fn(database) do require_backup_archive_snapshot(database,
      f.original,
      f.account_id,
      f.archive_id) end)
  assert(case refused do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(load_blob(f.path, f.source_label)?, winner))
  let row = "backup-archive/v1/#{Bytes.to_hex(f.account_id)}/#{Bytes.to_hex(f.archive_id)}"
  let index = "backup-archives/v1/#{Bytes.to_hex(f.account_id)}"
  assert(Result.is_err(load_blob(f.path, row)))
  assert(Result.is_err(load_blob(f.path, index)))
  d4_core_cleanup(f)
end

test("backup supplied writer accepts the original source then refuses drift without publication") do
  assert(Result.is_ok(d4_original_source_guard()))
end

from Mobile.BackupAuthority import capture_backup_authority, require_backup_authority_current
from Mobile.Codec import current_time
from Mobile.Transparency import verify_backup_captured_transparency
from Mobile.DeviceSet import verified_device_set
from Storage.Keys import platform_key, context, seal_signing, seal_x25519
from Tests.BackupArchiveFixture import d4_core_revoked_fixture, d4_core_expired_fixture
from Tests.GroupConsistencySupport import wide

fn d4_final_frames_and_clock() -> Result<(), String> do
  let f = d4_core_fixture()?
  let authority = capture_backup_authority(f.path, f.public_profile)?
  assert(Result.is_ok(with_record_transaction(f.path,
    fn(database) -> require_backup_authority_current(database, authority) end)))
  let selectors = ["messenger/network/v1", "messenger/config/v1", "messenger/ohttp/v1"]
  let originals = [
    authority.context.network_frame,
    authority.context.security_frame,
    authority.context.companion_frame
  ]
  for index in 0..3 do
    let selector = Bytes.from_utf8(List.get(selectors, index))
    assert(Test.set_push_token(selector, Bytes.from_utf8("changed exact native frame")))
    let refused = with_record_transaction(f.path,
      fn(database) -> require_backup_authority_current(database, authority) end)
    assert(case refused do
      Err("account_state_changed") -> true
      _ -> false
    end)
    assert(Test.set_push_token(selector, List.get(originals, index)))
  end
  # Scoped guard math: alter only this INTERNAL fixture record; the supplied
  # writer still reads the real system clock. Whole operations accept no time.
  let future = U64.add(current_time()?, wide(60000)?)?
  let rollback = with_record_transaction(f.path,
    fn(database) -> require_backup_authority_current(database,
      %{authority | captured_at: future}) end)
  assert(case rollback do
    Err("backup_clock_rollback") -> true
    _ -> false
  end)
  let expired = with_record_transaction(f.path,
    fn(database) -> require_backup_authority_current(database,
      %{authority | fresh_through: wide(0)?}) end)
  assert(case expired do
    Err("backup_authority_expired") -> true
    _ -> false
  end)
  assert(Result.is_ok(with_record_transaction(f.path,
    fn(database) -> require_backup_authority_current(database, authority) end)))
  d4_core_cleanup(f)
end

test("backup final writer checks each actual native frame and scoped actual clock guard math") do
  assert(Result.is_ok(d4_final_frames_and_clock()))
end

fn d4_final_custody_drift() -> Result<(), String> do
  let f = d4_core_fixture()?
  let authority = capture_backup_authority(f.path, f.public_profile)?
  let labels = ["profile/v1", "ohttp-revision/v1"]
  let originals = for label in labels do
    load_blob(f.path, label)?
  end
  for index in 0..2 do
    let label = List.get(labels, index)
    let winner = Bytes.from_utf8("winning original custody ciphertext")
    store_updated_blobs(f.path, [label], [winner])?
    let refused = with_record_transaction(f.path,
      fn(database) -> require_backup_authority_current(database, authority) end)
    assert(case refused do
      Err("account_state_changed") -> true
      _ -> false
    end)
    assert(Bytes.secure_equals(load_blob(f.path, label)?, winner))
    store_updated_blobs(f.path, [label], [List.get(originals, index)])?
  end
  assert(Result.is_ok(with_record_transaction(f.path,
    fn(database) -> require_backup_authority_current(database, authority) end)))
  d4_core_cleanup(f)
end

test("backup final writer refuses original profile and revision drift without overwriting winners") do
  assert(Result.is_ok(d4_final_custody_drift()))
end

fn d4_replace_owned_key(f :: D4CoreFixture, signing :: Bool) -> Bytes!String do
  let profile = decode_client_profile(f.public_profile)?
  let label = if signing do
    "device-signing-key/v1"
  else
    "device-identity-key/v1"
  end
  let purpose = if signing do
    7
  else
    8
  end
  let bound_context = context(profile.account_id, profile.device_id, label, purpose)?
  let key = platform_key()?
  let result = if signing do
    case Crypto.signing_generate() do
      Err(_) -> Err("d4_fixture_wrong_signing_key")
      Ok(pair) -> do
        let blob = seal_signing(pair.private_key, key, bound_context)
        Secret.destroy(pair.private_key)
        blob
      end
    end
  else
    case Crypto.x25519_generate() do
      Err(_) -> Err("d4_fixture_wrong_identity_key")
      Ok(pair) -> do
        let blob = seal_x25519(pair.private_key, key, bound_context)
        Secret.destroy(pair.private_key)
        blob
      end
    end
  end
  Secret.destroy(key)
  result
end

fn d4_owned_key_mismatch() -> Result<(), String> do
  let f = d4_core_fixture()?
  for index in 0..2 do
    let signing = index == 0
    let label = if signing do
      "device-signing-key/v1"
    else
      "device-identity-key/v1"
    end
    let original = load_blob(f.path, label)?
    let mismatch = d4_replace_owned_key(f, signing)?
    store_updated_blobs(f.path, [label], [mismatch])?
    assert(case capture_backup_authority(f.path, f.public_profile) do
      Err("backup_custody_invalid") -> true
      _ -> false
    end)
    assert(Bytes.secure_equals(load_blob(f.path, label)?, mismatch))
    store_updated_blobs(f.path, [label], [original])?
  end
  assert(Result.is_ok(capture_backup_authority(f.path, f.public_profile)))
  d4_core_cleanup(f)
end

test("backup capture refuses correctly sealed mismatched signing and identity owners and preserves rows") do
  assert(Result.is_ok(d4_owned_key_mismatch()))
end

fn d4_revoked_and_expired_membership() -> Result<(), String> do
  let revoked = d4_core_revoked_fixture()?
  let trust = verify_backup_captured_transparency(revoked.input, revoked.config, revoked.now)?
  let set = verified_device_set(trust.verified.device_set)?
  let local = decode_client_profile(revoked.public_profile)?
  assert(List.length(set.profiles) == 1 && List.length(set.expired) == 0)
  assert(List.any(set.value.revoked_device_ids,
    fn(id) -> Bytes.secure_equals(id, local.device_id) end))
  assert(!List.any(set.profiles,
    fn(member) -> Bytes.secure_equals(member.device_id, local.device_id) end))
  assert(case capture_backup_authority(revoked.path, revoked.public_profile) do
    Err("backup_custody_invalid") -> true
    _ -> false
  end)
  d4_core_cleanup(revoked)?
  let expired = d4_core_expired_fixture()?
  let trust = verify_backup_captured_transparency(expired.input, expired.config, expired.now)?
  let set = verified_device_set(trust.verified.device_set)?
  assert(List.length(set.profiles) == 0 && List.length(set.expired) == 1)
  assert(case capture_backup_authority(expired.path, expired.public_profile) do
    Err("backup_custody_invalid") -> true
    _ -> false
  end)
  d4_core_cleanup(expired)
end

test("backup capture refuses genuinely signed revoked and expired local membership") do
  assert(Result.is_ok(d4_revoked_and_expired_membership()))
end

from Tests.BackupArchiveFixture import d4_core_legacy_fixture

fn d4_legacy_absent_witness() -> Result<(), String> do
  let f = d4_core_legacy_fixture()?
  assert(Result.is_err(load_blob(f.path, "transparency-witnesses/v2")))
  verify_backup_captured_transparency(f.input, f.config, f.now)?
  let authority = capture_backup_authority(f.path, f.public_profile)?
  assert(Bytes.secure_equals(authority.public_profile, f.public_profile))
  let winner = Bytes.from_utf8("newly inserted legacy witness row")
  store_updated_blobs(f.path, ["transparency-witnesses/v2"], [winner])?
  let refused = with_record_transaction(f.path,
    fn(database) -> require_backup_authority_current(database, authority) end)
  assert(case refused do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(load_blob(f.path, "transparency-witnesses/v2")?, winner))
  d4_core_cleanup(f)
end

test("legacy backup custody accepts absent witness cache and fences a later insertion") do
  assert(Result.is_ok(d4_legacy_absent_witness()))
end

from Mobile.BackupAuthority import capture_backup_snapshot
from Storage.AccountGuard import AccountBasis, load_account_basis, account_basis_current
from Storage.FanoutCommit import FanoutSnapshot
from Tests.BackupArchiveFixture import (
  d4_core_import_bundle,
  d4_core_backup_id,
  d4_core_legacy_import_bundle,
  d4_core_stored_matches
)
from Mobile.BackupArchive import import_backup_archive, read_backup_archive

fn d4_original_conjunction_normalization() -> Result<(), String> do
  let f = d4_core_fixture()?
  let profile = List.head(f.original.bases).profile
  let one = AccountBasis {
    profile: profile,
    labels: [f.source_label],
    records: [f.source_ciphertext]
  }
  let equivalent = FanoutSnapshot { bases: [one, one] }
  let normalized = capture_backup_snapshot(f.path, equivalent, [])?
  assert(List.length(normalized.bases) == 1)
  assert(List.head(normalized.bases).labels == [f.source_label])
  assert(Bytes.secure_equals(List.head(List.head(normalized.bases).records), f.source_ciphertext))
  let conflict = %{one | records: [Bytes.from_utf8("conflicting original ciphertext")]}
  assert(Result.is_err(capture_backup_snapshot(f.path,
    FanoutSnapshot { bases: [one, conflict] },
    [])))
  let absent = %{one | records: [Bytes.empty()]}
  assert(Result.is_err(capture_backup_snapshot(f.path,
    FanoutSnapshot { bases: [absent, one] },
    [])))
  let foreign = %{one | profile: Bytes.from_utf8("different encrypted original custody")}
  assert(Result.is_err(capture_backup_snapshot(f.path,
    FanoutSnapshot { bases: [one, foreign] },
    [])))
  assert(account_basis_current(f.path, List.head(f.original.bases)))
  d4_core_cleanup(f)
end

test("backup normalization preserves identical guards and refuses conflicting absent or cross profile originals") do
  assert(Result.is_ok(d4_original_conjunction_normalization()))
end

fn d4_destination_storage_races() -> Result<(), String> do
  let f = d4_core_fixture()?
  let index = "backup-archives/v1/#{Bytes.to_hex(f.account_id)}"
  let destination = "backup-archive/v1/#{Bytes.to_hex(f.account_id)}/#{Bytes.to_hex(f.archive_id)}"
  let before = load_account_basis(f.path, [index, destination])?
  let original = FanoutSnapshot { bases: [before] }
  assert(Result.is_ok(with_record_transaction(f.path,
    fn(database) -> require_backup_archive_snapshot(database,
      original,
      f.account_id,
      f.archive_id) end)))
  # A real separately completed whole import wins the originally absent index.
  let winner = d4_core_import_bundle(f, false)?
  let winner_id = d4_core_backup_id(winner.wire)?
  import_backup_archive(f.path, f.public_profile, winner.wire, winner.recovery_code, winner_id)?
  let winning_index = load_blob(f.path, index)?
  let refused = with_record_transaction(f.path,
    fn(database) -> require_backup_archive_snapshot(database,
      original,
      f.account_id,
      f.archive_id) end)
  assert(case refused do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(load_blob(f.path, index)?, winning_index))
  assert(Result.is_err(load_blob(f.path, destination)))
  let next = FanoutSnapshot { bases: [load_account_basis(f.path, [index, destination])?] }
  # An authenticated legacy file wins the previously absent exact destination.
  let inserted = d4_core_legacy_import_bundle(f, f.archive_id, false)?
  import_backup_archive(f.path,
    f.public_profile,
    inserted.wire,
    inserted.recovery_code,
    f.archive_id)?
  let winning_row = load_blob(f.path, destination)?
  let winning_index = load_blob(f.path, index)?
  let refused = with_record_transaction(f.path,
    fn(database) -> require_backup_archive_snapshot(database, next, f.account_id, f.archive_id) end)
  assert(case refused do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(load_blob(f.path, destination)?, winning_row))
  assert(Bytes.secure_equals(load_blob(f.path, index)?, winning_index))
  assert(d4_core_stored_matches(f,
    winner_id,
    read_backup_archive(f.path, f.public_profile, winner_id)))
  assert(d4_core_stored_matches(f,
    f.archive_id,
    read_backup_archive(f.path, f.public_profile, f.archive_id)))
  d4_core_cleanup(f)
end

test("backup supplied writer refuses original index and absent destination races while preserving real imports") do
  assert(Result.is_ok(d4_destination_storage_races()))
end
