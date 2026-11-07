# Test-runner-only fragment. Ordinary module discovery excludes this file.
from Storage.Records import store_updated_blobs
from Tests.Support import repeated

pub fn d4_manage_list_matches(raw :: Result<Plaintext<List<D4BackupArchiveSummary>>, String>,
  ids :: List<Bytes>,
  times :: List<U64>) -> Bool do
  let matches = case raw do
    Err(_) -> false
    Ok(rows) -> if List.length(rows) != List.length(ids)
      || List.length(ids) != List.length(times) do
      false
    else
      List.all(for index in 0..List.length(ids) do
          Bytes.secure_equals(List.get(rows, index).backup_id, List.get(ids, index))
            && U64.compare(List.get(rows, index).created_at, List.get(times, index)) == 0
        end,
        fn(value) -> value end)
    end
  end
  declassify(matches,
    "TEST ONLY exact Boolean equality against authored synthetic archive IDs and original snapshot times or empty fixture listing; no application metadata is disclosed")
end

pub fn d4_manage_seed_index(path :: String,
  account :: Bytes,
  ids :: List<Bytes>,
  times :: List<U64>,
  rows :: List<Bytes>) -> Result<(), String> do
  let entries = for index in 0..List.length(ids) do
    D4BackupIndexEntry {
      backup_id: List.get(ids, index),
      digest: repeated(44, 32)?,
      created_at: List.get(times, index)
    }
  end
  let wire = backup_encode_index(entries)?
  d4_manage_index_wire(path, account, wire)?
  for index in 0..List.length(rows) do
    if Bytes.length(List.get(rows, index)) > 0 do
      store_updated_blobs(path,
        [backup_archive_label(account, List.get(ids, index))?],
        [List.get(rows, index)])?
    end
  end
  Ok(nil)
end

pub fn d4_manage_index_wire(path :: String,
  account :: Bytes,
  wire :: Bytes) -> Result<(), String> do
  let label = backup_archive_index_label(account)?
  let key = platform_key()?
  let raw = seal_local(wire, key, local_context(label)?)
  Secret.destroy(key)
  store_updated_blobs(path, [label], [raw?])
end

fn d4_manage_drift_with_key(path :: String,
  expected :: Bytes,
  id :: Bytes,
  winner :: Bytes,
  mode :: Int,
  key :: borrow StorageKey) -> Result<(), String> do
  let authority = capture_backup_authority_with_key(path, expected, key)?
  if mode == 2 do
    let captured = backup_capture_list_sources(path, authority, key)?
    let plan = backup_prepare_list(captured, authority.profile.account_id, key)
    if backup_observe_admission(plan.admission) != 1 do
      return Err("backup_archive_refused")
    end
    println("ARCHIVE_MANAGEMENT_LIST_PREPARED_BEFORE_DRIFT")
    store_updated_blobs(path,
      [backup_archive_index_label(authority.profile.account_id)?],
      [winner])?
    backup_finalize(path, key, BackupFinalFence(%{authority | sources: captured}))
  else
    let ready = backup_prepare_remove(path, authority, id, key)?
    println("ARCHIVE_MANAGEMENT_REMOVE_PREPARED_BEFORE_DRIFT")
    let label = if mode == 0 do
      backup_archive_label(authority.profile.account_id, id)?
    else
      backup_archive_index_label(authority.profile.account_id)?
    end
    store_updated_blobs(path, [label], [winner])?
    backup_finalize(path, key, BackupFinalRemove(authority, ready, id))
  end
end

pub fn d4_manage_drift(path :: String,
  expected :: Bytes,
  id :: Bytes,
  winner :: Bytes,
  mode :: Int) -> Result<(), String> do
  let key = platform_key()?
  let result = d4_manage_drift_with_key(path, expected, id, winner, mode, key)
  Secret.destroy(key)
  result
end

fn d4_preview_drift_on_key(path :: String,
  expected :: Bytes,
  wire :: Bytes,
  code :: String,
  winner :: Bytes,
  mode :: Int,
  key :: borrow StorageKey) -> Result<Plaintext<Bytes>, String> do
  let authority = capture_backup_authority_with_key(path, expected, key)?
  let plan = backup_prepare_preview(authority, wire, code)
  if backup_observe_admission(plan.admission) != 1 do
    return Err("backup_archive_refused")
  end
  println("ARCHIVE_PREVIEW_PREPARED_BEFORE_DRIFT")
  if mode == 2 do
    if !Test.set_push_token(Bytes.from_utf8("messenger/network/v1"), winner) do
      return Err("preview_fixture_frame_change_failed")
    end
  else
    let label = if mode == 0 do
      "profile/v1"
    else
      "ohttp-revision/v1"
    end
    store_updated_blobs(path, [label], [winner])?
  end
  backup_finalize(path, key, BackupFinalFence(authority))?
  Ok(plan.payload)
end

pub fn d4_preview_drift(path :: String,
  expected :: Bytes,
  wire :: Bytes,
  code :: String,
  winner :: Bytes,
  mode :: Int) -> Result<Plaintext<Bytes>, String> do
  let key = platform_key()?
  let result = d4_preview_drift_on_key(path, expected, wire, code, winner, mode, key)
  Secret.destroy(key)
  result
end

fn d4_pending_inject_race(path :: String,
  authority :: D4BackupAuthority,
  winner_wire :: Bytes,
  winner_descriptor :: Bytes,
  mode :: Int) -> Result<(), String> do
  println("PENDING_PREPARED_BEFORE_FINAL_RACE")
  if mode == 3 do
    if !Test.set_push_token(Bytes.from_utf8("messenger/network/v1"), winner_wire) do
      return Err("pending_fixture_frame_change_failed")
    end
  else if mode == 0 do
    store_updated_blobs(path, backup_pending_labels(authority)?, [winner_wire, winner_descriptor])?
  else
    let label = if mode == 1 do
      "profile/v1"
    else
      "ohttp-revision/v1"
    end
    store_updated_blobs(path, [label], [winner_wire])?
  end
  Ok(nil)
end

fn d4_race_backup_pending_create_with_key(path :: String,
  expected_profile :: Bytes,
  selection :: List<D4BackupSelection>,
  winner_wire :: Bytes,
  winner_descriptor :: Bytes,
  mode :: Int,
  key :: borrow StorageKey) -> D4BackupPendingCreated!String do
  let authority = capture_backup_authority_with_key(path, expected_profile, key)?
  let before = backup_pending_capture(path, authority, key)?
  if before.wire.present || before.descriptor.present do
    return Err("pending_export_exists")
  end
  # Include both original absences in history discovery's192-label/32MiB budget.
  let sources = capture_backup_snapshot_with_key(path,
    FanoutSnapshot {
      bases: List.append(authority.sources.bases,
        AccountBasis {
          profile: before.profile,
          labels: [before.wire_label, before.descriptor_label],
          records: [Bytes.empty(), Bytes.empty()]
        })
    },
    [],
    key)?
  let prepared = backup_prepare_create(path, %{authority | sources: sources}, selection, key)?
  let draft = case Crypto.random_bytes(32) do
    Err(_) -> return Err("pending_export_refused")
    Ok(value) -> value
  end
  let descriptor = D4PendingDescriptor {
    account: authority.profile.account_id,
    authorization: authority.profile.account.authorization_public_key,
    realm: authority.service_realm,
    device: authority.profile.device_id,
    draft_id: draft,
    backup_id: backup_pending_wire_id(prepared.created.wire)?,
    wire_digest: Crypto.sha256(prepared.created.wire),
    wire_size: Bytes.length(prepared.created.wire),
    created_at: authority.captured_at
  }
  let sealed = seal_local(backup_pending_descriptor_wire(descriptor)?,
    key,
    backup_pending_context(authority)?)?
  d4_pending_inject_race(path, authority, winner_wire, winner_descriptor, mode)?
  backup_finalize(path,
    key,
    BackupFinalPending(%{authority | sources: prepared.sources},
      before,
      PendingPublish(prepared.created.wire, sealed)))?
  Ok(D4BackupPendingCreated {
    draft_id: draft,
    wire: prepared.created.wire,
    recovery_code: prepared.created.recovery_code
  })
end

pub fn d4_pending_race_create(path :: String,
  expected_profile :: Bytes,
  selection :: List<D4BackupSelection>,
  winner_wire :: Bytes,
  winner_descriptor :: Bytes,
  mode :: Int) -> D4BackupPendingCreated!String do
  let key = platform_key()?
  let result = d4_race_backup_pending_create_with_key(path,
    expected_profile,
    selection,
    winner_wire,
    winner_descriptor,
    mode,
    key)
  Secret.destroy(key)
  result
end

fn d4_race_backup_pending_state_with_key(path :: String,
  expected_profile :: Bytes,
  winner_wire :: Bytes,
  winner_descriptor :: Bytes,
  mode :: Int,
  key :: borrow StorageKey) -> Result<Plaintext<D4BackupPendingState>, String> do
  let authority = capture_backup_authority_with_key(path, expected_profile, key)?
  let before = backup_pending_capture(path, authority, key)?
  let plan = backup_pending_prepare_plan(authority, before, key)?
  d4_pending_inject_race(path, authority, winner_wire, winner_descriptor, mode)?
  backup_finalize(path, key, BackupFinalPending(authority, before, PendingFence))?
  Ok(plan.state)
end

pub fn d4_pending_race_state(path :: String,
  expected_profile :: Bytes,
  winner_wire :: Bytes,
  winner_descriptor :: Bytes,
  mode :: Int) -> Result<Plaintext<D4BackupPendingState>, String> do
  let key = platform_key()?
  let result = d4_race_backup_pending_state_with_key(path,
    expected_profile,
    winner_wire,
    winner_descriptor,
    mode,
    key)
  Secret.destroy(key)
  result
end

fn d4_race_backup_pending_resume_with_key(path :: String,
  expected_profile :: Bytes,
  draft_id :: Bytes,
  recovery_code :: String,
  winner_wire :: Bytes,
  winner_descriptor :: Bytes,
  mode :: Int,
  key :: borrow StorageKey) -> Bytes!String do
  let authority = capture_backup_authority_with_key(path, expected_profile, key)?
  let before = backup_pending_capture(path, authority, key)?
  let plan = backup_pending_prepare_plan(authority, before, key)?
  let restored = restore_portable_archive(recovery_code, before.wire.value)
  let accepted = backup_pending_resume_valid(authority, plan, draft_id, restored)
  if !backup_pending_observe_admission(accepted) do
    return Err("pending_export_refused")
  end
  d4_pending_inject_race(path, authority, winner_wire, winner_descriptor, mode)?
  backup_finalize(path, key, BackupFinalPending(authority, before, PendingFence))?
  Ok(before.wire.value)
end

pub fn d4_pending_race_resume(path :: String,
  expected_profile :: Bytes,
  draft_id :: Bytes,
  recovery_code :: String,
  winner_wire :: Bytes,
  winner_descriptor :: Bytes,
  mode :: Int) -> Bytes!String do
  let key = platform_key()?
  let result = d4_race_backup_pending_resume_with_key(path,
    expected_profile,
    draft_id,
    recovery_code,
    winner_wire,
    winner_descriptor,
    mode,
    key)
  Secret.destroy(key)
  result
end

fn d4_race_backup_pending_discard_with_key(path :: String,
  expected_profile :: Bytes,
  draft_id :: Bytes,
  winner_wire :: Bytes,
  winner_descriptor :: Bytes,
  mode :: Int,
  key :: borrow StorageKey) -> Int!String do
  let authority = capture_backup_authority_with_key(path, expected_profile, key)?
  let before = backup_pending_capture(path, authority, key)?
  let plan = backup_pending_prepare_plan(authority, before, key)?
  let accepted = plan.state.kind == 0
    || (plan.state.kind == 1 && Bytes.secure_equals(plan.state.draft_id, draft_id))
  if !backup_pending_observe_admission(accepted) do
    return Err("pending_export_refused")
  end
  d4_pending_inject_race(path, authority, winner_wire, winner_descriptor, mode)?
  backup_finalize(path, key, BackupFinalPending(authority, before, PendingDelete))?
  Ok(if before.wire.present || before.descriptor.present do
    1
  else
    2
  end)
end

pub fn d4_pending_race_discard(path :: String,
  expected_profile :: Bytes,
  draft_id :: Bytes,
  winner_wire :: Bytes,
  winner_descriptor :: Bytes,
  mode :: Int) -> Int!String do
  let key = platform_key()?
  let result = d4_race_backup_pending_discard_with_key(path,
    expected_profile,
    draft_id,
    winner_wire,
    winner_descriptor,
    mode,
    key)
  Secret.destroy(key)
  result
end

fn d4_race_backup_pending_repair_with_key(path :: String,
  expected_profile :: Bytes,
  winner_wire :: Bytes,
  winner_descriptor :: Bytes,
  mode :: Int,
  key :: borrow StorageKey) -> Int!String do
  let authority = capture_backup_authority_with_key(path, expected_profile, key)?
  let before = backup_pending_capture(path, authority, key)?
  let plan = backup_pending_prepare_plan(authority, before, key)?
  if !backup_pending_observe_admission(plan.state.kind != 1) do
    return Err("pending_export_refused")
  end
  d4_pending_inject_race(path, authority, winner_wire, winner_descriptor, mode)?
  backup_finalize(path, key, BackupFinalPending(authority, before, PendingDelete))?
  Ok(if before.wire.present || before.descriptor.present do
    1
  else
    2
  end)
end

pub fn d4_pending_race_repair(path :: String,
  expected_profile :: Bytes,
  winner_wire :: Bytes,
  winner_descriptor :: Bytes,
  mode :: Int) -> Int!String do
  let key = platform_key()?
  let result = d4_race_backup_pending_repair_with_key(path,
    expected_profile,
    winner_wire,
    winner_descriptor,
    mode,
    key)
  Secret.destroy(key)
  result
end

# Permanent test-only publication checks: standard sibling .test-support merge.
# PROOF ONLY: appended to the owned test run copy, never production.
# Genuine custody/reader, caller-owned key and captured absences are retained.
# Only the archive content is explicitly authored to isolate this publication
# unit from the still-incomplete HTTP capture unit.
from Protocol.V1 import ProtocolError

fn d4_publication_authored_payload(content :: Plaintext<PortableBackupContentArchive>,
  id :: Bytes,
  time :: U64) -> Result<Plaintext<Bytes>, ProtocolError> do
  encode_content_archive(BackupContentArchive {
    policy: content.policy,
    backup_id: id,
    owner_account: content.owner_account,
    owner_authorization_key: content.owner_authorization_key,
    service_realm: content.service_realm,
    created_at: time,
    candidate_count: content.candidate_count,
    omitted_timed: content.omitted_timed,
    omitted_unknown: content.omitted_unknown,
    omitted_nontext: content.omitted_nontext,
    omitted_empty: content.omitted_empty,
    attachment_messages: content.attachment_messages,
    scopes: content.scopes
  })
end

fn d4_publication_authored_extent(content :: Plaintext<PortableBackupContentArchive>,
  time :: U64) -> Plaintext<Int> do
  case d4_publication_authored_payload(content, Bytes.from_utf8(String.repeat("0", 32)), time) do
    Err(_) -> 0
    Ok(value) -> Bytes.length(value)
  end
end

fn d4_publication_descriptor_matches(raw :: Result<Plaintext<Bytes>, String>,
  authority :: D4BackupAuthority,
  created :: D4BackupPendingCreated) -> Plaintext<Bool> do
  let wire = case raw do
    Err(_) -> return false
    Ok(value) -> value
  end
  let descriptor = case backup_pending_decode_descriptor(wire) do
    Err(_) -> return false
    Ok(value) -> value
  end
  let id = case backup_pending_wire_id(created.wire) do
    Err(_) -> return false
    Ok(value) -> value
  end
  Bytes.length(wire) == 225
    && Bytes.secure_equals(descriptor.account, authority.profile.account_id)
    && Bytes.secure_equals(descriptor.authorization, authority.profile.account.authorization_public_key)
    && Bytes.secure_equals(descriptor.realm, authority.service_realm)
    && Bytes.secure_equals(descriptor.device, authority.profile.device_id)
    && Bytes.secure_equals(descriptor.draft_id, created.draft_id)
    && Bytes.secure_equals(descriptor.backup_id, id)
    && Bytes.secure_equals(descriptor.wire_digest, Crypto.sha256(created.wire))
    && descriptor.wire_size == Bytes.length(created.wire)
    && U64.compare(descriptor.created_at, authority.captured_at) == 0
end

fn d4_publication_prepared_matches(captured :: borrow D4BackupCapturedContent,
  raw :: Result<D4BackupPreparedContentPending, String>,
  key :: borrow StorageKey) -> Plaintext<Bool> do
  let prepared = case raw do
    Err(_) -> return false
    Ok(value) -> value
  end
  let id = case backup_pending_wire_id(prepared.created.wire) do
    Err(_) -> return false
    Ok(value) -> value
  end
  let actual = restore_portable_archive(prepared.created.recovery_code, prepared.created.wire)
  let expected = d4_publication_authored_payload(captured.content, id, captured.reader.authority.captured_at)
  let same = case (actual, expected) do
    (Ok(a), Ok(b)) -> Bytes.secure_equals(a, b)
    _ -> false
  end
  let context = case backup_pending_context(captured.reader.authority) do
    Err(_) -> return false
    Ok(value) -> value
  end
  !prepared.before.wire.present && !prepared.before.descriptor.present
    && Bytes.length(prepared.created.draft_id) == 32
    && same
    && d4_publication_descriptor_matches(backup_protect_opened(open_local(prepared.descriptor,
      key, context)), captured.reader.authority, prepared.created)
end

fn d4_publication_retire(captured :: consume D4BackupCapturedContent) do
  nil
end

pub fn d4_publication_prepare_proof(path :: String,
  profile :: Bytes,
  authored :: PortableBackupContentArchive,
  history_labels :: List<String>) -> Plaintext<Bool>!String do
  let key = platform_key()?
  let result = d4_publication_prepare_proof_with_key(path, profile, authored, history_labels, key)
  Secret.destroy(key)
  result
end

fn d4_publication_prepare_proof_with_key(path :: String,
  profile :: Bytes,
  authored :: PortableBackupContentArchive,
  history_labels :: List<String>,
  key :: borrow StorageKey) -> Plaintext<Bool>!String do
  let authority = capture_backup_authority_with_key(path, profile, key)?
  let before = backup_pending_capture(path, authority, key)?
  let seeded = capture_backup_snapshot_with_key(path,
    FanoutSnapshot { bases: List.append(authority.sources.bases, AccountBasis {
      profile: before.profile,
      labels: [before.wire_label, before.descriptor_label],
      records: [Bytes.empty(), Bytes.empty()]
    }) }, history_labels, key)?
  let reader = capture_backup_attachment_reader(path, %{authority | sources: seeded}, key)?
  let observed = case current_time() do
    Err(error) -> do
      d4_publication_test_retire_reader(reader)
      return Err(error)
    end
    Ok(value) -> value
  end
  let captured = D4BackupCapturedContent {
    reader: reader,
    content: authored,
    min_expiry: None,
    encoded_extent: d4_publication_authored_extent(authored, authority.captured_at),
    observed_at: observed
  }
  println("PUBLICATION_PREPARE_READY")
  let raw = backup_prepare_pending_content(captured, before, key)
  let matches = d4_publication_prepared_matches(captured, raw, key)
  d4_publication_retire(captured)
  Ok(matches)
end

fn d4_publication_test_retire_reader(reader :: consume D4BackupAttachmentReader) do
  nil
end

# PROOF ONLY: caller-owned original key and real reader remain held until the
# actual writer returns. Constructor content is authored; no HTTP is bypassed
# or claimed. A refusal after the commit marker is separate from setup failure.
type D4PublicationTestCommitResult do
  D4PublicationTestCommitRefused
  D4PublicationTestCommitted(created :: D4BackupPendingCreated, created_at :: U64)
end

fn d4_publication_commit_fixture_with_key(path :: String,
  profile :: Bytes,
  authored :: PortableBackupContentArchive,
  history_labels :: List<String>,
  key :: borrow StorageKey) -> D4PublicationTestCommitResult!String do
  let authority = capture_backup_authority_with_key(path, profile, key)?
  let before = backup_pending_capture(path, authority, key)?
  let seeded = capture_backup_snapshot_with_key(path,
    FanoutSnapshot { bases: List.append(authority.sources.bases, AccountBasis {
      profile: before.profile,
      labels: [before.wire_label, before.descriptor_label],
      records: [Bytes.empty(), Bytes.empty()]
    }) }, history_labels, key)?
  let reader = capture_backup_attachment_reader(path, %{authority | sources: seeded}, key)?
  let observed = case current_time() do
    Err(error) -> do
      d4_publication_test_retire_reader(reader)
      return Err(error)
    end
    Ok(value) -> value
  end
  let captured = D4BackupCapturedContent {
    reader: reader,
    content: authored,
    min_expiry: None,
    encoded_extent: d4_publication_authored_extent(authored, authority.captured_at),
    observed_at: observed
  }
  let prepared = case backup_prepare_pending_content(captured, before, key) do
    Err(error) -> do
      d4_publication_retire(captured)
      return Err(error)
    end
    Ok(value) -> value
  end
  let created_at = captured.reader.authority.captured_at
  println("PUBLICATION_COMMIT_READY")
  let result = backup_publish_pending_content(path, key, captured, prepared)
  d4_publication_retire(captured)
  case result do
    Err(_) -> Ok(D4PublicationTestCommitRefused)
    Ok(_) -> Ok(D4PublicationTestCommitted(prepared.created, created_at))
  end
end

fn d4_publication_pair_matches(state :: Result<Plaintext<D4BackupPendingState>, String>,
  resumed :: Result<Bytes, String>,
  created :: D4BackupPendingCreated,
  created_at :: U64) -> Plaintext<Bool> do
  case (state, resumed) do
    (Ok(value), Ok(wire)) -> value.kind == 1
      && Bytes.secure_equals(value.draft_id, created.draft_id)
      && value.wire_size == Bytes.length(created.wire)
      && U64.compare(value.created_at, created_at) == 0
      && Bytes.secure_equals(wire, created.wire)
    _ -> false
  end
end

pub fn d4_publication_commit_proof(path :: String,
  profile :: Bytes,
  authored :: PortableBackupContentArchive,
  history_labels :: List<String>) -> Plaintext<Bool>!String do
  let key = platform_key()?
  let raw = d4_publication_commit_fixture_with_key(path, profile, authored, history_labels, key)
  Secret.destroy(key)
  let committed = raw?
  case committed do
    D4PublicationTestCommitRefused -> Ok(false)
    D4PublicationTestCommitted(created, created_at) -> do
      # Both real fresh-custody operations finish before any private state field
      # is examined. No retained reader/key is refreshed to admit publication.
      let state = pending_backup_export_state(path, profile)
      let resumed = resume_pending_backup_export(path, profile, created.draft_id, created.recovery_code)
      Ok(d4_publication_pair_matches(state, resumed, created, created_at))
    end
  end
end

# Pure synthetic test of the ACTUAL private production policy at both writer
# boundaries. No resource assignment is the oracle and no caller clock API is
# exposed by production. Only closed Refuse/PublishReady pairs match.
pub fn d4_publication_clock_pair_proof(captured_at :: U64,
  fresh_through :: U64,
  expiry :: Option<U64>,
  held_completion :: U64,
  first :: U64,
  last :: U64,
  expected :: Bool) -> Plaintext<Bool> do
  let before = backup_pending_content_action(captured_at,
    fresh_through, expiry, held_completion, first)
  let finished = backup_pending_content_action(captured_at,
    fresh_through, expiry, first, last)
  case (before, finished) do
    (D4BackupRetrievalPublishReady, D4BackupRetrievalPublishReady) -> expected
    (D4BackupRetrievalRefuse, D4BackupRetrievalPublishReady) -> !expected
    (D4BackupRetrievalPublishReady, D4BackupRetrievalRefuse) -> !expected
    (D4BackupRetrievalRefuse, D4BackupRetrievalRefuse) -> !expected
    _ -> false
  end
end
