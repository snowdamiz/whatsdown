from Tests.BackupArchiveFixture import (
  d4_core_fixture,
  d4_core_cleanup,
  d4_core_actual_group,
  d4_core_malformed_group,
  d4_core_foreign_group,
  d4_core_replace_group_history,
  d4_core_foreign_sent_bundle,
  d4_core_foreign_sent_content,
  d4_core_content_matches,
  d4_core_backup_id,
  d4_core_inject_foreign_sent,
  d4_core_read_refused
)
from Mobile.BackupArchive import (
  D4BackupSelection,
  create_backup_archive,
  import_backup_archive,
  read_backup_archive
)
from Tests.Support import repeated

test("whole backup refuses authenticated outer malformed group state before export") do
  let f = d4_core_fixture()?
  let id = d4_core_malformed_group(f)?
  println("D4_GROUP_MALFORMED_READY")
  assert(Result.is_err(create_backup_archive(f.path,
    f.public_profile,
    [D4BackupSelection { kind: 2, scope_id: id, from_time: None, through_time: None }])))
  d4_core_cleanup(f)?
  Ok(nil)
end

test("whole backup refuses independently authenticated foreign owner group state before export") do
  let f = d4_core_fixture()?
  let id = d4_core_foreign_group(f)?
  println("D4_GROUP_FOREIGN_STATE_READY")
  assert(Result.is_err(create_backup_archive(f.path,
    f.public_profile,
    [D4BackupSelection { kind: 2, scope_id: id, from_time: None, through_time: None }])))
  d4_core_cleanup(f)?
  Ok(nil)
end

test("whole backup export refuses outgoing group text attributed to another account") do
  let f = d4_core_fixture()?
  let id = d4_core_actual_group(f)?
  d4_core_replace_group_history(f, id, repeated(61, 32)?)?
  println("D4_GROUP_FOREIGN_SENT_CREATE_READY")
  assert(Result.is_err(create_backup_archive(f.path,
    f.public_profile,
    [D4BackupSelection { kind: 2, scope_id: id, from_time: None, through_time: None }])))
  d4_core_cleanup(f)?
  Ok(nil)
end

test("whole backup import refuses authenticated outgoing group text attributed to another account") do
  let f = d4_core_fixture()?
  let id = repeated(81, 32)?
  let bundle = d4_core_foreign_sent_bundle(f, id)?
  let confirmed = d4_core_backup_id(bundle.wire)?
  assert(d4_core_content_matches(bundle, d4_core_foreign_sent_content(f, id)?, f.now, f.now))
  println("D4_GROUP_FOREIGN_SENT_IMPORT_READY")
  assert(Result.is_err(import_backup_archive(f.path,
    f.public_profile,
    bundle.wire,
    bundle.recovery_code,
    confirmed)))
  d4_core_cleanup(f)?
  Ok(nil)
end

test("whole backup read refuses valid target containers with foreign outgoing group attribution") do
  let f = d4_core_fixture()?
  let id = repeated(82, 32)?
  d4_core_inject_foreign_sent(f, id)?
  println("D4_GROUP_FOREIGN_SENT_READ_READY")
  assert(d4_core_read_refused(read_backup_archive(f.path, f.public_profile, id)))
  d4_core_cleanup(f)?
  Ok(nil)
end
