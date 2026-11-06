from Storage.AccountGuard import load_account_basis, commit_account_changes
from Storage.Blobs import ensure_schema, load_blob
from Storage.Records import (
  store_updated_blobs,
  with_record_transaction,
  put_blobs,
  erase_local_state
)
from Tests.Support import database_path

fn busy_writer_refuses_without_relabeling() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("keyed_index_busy_writer")?
  ensure_schema(path)?
  let original = Bytes.from_utf8("original generation")
  store_updated_blobs(path, ["profile/v1", "state/v1"], [original, original])?
  let before = load_account_basis(path, ["state/v1", "absent/v1"])?
  # This actor holds a different connection's writer lock until the bounded
  # attempt has returned. No timer or scheduling race can release it early.
  let locker = Sqlite.open(path)?
  Sqlite.execute(locker, "BEGIN IMMEDIATE", [])?
  let blocked = commit_account_changes(path,
    before,
    ["state/v1", "absent/v1"],
    [Bytes.from_utf8("blocked generation"), Bytes.from_utf8("must not appear")],
    [])
  Sqlite.rollback(locker)?
  Sqlite.close(locker)
  assert(case blocked do
    Err("database_write_failed") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(load_blob(path, "state/v1")?, original))
  assert(case load_blob(path, "absent/v1") do
    Err("local_state_not_found") -> true
    _ -> false
  end)
  # Reopening after the real storage failure does not mark the unchanged basis
  # stale. The same exact generation may commit once the writer lock is free.
  let winner = Bytes.from_utf8("committed generation")
  commit_account_changes(path, before, ["state/v1"], [winner], [])?
  assert(Bytes.secure_equals(load_blob(path, "state/v1")?, winner))
  erase_local_state(path)
end

fn callback_failure_rolls_back() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("keyed_index_writer_rollback")?
  ensure_schema(path)?
  let original = Bytes.from_utf8("original generation")
  store_updated_blobs(path, ["profile/v1", "state/v1"], [original, original])?
  let attempted = with_record_transaction(path,
    fn(database) do
      put_blobs(database,
        ["state/v1", "new/v1"],
        [Bytes.from_utf8("partial generation"), Bytes.from_utf8("must not appear")],
        0)?
      Err("synthetic_callback_failure")
    end)
  assert(case attempted do
    Err("synthetic_callback_failure") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(load_blob(path, "state/v1")?, original))
  assert(case load_blob(path, "new/v1") do
    Err("local_state_not_found") -> true
    _ -> false
  end)
  store_updated_blobs(path, ["state/v1"], [Bytes.from_utf8("after reopen")])?
  assert(Bytes.to_utf8(load_blob(path, "state/v1")?)? == "after reopen")
  erase_local_state(path)
end

test("a busy writer remains a bounded storage failure and preserves the exact generation") do
  assert(Result.is_ok(busy_writer_refuses_without_relabeling()))
end

test("writer callback failure rolls back every keyed row and a reopened writer succeeds") do
  assert(Result.is_ok(callback_failure_rolls_back()))
end
