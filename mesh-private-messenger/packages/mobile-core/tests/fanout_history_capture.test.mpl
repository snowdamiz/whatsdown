from Storage.AccountGuard import same_account_basis
from Storage.FanoutCommit import (
  capture_fanout_snapshot,
  capture_fanout_history,
  commit_fanout_records
)
from Storage.Blobs import ensure_schema, load_blob
from Storage.Records import store_updated_blobs, erase_local_state
from Tests.Support import database_path, repeated

fn history_race(existing :: Bool) -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("fanout_history_race_#{existing}")?
  ensure_schema(path)?
  let profile = Bytes.from_utf8("sealed owner")
  let source = Bytes.from_utf8("sealed source index")
  let conversation = repeated(47, 16)?
  let label = "history/v1/#{Bytes.to_hex(conversation)}"
  let winner = Bytes.from_utf8("compacted or concurrently created history")
  store_updated_blobs(path, ["profile/v1", "sessions/v1"], [profile, source])?
  if existing do
    store_updated_blobs(path, [label], [Bytes.from_utf8("old history with expired messages")])?
  end
  let before = capture_fanout_snapshot(path, profile, ["sessions/v1"])?
  let captured = capture_fanout_history(path, before, conversation)?
  assert(List.length(captured.bases) == 2)
  assert(same_account_basis(List.head(before.bases), List.head(captured.bases)))
  assert(List.last(captured.bases).labels == [label])
  if !existing do
    assert(Bytes.length(List.head(List.last(captured.bases).records)) == 0)
  end
  store_updated_blobs(path, [label], [winner])?
  assert(case commit_fanout_records(path,
    captured,
    [label],
    [Bytes.from_utf8("stale history must not restore expired messages")],
    []) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(load_blob(path, label)?, winner))
  assert(Bytes.secure_equals(load_blob(path, "sessions/v1")?, source))
  let fresh = capture_fanout_history(path, before, conversation)?
  let repeated_capture = capture_fanout_history(path, fresh, conversation)?
  assert(List.length(repeated_capture.bases) == List.length(fresh.bases))
  assert(same_account_basis(List.last(repeated_capture.bases), List.last(fresh.bases)))
  let appended = Bytes.from_utf8("current history and newly sent message")
  commit_fanout_records(path, repeated_capture, [label], [appended], [])?
  assert(Bytes.secure_equals(load_blob(path, label)?, appended))
  # The source extension must not replace an earlier source with a later read.
  store_updated_blobs(path, ["sessions/v1"], [Bytes.from_utf8("newer index")])?
  assert(case capture_fanout_history(path, before, conversation) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  store_updated_blobs(path, ["sessions/v1"], [source])?
  store_updated_blobs(path, ["profile/v1"], [Bytes.from_utf8("replacement owner")])?
  assert(case capture_fanout_history(path, before, conversation) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(load_blob(path, label)?, appended))
  erase_local_state(path)?
  File.delete(path)?
  Ok(nil)
end

test("fanout history extension preserves earlier sources and refuses a concurrent compaction") do
  case history_race(true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("fanout history extension captures absence and refuses a concurrent first writer") do
  case history_race(false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
