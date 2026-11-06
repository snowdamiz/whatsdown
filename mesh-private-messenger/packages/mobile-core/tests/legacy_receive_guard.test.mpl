from Storage.AccountGuard import AccountBasis
from Mobile.HeaderAdmission import (
  capture_legacy_receive,
  capture_header_history,
  commit_legacy_receive
)
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import platform_key, seal_local, local_context
from Storage.Records import store_updated_blobs, store_record_changes, erase_local_state
from Tests.Support import database_path

fn bytes(value :: String) -> Bytes do
  Bytes.from_utf8(value)
end

fn id(value :: Int, size :: Int) -> Bytes!String do
  case Bytes.repeat(value, size) do
    Err(_) -> Err("fixture bytes")
    Ok(value) -> Ok(value)
  end
end

fn selected(before :: Option<AccountBasis>) -> AccountBasis!String do
  case before do
    None -> Err("fixture missing legacy source")
    Some(value) -> Ok(value)
  end
end

fn stale_history() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("legacy-receive-history-guard")?
  ensure_schema(path)?
  let key = platform_key()?
  let profile = bytes("public profile")
  let session_id = id(3, 32)?
  let session = "session/v1/#{Bytes.to_hex(session_id)}"
  let conversation = id(7, 16)?
  let history = "history/v1/#{Bytes.to_hex(conversation)}"
  for mode in 0..2 do
    store_updated_blobs(path,
      ["profile/v1", "sessions/v1", session],
      [
        seal_local(profile, key, local_context("profile/v1")?)?,
        bytes("source index"),
        bytes("source ratchet")
      ])?
    if mode == 0 do
      store_updated_blobs(path, [history], [bytes("old expired and retained entries")])?
    end
    let before = capture_legacy_receive(path, key, profile, session_id)?
    let extended = selected(capture_header_history(path, Some(before), conversation)?)?
    # Independent cold database opens: capture, history read, competing cleanup,
    # and final ratchet/history commit each acquire their own real connection.
    if mode == 0 do
      assert(Bytes.secure_equals(load_blob(path, history)?,
        bytes("old expired and retained entries")))
    else
      assert(Result.is_err(load_blob(path, history)))
    end
    store_updated_blobs(path, [history], [bytes("compaction or concurrent first history won")])?
    assert(case commit_legacy_receive(path,
      extended,
      [session, history],
      [bytes("next ratchet"), bytes("stale history would resurrect expired entry")]) do
      Err("account_state_changed") -> true
      _ -> false
    end)
    assert(Bytes.secure_equals(load_blob(path, history)?,
      bytes("compaction or concurrent first history won")))
    assert(Bytes.secure_equals(load_blob(path, session)?, bytes("source ratchet")))
    store_record_changes(path, [], [], [history])?
  end
  erase_local_state(path)
end

fn stale_selection_and_positive() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("legacy-receive-source-guard")?
  ensure_schema(path)?
  let key = platform_key()?
  let profile = bytes("public profile")
  let session_id = id(3, 32)?
  let session = "session/v1/#{Bytes.to_hex(session_id)}"
  for changed in ["profile/v1", "sessions/v1", session] do
    store_updated_blobs(path,
      ["profile/v1", "sessions/v1", session],
      [
        seal_local(profile, key, local_context("profile/v1")?)?,
        bytes("source index"),
        bytes("source ratchet")
      ])?
    let before = capture_legacy_receive(path, key, profile, session_id)?
    store_updated_blobs(path, [changed], [bytes("newer source")])?
    assert(case commit_legacy_receive(path, before, [session], [bytes("stale ratchet")]) do
      Err("account_state_changed") -> true
      _ -> false
    end)
    assert(Bytes.secure_equals(load_blob(path, changed)?, bytes("newer source")))
  end
  store_updated_blobs(path,
    ["profile/v1", "sessions/v1", session],
    [
      seal_local(profile, key, local_context("profile/v1")?)?,
      bytes("source index"),
      bytes("source ratchet")
    ])?
  let before = capture_legacy_receive(path, key, profile, session_id)?
  commit_legacy_receive(path, before, [session], [bytes("committed next ratchet")])?
  assert(Bytes.secure_equals(load_blob(path, session)?, bytes("committed next ratchet")))
  erase_local_state(path)
end

test("legacy receive cannot resurrect history after cleanup or a competing first history") do
  case stale_history() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("legacy receive retains exact profile index and selected session fence with fresh positive commit") do
  case stale_selection_and_positive() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
