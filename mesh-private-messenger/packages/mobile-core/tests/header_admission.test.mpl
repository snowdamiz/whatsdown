from Mobile.HeaderAdmission import (
  capture_header_initial,
  capture_header_history,
  commit_initial_admission
)
from Mobile.HeaderCapabilities import require_new_header_capacity
from Storage.AccountGuard import AccountBasis, load_account_basis
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import platform_key, seal_local, local_context
from Storage.Records import store_updated_blobs, store_record_changes, erase_local_state
from Tests.Support import database_path

fn await_file(path :: String, attempts :: Int) -> Bool do
  if File.exists(path) do
    case File.read(path) do
      Ok(value) -> if String.length(value) > 0 do
        return true
      end
      Err(_) -> nil
    end
  end
  if attempts <= 0 do
    false
  else
    Timer.sleep(5)
    await_file(path, attempts - 1)
  end
end

fn wire(value :: String) -> Bytes do
  Bytes.from_utf8(value)
end

actor contender(path :: String, before :: AccountBasis, index :: Int) do
  let name = path <> ".#{index}"
  File.write(name <> ".ready", "ready")
  if await_file(path <> ".go", 1000) do
    # Each writer independently passed count4095 +1 before another commit.
    let result = case require_new_header_capacity(4095, 1) do
      Err(error) -> Err(error)
      Ok(_) -> commit_initial_admission(path,
        Some(before),
        "session/v1/candidate#{index}",
        wire("session#{index}"),
        wire("index#{index}"),
        ["history/v1/new"],
        [wire("history#{index}")],
        ["selected-prekey"],
        ["one-time-prekeys/v1"],
        [wire("remaining#{index}")])
    end
    File.write(name <> ".done",
      case result do
        Ok(_) -> "ok"
        Err(error) -> error
      end)
  end
end

fn concurrent_admission() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("he-admission-concurrent")?
  ensure_schema(path)?
  store_updated_blobs(path,
    ["profile/v1", "sessions/v1", "one-time-prekeys/v1", "selected-prekey"],
    [wire("custody"), wire("4095 source sessions"), wire("original pool"), wire("original key")])?
  let before = load_account_basis(path,
    ["sessions/v1", "one-time-prekeys/v1", "selected-prekey", "history/v1/new"])?
  for index in 0..8 do
    let _writer = spawn(contender, path, before, index)
    nil
  end
  for index in 0..8 do
    assert(await_file(path <> ".#{index}.ready", 1000))
  end
  File.write(path <> ".go", "go")?
  let outcomes = for index in 0..8 do
    let name = path <> ".#{index}"
    assert(await_file(name <> ".done", 1000))
    let result = File.read(name <> ".done")?
    File.delete(name <> ".ready")?
    File.delete(name <> ".done")?
    result
  end
  assert(List.length(List.filter(outcomes, fn(value) -> value == "ok" end)) == 1)
  assert(List.all(outcomes, fn(value) -> value == "ok" || value == "account_state_changed" end))
  let winner = List.head(List.filter(for index in 0..8 do
      if List.get(outcomes, index) == "ok" do
        index
      else
        -1
      end
    end,
    fn(value) -> value >= 0 end))
  assert(Bytes.secure_equals(load_blob(path, "sessions/v1")?, wire("index#{winner}")))
  assert(Bytes.secure_equals(load_blob(path, "history/v1/new")?, wire("history#{winner}")))
  assert(Bytes.secure_equals(load_blob(path, "one-time-prekeys/v1")?, wire("remaining#{winner}")))
  assert(Result.is_err(load_blob(path, "selected-prekey")))
  for index in 0..8 do
    if index != winner do
      assert(Result.is_err(load_blob(path, "session/v1/candidate#{index}")))
    end
  end
  File.delete(path <> ".go")?
  erase_local_state(path)
end

fn stale_sources() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("he-admission-stale")?
  ensure_schema(path)?
  for changed in ["profile/v1", "sessions/v1", "one-time-prekeys/v1", "selected-prekey"] do
    store_updated_blobs(path,
      ["profile/v1", "sessions/v1", "one-time-prekeys/v1", "selected-prekey"],
      [wire("custody"), wire("index"), wire("pool"), wire("key")])?
    let before = load_account_basis(path,
      ["sessions/v1", "one-time-prekeys/v1", "selected-prekey", "history/v1/stale"])?
    store_updated_blobs(path, [changed], [wire("newer winner")])?
    assert(case commit_initial_admission(path,
      Some(before),
      "session/v1/stale",
      wire("stale session"),
      wire("stale index"),
      ["history/v1/stale"],
      [wire("stale history")],
      ["selected-prekey"],
      ["one-time-prekeys/v1"],
      [wire("stale pool")]) do
      Err("account_state_changed") -> true
      _ -> false
    end)
    assert(Bytes.secure_equals(load_blob(path, changed)?, wire("newer winner")))
    assert(Result.is_err(load_blob(path, "session/v1/stale")))
    assert(Result.is_err(load_blob(path, "history/v1/stale")))
  end
  erase_local_state(path)
end

fn capture_and_legacy() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("he-admission-profile-and-legacy")?
  ensure_schema(path)?
  let key = platform_key()?
  let profile = wire("exact public profile source")
  store_updated_blobs(path,
    ["profile/v1"],
    [seal_local(profile, key, local_context("profile/v1")?)?])?
  let before = capture_header_initial(path, key, profile, U64.parse("1")?)?
  assert(List.contains(before.labels, "sessions/v1"))
  assert(List.contains(before.labels, "last-resort-replays/v1"))
  assert(case capture_header_initial(path, key, wire("stale profile"), U64.parse("1")?) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  commit_initial_admission(path,
    None,
    "session/v1/legacy",
    wire("legacy session"),
    wire("legacy index"),
    [],
    [],
    [],
    [],
    [])?
  assert(Bytes.secure_equals(load_blob(path, "session/v1/legacy")?, wire("legacy session")))
  erase_local_state(path)
end

test("eight HE initial writers sharing the last admitted slot commit one complete generation") do
  case concurrent_admission() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("stale profile index and selected prekey sources refuse the whole HE initial commit") do
  case stale_sources() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("HE capture requires exact profile and includes absent sources; explicit legacy commit stays supported") do
  case capture_and_legacy() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

fn history_winner() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("he-history-expiry-race")?
  ensure_schema(path)?
  let conversation = case Bytes.repeat(7, 16) do
    Err(_) -> return Err("fixture conversation")
    Ok(value) -> value
  end
  let history = "history/v1/#{Bytes.to_hex(conversation)}"
  for mode in 0..2 do
    store_updated_blobs(path,
      ["profile/v1", "sessions/v1", "selected-prekey"],
      [wire("custody"), wire("index"), wire("selected key")])?
    if mode == 0 do
      store_updated_blobs(path, [history], [wire("old entries including expired message")])?
    end
    let base = load_account_basis(path, ["sessions/v1", "selected-prekey"])?
    let guarded = capture_header_history(path, Some(base), conversation)?
    # The actual history read is after capture. An absent row is a source too.
    if mode == 0 do
      assert(Bytes.secure_equals(load_blob(path, history)?,
        wire("old entries including expired message")))
    else
      assert(Result.is_err(load_blob(path, history)))
    end
    store_updated_blobs(path, [history], [wire("newer compacted or concurrently created history")])?
    assert(case commit_initial_admission(path,
      guarded,
      "session/v1/history-stale#{mode}",
      wire("new session"),
      wire("stale index"),
      [history],
      [wire("stale entries would resurrect expired message")],
      ["selected-prekey"],
      [],
      []) do
      Err("account_state_changed") -> true
      _ -> false
    end)
    assert(Bytes.secure_equals(load_blob(path, history)?,
      wire("newer compacted or concurrently created history")))
    assert(Bytes.secure_equals(load_blob(path, "selected-prekey")?, wire("selected key")))
    assert(Result.is_err(load_blob(path, "session/v1/history-stale#{mode}")))
    store_updated_blobs(path, ["profile/v1"], [wire("custody")])?
    let source = load_account_basis(path, ["sessions/v1"])?
    store_updated_blobs(path, ["sessions/v1"], [wire("newer source index")])?
    assert(case capture_header_history(path, Some(source), conversation) do
      Err("account_state_changed") -> true
      _ -> false
    end)
    # Reset only this owned fixture row before the absent-source iteration.
    from_fixture_delete(path, history)?
  end
  assert(Option.is_none(capture_header_history(path, None, conversation)?))
  erase_local_state(path)
end

fn from_fixture_delete(path :: String, label :: String) -> Unit!String do
  store_record_changes(path, [], [], [label])
end

test("HE history capture precedes read and refuses stale compaction or concurrent first history without resurrecting entries") do
  case history_winner() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
