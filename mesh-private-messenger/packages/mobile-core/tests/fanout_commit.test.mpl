from Storage.AccountGuard import AccountBasis, load_account_basis
from Storage.FanoutCommit import commit_fanout
from Storage.OutboxGuard import OutboxBasis, PreparedOutboxIndex
from Storage.Blobs import ensure_schema, load_blob
from Storage.Records import store_updated_blobs, erase_local_state
from Tests.Support import database_path

fn prepared(profile :: Bytes, index :: Bytes) -> PreparedOutboxIndex do
  PreparedOutboxIndex {
    value: Bytes.from_utf8("sealed prepared outbox"),
    before: OutboxBasis {
      profile: profile,
      index: index,
      postage: Bytes.empty(),
      delivery: Bytes.empty()
    }
  }
end

fn commit(path :: String,
  before :: AccountBasis,
  final_index :: PreparedOutboxIndex) -> Result<(), String> do
  commit_fanout(path,
    before,
    [],
    [],
    Bytes.from_utf8("prepared ratchets"),
    ["history/v1/test"],
    [Bytes.from_utf8("prepared history")],
    ["outbox-envelope/v1/test"],
    [Bytes.from_utf8("prepared envelope")],
    final_index)
end

fn erased_fixture() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("fanout_late_replacement")?
  ensure_schema(path)?
  let old = Bytes.from_utf8("old encrypted profile")
  let replacement = Bytes.from_utf8("replacement encrypted profile")
  store_updated_blobs(path, ["profile/v1"], [old])?
  let before = load_account_basis(path, ["history/v1/test"])?
  erase_local_state(path)?
  store_updated_blobs(path,
    ["profile/v1", "sessions/v1"],
    [replacement, Bytes.from_utf8("replacement custody")])?
  # This is the dangerous interleaving: the outbox helper takes its snapshot
  # after old-account crypto has finished, and therefore sees replacement B.
  assert(Result.is_err(commit(path, before, prepared(replacement, Bytes.empty()))))
  assert(Bytes.secure_equals(load_blob(path, "profile/v1")?, replacement))
  assert(Bytes.to_utf8(load_blob(path, "sessions/v1")?)? == "replacement custody")
  assert(Result.is_err(load_blob(path, "outbox-envelope/v1/test")))
  erase_local_state(path)?
  File.delete(path)?
  Ok(nil)
end

fn changed_source_fixture() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("fanout_late_ratchet")?
  ensure_schema(path)?
  let profile = Bytes.from_utf8("encrypted account profile")
  let old = Bytes.from_utf8("encrypted ratchet before receive")
  let next = Bytes.from_utf8("encrypted ratchet after receive")
  store_updated_blobs(path, ["profile/v1", "session/v1/test"], [profile, old])?
  let before = load_account_basis(path, ["session/v1/test", "history/v1/test"])?
  # Receiving a new DH step may change this session without changing the
  # outbox index. The late outbox snapshot alone cannot detect that change.
  store_updated_blobs(path, ["session/v1/test"], [next])?
  assert(Result.is_err(commit(path, before, prepared(profile, Bytes.empty()))))
  assert(Bytes.secure_equals(load_blob(path, "session/v1/test")?, next))
  assert(Result.is_err(load_blob(path, "outbox-envelope/v1/test")))
  let fresh = load_account_basis(path, ["session/v1/test", "history/v1/test"])?
  commit(path, fresh, prepared(profile, Bytes.empty()))?
  assert(Bytes.to_utf8(load_blob(path, "outbox-envelope/v1/test")?)? == "prepared envelope")
  erase_local_state(path)?
  File.delete(path)?
  Ok(nil)
end

test("a late outbox snapshot cannot let old fanout crypto write into replacement custody") do
  case erased_fixture() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("fanout guards ratchet source changes even when the outbox has not changed") do
  case changed_source_fixture() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

from Storage.FanoutCommit import capture_fanout_snapshot, commit_fanout_snapshot

fn chunked_fixture() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("fanout_guard_chunks")?
  ensure_schema(path)?
  let profile = Bytes.from_utf8("sealed fanout custody")
  store_updated_blobs(path, ["profile/v1"], [profile])?
  let labels = for index in 0..75 do
    "guarded-source/v1/#{index}"
  end
  let before = capture_fanout_snapshot(path, profile, labels)?
  assert(List.length(before.bases) == 2)
  # Sources in the second chunk are mandatory too; no target may be omitted
  # merely because the first AccountBasis reached its64-row bound.
  store_updated_blobs(path, [List.get(labels, 74)], [Bytes.from_utf8("new source")])?
  assert(Result.is_err(commit_fanout_snapshot(path,
    before,
    [],
    [],
    Bytes.empty(),
    [],
    [],
    ["outbox-envelope/v1/test"],
    [Bytes.from_utf8("prepared envelope")],
    prepared(profile, Bytes.empty()))))
  assert(Result.is_err(load_blob(path, "outbox-envelope/v1/test")))
  let fresh = capture_fanout_snapshot(path, profile, labels)?
  commit_fanout_snapshot(path,
    fresh,
    [],
    [],
    Bytes.from_utf8("new ratchets"),
    [],
    [],
    ["outbox-envelope/v1/test"],
    [Bytes.from_utf8("prepared envelope")],
    prepared(profile, Bytes.empty()))?
  assert(Bytes.to_utf8(load_blob(path, "outbox-envelope/v1/test")?)? == "prepared envelope")
  assert(Result.is_err(capture_fanout_snapshot(path,
    profile,
    for index in 0..257 do
      "guarded-source/v1/#{index}"
    end)))
  erase_local_state(path)?
  File.delete(path)?
  Ok(nil)
end

test("bounded chunked fanout guards preserve every target beyond the first64 source rows") do
  case chunked_fixture() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

from Storage.FanoutCommit import commit_fanout_records

fn claim_fixture() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("fanout_claim_race")?
  ensure_schema(path)?
  let profile = Bytes.from_utf8("encrypted claimant profile")
  let label = "fanout-prekey-claim/v1/test"
  store_updated_blobs(path, ["profile/v1"], [profile])?
  let before = capture_fanout_snapshot(path, profile, [label])?
  let first = Bytes.from_utf8("sealed stable first reservation ID")
  commit_fanout_records(path, before, [label], [first], [])?
  assert(Result.is_err(commit_fanout_records(path,
    before,
    [label],
    [Bytes.from_utf8("different racing reservation ID")],
    [])))
  assert(Bytes.secure_equals(load_blob(path, label)?, first))
  let fresh = capture_fanout_snapshot(path, profile, [label])?
  assert(Result.is_err(commit_fanout_records(path, fresh, ["not-captured"], [first], [])))
  assert(Result.is_err(load_blob(path, "not-captured")))
  erase_local_state(path)?
  File.delete(path)?
  Ok(nil)
end

test("prekey writers preserve the first durable claim ID and cannot mutate unguarded rows") do
  case claim_fixture() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

from Storage.FanoutCommit import combine_fanout_snapshots

fn earlier_invitation_fixture() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("fanout_group_basis")?
  ensure_schema(path)?
  let profile = Bytes.from_utf8("encrypted group owner")
  store_updated_blobs(path,
    ["profile/v1", "group-invitations/v1"],
    [profile, Bytes.from_utf8("invitation state before crypto")])?
  let planned = capture_fanout_snapshot(path, profile, ["group-invitations/v1"])?
  store_updated_blobs(path,
    ["group-invitations/v1"],
    [Bytes.from_utf8("concurrent accepted invitation")])?
  let late = capture_fanout_snapshot(path, profile, ["group-invitations/v1"])?
  let combined = combine_fanout_snapshots(planned, late)?
  assert(Result.is_err(commit_fanout_snapshot(path,
    combined,
    [],
    [],
    Bytes.from_utf8("prepared session index"),
    ["group-invitations/v1"],
    [Bytes.from_utf8("obsolete planned invitation")],
    [],
    [],
    prepared(profile, Bytes.empty()))))
  assert(Bytes.to_utf8(load_blob(path,
    "group-invitations/v1")?)? == "concurrent accepted invitation")
  let current = capture_fanout_snapshot(path, profile, ["group-invitations/v1"])?
  commit_fanout_snapshot(path,
    combine_fanout_snapshots(current, current)?,
    [],
    [],
    Bytes.from_utf8("prepared session index"),
    ["group-invitations/v1"],
    [Bytes.from_utf8("fresh planned invitation")],
    [],
    [],
    prepared(profile, Bytes.empty()))?
  assert(Bytes.to_utf8(load_blob(path, "group-invitations/v1")?)? == "fresh planned invitation")
  erase_local_state(path)?
  File.delete(path)?
  Ok(nil)
end

test("a later ratchet snapshot cannot bless an obsolete prepared group invitation") do
  case earlier_invitation_fixture() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

fn missing_history_source(existing :: Bool) -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("fanout_missing_history_#{existing}")?
  ensure_schema(path)?
  let profile = Bytes.from_utf8("sealed history owner")
  let history = "history/v1/test"
  let winner = Bytes.from_utf8("concurrent history without expired entries")
  store_updated_blobs(path, ["profile/v1"], [profile])?
  if existing do
    store_updated_blobs(path, [history], [winner])?
  end
  # A new fanout may resolve its conversation only after source discovery.
  # The outbox and session sources cannot authorize an uncaptured history row.
  let before = load_account_basis(path, ["sessions/v1"])?
  assert(case commit(path, before, prepared(profile, Bytes.empty())) do
    Err("invalid_fanout_history_commit") -> true
    _ -> false
  end)
  if existing do
    assert(Bytes.secure_equals(load_blob(path, history)?, winner))
  else
    assert(Result.is_err(load_blob(path, history)))
  end
  assert(Result.is_err(load_blob(path, "sessions/v1")))
  assert(Result.is_err(load_blob(path, "outbox-envelope/v1/test")))
  erase_local_state(path)?
  File.delete(path)?
  Ok(nil)
end

test("fanout cannot resurrect compacted history whose source was not captured") do
  case missing_history_source(true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("fanout must capture history absence before creating its first row") do
  case missing_history_source(false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
