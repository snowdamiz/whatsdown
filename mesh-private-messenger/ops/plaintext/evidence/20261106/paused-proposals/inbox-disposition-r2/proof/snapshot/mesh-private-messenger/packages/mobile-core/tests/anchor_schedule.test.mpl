from Mobile.AnchorSchedule import (
  AnchorClaim,
  AnchorSchedule,
  claim_anchor_check,
  finish_anchor_check,
  finish_anchor_check_with_blobs,
  load_anchor_schedule
)
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import platform_key
from Storage.Records import compare_and_swap_blobs, store_updated_session
from Tests.Support import database_path, repeated

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

fn required(claim :: Option<AnchorClaim>) -> AnchorClaim!String do
  case claim do
    Some(value) -> Ok(value)
    None -> Err("missing scheduled claim")
  end
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("anchor-schedule")?
  ensure_schema(path)?
  let identity = repeated(1, 32)?
  let first = required(claim_anchor_check(path, key, identity, wide("1000")?, false)?)?
  assert(Bytes.length(first.token) == 16)
  assert(claim_anchor_check(path, key, identity, wide("1001")?, true)? == None)
  # Each call opens the database again: in-flight reservations survive restart.
  assert(claim_anchor_check(path, key, identity, wide("3600999")?, false)? == None)
  finish_anchor_check(path, key, first, wide("1002")?, false, Bytes.from_utf8("observed"))?
  let state = load_anchor_schedule(path, key, identity)?
  assert(Bytes.to_utf8(state.last_result)? == "observed")
  assert(U64.to_string(state.next_daily) == "86401002")
  assert(claim_anchor_check(path, key, identity, wide("3601000")?, false)? == None)
  let changed = required(claim_anchor_check(path, key, identity, wide("3601000")?, true)?)?
  assert(!Bytes.secure_equals(changed.token, first.token))
  case finish_anchor_check(path,
    key,
    first,
    wide("3601001")?,
    false,
    Bytes.from_utf8("stale completion")) do
    Err(error) -> assert(error == "anchor_claim_superseded")
    Ok(_) -> assert(false)
  end
  finish_anchor_check(path, key, changed, wide("3601002")?, true, Bytes.from_utf8("unavailable"))?
  assert(claim_anchor_check(path, key, identity, wide("7200999")?, false)? == None)
  let retry = required(claim_anchor_check(path, key, identity, wide("7201000")?, false)?)?
  finish_anchor_check(path, key, retry, wide("7201001")?, false, Bytes.from_utf8("observed"))?
  assert(claim_anchor_check(path, key, identity, wide("93601000")?, false)? == None)
  let daily = required(claim_anchor_check(path, key, identity, wide("93601001")?, false)?)?
  # A clock rollback never authorizes extra network reads or a false completion.
  assert(claim_anchor_check(path, key, identity, wide("1")?, true)? == None)
  case finish_anchor_check(path, key, daily, wide("1")?, false, Bytes.empty()) do
    Err(error) -> assert(error == "invalid_anchor_clock")
    Ok(_) -> assert(false)
  end
  # New native trust pins require a new observation; old replies cannot overwrite it.
  let next = required(claim_anchor_check(path, key, repeated(2, 32)?, wide("93601002")?, false)?)?
  case finish_anchor_check(path, key, daily, wide("93601003")?, false, Bytes.empty()) do
    Err(error) -> assert(error == "anchor_claim_superseded")
    Ok(_) -> assert(false)
  end
  let blob = load_blob(path, "anchor-schedule/v1")?
  assert(!Bytes.secure_equals(blob, Bytes.from_utf8("observed")))
  case claim_anchor_check(path, key, repeated(3, 32)?, wide("18446744073709551615")?, true) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  assert(Bytes.secure_equals(blob, load_blob(path, "anchor-schedule/v1")?))
  finish_anchor_check(path, key, next, wide("93601003")?, false, Bytes.from_utf8("latest"))?
  assert(Bytes.to_utf8(load_anchor_schedule(path, key, repeated(2, 32)?)?.last_result)? == "latest")
  File.delete(path)?
  Ok(true)
end

test("durable anchor claims enforce daily cadence, hourly key-change limits and stale-completion fencing") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn concurrent_claim(path :: String, now :: U64) -> Option<AnchorClaim>!String do
  let key = platform_key()?
  claim_anchor_check(path, key, repeated(9, 32)?, now, true)
end

fn race(path :: String, now :: U64) -> AnchorClaim!String do
  let attempts = Job.map([0, 1, 2, 3, 4, 5, 6, 7], fn(_index) do concurrent_claim(path, now) end)
  let claims = for attempt in attempts do
    attempt??
  end
  let winners = List.filter(claims, fn(value) do value != None end)
  assert(List.length(winners) == 1)
  required(List.head(winners))
end

fn concurrent_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("anchor-race")?
  ensure_schema(path)?
  let first = race(path, wide("1000")?)?
  # The winning actor disappears without completing its check. A replacement
  # cannot start before its hour, and only one replacement wins at the boundary.
  assert(concurrent_claim(path, wide("3600999")?)? == None)
  let next = race(path, wide("3601000")?)?
  case finish_anchor_check(path, key, first, wide("3601001")?, false, Bytes.empty()) do
    Err(error) -> assert(error == "anchor_claim_superseded")
    Ok(_) -> assert(false)
  end
  finish_anchor_check(path, key, next, wide("3601001")?, false, repeated(7, 4096)?)?
  assert(Bytes.length(load_anchor_schedule(path, key, repeated(9, 32)?)?.last_result) == 4096)
  let with_previous = required(claim_anchor_check(path,
    key,
    repeated(9, 32)?,
    wide("7201000")?,
    true)?)?
  assert(Bytes.length(load_anchor_schedule(path, key, repeated(9, 32)?)?.last_result) == 4096)
  finish_anchor_check(path, key, with_previous, wide("7201001")?, false, Bytes.empty())?
  File.delete(path)?
  Ok(true)
end

test("simultaneous callers and crashed checks share one durable hourly reservation") do
  case concurrent_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn failure_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("anchor-storage-errors")?
  ensure_schema(path)?
  let identity = repeated(8, 32)?
  # A failed durable insert never authorizes work.
  let db = Sqlite.open(path)?
  Sqlite.execute(db,
    "CREATE TRIGGER refuse_anchor BEFORE INSERT ON encrypted_blobs BEGIN SELECT RAISE(ABORT, 'fixture'); END",
    [])?
  Sqlite.close(db)
  case claim_anchor_check(path, key, identity, wide("1000")?, false) do
    Err(error) -> assert(error == "database_write_failed")
    Ok(_) -> assert(false)
  end
  let db2 = Sqlite.open(path)?
  Sqlite.execute(db2, "DROP TRIGGER refuse_anchor", [])?
  Sqlite.close(db2)
  let claim = required(claim_anchor_check(path, key, identity, wide("1000")?, false)?)?
  let original = load_blob(path, "anchor-schedule/v1")?
  let atomic_db = Sqlite.open(path)?
  Sqlite.execute(atomic_db,
    "CREATE TRIGGER refuse_evidence BEFORE INSERT ON encrypted_blobs BEGIN SELECT RAISE(ABORT, 'fixture'); END",
    [])?
  Sqlite.close(atomic_db)
  case finish_anchor_check_with_blobs(path,
    key,
    claim,
    wide("1001")?,
    true,
    Bytes.from_utf8("mismatch"),
    ["anchor-evidence/v1"],
    [Bytes.from_utf8("evidence")]) do
    Err(error) -> assert(error == "database_write_failed")
    Ok(_) -> assert(false)
  end
  assert(Bytes.secure_equals(original, load_blob(path, "anchor-schedule/v1")?))
  let atomic_db2 = Sqlite.open(path)?
  Sqlite.execute(atomic_db2, "DROP TRIGGER refuse_evidence", [])?
  Sqlite.close(atomic_db2)
  case finish_anchor_check(path, key, claim, wide("1001")?, false, repeated(0, 4097)?) do
    Err(error) -> assert(error == "invalid_anchor_schedule")
    Ok(_) -> assert(false)
  end
  assert(Bytes.secure_equals(original, load_blob(path, "anchor-schedule/v1")?))
  # A failed absent-value CAS rolls back its other writes as well.
  case compare_and_swap_blobs(path,
    ["anchor-schedule/v1", "must-not-exist"],
    [Bytes.from_utf8("replacement"), Bytes.from_utf8("partial")],
    Bytes.empty()) do
    Err(error) -> assert(error == "local_state_changed")
    Ok(_) -> assert(false)
  end
  case load_blob(path, "must-not-exist") do
    Err(error) -> assert(error == "local_state_not_found")
    Ok(_) -> assert(false)
  end
  # Corruption must never silently reset the rate limit, even after pin changes.
  store_updated_session(path, "anchor-schedule/v1", Bytes.from_utf8("corrupted"))?
  for candidate in [identity, repeated(4, 32)?] do
    case claim_anchor_check(path, key, candidate, wide("3601000")?, true) do
      Err(_) -> nil
      Ok(_) -> assert(false)
    end
  end
  assert(Bytes.to_utf8(load_blob(path, "anchor-schedule/v1")?)? == "corrupted")
  File.delete(path)?
  Ok(true)
end

test("storage errors and corrupt sealed schedules fail closed without partial writes") do
  case failure_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
