from Storage.TransparencyCommit import commit_transparency_cache
from Storage.Blobs import ensure_schema, load_blob
from Storage.Records import store_blobs, erase_local_state
from Tests.Support import database_path

fn fixture() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("transparency_commit")?
  ensure_schema(path)?
  let profile = Bytes.from_utf8("sealed original profile")
  let first = Bytes.from_utf8("sealed checkpoint one")
  let second = Bytes.from_utf8("sealed checkpoint two")
  store_blobs(path, ["profile/v1"], [profile])?
  commit_transparency_cache(path,
    profile,
    Bytes.empty(),
    ["transparency-checkpoint/v1", "transparency-view/v1"],
    [first, first])?
  assert(Bytes.secure_equals(load_blob(path, "transparency-checkpoint/v1")?, first))
  # An exact checkpoint basis can be refreshed repeatedly without rollback.
  commit_transparency_cache(path,
    profile,
    first,
    ["transparency-checkpoint/v1", "transparency-view/v1"],
    [first, first])?
  # A second first-lookup writer cannot overwrite the winner.
  assert(Result.is_err(commit_transparency_cache(path,
    profile,
    Bytes.empty(),
    ["transparency-checkpoint/v1", "transparency-view/v1"],
    [second, second])))
  assert(Bytes.secure_equals(load_blob(path, "transparency-view/v1")?, first))
  commit_transparency_cache(path,
    profile,
    first,
    ["transparency-checkpoint/v1", "transparency-view/v1"],
    [second, second])?
  assert(Result.is_err(commit_transparency_cache(path,
    profile,
    first,
    ["transparency-checkpoint/v1", "transparency-view/v1"],
    [first, first])))
  assert(Bytes.secure_equals(load_blob(path, "transparency-checkpoint/v1")?, second))
  # A late first lookup must not recreate state after account erasure.
  erase_local_state(path)?
  assert(Result.is_err(commit_transparency_cache(path,
    profile,
    Bytes.empty(),
    ["transparency-checkpoint/v1"],
    [first])))
  assert(Result.is_err(load_blob(path, "transparency-checkpoint/v1")))
  store_blobs(path, ["profile/v1"], [Bytes.from_utf8("sealed replacement profile")])?
  assert(Result.is_err(commit_transparency_cache(path,
    profile,
    Bytes.empty(),
    ["transparency-checkpoint/v1"],
    [first])))
  assert(Result.is_err(load_blob(path, "transparency-checkpoint/v1")))
  erase_local_state(path)?
  # Preprofile admission is a distinct absent-profile basis, never an erased
  # owned profile. Creating an account invalidates that basis atomically.
  commit_transparency_cache(path,
    Bytes.empty(),
    Bytes.empty(),
    ["transparency-checkpoint/v1"],
    [first])?
  store_blobs(path, ["profile/v1"], [profile])?
  assert(Result.is_err(commit_transparency_cache(path,
    Bytes.empty(),
    first,
    ["transparency-checkpoint/v1"],
    [second])))
  assert(Bytes.secure_equals(load_blob(path, "transparency-checkpoint/v1")?, first))
  erase_local_state(path)?
  File.delete(path)?
  Ok(nil)
end

test("transparency commit fences profile replacement and obsolete checkpoint bases atomically") do
  assert(Result.is_ok(fixture()))
end

fn await_file(path :: String, attempts :: Int) -> Bool do
  if File.exists(path) do
    case File.read(path) do
      Ok(value) -> if String.length(value) > 0 do
        return true
      end
      Err(_) -> nil
    end
  end
  if attempts == 0 do
    false
  else
    Timer.sleep(5)
    await_file(path, attempts - 1)
  end
end

actor contender(path :: String, profile :: Bytes, index :: Int) do
  let name = path <> ".#{index}"
  File.write(name <> ".ready", "ready")
  if await_file(path <> ".go", 1000) do
    let checkpoint = Bytes.from_utf8("sealed checkpoint #{index}")
    let result = commit_transparency_cache(path,
      profile,
      Bytes.empty(),
      ["transparency-checkpoint/v1", "transparency-view/v1"],
      [checkpoint, checkpoint])
    File.write(name <> ".done",
      case result do
        Ok(_) -> "ok"
        Err(error) -> error
      end)
  end
end

fn concurrent() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("transparency_race")?
  ensure_schema(path)?
  let profile = Bytes.from_utf8("sealed original profile")
  store_blobs(path, ["profile/v1"], [profile])?
  for index in 0..8 do
    let _worker = spawn(contender, path, profile, index)
    nil
  end
  for index in 0..8 do
    assert(await_file(path <> ".#{index}.ready", 1000))
  end
  File.write(path <> ".go", "go")?
  let results = for index in 0..8 do
    let name = path <> ".#{index}"
    assert(await_file(name <> ".done", 1000))
    let result = File.read(name <> ".done")?
    File.delete(name <> ".ready")?
    File.delete(name <> ".done")?
    result
  end
  assert(List.length(List.filter(results, fn(value) -> value == "ok" end)) == 1)
  assert(List.all(results, fn(value) -> value == "ok" || value == "transparency_state_changed" end))
  assert(Bytes.secure_equals(load_blob(path, "transparency-checkpoint/v1")?,
    load_blob(path, "transparency-view/v1")?))
  File.delete(path <> ".go")?
  erase_local_state(path)?
  File.delete(path)?
  Ok(nil)
end

test("eight concurrent first lookups commit exactly one consistent cache bundle") do
  case concurrent() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
