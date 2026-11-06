from Storage.AccountGuard import (
  AccountBasis,
  load_account_basis,
  commit_account_changes,
  erase_account_if_current
)
from Storage.Blobs import ensure_schema, load_blob
from Storage.Records import store_updated_blobs, erase_local_state
from Tests.Support import database_path

fn refuses_old_delete() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("account-guard-replacement-delete")?
  ensure_schema(path)?
  store_updated_blobs(path,
    ["profile/v1", "prekey-bundles/v1"],
    [Bytes.from_utf8("old sealed profile"), Bytes.from_utf8("old sealed bundles")])?
  let before = load_account_basis(path, ["prekey-bundles/v1"])?
  erase_local_state(path)?
  let replacement = Bytes.from_utf8("new sealed profile")
  store_updated_blobs(path,
    ["profile/v1", "new-account-secret"],
    [replacement, Bytes.from_utf8("new account custody")])?
  assert(case erase_account_if_current(path, before.profile) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(load_blob(path, "profile/v1")?, replacement))
  assert(Bytes.to_utf8(load_blob(path, "new-account-secret")?)? == "new account custody")
  Ok(nil)
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
  if attempts <= 0 do
    false
  else
    Timer.sleep(5)
    await_file(path, attempts - 1)
  end
end

actor account_contender(path :: String, before :: AccountBasis, index :: Int) do
  let name = path <> ".#{index}"
  File.write(name <> ".ready", "ready")
  if await_file(path <> ".go", 1000) do
    let value = Bytes.from_utf8("sealed generation #{index}")
    let result = commit_account_changes(path,
      before,
      ["prekey-bundles/v1", "renewal-request/v1"],
      [value, value],
      [])
    File.write(name <> ".done",
      case result do
        Ok(_) -> "ok"
        Err(error) -> error
      end)
  end
end

fn concurrent_proof() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("account_renewal_writers")?
  ensure_schema(path)?
  let first = Bytes.from_utf8("sealed first generation")
  store_updated_blobs(path,
    ["profile/v1", "prekey-bundles/v1", "renewal-request/v1"],
    [Bytes.from_utf8("sealed account custody"), first, first])?
  let before = load_account_basis(path, ["prekey-bundles/v1", "renewal-request/v1"])?
  for index in 0..8 do
    let _writer = spawn(account_contender, path, before, index)
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
  assert(List.all(results, fn(value) -> value == "ok" || value == "account_state_changed" end))
  assert(Bytes.secure_equals(load_blob(path, "prekey-bundles/v1")?,
    load_blob(path, "renewal-request/v1")?))
  let fresh = load_account_basis(path, ["prekey-bundles/v1", "renewal-request/v1"])?
  commit_account_changes(path, fresh, ["prekey-bundles/v1"], [first], ["renewal-request/v1"])?
  assert(Bytes.secure_equals(load_blob(path, "prekey-bundles/v1")?, first))
  assert(Result.is_err(load_blob(path, "renewal-request/v1")))
  File.delete(path <> ".go")?
  erase_local_state(path)?
  Ok(nil)
end

test("eight renewal writers commit exactly one coherent generation and a fresh guarded update succeeds") do
  case concurrent_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("a delayed deletion cannot erase a replacement account") do
  case refuses_old_delete() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

fn refuses_stale_renewal() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("account-guard-stale-renewal")?
  ensure_schema(path)?
  let profile = Bytes.from_utf8("sealed profile")
  store_updated_blobs(path,
    ["profile/v1", "prekey-bundles/v1"],
    [profile, Bytes.from_utf8("first pending bundle")])?
  let before = load_account_basis(path, ["prekey-bundles/v1", "renewal-request/v1"])?
  let winner = Bytes.from_utf8("newer pending bundle")
  store_updated_blobs(path, ["prekey-bundles/v1"], [winner])?
  assert(case commit_account_changes(path,
    before,
    ["prekey-bundles/v1", "new-signed-key"],
    [Bytes.from_utf8("stale bundle"), Bytes.from_utf8("stale key")],
    []) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(load_blob(path, "prekey-bundles/v1")?, winner))
  assert(case load_blob(path, "new-signed-key") do
    Err("local_state_not_found") -> true
    _ -> false
  end)
  erase_local_state(path)?
  assert(case commit_account_changes(path,
    before,
    ["prekey-bundles/v1"],
    [Bytes.from_utf8("resurrected")],
    []) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(case load_blob(path, "prekey-bundles/v1") do
    Err("local_state_not_found") -> true
    _ -> false
  end)
  Ok(nil)
end

test("stale renewal state cannot overwrite a winner or revive erased custody") do
  case refuses_stale_renewal() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
