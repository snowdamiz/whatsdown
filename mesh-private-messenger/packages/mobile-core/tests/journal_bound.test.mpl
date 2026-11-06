from Mobile.JournalBound import (
  native_journal_load,
  native_journal_save,
  prepare_journal_write,
  commit_journal_write
)
from MobileCore import create_account_export, erase_account_export
from Mobile.Profile import load_profile
from Tests.GroupLifecycleWire import group_vectors
from Tests.Support import database_path, repeated

fn create(path :: String) -> Bytes!String do
  create_account_export(group_vectors([Bytes.from_utf8(path), Bytes.from_utf8("alice")])?)
end

fn read_request(path :: String, profile :: Bytes) -> Bytes!String do
  group_vectors([Bytes.from_utf8(path), profile, Bytes.from_utf8("read-state/index")])
end

fn write_request(path :: String, profile :: Bytes, data :: Bytes) -> Bytes!String do
  group_vectors([Bytes.from_utf8(path), profile, Bytes.from_utf8("read-state/index"), data])
end

fn replacement_proof() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("bound-journal-replacement")?
  let old = create(path)?
  let value = Bytes.from_utf8("old journal")
  native_journal_save(write_request(path, old, value)?)?
  erase_account_export(Bytes.from_utf8(path))?
  let next = create(path)?
  let winner = Bytes.from_utf8("replacement journal")
  native_journal_save(write_request(path, next, winner)?)?
  assert(case native_journal_load(read_request(path, old)?) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(case native_journal_save(write_request(path, old, value)?) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(native_journal_load(read_request(path, next)?)?, winner))
  assert(Bytes.secure_equals(load_profile(path)?, next))
  File.delete(path)?
  Ok(nil)
end

fn delayed_proof(replacement :: Bool) -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("bound-journal-delayed")?
  let old = create(path)?
  let pending = prepare_journal_write(write_request(path, old, Bytes.from_utf8("stale writer"))?)?
  let deletion = prepare_journal_write(write_request(path, old, Bytes.from_hex("00")?)?)?
  let next = if replacement do
    erase_account_export(Bytes.from_utf8(path))?
    create(path)?
  else
    old
  end
  let winner = repeated(91, 262144)?
  native_journal_save(write_request(path, next, winner)?)?
  assert(case commit_journal_write(pending) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(case commit_journal_write(deletion) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(native_journal_load(read_request(path, next)?)?, winner))
  native_journal_save(write_request(path, next, Bytes.from_hex("00")?)?)?
  assert(Bytes.length(native_journal_load(read_request(path, next)?)?) == 0)
  File.delete(path)?
  Ok(nil)
end

test("queued journal reads and writes reject a replacement account") do
  case replacement_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("sealed journal plans cannot overwrite or delete a replacement account") do
  case delayed_proof(true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("only one journal writer can commit against the same stored record") do
  case delayed_proof(false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

fn malformed_proof() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("bound-journal-malformed")?
  let profile = create(path)?
  let good = write_request(path, profile, Bytes.from_utf8("preserved"))?
  native_journal_save(good)?
  for request in [
    Bytes.empty(),
    Bytes.concat(good, Bytes.from_hex("00")?)?,
    group_vectors([
      Bytes.from_utf8(path),
      profile,
      Bytes.from_utf8("profile/v1"),
      Bytes.from_utf8("bad")
    ])?,
    group_vectors([
      Bytes.from_utf8(path),
      profile,
      Bytes.from_utf8("read-state/index"),
      Bytes.empty()
    ])?,
    group_vectors([
      Bytes.from_utf8(path),
      profile,
      Bytes.from_utf8("read-state/index"),
      repeated(91, 262145)?
    ])?
  ] do
    assert(Result.is_err(native_journal_save(request)))
    assert(Bytes.to_utf8(native_journal_load(read_request(path, profile)?)?)? == "preserved")
    assert(Bytes.secure_equals(load_profile(path)?, profile))
  end
  let absent = group_vectors([
    Bytes.from_utf8(path),
    profile,
    Bytes.from_utf8("receipt-marks/index")
  ])?
  assert(Bytes.length(native_journal_load(absent)?) == 0)
  assert(Result.is_err(native_journal_load(Bytes.concat(absent, Bytes.from_hex("00")?)?)))
  File.delete(path)?
  Ok(nil)
end

test("malformed journal actions preserve both account and existing record") do
  case malformed_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

fn preference_proof() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("bound-journal-preferences")?
  let profile = create(path)?
  for pair in [
    ["preferences/read-receipts", "off"],
    ["preferences/notification-preview", "none"]
  ] do
    let key = Bytes.from_utf8(List.head(pair))
    let value = Bytes.from_utf8(List.get(pair, 1))
    native_journal_save(group_vectors([Bytes.from_utf8(path), profile, key, value])?)?
    assert(Bytes.secure_equals(native_journal_load(group_vectors([
        Bytes.from_utf8(path),
        profile,
        key
      ])?)?,
      value))
    assert(case native_journal_save(group_vectors([
      Bytes.from_utf8(path),
      profile,
      key,
      Bytes.from_utf8("unknown")
    ])?) do
      Err("invalid_journal_preference") -> true
      _ -> false
    end)
    assert(Bytes.secure_equals(native_journal_load(group_vectors([
        Bytes.from_utf8(path),
        profile,
        key
      ])?)?,
      value))
  end
  File.delete(path)?
  Ok(nil)
end

test("read-receipt and notification-preview preferences are account-bound sealed values with a fixed vocabulary") do
  case preference_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

fn desktop_notification_preference_proof(replace_account :: Bool) -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("desktop-notifications")?
  let profile = create(path)?
  let key = Bytes.from_utf8("preferences/desktop-notifications")
  let off = Bytes.from_utf8("off")
  let on = Bytes.from_utf8("on")
  let read = group_vectors([Bytes.from_utf8(path), profile, key])?
  assert(Bytes.length(native_journal_load(read)?) == 0)
  native_journal_save(group_vectors([Bytes.from_utf8(path), profile, key, on])?)?
  assert(Bytes.secure_equals(native_journal_load(read)?, on))
  assert(case native_journal_save(group_vectors([
    Bytes.from_utf8(path),
    profile,
    key,
    Bytes.from_utf8("granted")
  ])?) do
    Err("invalid_journal_preference") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(native_journal_load(read)?, on))
  let pending = prepare_journal_write(group_vectors([Bytes.from_utf8(path), profile, key, on])?)?
  let next = if replace_account do
    erase_account_export(Bytes.from_utf8(path))?
    let replacement = create(path)?
    assert(Bytes.length(native_journal_load(group_vectors([
      Bytes.from_utf8(path),
      replacement,
      key
    ])?)?) == 0)
    replacement
  else
    profile
  end
  native_journal_save(group_vectors([Bytes.from_utf8(path), next, key, off])?)?
  assert(case commit_journal_write(pending) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(native_journal_load(group_vectors([
      Bytes.from_utf8(path),
      next,
      key
    ])?)?,
    off))
  println("DESKTOP_NOTIFICATION_PREFERENCE_COMPLETE")
  File.delete(path)?
  Ok(nil)
end

test("desktop notification opt-in is sealed and cannot overwrite a later disable or replacement account") do
  case desktop_notification_preference_proof(false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
  case desktop_notification_preference_proof(true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
