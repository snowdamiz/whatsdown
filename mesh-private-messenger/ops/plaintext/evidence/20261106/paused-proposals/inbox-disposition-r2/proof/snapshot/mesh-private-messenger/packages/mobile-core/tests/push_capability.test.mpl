from MobileCore import create_account_export, erase_account_export
from Mobile.PushNetwork import (
  native_push_begin,
  native_push_intent,
  native_push_complete,
  native_push_validate
)
from Tests.PushNetworkSupport import fields, intent, complete, config
from Tests.Support import database_path
from Mobile.Codec import mobile_byte

fn old_intent() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  config(20632)?
  let path = database_path("push_bound_intent")?
  let original = create_account_export(fields([Bytes.from_utf8(path), Bytes.from_utf8("alice")])?)?
  erase_account_export(Bytes.from_utf8(path))?
  let replacement = create_account_export(fields([Bytes.from_utf8(path), Bytes.from_utf8("bob")])?)?
  let before = native_push_intent(intent(path, 0)?)?
  assert(Result.is_err(native_push_begin(fields([
    Bytes.from_utf8(path),
    original,
    mobile_byte(1)?
  ])?)))
  assert(Bytes.secure_equals(before, native_push_intent(intent(path, 0)?)?))
  let permission = native_push_begin(fields([
    Bytes.from_utf8(path),
    replacement,
    mobile_byte(1)?
  ])?)?
  assert(Bytes.get(permission, 4)? == 1)
  erase_account_export(Bytes.from_utf8(path))?
  Ok(nil)
end

test("queued push intent cannot cross account replacement") do
  case old_intent() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

fn stale_platform_action() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  config(20632)?
  let path = database_path("push_platform_fence")?
  create_account_export(fields([Bytes.from_utf8(path), Bytes.from_utf8("alice")])?)?
  let permission = native_push_intent(intent(path, 1)?)?
  let prime = native_push_complete(complete(path, permission, 0)?)?
  assert(Bytes.get(native_push_validate(fields([Bytes.from_utf8(path), prime])?)?, 0)? == 2)
  let clear = native_push_intent(intent(path, 2)?)?
  assert(Result.is_err(native_push_validate(fields([Bytes.from_utf8(path), prime])?)))
  assert(Bytes.get(native_push_validate(fields([Bytes.from_utf8(path), clear])?)?, 0)? == 5)
  erase_account_export(Bytes.from_utf8(path))?
  create_account_export(fields([Bytes.from_utf8(path), Bytes.from_utf8("bob")])?)?
  assert(Result.is_err(native_push_validate(fields([Bytes.from_utf8(path), clear])?)))
  erase_account_export(Bytes.from_utf8(path))?
  Ok(nil)
end

test("platform work requires the exact current account and push ticket") do
  case stale_platform_action() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

fn invalid_platform_actions() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  config(20632)?
  let path = database_path("push_invalid_platform")?
  let profile = create_account_export(fields([Bytes.from_utf8(path), Bytes.from_utf8("alice")])?)?
  let permission = native_push_begin(fields([Bytes.from_utf8(path), profile, mobile_byte(1)?])?)?
  assert(Result.is_err(native_push_validate(fields([Bytes.from_utf8(path), permission])?)))
  let prime = native_push_complete(complete(path, permission, 0)?)?
  let bad = Bytes.concat(Bytes.slice(prime, 0, 49)?,
    mobile_byte((Bytes.get(prime, 49)? + 1) % 256)?)?
  assert(Result.is_err(native_push_validate(fields([Bytes.from_utf8(path), bad])?)))
  assert(Result.is_err(native_push_begin(fields([
    Bytes.from_utf8(path),
    profile,
    mobile_byte(3)?
  ])?)))
  assert(Result.is_err(native_push_begin(fields([Bytes.from_utf8(path), profile, Bytes.empty()])?)))
  assert(Bytes.secure_equals(prime, native_push_intent(intent(path, 0)?)?))
  erase_account_export(Bytes.from_utf8(path))?
  Ok(nil)
end

test("platform validation rejects wrong kinds and forged frames without mutation") do
  case invalid_platform_actions() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
