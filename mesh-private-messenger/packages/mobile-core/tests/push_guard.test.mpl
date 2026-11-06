from MobileCore import create_account_export, erase_account_export
from Storage.Blobs import load_blob
from Storage.PushGuard import load_push_basis, commit_push_basis
from Storage.Records import store_updated_session
from Tests.Support import database_path, vector, append

fn stale_state() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("push_stale_state")?
  create_account_export(append(vector(Bytes.from_utf8(path))?, vector(Bytes.from_utf8("alice"))?)?)?
  store_updated_session(path, "push-binding/v1", Bytes.from_utf8("old sealed state"))?
  let before = load_push_basis(path)?
  let winner = Bytes.from_utf8("newer disable intent")
  store_updated_session(path, "push-binding/v1", winner)?
  assert(Result.is_err(commit_push_basis(path,
    before,
    Bytes.from_utf8("late bind acknowledgement"))))
  assert(Bytes.secure_equals(load_blob(path, "push-binding/v1")?, winner))
  erase_account_export(Bytes.from_utf8(path))?
  Ok(nil)
end

fn replaced_account() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("push_replaced_account")?
  create_account_export(append(vector(Bytes.from_utf8(path))?, vector(Bytes.from_utf8("alice"))?)?)?
  let before = load_push_basis(path)?
  erase_account_export(Bytes.from_utf8(path))?
  create_account_export(append(vector(Bytes.from_utf8(path))?, vector(Bytes.from_utf8("alice"))?)?)?
  let current = load_push_basis(path)?
  assert(Result.is_err(commit_push_basis(path, before, Bytes.from_utf8("old account binding"))))
  assert(Result.is_err(load_blob(path, "push-binding/v1")))
  assert(Bytes.secure_equals(load_push_basis(path)?.profile, current.profile))
  erase_account_export(Bytes.from_utf8(path))?
  Ok(nil)
end

fn first_writer() -> Result<(), String> do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("push_first_writer")?
  create_account_export(append(vector(Bytes.from_utf8(path))?, vector(Bytes.from_utf8("alice"))?)?)?
  let before = load_push_basis(path)?
  let winner = Bytes.from_utf8("first permission intent")
  commit_push_basis(path, before, winner)?
  assert(Result.is_err(commit_push_basis(path, before, Bytes.from_utf8("stale permission intent"))))
  assert(Bytes.secure_equals(load_blob(path, "push-binding/v1")?, winner))
  erase_account_export(Bytes.from_utf8(path))?
  Ok(nil)
end

test("a late push acknowledgement cannot replace a newer intent") do
  case stale_state() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("a push completion cannot write into a replacement account") do
  case replaced_account() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("concurrent first push intents have one winner") do
  case first_writer() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
