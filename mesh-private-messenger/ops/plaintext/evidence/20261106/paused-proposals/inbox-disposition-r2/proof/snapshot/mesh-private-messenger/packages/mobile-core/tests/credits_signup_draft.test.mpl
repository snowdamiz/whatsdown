from Storage.Blobs import blob_record_hash
import File
from MobileCore import register_request_export
from Mobile.Account import create_account, create_signup_draft_account
from Mobile.SignupDraft import signup_draft_state, require_free_registration_allowed
from Mobile.Profile import load_profile
from Mobile.Types import MobileAccountRequest
from Storage.Blobs import load_blob, ensure_schema
from Tests.Support import database_path

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("signup_draft")?
  let request = MobileAccountRequest {
    database_path: Bytes.from_utf8(path),
    username: Bytes.from_utf8("paid-draft")
  }
  let profile = create_signup_draft_account(request)?
  assert(Bytes.secure_equals(load_profile(path)?, profile))
  assert(signup_draft_state(path)? == 1)
  assert(Result.is_err(require_free_registration_allowed(path)))
  case register_request_export(Bytes.from_utf8(path)) do
    Err(error) -> assert(error == "paid_signup_draft_pending")
    Ok(_) -> return Err("native free registration bypassed the paid draft")
  end
  let marker = load_blob(path, "signup-draft/v1")?
  assert(Bytes.length(marker) > 85)
  # Neither another draft nor the legacy creation path may overwrite a funded
  # draft's account or durable intent during a concurrent/restarted onboarding.
  assert(Result.is_err(create_account(request)))
  assert(Result.is_err(create_signup_draft_account(request)))
  assert(Bytes.secure_equals(load_blob(path, "signup-draft/v1")?, marker))
  assert(Bytes.secure_equals(load_profile(path)?, profile))
  let free_path = database_path("signup_free")?
  create_account(%{request | database_path: Bytes.from_utf8(free_path)})?
  assert(signup_draft_state(free_path)? == 0)
  require_free_registration_allowed(free_path)?
  let failing_path = database_path("signup_atomic_failure")?
  ensure_schema(failing_path)?
  let database = case Sqlite.open(failing_path) do
    Err(_) -> return Err("test database failed")
    Ok(value) -> value
  end
  let marker_hash = blob_record_hash(database, "signup-draft/v1")?
  case Sqlite.execute(database,
    "CREATE TRIGGER fail_signup_marker BEFORE INSERT ON encrypted_blobs WHEN NEW.record_hash = '"
      <> marker_hash
      <> "' BEGIN SELECT RAISE(ABORT, 'test draft failure'); END",
    []) do
    Err(_) -> return Err("test trigger failed")
    Ok(_) -> nil
  end
  Sqlite.close(database)
  assert(Result.is_err(create_signup_draft_account(%{request |
    database_path: Bytes.from_utf8(failing_path)
  })))
  assert(Result.is_err(load_profile(failing_path)))
  assert(Result.is_err(load_blob(failing_path, "account-signing-key/v1")))
  File.delete(failing_path)?
  File.delete(path)?
  File.delete(free_path)?
  Ok(true)
end

test("paid signup draft identity and registration intent are committed together without changing free creation") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
