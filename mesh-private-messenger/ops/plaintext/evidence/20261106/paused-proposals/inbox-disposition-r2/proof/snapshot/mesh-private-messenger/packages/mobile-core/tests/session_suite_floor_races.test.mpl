from Mobile.SessionPolicy import (
  NativeSessionPolicy,
  capture_native_session_policy,
  native_session_minimum,
  require_current_session_policy
)
from Storage.AccountGuard import load_account_basis
from Storage.FanoutCommit import (
  FanoutSnapshot,
  capture_fanout_snapshot,
  commit_fanout_snapshot_at_policy
)
from Storage.OutboxGuard import OutboxBasis, PreparedOutboxIndex
from Storage.Blobs import ensure_schema, load_blob
from Storage.Records import store_updated_blobs, erase_local_state
from Tests.Support import database_path
import File

fn bare_frame() -> Bytes do
  Bytes.from_utf8(String.join([
      "1",
      String.repeat("11", 32),
      String.repeat("01", 32),
      String.repeat("02", 32),
      "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
      "1"
    ],
    "\n"))
end

fn with_minimum(minimum :: Int) -> Bytes!String do
  Ok(Bytes.from_utf8("6\n#{minimum}\n" <> Bytes.to_utf8(bare_frame())?))
end

fn installed(frame :: Bytes) -> Unit!String do
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), frame))
  Ok(nil)
end

fn prepared(profile :: Bytes) -> PreparedOutboxIndex do
  PreparedOutboxIndex {
    value: Bytes.from_utf8("prepared sealed outbox index"),
    before: OutboxBasis {
      profile: profile,
      index: Bytes.empty(),
      postage: Bytes.empty(),
      delivery: Bytes.empty()
    }
  }
end

fn commit(path :: String,
  before :: FanoutSnapshot,
  policy :: NativeSessionPolicy,
  outbox_profile :: Bytes) -> Unit!String do
  commit_fanout_snapshot_at_policy(path,
    before,
    policy,
    [],
    [],
    Bytes.from_utf8("prepared sealed session index"),
    ["history/v1/test"],
    [Bytes.from_utf8("prepared sealed history")],
    ["outbox-envelope/v1/test"],
    [Bytes.from_utf8("prepared sealed envelope")],
    prepared(outbox_profile))
end

fn policy_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  installed(with_minimum(2)?)?
  let policy = capture_native_session_policy()?
  assert(native_session_minimum(policy)? == 2)
  for altered in [bare_frame(), with_minimum(1)?] do
    let forged = NativeSessionPolicy { frame: altered }
    assert(native_session_minimum(forged) == Err("account_state_changed"))
    assert(require_current_session_policy(forged) == Err("account_state_changed"))
  end
  for malformed in [
    Bytes.empty(),
    Bytes.from_utf8("6\n0\n" <> Bytes.to_utf8(bare_frame())?),
    Bytes.from_utf8("6\n2\n6\n1\n" <> Bytes.to_utf8(bare_frame())?)
  ] do
    assert(Result.is_err(native_session_minimum(NativeSessionPolicy { frame: malformed })))
  end
  installed(bare_frame())?
  assert(require_current_session_policy(policy) == Err("account_state_changed"))
  let old = capture_native_session_policy()?
  assert(native_session_minimum(old)? == 1)
  installed(Bytes.empty())?
  assert(Result.is_err(capture_native_session_policy()))
  println("c3-policy-raw-authority:passed")
  Ok(true)
end

# These are real SQLite writer/CAS tests over controlled opaque blob bytes.
# They qualify source equality/atomicity, not cryptographic session acceptance;
# the separate native suite and copied-source after-crypto probes cover that.
fn writer_proof(replace_account :: Bool) -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  installed(bare_frame())?
  let path = database_path("c3-final-writer")?
  ensure_schema(path)?
  let original = Bytes.from_utf8("original owned encrypted profile")
  let replacement = Bytes.from_utf8("concurrent owned encrypted profile")
  let source = Bytes.from_utf8("original owned encrypted session")
  store_updated_blobs(path, ["profile/v1", "session/v1/source"], [original, source])?
  let before = capture_fanout_snapshot(path, original, ["session/v1/source", "history/v1/test"])?
  let policy = capture_native_session_policy()?
  if replace_account do
    store_updated_blobs(path, ["profile/v1"], [replacement])?
  else
    installed(with_minimum(2)?)?
  end
  assert(commit(path,
    before,
    policy,
    if replace_account do
      replacement
    else
      original
    end) == Err("account_state_changed"))
  assert(Bytes.secure_equals(load_blob(path, "profile/v1")?,
    if replace_account do
      replacement
    else
      original
    end))
  assert(Bytes.secure_equals(load_blob(path, "session/v1/source")?, source))
  for label in ["sessions/v1", "history/v1/test", "outbox/v1", "outbox-envelope/v1/test"] do
    assert(Result.is_err(load_blob(path, label)))
  end
  # A fresh basis/policy after the loser can make progress without erasing the
  # concurrent winner or silently lowering a selected minimum.
  let current_profile = load_blob(path, "profile/v1")?
  let current = capture_fanout_snapshot(path,
    current_profile,
    ["session/v1/source", "history/v1/test"])?
  let policy = capture_native_session_policy()?
  assert(native_session_minimum(policy)? == if replace_account do
      1
    else
      2
    end)
  commit(path, current, policy, current_profile)?
  assert(Bytes.to_utf8(load_blob(path, "outbox-envelope/v1/test")?)? == "prepared sealed envelope")
  assert(Bytes.secure_equals(load_blob(path, "profile/v1")?, current_profile))
  erase_local_state(path)?
  File.delete(path)?
  println("c3-final-writer-account=#{replace_account}:passed")
  Ok(true)
end

test("a mutable ordinary policy record cannot lower the release-owned floor or bypass canonical parsing") do
  case policy_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("release frame changed after preparation is refused inside the final writer with no partial rows") do
  case writer_proof(false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("a fresh outbox snapshot cannot bless a stale original account basis") do
  case writer_proof(true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
