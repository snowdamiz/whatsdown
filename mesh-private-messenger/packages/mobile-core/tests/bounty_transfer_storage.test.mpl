from Storage.Blobs import ensure_schema, load_blob, blob_record_hash
from Storage.Keys import platform_key, seal_local, local_context
from Storage.Records import store_blobs, store_updated_blobs, erase_local_state
from Storage.BountyTransfer import (
  store_bounty_transfer_snapshot,
  store_bounty_transfer_legacy_snapshot,
  initialize_bounty_transfer_root,
  store_bounty_transfer_route_snapshot,
  read_bounty_transfer_rows,
  bounty_transfer_row_label
)
from Tests.Support import database_path

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("bounty-append-only")?
  ensure_schema(path)?
  let custody = seal_local(Bytes.from_utf8("selected"), key, local_context("fork-bounty/v1")?)?
  let profile = seal_local(Bytes.from_utf8("profile"), key, local_context("profile/v1")?)?
  let active = seal_local(Bytes.from_utf8("active"), key, local_context("bounty-transfer/v1")?)?
  let history_label = "bounty-transfer/v1/history/old-signature"
  let original = seal_local(Bytes.from_utf8("failed packet A"), key, local_context(history_label)?)?
  let replacement = seal_local(Bytes.from_utf8("failed packet B"),
    key,
    local_context(history_label)?)?
  store_blobs(path,
    ["fork-bounty/v1", "profile/v1", "bounty-transfer/v1", history_label],
    [custody, profile, active, original])?
  # A retry cannot overwrite signed historical evidence, even with the right
  # active-row and custody CAS. The whole replacement must roll back.
  let changed = store_bounty_transfer_snapshot(path,
    ["bounty-transfer/v1", history_label],
    [replacement, replacement],
    active,
    custody)
  assert(Result.is_err(changed))
  assert(Bytes.secure_equals(load_blob(path, "bounty-transfer/v1")?, active))
  assert(Bytes.secure_equals(load_blob(path, history_label)?, original))
  Ok(true)
end

test("failed movement history is append-only at the real SQLite boundary") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn cas_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("bounty-root-cas")?
  ensure_schema(path)?
  let claim = String.repeat("ab", 32)
  let a = bounty_transfer_row_label(claim, 1)?
  let b = bounty_transfer_row_label(claim, 2)?
  let custody = seal_local(Bytes.from_utf8("selected"), key, local_context("fork-bounty/v1")?)?
  let profile = seal_local(Bytes.from_utf8("profile"), key, local_context("profile/v1")?)?
  let root = seal_local(Bytes.from_utf8("immutable terms"),
    key,
    local_context("bounty-authority/v2")?)?
  let marker = seal_local(Bytes.from_utf8("forward"), key, local_context("bounty-transfer/v1")?)?
  let first_a = seal_local(Bytes.from_utf8("A ready"), key, local_context(a)?)?
  let first_b = seal_local(Bytes.from_utf8("B ready"), key, local_context(b)?)?
  let next_a = seal_local(Bytes.from_utf8("A signed"), key, local_context(a)?)?
  let next_b = seal_local(Bytes.from_utf8("B signed"), key, local_context(b)?)?
  store_blobs(path, ["fork-bounty/v1", "profile/v1"], [custody, profile])?
  # A stale absent-v1 capture must lose to an old writer before admission.
  let old = seal_local(Bytes.from_utf8("old journal"), key, local_context("bounty-transfer/v1")?)?
  store_bounty_transfer_legacy_snapshot(path,
    ["bounty-transfer/v1"],
    [old],
    Bytes.empty(),
    custody,
    profile)?
  assert(Result.is_err(initialize_bounty_transfer_root(path,
    claim,
    root,
    marker,
    Bytes.empty(),
    custody,
    profile,
    Bytes.empty(),
    first_a,
    first_b)))
  assert(Bytes.secure_equals(load_blob(path, "bounty-transfer/v1")?, old))
  assert(Result.is_err(load_blob(path, "bounty-authority/v2")))
  # Successful admission compares exact old bytes and installs every row.
  initialize_bounty_transfer_root(path,
    claim,
    root,
    marker,
    old,
    custody,
    profile,
    Bytes.empty(),
    first_a,
    first_b)?
  let observed = read_bounty_transfer_rows(path, claim)?
  assert(Bytes.secure_equals(List.get(observed, 0), root))
  assert(Bytes.secure_equals(List.get(observed, 1), marker))
  assert(Bytes.secure_equals(List.get(observed, 5), first_a))
  assert(Bytes.secure_equals(List.get(observed, 6), first_b))
  assert(Bytes.secure_equals(load_blob(path,
      bounty_transfer_row_label(claim, 0)? <> "/archive/v1")?,
    old))
  # Old first inserts and stale old CAS writers both lose after forwarding.
  assert(Result.is_err(store_bounty_transfer_snapshot(path,
    ["bounty-transfer/v1"],
    [old],
    Bytes.empty(),
    custody)))
  assert(Result.is_err(store_bounty_transfer_snapshot(path,
    ["bounty-transfer/v1"],
    [old],
    marker,
    custody)))
  # Both actors captured this aggregate. B commits first; A still commits with
  # its own old target because sibling progress is not part of A's predicate.
  store_bounty_transfer_route_snapshot(path,
    claim,
    2,
    root,
    marker,
    first_b,
    custody,
    profile,
    next_b,
    "",
    Bytes.empty(),
    Bytes.empty())?
  store_bounty_transfer_route_snapshot(path,
    claim,
    1,
    root,
    marker,
    first_a,
    custody,
    profile,
    next_a,
    "",
    Bytes.empty(),
    Bytes.empty())?
  assert(Bytes.secure_equals(load_blob(path, a)?, next_a))
  assert(Bytes.secure_equals(load_blob(path, b)?, next_b))
  assert(Result.is_err(store_bounty_transfer_route_snapshot(path,
    claim,
    1,
    root,
    marker,
    first_a,
    custody,
    profile,
    first_a,
    "",
    Bytes.empty(),
    Bytes.empty())))
  # Every authority predicate is independently decisive and leaves both legs.
  let different = Bytes.from_utf8("not the captured ciphertext")
  assert(Result.is_err(store_bounty_transfer_route_snapshot(path,
    claim,
    1,
    different,
    marker,
    next_a,
    custody,
    profile,
    first_a,
    "",
    Bytes.empty(),
    Bytes.empty())))
  assert(Result.is_err(store_bounty_transfer_route_snapshot(path,
    claim,
    1,
    root,
    different,
    next_a,
    custody,
    profile,
    first_a,
    "",
    Bytes.empty(),
    Bytes.empty())))
  assert(Result.is_err(store_bounty_transfer_route_snapshot(path,
    claim,
    1,
    root,
    marker,
    next_a,
    different,
    profile,
    first_a,
    "",
    Bytes.empty(),
    Bytes.empty())))
  assert(Result.is_err(store_bounty_transfer_route_snapshot(path,
    claim,
    1,
    root,
    marker,
    next_a,
    custody,
    different,
    first_a,
    "",
    Bytes.empty(),
    Bytes.empty())))
  let changed_profile = seal_local(Bytes.from_utf8("new profile"),
    key,
    local_context("profile/v1")?)?
  store_updated_blobs(path, ["profile/v1"], [changed_profile])?
  assert(Result.is_err(store_bounty_transfer_route_snapshot(path,
    claim,
    1,
    root,
    marker,
    next_a,
    custody,
    profile,
    first_a,
    "",
    Bytes.empty(),
    Bytes.empty())))
  assert(Bytes.secure_equals(load_blob(path, a)?, next_a))
  assert(Bytes.secure_equals(load_blob(path, b)?, next_b))
  # Erasure between capture and final CAS cannot resurrect either target.
  erase_local_state(path)?
  assert(Result.is_err(store_bounty_transfer_route_snapshot(path,
    claim,
    1,
    root,
    marker,
    next_a,
    custody,
    changed_profile,
    first_a,
    "",
    Bytes.empty(),
    Bytes.empty())))
  assert(Result.is_err(load_blob(path, a)))
  assert(Result.is_err(load_blob(path, b)))
  Ok(true)
end

test("atomic admission and per-leg SQLite CAS fence old writers, siblings, profile and erase") do
  case cas_proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn rollback_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let key = platform_key()?
  let path = database_path("bounty-admission-rollback")?
  ensure_schema(path)?
  let claim = String.repeat("cd", 32)
  let custody = seal_local(Bytes.from_utf8("selected"), key, local_context("fork-bounty/v1")?)?
  let profile = seal_local(Bytes.from_utf8("profile"), key, local_context("profile/v1")?)?
  let root = seal_local(Bytes.from_utf8("terms"), key, local_context("bounty-authority/v2")?)?
  let marker = seal_local(Bytes.from_utf8("marker"), key, local_context("bounty-transfer/v1")?)?
  let target = bounty_transfer_row_label(claim, 1)?
  let row = seal_local(Bytes.from_utf8("ready"), key, local_context(target)?)?
  store_blobs(path, ["fork-bounty/v1", "profile/v1"], [custody, profile])?
  # Even a label for a proposed omitted/zero asset must be absent. Collision
  # cannot be hidden by writing only the requested positive rows.
  let collision_path = database_path("bounty-target-collision")?
  ensure_schema(collision_path)?
  store_blobs(collision_path, ["fork-bounty/v1", "profile/v1", target], [custody, profile, row])?
  assert(Result.is_err(initialize_bounty_transfer_root(collision_path,
    claim,
    root,
    marker,
    Bytes.empty(),
    custody,
    profile,
    Bytes.empty(),
    Bytes.empty(),
    Bytes.empty())))
  assert(Result.is_err(load_blob(collision_path, "bounty-authority/v2")))
  assert(Result.is_err(load_blob(collision_path, "bounty-transfer/v1")))
  assert(Bytes.secure_equals(load_blob(collision_path, target)?, row))
  let database = Sqlite.open(path)?
  let hash = blob_record_hash(database, target)?
  # Fail after root and marker INSERTs have actually occurred in the same
  # production transaction, rather than merely rejecting an early predicate.
  Sqlite.execute(database,
    "CREATE TRIGGER bounty_abort BEFORE INSERT ON encrypted_blobs WHEN NEW.record_hash = '"
      <> hash
      <> "' BEGIN SELECT RAISE(ABORT, 'injected admission failure'); END",
    [])?
  Sqlite.close(database)
  assert(Result.is_err(initialize_bounty_transfer_root(path,
    claim,
    root,
    marker,
    Bytes.empty(),
    custody,
    profile,
    Bytes.empty(),
    row,
    Bytes.empty())))
  assert(Result.is_err(load_blob(path, "bounty-authority/v2")))
  assert(Result.is_err(load_blob(path, "bounty-transfer/v1")))
  assert(Result.is_err(load_blob(path, target)))
  assert(Bytes.secure_equals(load_blob(path, "fork-bounty/v1")?, custody))
  assert(Bytes.secure_equals(load_blob(path, "profile/v1")?, profile))
  Ok(true)
end

test("a real SQLite write failure rolls back root, marker and every admission target") do
  case rollback_proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
