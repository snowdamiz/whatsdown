from Mobile.Codec import encode_output_list, mobile_byte, mobile_wide, mobile_write_u32
from Mobile.GroupState import (
  decode_group_history,
  encode_group_history,
  group_history_label,
  group_state_label
)
from Mobile.GroupHistoryExpiry import (
  prepare_group_history_expiry,
  commit_group_history_expiry,
  expire_group_history
)
from Mobile.Types import MobileGroupHistoryEntry
from Storage.Blobs import load_blob
from Storage.Keys import platform_key, seal_local, open_local, local_context
from Storage.Records import store_updated_blobs
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleSupport import group_account_fixture
from Tests.Support import repeated

fn row(seconds :: Int, timestamp :: String, marker :: Int) -> MobileGroupHistoryEntry!String do
  Ok(MobileGroupHistoryEntry {
    disappearing_seconds: seconds,
    message_id: repeated(marker, 32)?,
    direction: 2,
    epoch: mobile_wide("1")?,
    sender_account_id: repeated(1, 32)?,
    sender_device_id: repeated(2, 16)?,
    timestamp: mobile_wide(timestamp)?,
    body: Bytes.from_utf8("synthetic group history"),
    attachment: Bytes.empty()
  })
end

fn require(value :: Bool) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err("group expiry fixture assertion")
  end
end

fn storage_expiry() -> Bool!String do
  if !Test.install_in_memory_secure_store() do
    return Err("fixture secure store")
  end
  let accounts = group_account_fixture()?
  let group = create_group_with_bob(accounts)?
  let path = accounts.alice_path
  let key = platform_key()?
  let label = group_history_label(group)
  let original = seal_local(encode_group_history([
      row(0, "1000", 1)?,
      row(60, "1000", 2)?,
      row(60, "62000", 3)?
    ])?,
    key,
    local_context(label)?)?
  let unrelated = seal_local(Bytes.from_utf8("unrelated encrypted record"),
    key,
    local_context("group-expiry-unrelated/v1")?)?
  store_updated_blobs(path, [label, "group-expiry-unrelated/v1"], [original, unrelated])?
  # The inclusive expiration boundary removes the past timed row; future and legacy rows survive.
  commit_group_history_expiry(path,
    prepare_group_history_expiry(path, group, mobile_wide("61000")?)?)?
  let partial = load_blob(path, label)?
  let entries = decode_group_history(open_local(partial, key, local_context(label)?)?)?
  require(List.length(entries) == 2
    && List.head(entries).disappearing_seconds == 0
    && List.get(entries, 1).disappearing_seconds == 60)?
  expire_group_history(path, mobile_wide("61000")?)?
  require(Bytes.secure_equals(partial, load_blob(path, label)?))?
  expire_group_history(path, mobile_wide("122000")?)?
  let permanent = decode_group_history(open_local(load_blob(path, label)?,
    key,
    local_context(label)?)?)?
  require(List.length(permanent) == 1 && List.head(permanent).disappearing_seconds == 0)?
  require(Bytes.secure_equals(unrelated, load_blob(path, "group-expiry-unrelated/v1")?))?
  store_updated_blobs(path,
    [label],
    [seal_local(encode_group_history([row(1, "1", 4)?])?, key, local_context(label)?)?])?
  expire_group_history(path, mobile_wide("1001")?)?
  require(load_blob(path, label) == Err("local_state_not_found"))?
  # A reopen of the same database sees the durable deletion, not a display-only filter.
  expire_group_history(path, mobile_wide("1001")?)?
  require(load_blob(path, label) == Err("local_state_not_found"))?
  Ok(true)
end

fn stale_plan_refuses() -> Bool!String do
  if !Test.install_in_memory_secure_store() do
    return Err("fixture secure store")
  end
  let accounts = group_account_fixture()?
  let group = create_group_with_bob(accounts)?
  let path = accounts.alice_path
  let key = platform_key()?
  let history = group_history_label(group)
  let blob = seal_local(encode_group_history([row(1, "1", 7)?])?, key, local_context(history)?)?
  store_updated_blobs(path, [history], [blob])?
  for label in ["profile/v1", "groups/v1", group_state_label(group)?, history] do
    let original = load_blob(path, label)?
    let plan = prepare_group_history_expiry(path, group, mobile_wide("1001")?)?
    let replacement = Bytes.from_utf8("concurrent replacement")
    store_updated_blobs(path, [label], [replacement])?
    require(commit_group_history_expiry(path, plan) == Err("account_state_changed"))?
    require(Bytes.secure_equals(load_blob(path, history)?,
      if label == history do
        replacement
      else
        blob
      end))?
    store_updated_blobs(path, [label], [original])?
  end
  # A corrupt authenticated history is refused, never silently treated as empty.
  let corrupt = seal_local(Bytes.from_utf8("not a history"), key, local_context(history)?)?
  store_updated_blobs(path, [history], [corrupt])?
  require(Result.is_err(prepare_group_history_expiry(path, group, mobile_wide("1001")?)))?
  require(Bytes.secure_equals(corrupt, load_blob(path, history)?))?
  Ok(true)
end

test("group expiry persists partial, no-op and complete cleanup while preserving legacy and unrelated rows") do
  case storage_expiry() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("group expiry refuses profile, index, ratchet and history races without overwriting newer rows") do
  case stale_plan_refuses() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
