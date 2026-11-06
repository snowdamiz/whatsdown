from Mobile.Codec import mobile_wide
from Mobile.GroupState import (
  group_state_label,
  group_history_label,
  encode_group_history,
  decode_group_history,
  updated_group_history_blob
)
from Mobile.GroupHistoryExpiry import expire_group_history_for
from Mobile.Types import MobileGroupHistoryEntry
from Storage.AccountGuard import load_account_basis
from Storage.FanoutCommit import FanoutSnapshot
from Storage.GroupRecords import store_group_state_history, store_group_state_history_guarded
from Storage.Blobs import load_blob
from Storage.Keys import platform_key, seal_local, open_local, local_context
from Storage.Records import store_updated_blobs, store_record_changes
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleSupport import group_account_fixture
from Tests.Support import repeated

fn entry(marker :: Int, seconds :: Int) -> MobileGroupHistoryEntry!String do
  Ok(MobileGroupHistoryEntry {
    disappearing_seconds: seconds,
    message_id: repeated(marker, 32)?,
    direction: 2,
    epoch: mobile_wide("1")?,
    sender_account_id: repeated(1, 32)?,
    sender_device_id: repeated(2, 16)?,
    timestamp: mobile_wide("1")?,
    body: Bytes.from_utf8("synthetic group receive"),
    attachment: Bytes.empty()
  })
end

fn history_races() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let accounts = group_account_fixture()?
  let group = create_group_with_bob(accounts)?
  let path = accounts.alice_path
  let key = platform_key()?
  let state = group_state_label(group)?
  let history = group_history_label(group)
  let original_state = load_blob(path, state)?
  for mode in 0..2 do
    if mode == 0 do
      store_updated_blobs(path,
        [history],
        [
          seal_local(encode_group_history([entry(21, 1)?, entry(22, 0)?])?,
            key,
            local_context(history)?)?
        ])?
    else
      store_record_changes(path, [], [], [history])?
    end
    let before = FanoutSnapshot {
      bases: [load_account_basis(path, ["groups/v1", state, history])?]
    }
    let (labels, blobs) = updated_group_history_blob(path,
      key,
      group,
      accounts.alice_account.account_id,
      entry(23, 0)?)?
    if mode == 0 do
      # Real cleanup commits after the receiver read the old history.
      expire_group_history_for(path, group, mobile_wide("1001")?)?
    else
      let (winner_labels, winner_blobs) = updated_group_history_blob(path,
        key,
        group,
        accounts.alice_account.account_id,
        entry(24, 0)?)?
      store_group_state_history(path, state, original_state, winner_labels, winner_blobs)?
    end
    let winner = load_blob(path, history)?
    assert(case store_group_state_history_guarded(path,
      state,
      Bytes.from_utf8("stale next ratchet"),
      labels,
      blobs,
      before) do
      Err("account_state_changed") -> true
      _ -> false
    end)
    assert(Bytes.secure_equals(load_blob(path, state)?, original_state))
    assert(Bytes.secure_equals(load_blob(path, history)?, winner))
    # A fresh retry may append while retaining the winner and current ratchet.
    let fresh = FanoutSnapshot { bases: [load_account_basis(path, ["groups/v1", state, history])?] }
    let (fresh_labels, fresh_blobs) = updated_group_history_blob(path,
      key,
      group,
      accounts.alice_account.account_id,
      entry(25, 0)?)?
    store_group_state_history_guarded(path,
      state,
      original_state,
      fresh_labels,
      fresh_blobs,
      fresh)?
    let rows = decode_group_history(open_local(load_blob(path, history)?,
      key,
      local_context(history)?)?)?
    assert(List.length(rows) == 2)
    assert(Bytes.secure_equals(List.last(rows).message_id, repeated(25, 32)?))
  end
  Ok(nil)
end

fn source_races() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let accounts = group_account_fixture()?
  let group = create_group_with_bob(accounts)?
  let path = accounts.alice_path
  let key = platform_key()?
  let state = group_state_label(group)?
  let history = group_history_label(group)
  let original_state = load_blob(path, state)?
  for changed in ["profile/v1", "groups/v1", state] do
    let original = load_blob(path, changed)?
    let before = FanoutSnapshot {
      bases: [load_account_basis(path, ["groups/v1", state, history])?]
    }
    let (labels, blobs) = updated_group_history_blob(path,
      key,
      group,
      accounts.alice_account.account_id,
      entry(31, 0)?)?
    let newer = Bytes.from_utf8("newer group receive source")
    store_updated_blobs(path, [changed], [newer])?
    assert(case store_group_state_history_guarded(path,
      state,
      original_state,
      labels,
      blobs,
      before) do
      Err("account_state_changed") -> true
      _ -> false
    end)
    assert(load_blob(path, history) == Err("local_state_not_found"))
    assert(Bytes.secure_equals(load_blob(path, changed)?, newer))
    store_updated_blobs(path, [changed], [original])?
  end
  let before = FanoutSnapshot { bases: [load_account_basis(path, ["groups/v1", state])?] }
  let (labels, blobs) = updated_group_history_blob(path,
    key,
    group,
    accounts.alice_account.account_id,
    entry(32, 0)?)?
  assert(case store_group_state_history_guarded(path,
    state,
    original_state,
    labels,
    blobs,
    before) do
    Err("invalid_group_receive_guard") -> true
    _ -> false
  end)
  assert(load_blob(path, history) == Err("local_state_not_found"))
  Ok(nil)
end

test("group receive cannot resurrect compacted history or overwrite a first writer; fresh retry succeeds") do
  case history_races() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("group receive preserves newer account index and state and refuses uncaptured history") do
  case source_races() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
