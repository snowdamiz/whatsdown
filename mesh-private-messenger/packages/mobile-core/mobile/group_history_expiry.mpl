from Mobile.GroupState import (
  decode_group_ids,
  decode_group_history,
  encode_group_history,
  unexpired_group_history,
  group_history_label,
  group_state_label,
  load_group,
  consume_group_state
)
from Mobile.Profile import load_profile
from Storage.AccountGuard import AccountBasis, load_account_basis
from Storage.FanoutCommit import FanoutSnapshot, commit_fanout_records
from Storage.Keys import platform_key, local_context, open_local, seal_local
from Transport.Packet import decode_client_profile

pub struct GroupHistoryExpiryPlan do
  before :: FanoutSnapshot
  labels :: List<String>
  blobs :: List<Bytes>
  removed :: List<String>
end

fn indexed_groups(basis :: AccountBasis, key :: borrow StorageKey) -> List<Bytes>!String do
  let blob = List.head(basis.records)
  if Bytes.length(blob) == 0 do
    Ok([])
  else
    decode_group_ids(open_local(blob, key, local_context("groups/v1")?)?)
  end
end

fn prepare_indexed_expiry(path :: String,
  key :: borrow StorageKey,
  index_basis :: AccountBasis,
  group :: Bytes,
  now :: U64) -> GroupHistoryExpiryPlan!String do
  let label = group_history_label(group)
  let records = load_account_basis(path, [group_state_label(group)?, label])?
  if !Bytes.secure_equals(records.profile, index_basis.profile) do
    return Err("account_state_changed")
  end
  let profile = decode_client_profile(load_profile(path)?)?
  let state = load_group(path, profile, key, group)?
  consume_group_state(state)
  let plan = GroupHistoryExpiryPlan {
    before: FanoutSnapshot { bases: [index_basis, records] },
    labels: [],
    blobs: [],
    removed: []
  }
  let blob = List.get(records.records, 1)
  if Bytes.length(blob) == 0 do
    return Ok(plan)
  end
  let entries = decode_group_history(open_local(blob, key, local_context(label)?)?)?
  let visible = unexpired_group_history(entries, now)?
  if List.length(visible) == List.length(entries) do
    Ok(plan)
  else if List.length(visible) == 0 do
    Ok(%{plan | removed: [label]})
  else
    Ok(%{plan |
      labels: [label],
      blobs: [seal_local(encode_group_history(visible)?, key, local_context(label)?)?]
    })
  end
end

pub fn prepare_group_history_expiry(path :: String,
  group :: Bytes,
  now :: U64) -> GroupHistoryExpiryPlan!String do
  let key = platform_key()?
  let before = load_account_basis(path, ["groups/v1"])?
  if !List.any(indexed_groups(before, key)?, fn(id) -> Bytes.secure_equals(id, group) end) do
    return Err("group_not_found")
  end
  prepare_indexed_expiry(path, key, before, group, now)
end

pub fn commit_group_history_expiry(path :: String,
  plan :: GroupHistoryExpiryPlan) -> Result<(), String> do
  if List.length(plan.labels) == 0 && List.length(plan.removed) == 0 do
    Ok(nil)
  else
    commit_fanout_records(path, plan.before, plan.labels, plan.blobs, plan.removed)
  end
end

pub fn expire_group_history_for(path :: String, group :: Bytes, now :: U64) -> Result<(), String> do
  commit_group_history_expiry(path, prepare_group_history_expiry(path, group, now)?)
end

fn expire_groups(path :: String,
  key :: borrow StorageKey,
  before :: AccountBasis,
  groups :: List<Bytes>,
  now :: U64,
  index :: Int) -> Result<(), String> do
  if index >= List.length(groups) do
    Ok(nil)
  else
    commit_group_history_expiry(path,
      prepare_indexed_expiry(path, key, before, List.get(groups, index), now)?)?
    expire_groups(path, key, before, groups, now, index + 1)
  end
end

## Called after each sync's deliveries; no protocol/outbox/delivery state is removed.
pub fn expire_group_history(path :: String, now :: U64) -> Result<(), String> do
  let key = platform_key()?
  let before = load_account_basis(path, ["groups/v1"])?
  expire_groups(path, key, before, indexed_groups(before, key)?, now, 0)
end
