from Mobile.Sessions import load_session_ids, load_session_record
from Mobile.DeviceSet import device_set_label
from Mobile.SiblingMembership import sibling_source_labels
from Storage.AccountGuard import load_account_basis
from Storage.FanoutCommit import FanoutSnapshot, capture_fanout_snapshot
from Transport.Packet import ClientProfile

pub fn prekey_claim_label(profile :: ClientProfile) -> String do
  "fanout-prekey-claim/v1/#{Bytes.to_hex(profile.account_id)}/#{Bytes.to_hex(profile.device_id)}"
end

pub fn prekey_reservation_label(profile :: ClientProfile) -> String do
  "fanout-prekey-reservation/v1/#{Bytes.to_hex(profile.account_id)}/#{Bytes.to_hex(profile.device_id)}"
end

fn add(labels :: List<String>, label :: String) -> List<String> do
  if List.contains(labels, label) do
    labels
  else
    List.append(labels, label)
  end
end

fn device_labels(profiles :: List<ClientProfile>,
  index :: Int,
  labels :: List<String>) -> List<String> do
  if index >= List.length(profiles) do
    labels
  else
    let value = List.get(profiles, index)
    device_labels(profiles,
      index + 1,
      add(add(add(add(labels, prekey_claim_label(value)), prekey_reservation_label(value)),
          "transparency-device-set/v1/#{Bytes.to_hex(value.account_id)}"),
        device_set_label(value.account_id)))
  end
end

fn merge_labels(values :: List<String>, index :: Int, labels :: List<String>) -> List<String> do
  if index >= List.length(values) do
    labels
  else
    merge_labels(values, index + 1, add(labels, List.get(values, index)))
  end
end

fn relevant(profile :: ClientProfile, account :: Bytes, device :: Bytes) -> Bool do
  Bytes.secure_equals(profile.account_id, account) && Bytes.secure_equals(profile.device_id, device)
end

fn session_labels(path :: String,
  key :: borrow StorageKey,
  ids :: List<Bytes>,
  targets :: List<ClientProfile>,
  index :: Int,
  labels :: List<String>) -> List<String>!String do
  if List.length(labels) > 256 do
    return Err("fanout_snapshot_capacity")
  end
  if index >= List.length(ids) do
    Ok(labels)
  else
    let value = load_session_record(path, key, List.get(ids, index))?
    let matches = List.any(targets,
      fn(profile) -> relevant(profile,
        value.record.peer_account_id,
        value.record.peer_device_id) end)
    let next = if matches do
      add(add(add(labels, value.label), "sibling-session/v1/#{Bytes.to_hex(value.session_id)}"),
        "history/v1/#{Bytes.to_hex(value.record.conversation_id)}")
    else
      labels
    end
    session_labels(path, key, ids, targets, index + 1, next)
  end
end

## Capture every matching session, including older candidates that could become
## preferred after a receive. A changed session index or relevant ratchet must
## fail the final transaction rather than overwrite a concurrent state change.
pub fn capture_fanout_sources(path :: String,
  key :: borrow StorageKey,
  profile :: Bytes,
  local :: ClientProfile,
  peers :: List<ClientProfile>,
  local_devices :: List<ClientProfile>,
  extra_labels :: List<String>) -> FanoutSnapshot!String do
  let header = load_account_basis(path, ["sessions/v1"])?
  if !Bytes.secure_equals(header.profile, profile) do
    return Err("account_state_changed")
  end
  let targets = peers ++ local_devices
  let labels = [
    "sessions/v1",
    "outbox/v1",
    "delivery/v1",
    "postage-queue/v1",
    "transparency-checkpoint/v1",
    "transparency-witnesses/v2",
    "transparency-fork/v1",
    "anchor-schedule/v1",
    "anchor-observation/v1",
    "group-invitations/v1",
    "contact-address/v1",
    "presentation/v1/user/#{Bytes.to_hex(local.account_id)}"
  ]
  let labels = merge_labels(sibling_source_labels(local.account_id), 0, labels)
  let labels = device_labels(targets, 0, labels)
  let labels = merge_labels(extra_labels, 0, labels)
  let labels = session_labels(path, key, load_session_ids(path, key)?, targets, 0, labels)?
  let value = capture_fanout_snapshot(path, profile, labels)?
  if !Bytes.secure_equals(List.head(List.head(value.bases).records), List.head(header.records)) do
    return Err("account_state_changed")
  end
  Ok(value)
end
