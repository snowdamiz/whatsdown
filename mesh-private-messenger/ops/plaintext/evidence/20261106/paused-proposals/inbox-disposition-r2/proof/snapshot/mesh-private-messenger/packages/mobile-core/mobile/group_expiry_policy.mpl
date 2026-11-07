from Binary.Reader import finish
from Mobile.Codec import (
  encode_output_list,
  mobile_byte,
  mobile_finish,
  mobile_read_u32,
  mobile_reader,
  mobile_utf8,
  mobile_write_u32,
  take_vector
)
from Mobile.GroupPolicyWire import group_policy_label, encode_group_policy, decode_group_policy
from Mobile.GroupState import decode_group_ids, group_state_label, load_group, consume_group_state
from Mobile.Profile import load_profile
from Storage.AccountGuard import load_account_basis, account_basis_current, commit_account_changes
from Storage.Blobs import load_blob
from Storage.Keys import platform_key, local_context, open_local, seal_local
from Transport.Packet import decode_client_profile

pub fn group_timer(path :: String, key :: borrow StorageKey, group :: Bytes) -> Int!String do
  let label = group_policy_label(group)?
  case load_blob(path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(0)
    else
      Err(error)
    end
    Ok(blob) -> decode_group_policy(open_local(blob, key, local_context(label)?)?)
  end
end

## A device-local sending preference, never a remotely imposed group rule.
## Exact account/index/ratchet/policy ciphertexts are compared before update.
pub fn native_group_policy(input :: Bytes) -> Bytes!String do
  let state = mobile_reader(input, 4144, "invalid_group_policy")?
  let path = take_vector(state, 4096)?
  let group = take_vector(path.state, 32)?
  let seconds = case finish(group.state) do
    Ok(_) -> None
    Err(_) -> do
      let value = take_vector(group.state, 4)?
      mobile_finish(value.state, "invalid_group_policy")?
      Some(mobile_read_u32(value.value)?)
    end
  end
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  if String.length(database_path) == 0 || Bytes.length(group.value) != 32 do
    return Err("invalid_group_policy")
  end
  let label = group_policy_label(group.value)?
  let before = load_account_basis(database_path,
    ["groups/v1", group_state_label(group.value)?, label])?
  let key = platform_key()?
  let ids = decode_group_ids(open_local(List.head(before.records),
    key,
    local_context("groups/v1")?)?)?
  if !List.any(ids, fn(id) -> Bytes.secure_equals(id, group.value) end) do
    return Err("group_not_found")
  end
  let profile = decode_client_profile(load_profile(database_path)?)?
  let group_state = load_group(database_path, profile, key, group.value)?
  consume_group_state(group_state)
  let previous = List.get(before.records, 2)
  let current = if Bytes.length(previous) == 0 do
    0
  else
    decode_group_policy(open_local(previous, key, local_context(label)?)?)?
  end
  let chosen = case seconds do
    None -> current
    Some(value) -> value
  end
  let encoded = encode_group_policy(chosen)?
  case seconds do
    None -> if !account_basis_current(database_path, before) do
      return Err("account_state_changed")
    end
    Some(_) -> commit_account_changes(database_path,
      before,
      [label],
      [seal_local(encoded, key, local_context(label)?)?],
      [])?
  end
  encode_output_list([mobile_byte(1)?, group.value, mobile_write_u32(chosen)?])
end
