from Mobile.Account import account_deletion, device_departure
from Mobile.AccountState import (
  load_bound_account,
  account_network_current,
  account_snapshot_current
)
from Mobile.Codec import mobile_reader, mobile_finish, take_vector_error, mobile_utf8, mobile_byte
from Mobile.NetworkPins import native_network_pins
from Mobile.Profile import open_account
from Storage.AccountGuard import erase_account_if_current
from Storage.Blobs import load_blob
from Storage.Keys import platform_key

pub struct AccountActionRequest do
  database_path :: String
  expected_profile :: Bytes
end

pub fn parse_account_action(input :: Bytes) -> AccountActionRequest!String do
  let state = mobile_reader(input, 40238, "invalid_account_action")?
  let path = take_vector_error(state, 4096, "invalid_account_action")?
  let expected = take_vector_error(path.state, 36134, "invalid_account_action")?
  mobile_finish(expected.state, "invalid_account_action")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  if Bytes.length(path.value) == 0
    || String.contains(database_path, "\0")
    || Bytes.length(expected.value) == 0 do
    return Err("invalid_account_action")
  end
  Ok(AccountActionRequest { database_path: database_path, expected_profile: expected.value })
end

fn output(tag :: String, kind :: Int) -> Bytes!String do
  Bytes.concat(Bytes.from_hex(tag)?, mobile_byte(kind)?)
end

## Capabilities never materialize a signed deletion or make a network request.
pub fn native_account_capabilities(input :: Bytes) -> Bytes!String do
  let request = parse_account_action(input)?
  let account = load_bound_account(request.database_path, request.expected_profile, false)?
  let can_manage = case load_blob(request.database_path, "account-signing-key/v1") do
    Err("local_state_not_found") -> false
    Err(error) -> return Err(error)
    Ok(_) -> do
      let key = platform_key()?
      let _keys = open_account(account.profile, key, request.database_path)?
      true
    end
  end
  if !account_snapshot_current(request.database_path, account.before.profile) do
    return Err("account_state_changed")
  end
  output("01414350",
    if can_manage do
      1
    else
      0
    end)
end

## The onboarding caller may discard only the exact profile whose registration
## was refused. A concurrent renewal or draft change requires a fresh decision.
pub fn native_account_discard(input :: Bytes) -> Bytes!String do
  let request = parse_account_action(input)?
  let account = load_bound_account(request.database_path, request.expected_profile, true)?
  erase_account_if_current(request.database_path, account.before.profile)?
  output("01414453", 1)
end

## Only a canonical204 from the pinned core commits local erasure. Unknown
## outcomes, redirects and unsupported routes retain the complete local account.
pub fn native_account_delete(input :: Bytes) -> Bytes!String do
  let request = parse_account_action(input)?
  let account = load_bound_account(request.database_path, request.expected_profile, false)?
  let pins = native_network_pins()?
  let deletion = account_deletion(request.database_path)?
  let primary = Bytes.length(deletion) > 0
  let wire = if primary do
    deletion
  else
    device_departure(request.database_path)?
  end
  let route = if primary do
    "/v1/accounts/delete"
  else
    "/v1/devices/leave"
  end
  if !account_network_current(request.database_path, account.before.profile, pins.core_origin) do
    return Err("account_state_changed")
  end
  let response = case Http.build(:post, pins.core_origin <> route)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Cache-Control", "no-store")
    |> Http.body_bytes(wire)
    |> Http.timeout(8000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(1024)
    |> Http.send() do
    Err(_) -> do
      if !account_network_current(request.database_path,
        account.before.profile,
        pins.core_origin) do
        return Err("account_state_changed")
      end
      return Err("account_transport_unavailable")
    end
    Ok(value) -> value
  end
  if !account_network_current(request.database_path, account.before.profile, pins.core_origin) do
    return Err("account_state_changed")
  end
  if response.status == 404 do
    return Err("account_deletion_unsupported")
  end
  if response.status == 403 do
    return Err("account_deletion_refused")
  end
  if response.status != 204 do
    return Err("account_http_" <> Int.to_string(response.status))
  end
  erase_account_if_current(request.database_path, account.before.profile)?
  output("0141444e",
    if primary do
      1
    else
      3
    end)
end
