from Groups.Tree import indexed_members
from Mobile.AccountState import load_bound_account, account_snapshot_current
from Mobile.AttachmentCapabilities import (
  require_attachment_profile,
  require_attachment_sets,
  require_attachment_local,
  require_padded_attachment_profile,
  require_padded_attachment_profiles
)
from Mobile.Codec import mobile_byte, mobile_read_byte
from Mobile.CreditState import pack_credit_parts, unpack_credit_parts
from Mobile.GroupState import load_group, consume_group_state, group_profile, group_state_label
from Mobile.NetworkPins import native_network_pins
from Mobile.Platform import native_security_config
from Mobile.Transparency import fresh_account_device_set
from Mobile.TransparencySafety import require_log_changes_allowed
from Storage.Blobs import load_blob
from Storage.Keys import platform_key, local_context, open_local, seal_local
from Transparency.Config import encode_security_config
from Transport.Packet import ClientProfile

##! An opaque local authorization binds an explicit attachment selection to
##! its account, destinations and release trust. Every consuming native action
##! rechecks current authenticated recipient credentials. A later send checks
##! them again; this ticket cannot waive final fanout/group authorization.

fn target_ids(kind :: Int, input :: Bytes) -> List<Bytes>!String do
  if (kind != 4 && kind != 5)
    || Bytes.length(input) < 32
    || Bytes.length(input) > 2048
    || Bytes.length(input) % 32 != 0
    || (kind == 4 && Bytes.length(input) != 32) do
    return Err("invalid_attachment_recipients")
  end
  let output = for index in 0..(Bytes.length(input) / 32) do
    Bytes.slice(input, index * 32, 32)?
  end
  Ok(output)
end

fn add_account(accounts :: List<Bytes>, value :: Bytes) -> List<Bytes> do
  if List.any(accounts, fn(item) -> Bytes.secure_equals(item, value) end) do
    accounts
  else
    List.append(accounts, value)
  end
end

pub fn attachment_target_accounts(path :: String,
  profile :: ClientProfile,
  kind :: Int,
  targets :: Bytes) -> List<Bytes>!String do
  let ids = target_ids(kind, targets)?
  if kind == 4 do
    return Ok(add_account(ids, profile.account_id))
  end
  let key = platform_key()?
  let members = for id in ids do
    let state = load_group(path, profile, key, id)?
    let accounts = for entry in indexed_members(state.tree) do
      entry.member.account_id
    end
    consume_group_state(state)
    accounts
  end
  let output = List.reduce(List.flatten(members),
    [],
    fn(accounts, value) do add_account(accounts, value) end)
  Ok(output)
end

fn require_group(path :: String,
  profile :: ClientProfile,
  id :: Bytes,
  padded :: Bool) -> Unit!String do
  let key = platform_key()?
  let label = group_state_label(id)?
  let before = load_blob(path, label)?
  let state = load_group(path, profile, key, id)?
  let members = indexed_members(state.tree)
  consume_group_state(state)
  if List.length(members) < 2 do
    return Err("group_has_no_recipients")
  end
  for entry in members do
    let member = entry.member
    let devices = fresh_account_device_set(path, key, member.account_id)?
    let current = group_profile(devices.profiles, member.account_id, member.device_id, 0)?
    if !Bytes.secure_equals(current.credential.signing_public_key,
      member.signing_public_key.bytes) do
      return Err("group_membership_changed")
    end
    require_attachment_profile(current)?
    if padded do
      require_padded_attachment_profile(current)?
    end
  end
  if !Bytes.secure_equals(before, load_blob(path, label)?) do
    return Err("group_membership_changed")
  end
  Ok(nil)
end

fn require_targets(path :: String,
  profile :: ClientProfile,
  kind :: Int,
  targets :: Bytes,
  padded :: Bool) -> Unit!String do
  let key = platform_key()?
  require_log_changes_allowed(path, key)?
  let ids = target_ids(kind, targets)?
  if kind == 4 do
    let peers = fresh_account_device_set(path, key, List.head(ids))?
    let own = fresh_account_device_set(path, key, profile.account_id)?
    require_attachment_local(profile, own)?
    require_attachment_sets(peers, own)?
    if padded do
      require_padded_attachment_profiles(peers.profiles)?
      require_padded_attachment_profiles(own.profiles)?
    end
    Ok(nil)
  else
    for id in ids do
      require_group(path, profile, id, padded)?
    end
    Ok(nil)
  end
end

fn trust_binding() -> Bytes!String do
  let pins = native_network_pins()?
  Ok(Crypto.sha256(pack_credit_parts([
    encode_security_config(native_security_config()?)?,
    Bytes.from_utf8(pins.core_origin),
    Bytes.from_utf8(pins.object_origin)
  ])?))
end

fn context(path :: String) -> Bytes!String do
  local_context("attachment-recipients/v1/" <> Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(path))))
end

## The native preflight refreshes these targets first. This helper is also
## usable by Mesh callers with already verified, unexpired transparency sets.
pub fn attachment_authorization(path :: String,
  expected_profile :: Bytes,
  kind :: Int,
  targets :: Bytes) -> Bytes!String do
  let who = load_bound_account(path, expected_profile, false)?
  let trust = trust_binding()?
  require_targets(path, who.profile, kind, targets, false)?
  let key = platform_key()?
  let sealed = seal_local(pack_credit_parts([
      Bytes.from_utf8("\u{1}ACA"),
      who.public_profile,
      mobile_byte(kind)?,
      targets,
      trust
    ])?,
    key,
    context(path)?)?
  if !account_snapshot_current(path, who.before.profile)
    || !Bytes.secure_equals(trust, trust_binding()?) do
    return Err("account_state_changed")
  end
  Ok(sealed)
end

fn require_authorization_for(path :: String, ticket :: Bytes, padded :: Bool) -> Unit!String do
  if Bytes.length(ticket) < 1 || Bytes.length(ticket) > 40000 do
    return Err("invalid_attachment_recipients")
  end
  let key = platform_key()?
  let values = unpack_credit_parts(open_local(ticket, key, context(path)?)?, 5, 36134)?
  if List.length(values) != 5
    || !Bytes.secure_equals(List.head(values), Bytes.from_utf8("\u{1}ACA"))
    || Bytes.length(List.get(values, 2)) != 1
    || Bytes.length(List.get(values, 4)) != 32 do
    return Err("invalid_attachment_recipients")
  end
  let who = load_bound_account(path, List.get(values, 1), false)?
  let trust = trust_binding()?
  if !Bytes.secure_equals(trust, List.get(values, 4)) do
    return Err("attachment_configuration_changed")
  end
  require_targets(path,
    who.profile,
    mobile_read_byte(List.get(values, 2))?,
    List.get(values, 3),
    padded)?
  if !account_snapshot_current(path, who.before.profile)
    || !Bytes.secure_equals(trust, trust_binding()?) do
    return Err("account_state_changed")
  end
  Ok(nil)
end

# The same target/account/release-bound ticket can recover a saved ACH3 intent.
# A new profile4 write additionally rechecks mask4 on every actual recipient.
pub fn require_attachment_authorization(path :: String, ticket :: Bytes) -> Unit!String do
  require_authorization_for(path, ticket, false)
end

pub fn require_padded_attachment_authorization(path :: String, ticket :: Bytes) -> Unit!String do
  require_authorization_for(path, ticket, true)
end
