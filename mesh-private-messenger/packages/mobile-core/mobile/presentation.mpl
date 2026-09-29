from Mobile.Profile import load_profile
from Transport.Packet import decode_client_profile
from Mobile.Codec import (
  mobile_read_u64,
  mobile_wide,
  mobile_reader,
  mobile_finish,
  mobile_utf8,
  mobile_join,
  mobile_vector,
  take_optional_vector,
  take_vector
)
from Mobile.Types import MobilePayloadRequest, MobileTriplePayloadRequest
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local, platform_key, seal_local
from Storage.Records import store_updated_session

##! Small presentation records travel inside authenticated encrypted messages.
##! Storage keys come from the authenticated sender/group, never from the payload.

pub struct PresentationFields do
  revision :: U64
  community :: Bytes
  owner :: Bytes
  admins :: List<Bytes>
end

# A record is a name and photo, then from newer clients a revision. A community's
# record adds its details, which the app encodes, and its roles: the owner's
# account, then each admin's in ascending order.

pub fn presentation_fields(input :: Bytes) -> PresentationFields!String do
  let state = mobile_reader(input, 29340, "invalid_presentation")?
  let name = take_vector(state, 96)?
  let avatar = take_vector(name.state, 12288)?
  let name_text = mobile_utf8(name.value, "invalid_presentation")?
  let avatar_text = mobile_utf8(avatar.value, "invalid_presentation")?
  if String.length(String.trim(name_text)) == 0
    || Regex.is_match(~r/[\x00-\x1f\x7f]/, name_text)
    || (Bytes.length(avatar.value) > 0
      && !Regex.is_match(~r/^data:image\/jpeg;base64,[A-Za-z0-9+\/]+={0,2}$/, avatar_text)) do
    return Err("invalid_presentation")
  end
  let plain = PresentationFields {
    revision: mobile_wide("0")?,
    community: Bytes.empty(),
    owner: Bytes.empty(),
    admins: []
  }
  case mobile_finish(avatar.state, "invalid_presentation") do
    Ok(_) -> return Ok(plain)
    Err(_) -> nil
  end
  let revision = take_vector(avatar.state, 8)?
  let value = mobile_read_u64(revision.value)?
  if U64.compare(value, mobile_wide("9007199254740991")?) > 0 do
    return Err("invalid_presentation")
  end
  case mobile_finish(revision.state, "invalid_presentation") do
    Ok(_) -> return Ok(%{plain | revision: value})
    Err(_) -> nil
  end
  let community = take_vector(revision.state, 16384)?
  let roles = take_vector(community.state, 544)?
  mobile_finish(roles.state, "invalid_presentation")?
  let text = mobile_utf8(community.value, "invalid_presentation")?
  let ids = role_ids(roles.value, 0, [])?
  if Bytes.length(community.value) == 0
    || Regex.is_match(~r/[\x00-\x1f\x7f]/, text)
    || List.length(ids) == 0
    || !ascending_admins(ids, 1) do
    return Err("invalid_presentation")
  end
  Ok(PresentationFields {
    revision: value,
    community: community.value,
    owner: List.head(ids),
    admins: List.drop(ids, 1)
  })
end

fn role_ids(value :: Bytes, index :: Int, output :: List<Bytes>) -> List<Bytes>!String do
  if index * 32 >= Bytes.length(value) do
    Ok(output)
  else if Bytes.length(value) - index * 32 < 32 do
    Err("invalid_presentation")
  else
    role_ids(value, index + 1, List.append(output, Bytes.slice(value, index * 32, 32)?))
  end
end

# Admins follow the owner in strictly ascending order, so equal roles are equal bytes.

fn ascending_admins(ids :: List<Bytes>, index :: Int) -> Bool do
  if index >= List.length(ids) do
    true
  else if Bytes.secure_equals(List.get(ids, index), List.head(ids))
    || (index > 1
      && Bytes.to_hex(List.get(ids, index - 1)) >= Bytes.to_hex(List.get(ids, index))) do
    false
  else
    ascending_admins(ids, index + 1)
  end
end

pub fn presentation_data(input :: Bytes) -> Bytes!String do
  presentation_fields(input)?
  Ok(input)
end

fn record_holds_role(fields :: PresentationFields, account :: Bytes) -> Bool do
  Bytes.secure_equals(fields.owner, account)
    || List.any(fields.admins, fn(admin) do Bytes.secure_equals(admin, account) end)
end

fn same_roles(left :: PresentationFields, right :: PresentationFields) -> Bool do
  Bytes.secure_equals(left.owner, right.owner)
    && List.length(left.admins) == List.length(right.admins)
    && List.all(List.zip(left.admins, right.admins),
      fn(pair) do
        let (a, b) = pair
        Bytes.secure_equals(a, b)
      end)
end

# Who may replace a group's record. A plain group's is its creator's. A member
# first learns a community from whoever added this device, when that record names
# them owner or admin; afterwards only the owner changes it, and admins may edit
# everything but the roles. A community never turns back into a plain group.

pub fn record_change_allowed(stored :: Bytes,
  incoming :: Bytes,
  sender :: Bytes,
  creator :: Bytes,
  anchor :: Bytes) -> Bool!String do
  let next = presentation_fields(incoming)?
  if Bytes.length(stored) == 0 do
    if Bytes.length(next.community) == 0 do
      Ok(Bytes.secure_equals(sender, creator))
    else
      let introduced = if Bytes.length(anchor) == 0 do
        Bytes.secure_equals(sender, creator)
      else
        Bytes.secure_equals(sender, anchor)
      end
      Ok(introduced && record_holds_role(next, sender))
    end
  else
    let current = presentation_fields(stored)?
    if Bytes.length(current.community) == 0 do
      Ok(Bytes.secure_equals(sender, creator))
    else if Bytes.length(next.community) == 0 do
      Ok(false)
    else if Bytes.secure_equals(sender, current.owner) do
      Ok(true)
    else
      Ok(record_holds_role(current, sender) && same_roles(current, next))
    end
  end
end

fn group_record_key(group_id :: Bytes) -> Bytes do
  Bytes.from_utf8("group/" <> Bytes.to_hex(group_id))
end

# In a community only its owner and admins change who is in it; the owner alone
# removes an admin, no one removes the owner, and anyone with a role may remove
# their own other devices. An empty target is an addition.

pub fn community_change_allowed(database_path :: String,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes,
  committer :: Bytes,
  target :: Bytes) -> Bool!String do
  let stored = load_presentation_record(database_path, wrapping_key, group_record_key(group_id))?
  if Bytes.length(stored) == 0 do
    return Ok(true)
  end
  let roles = presentation_fields(stored)?
  if Bytes.length(roles.community) == 0 do
    Ok(true)
  else if !record_holds_role(roles, committer) do
    Ok(false)
  else if Bytes.length(target) == 0 || Bytes.secure_equals(target, committer) do
    Ok(true)
  else if Bytes.secure_equals(target, roles.owner) do
    Ok(false)
  else
    Ok(!record_holds_role(roles, target) || Bytes.secure_equals(committer, roles.owner))
  end
end

pub fn community_group(database_path :: String,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes) -> Bool!String do
  let stored = load_presentation_record(database_path, wrapping_key, group_record_key(group_id))?
  if Bytes.length(stored) == 0 do
    Ok(false)
  else
    Ok(Bytes.length(presentation_fields(stored)?.community) > 0)
  end
end

# The member whose welcome added this device, the first voice it trusts for a community.

fn group_anchor_label(group_id :: Bytes) -> String do
  "group-anchor/v1/" <> Bytes.to_hex(group_id)
end

# What this device keeps about a group beside its state and history.

pub fn group_record_labels(group_id :: Bytes) -> List<String> do
  [group_anchor_label(group_id), "presentation/v1/group/" <> Bytes.to_hex(group_id)]
end

pub fn store_group_anchor(database_path :: String,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes,
  account :: Bytes) -> Result<(), String> do
  let label = group_anchor_label(group_id)
  store_updated_session(database_path,
    label,
    seal_local(account, wrapping_key, local_context(label)?)?)?
  Ok(nil)
end

fn load_group_anchor(database_path :: String,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes) -> Bytes!String do
  let label = group_anchor_label(group_id)
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
    Ok(blob) -> open_local(blob, wrapping_key, local_context(label)?)
  end
end

fn group_record_allowed(database_path :: String,
  wrapping_key :: borrow StorageKey,
  group_id :: Bytes,
  sender :: Bytes,
  creator :: Bytes,
  incoming :: Bytes) -> Bool!String do
  record_change_allowed(load_presentation_record(database_path,
      wrapping_key,
      group_record_key(group_id))?,
    incoming,
    sender,
    creator,
    load_group_anchor(database_path, wrapping_key, group_id)?)
end

fn presentation_label(key :: Bytes) -> String!String do
  let text = mobile_utf8(key, "invalid_presentation_key")?
  let parts = String.split(text, "/")
  if List.length(parts) != 2 do
    Err("invalid_presentation_key")
  else
    let kind = List.get(parts, 0)
    let id = List.get(parts, 1)
    if (kind != "user" && kind != "group" && kind != "nickname") || String.length(id) != 64 do
      Err("invalid_presentation_key")
    else
      let decoded = Bytes.from_hex(id)?
      if Bytes.to_hex(decoded) != id do
        Err("invalid_presentation_key")
      else
        Ok("presentation/v1/" <> text)
      end
    end
  end
end

pub fn load_presentation_record(database_path :: String,
  wrapping_key :: borrow StorageKey,
  key :: Bytes) -> Bytes!String do
  let label = presentation_label(key)?
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
    Ok(blob) -> open_local(blob, wrapping_key, local_context(label)?)
  end
end

fn save_record(database_path :: String,
  wrapping_key :: borrow StorageKey,
  key :: Bytes,
  data :: Bytes) -> Bytes!String do
  let label = presentation_label(key)?
  # Nicknames are device-local overrides. A single zero byte clears the override;
  # only user/group records are ever included by present_message.
  let nickname = String.starts_with(label, "presentation/v1/nickname/")
  let checked = if nickname && Bytes.secure_equals(data, Bytes.from_hex("00")?) do
    Bytes.empty()
  else
    presentation_data(data)?
  end
  let previous = load_presentation_record(database_path, wrapping_key, key)?
  if Bytes.secure_equals(previous, checked)
    || (!nickname
      && U64.compare(presentation_revision(previous)?, presentation_revision(checked)?) > 0) do
    Ok(previous)
  else
    store_updated_session(database_path,
      label,
      seal_local(checked, wrapping_key, local_context(label)?)?)?
    Ok(checked)
  end
end

pub fn load_presentation(request :: MobilePayloadRequest) -> Bytes!String do
  let wrapping_key = platform_key()?
  load_presentation_record(request.database_path, wrapping_key, request.payload)
end

pub fn save_presentation(request :: MobileTriplePayloadRequest) -> Bytes!String do
  let wrapping_key = platform_key()?
  save_record(request.database_path, wrapping_key, request.first, request.second)
end

pub fn encode_presented_message(body :: Bytes, profile :: Bytes, group :: Bytes) -> Bytes!String do
  encode_presented_message_with_attachment(body, profile, group, Bytes.empty())
end

# The trailing attachment vector is only written when present so older readers stay compatible.

pub fn encode_presented_message_with_attachment(body :: Bytes,
  profile :: Bytes,
  group :: Bytes,
  attachment :: Bytes) -> Bytes!String do
  presentation_data(profile)?
  if Bytes.length(group) > 0 do
    presentation_data(group)?
  else
    Bytes.empty()
  end
  let head = mobile_join([
      Bytes.from_utf8("MORSE-PRESENTATION/1\n"),
      mobile_vector(body)?,
      mobile_vector(profile)?,
      mobile_vector(group)?
    ],
    0,
    Bytes.empty())?
  if Bytes.length(attachment) == 0 do
    Ok(head)
  else
    mobile_join([head, mobile_vector(attachment)?], 0, Bytes.empty())
  end
end

fn decode_presented_message(input :: Bytes) -> Result<(Bytes, Bytes, Bytes, Bytes), String> do
  let state = mobile_reader(input, 65342, "invalid_presentation")?
  let body = take_vector(state, 40000)?
  let profile = take_vector(body.state, 12500)?
  let group = take_vector(profile.state, 29340)?
  let attachment = take_optional_vector(group.state, 65536, "invalid_presentation")?
  mobile_finish(attachment.state, "invalid_presentation")?
  presentation_data(profile.value)?
  if Bytes.length(group.value) > 0 do
    presentation_data(group.value)?
  else
    Bytes.empty()
  end
  Ok((body.value, profile.value, group.value, attachment.value))
end

# Return the body, the attachment envelope, and encrypted writes for the caller's transaction.

pub fn presented_message_writes(database_path :: String,
  wrapping_key :: borrow StorageKey,
  sender_id :: Bytes,
  group_id :: Bytes,
  creator_id :: Bytes,
  input :: Bytes) -> Result<(Bytes, Bytes, List<String>, List<Bytes>), String> do
  let prefix = Bytes.from_utf8("MORSE-PRESENTATION/1\n")
  if Bytes.length(input) < Bytes.length(prefix) do
    Ok((input, Bytes.empty(), [], []))
  else
    let head = Bytes.slice(input, 0, Bytes.length(prefix))?
    if !Bytes.secure_equals(head, prefix) do
      Ok((input, Bytes.empty(), [], []))
    else
      let encoded = Bytes.slice(input,
        Bytes.length(prefix),
        Bytes.length(input) - Bytes.length(prefix))?
      case decode_presented_message(encoded) do
        Err(_) -> Ok((input, Bytes.empty(), [], []))
        Ok(value) -> do
          let (body, profile, group, attachment) = value
          let (user_labels, user_blobs) = presentation_update(database_path,
            wrapping_key,
            Bytes.from_utf8("user/" <> Bytes.to_hex(sender_id)),
            profile)?
          if Bytes.length(group_id) == 32
            && Bytes.length(group) > 0
            && group_record_allowed(database_path,
              wrapping_key,
              group_id,
              sender_id,
              creator_id,
              group)? do
            let (group_labels, group_blobs) = presentation_update(database_path,
              wrapping_key,
              Bytes.from_utf8("group/" <> Bytes.to_hex(group_id)),
              group)?
            Ok((body,
              attachment,
              List.concat(user_labels, group_labels),
              List.concat(user_blobs, group_blobs)))
          else
            Ok((body, attachment, user_labels, user_blobs))
          end
        end
      end
    end
  end
end

fn presentation_update(database_path :: String,
  wrapping_key :: borrow StorageKey,
  key :: Bytes,
  data :: Bytes) -> Result<(List<String>, List<Bytes>), String> do
  let label = presentation_label(key)?
  let previous = load_presentation_record(database_path, wrapping_key, key)?
  if Bytes.secure_equals(previous, data)
    || U64.compare(presentation_revision(previous)?, presentation_revision(data)?) > 0 do
    Ok(([], []))
  else
    Ok(([label], [seal_local(data, wrapping_key, local_context(label)?)?]))
  end
end

# ponytail: omit metadata on maximum-size text; use separate profile announcements if those messages must sync photos.

pub fn present_message(database_path :: String, group_id :: Bytes, body :: Bytes) -> Bytes!String do
  present_message_with_attachment(database_path, group_id, body, Bytes.empty())
end

# An attachment envelope makes framing mandatory: dropping it would silently lose the file.

pub fn present_message_with_attachment(database_path :: String,
  group_id :: Bytes,
  body :: Bytes,
  attachment :: Bytes) -> Bytes!String do
  let local = decode_client_profile(load_profile(database_path)?)?
  let wrapping_key = platform_key()?
  let saved = load_presentation_record(database_path,
    wrapping_key,
    Bytes.from_utf8("user/" <> Bytes.to_hex(local.account_id)))?
  let profile = if Bytes.length(saved) > 0 do
    saved
  else
    mobile_join([mobile_vector(Bytes.from_utf8(local.username))?, mobile_vector(Bytes.empty())?],
      0,
      Bytes.empty())?
  end
  let group = if Bytes.length(group_id) == 32 do
    load_presentation_record(database_path,
      wrapping_key,
      Bytes.from_utf8("group/" <> Bytes.to_hex(group_id)))?
  else
    Bytes.empty()
  end
  let presented = encode_presented_message_with_attachment(body, profile, group, attachment)?
  let maximum = if Bytes.length(group_id) == 0 do
    32000
  else
    65342
  end
  if Bytes.length(attachment) > 0 do
    if Bytes.length(presented) > maximum || Bytes.length(body) > 40000 do
      Err("message_too_large")
    else
      Ok(presented)
    end
  else if Bytes.length(presented) > maximum || Bytes.length(body) > 40000 do
    Ok(body)
  else
    Ok(presented)
  end
end

pub fn presented_body(input :: Bytes) -> Bytes do
  let prefix = Bytes.from_utf8("MORSE-PRESENTATION/1\n")
  if Bytes.length(input) < Bytes.length(prefix) do
    return input
  end
  case Bytes.slice(input, 0, Bytes.length(prefix)) do
    Err(_) -> input
    Ok(head) -> if !Bytes.secure_equals(head, prefix) do
      input
    else
      case Bytes.slice(input, Bytes.length(prefix), Bytes.length(input) - Bytes.length(prefix)) do
        Err(_) -> input
        Ok(encoded) -> case decode_presented_message(encoded) do
          Err(_) -> input
          Ok(value) -> do
            let (body, profile, group, attachment) = value
            body
          end
        end
      end
    end
  end
end

fn presentation_revision(input :: Bytes) -> U64!String do
  if Bytes.length(input) == 0 do
    mobile_wide("0")
  else
    Ok(presentation_fields(input)?.revision)
  end
end
