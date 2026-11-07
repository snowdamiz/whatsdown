from Storage.Blobs import load_blob
from Mobile.Profile import directory_bytes
from Storage.Keys import local_context, seal_local, open_local
from Transport.Packet import ClientProfile, decode_client_profile

# Modes are local durable intent: 1 paid draft, 2 explicitly selected free
# registration, 3 verified completed signup. Missing marker is a legacy account.
pub fn seal_signup_draft(profile :: Bytes,
  mode :: Int,
  wrapping :: borrow StorageKey) -> Bytes!String do
  let value = decode_client_profile(profile)?
  if mode < 1 || mode > 3 do
    return Err("invalid_signup_draft")
  end
  let tag = case Bytes.from_list([1, 83, 68, 70, mode]) do
    Err(_) -> return Err("invalid_signup_draft")
    Ok(value) -> value
  end
  let identity = Bytes.concat(Bytes.concat(tag, value.account_id)?, value.device_id)?
  let payload = Bytes.concat(identity, Crypto.sha256(directory_bytes(value.entry)?))?
  seal_local(payload, wrapping, local_context("signup-draft/v1")?)
end

pub fn open_signup_draft(blob :: Bytes,
  profile :: ClientProfile,
  wrapping :: borrow StorageKey) -> Int!String do
  let value = open_local(blob, wrapping, local_context("signup-draft/v1")?)?
  if Bytes.length(value) != 85
    || Bytes.to_hex(Bytes.slice(value, 0, 4)?) != "01534446"
    || !Bytes.secure_equals(Bytes.slice(value, 5, 32)?, profile.account_id)
    || !Bytes.secure_equals(Bytes.slice(value, 37, 16)?, profile.device_id) do
    return Err("invalid_signup_draft")
  end
  let mode = Bytes.get(value, 4)?
  if mode < 1
    || mode > 3
    || (mode != 3
      && !Bytes.secure_equals(Bytes.slice(value, 53, 32)?,
        Crypto.sha256(directory_bytes(profile.entry)?))) do
    return Err("invalid_signup_draft")
  end
  Ok(mode)
end

pub struct SignupDraftSnapshot do
  profile :: ClientProfile
  encoded_profile :: Bytes
  profile_blob :: Bytes
  draft_blob :: Bytes
  mode :: Int
end

pub fn load_signup_draft(path :: String,
  wrapping :: borrow StorageKey) -> SignupDraftSnapshot!String do
  let profile_blob = load_blob(path, "profile/v1")?
  let encoded = open_local(profile_blob, wrapping, local_context("profile/v1")?)?
  let profile = decode_client_profile(encoded)?
  let draft = case load_blob(path, "signup-draft/v1") do
    Err("local_state_not_found") -> Bytes.empty()
    Err(error) -> return Err(error)
    Ok(value) -> value
  end
  Ok(SignupDraftSnapshot {
    profile: profile,
    encoded_profile: encoded,
    profile_blob: profile_blob,
    draft_blob: draft,
    mode: if Bytes.length(draft) == 0 do
      0
    else
      open_signup_draft(draft, profile, wrapping)?
    end
  })
end
