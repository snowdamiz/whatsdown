from Identity.Device import (
  AccountKeys,
  DeviceKeys,
  IdentityError,
  authorize_device_link,
  issue_account_deletion,
  issue_device_departure,
  issue_device_revocation,
  verify_account_deletion,
  verify_device_departure,
  verify_device_revocation,
  issue_hybrid_device_credential,
  verify_device_link_authorization
)
from Mobile.Codec import (
  current_time,
  encode_output_list,
  mobile_byte,
  mobile_join,
  mobile_utf8,
  mobile_vector,
  mobile_wide,
  mobile_write_u64,
  random_bytes
)
from Mobile.DeviceSet import (
  cached_device_set_changed,
  contains_device_id,
  device_set_label,
  local_device_set,
  verified_device_set
)
from Mobile.Prekeys import seal_active_prekey_pool, seal_prekey_pool, seal_prekey_wide
from Mobile.Profile import (
  account_keys,
  device_keys,
  directory_bytes,
  load_profile,
  open_account,
  open_device,
  open_pending_device,
  open_pending_post_quantum_prekey
)
from Mobile.Transparency import require_transparency_device_set
from Mobile.Types import (
  MobileAccountRequest,
  MobileOneTimePrekey,
  MobilePayloadRequest,
  MobileTriplePayloadRequest,
  MobileVerifiedDeviceSet
)
from Prekeys.Bundle import (
  OneTimePrekeySecrets,
  PostQuantumPrekeySecrets,
  PrekeyError,
  SignedPrekeySecrets,
  build_hybrid_prekey_bundle,
  generate_one_time_prekey,
  generate_post_quantum_prekey,
  generate_signed_prekey
)
from Protocol.DirectoryWire import (
  decode_account_deletion,
  decode_device_departure,
  decode_device_link_authorization,
  decode_device_link_request,
  decode_device_revocation,
  decode_directory_entry,
  encode_account_deletion,
  encode_device_departure,
  encode_device_link_authorization,
  encode_device_link_request,
  encode_device_revocation,
  encode_directory_lookup
)
from Protocol.IdentityWire import (
  decode_account_identity,
  decode_device_credential,
  encode_account_identity
)
from Protocol.MailboxWire import sign_mailbox_fetch
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import (
  AccountIdentity,
  DeviceCredential,
  DeviceLinkAuthorization,
  DeviceLinkRequest,
  DeviceSet,
  DirectoryEntry,
  PrekeyBundle
)
from Mobile.InboxState import load_fetch_cursor
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import (
  context,
  local_context,
  one_time_prekey_label,
  open_local,
  pending_context,
  platform_key,
  seal_local,
  seal_mlkem,
  seal_signing,
  seal_x25519
)
from Storage.Records import (
  ensure_account_missing,
  erase_local_state,
  store_blobs,
  store_linked_blobs,
  store_new_account,
  store_updated_session
)
from Transport.Packet import ClientProfile, decode_client_profile, encode_client_profile

##! Mobile.Account implementation.

pub fn create_account(request :: MobileAccountRequest) -> Bytes!String do
  let database_path = mobile_utf8(request.database_path, "invalid_database_path")?
  let username = mobile_utf8(request.username, "invalid_username")?
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_account_request")
  else
    let created_at = mobile_wide(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))?
    let expires_at = U64.add(created_at, mobile_wide("31536000000")?)?
    ensure_schema(database_path)?
    ensure_account_missing(database_path)?
    let (account, identity) = account_keys(created_at)?
    let device = device_keys()?
    let post_quantum = case generate_post_quantum_prekey() do
      Err(_) -> Err("post_quantum_prekey_generation_failed")
      Ok(value)
    end?
    let credential = case issue_hybrid_device_credential(account,
      device,
      post_quantum.public_key,
      mobile_wide("1")?,
      created_at,
      expires_at,
      mobile_wide("1")?) do
      Err(_) -> Err("credential_generation_failed")
      Ok(value)
    end?
    let signed = case generate_signed_prekey(device, credential, mobile_wide("1")?, expires_at) do
      Err(_) -> Err("prekey_generation_failed")
      Ok(value)
    end?
    let one_time = case generate_one_time_prekey(mobile_wide("2")?) do
      Err(_) -> Err("prekey_generation_failed")
      Ok(value)
    end?
    let bundle = case build_hybrid_prekey_bundle(credential, signed, one_time, post_quantum) do
      Err(_) -> Err("prekey_bundle_failed")
      Ok(value)
    end?
    let account_wire = case encode_account_identity(identity) do
      Err(_) -> Err("account_encoding_failed")
      Ok(value)
    end?
    let bundle_wire = case encode_prekey_bundle(bundle) do
      Err(_) -> Err("prekey_encoding_failed")
      Ok(value)
    end?
    let mailbox_token = case Crypto.random_bytes(32) do
      Err(_) -> Err("mailbox_generation_failed")
      Ok(value)
    end?
    let entry = DirectoryEntry {
      version: 1,
      username: username,
      account_identity: account_wire,
      prekey_bundle: bundle_wire,
      mailbox_token: mailbox_token
    }
    let profile = encode_client_profile(entry, identity.account_id, credential.device_id)?
    let wrapping_key = platform_key()?
    let account_blob = case seal_signing(account.private_key,
      wrapping_key,
      context(identity.account_id, credential.device_id, "account-signing-key/v1", 6)?) do
      Err(_) -> Err("account_key_seal_failed")
      Ok(value)
    end?
    let device_signing_blob = case seal_signing(device.signing_private_key,
      wrapping_key,
      context(identity.account_id, credential.device_id, "device-signing-key/v1", 7)?) do
      Err(_) -> Err("device_signing_key_seal_failed")
      Ok(value)
    end?
    let device_identity_blob = case seal_x25519(device.identity_private_key,
      wrapping_key,
      context(identity.account_id, credential.device_id, "device-identity-key/v1", 8)?) do
      Err(_) -> Err("device_identity_key_seal_failed")
      Ok(value)
    end?
    let signed_prekey_blob = case seal_x25519(signed.private_key,
      wrapping_key,
      context(identity.account_id, credential.device_id, "signed-prekey/v1", 9)?) do
      Err(_) -> Err("signed_prekey_seal_failed")
      Ok(value)
    end?
    let one_time_label = one_time_prekey_label(one_time.id)
    let one_time_prekey_blob = case seal_x25519(one_time.private_key,
      wrapping_key,
      context(identity.account_id, credential.device_id, one_time_label, 10)?) do
      Err(_) -> Err("one_time_prekey_seal_failed")
      Ok(value)
    end?
    let post_quantum_prekey_blob = case seal_mlkem(post_quantum.private_key,
      wrapping_key,
      context(identity.account_id, credential.device_id, "post-quantum-prekey/v1", 15)?) do
      Err(_) -> Err("post_quantum_prekey_seal_failed")
      Ok(value)
    end?
    let profile_blob = seal_local(profile, wrapping_key, local_context("profile/v1")?)?
    let prekey_index_blob = seal_prekey_pool([
        MobileOneTimePrekey { id: one_time.id, public_key: one_time.public_key.bytes }
      ],
      wrapping_key)?
    let prekey_active_blob = seal_active_prekey_pool([one_time.id], wrapping_key)?
    let prekey_next_id_blob = seal_prekey_wide("one-time-prekey-next-id/v1",
      U64.add(one_time.id, mobile_wide("1")?)?,
      wrapping_key)?
    store_new_account(database_path,
      [
        "account-signing-key/v1",
        "device-signing-key/v1",
        "device-identity-key/v1",
        "signed-prekey/v1",
        one_time_label,
        "post-quantum-prekey/v1",
        "profile/v1",
        "one-time-prekeys/v1",
        "one-time-prekey-active/v1",
        "one-time-prekey-next-id/v1"
      ],
      [
        account_blob,
        device_signing_blob,
        device_identity_blob,
        signed_prekey_blob,
        one_time_prekey_blob,
        post_quantum_prekey_blob,
        profile_blob,
        prekey_index_blob,
        prekey_active_blob,
        prekey_next_id_blob
      ])?
    Ok(profile)
  end
end

fn link_request_bytes(value :: DeviceLinkRequest) -> Bytes!String do
  case encode_device_link_request(value) do
    Err(_) -> Err("link_request_encoding_failed")
    Ok(encoded)
  end
end

fn parse_link_request(input :: Bytes) -> DeviceLinkRequest!String do
  case decode_device_link_request(input) do
    Err(_) -> Err("invalid_link_request")
    Ok(value) -> if Bytes.secure_equals(link_request_bytes(value)?, input) do
      Ok(value)
    else
      Err("noncanonical_link_request")
    end
  end
end

fn link_authorization_bytes(value :: DeviceLinkAuthorization) -> Bytes!String do
  case encode_device_link_authorization(value) do
    Err(_) -> Err("link_authorization_encoding_failed")
    Ok(encoded)
  end
end

fn parse_link_authorization(input :: Bytes) -> DeviceLinkAuthorization!String do
  case decode_device_link_authorization(input) do
    Err(_) -> Err("invalid_link_authorization")
    Ok(value) -> if Bytes.secure_equals(link_authorization_bytes(value)?, input) do
      Ok(value)
    else
      Err("noncanonical_link_authorization")
    end
  end
end

fn load_pending_link_request(database_path :: String, wrapping_key :: borrow StorageKey) -> Bytes!String do
  open_local(load_blob(database_path, "pending-link-request/v1")?,
    wrapping_key,
    local_context("pending-link-request/v1")?)
end

pub fn create_device_link_request(database_path :: String) -> Bytes!String do
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    ensure_schema(database_path)?
    ensure_account_missing(database_path)?
    let wrapping_key = platform_key()?
    case load_pending_link_request(database_path, wrapping_key) do
      Ok(existing) -> do
        let pending = parse_link_request(existing)?
        if U64.compare(pending.expires_at, current_time()?) >= 0 do
          Ok(existing)
        else
          store_linked_blobs(database_path, List.new(), List.new())?
          create_device_link_request(database_path)
        end
      end
      Err(error) -> if error != "local_state_not_found" do
        Err(error)
      else
        let now = current_time()?
        let device = device_keys()?
        let post_quantum = case generate_post_quantum_prekey() do
          Err(_) -> Err("post_quantum_prekey_generation_failed")
          Ok(value)
        end?
        let request = DeviceLinkRequest {
          version: 2,
          suite: 2,
          nonce: random_bytes(32)?,
          device_id: device.device_id,
          signing_public_key: device.signing_public_key.bytes,
          dh_public_key: device.identity_public_key.bytes,
          post_quantum_public_key: post_quantum.public_key.bytes,
          capabilities: mobile_wide("1")?,
          created_at: now,
          expires_at: U64.add(now, mobile_wide("600000")?)?
        }
        let request_wire = link_request_bytes(request)?
        let request_blob = seal_local(request_wire,
          wrapping_key,
          local_context("pending-link-request/v1")?)?
        let signing_blob = seal_signing(device.signing_private_key,
          wrapping_key,
          pending_context("pending-device-signing-key/v1", 7)?)?
        let identity_blob = seal_x25519(device.identity_private_key,
          wrapping_key,
          pending_context("pending-device-identity-key/v1", 8)?)?
        let post_quantum_blob = seal_mlkem(post_quantum.private_key,
          wrapping_key,
          pending_context("pending-post-quantum-prekey/v1", 15)?)?
        store_blobs(database_path,
          [
            "pending-link-request/v1",
            "pending-device-signing-key/v1",
            "pending-device-identity-key/v1",
            "pending-post-quantum-prekey/v1"
          ],
          [request_blob, signing_blob, identity_blob, post_quantum_blob])?
        Ok(request_wire)
      end
    end
  end
end

pub fn authorize_link(request :: MobilePayloadRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let local = decode_client_profile(load_profile(request.database_path)?)?
  let requested_device = parse_link_request(request.payload)?
  let now = current_time()?
  if U64.compare(requested_device.created_at, now) > 0 || U64.compare(requested_device.expires_at,
    now) < 0 do
    Err("link_request_expired")
  else
    let wrapping_key = platform_key()?
    let account = open_account(local, wrapping_key, request.database_path)?
    let authorization = case authorize_device_link(account,
      local.account,
      requested_device,
      local.username,
      U64.add(now, mobile_wide("31536000000")?)?,
      U64.add(local.account.directory_sequence, mobile_wide("1")?)?) do
      Err(_) -> Err("link_authorization_failed")
      Ok(value)
    end?
    link_authorization_bytes(authorization)
  end
end

pub fn complete_link(request :: MobilePayloadRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  ensure_account_missing(request.database_path)?
  let authorization = parse_link_authorization(request.payload)?
  let wrapping_key = platform_key()?
  let pending_wire = load_pending_link_request(request.database_path, wrapping_key)?
  let pending = parse_link_request(pending_wire)?
  let now = current_time()?
  let valid = case verify_device_link_authorization(pending, authorization, now, mobile_wide("1")?) do
    Err(_) -> Err("link_authorization_failed")
    Ok(value)
  end?
  if !valid do
    Err("link_authorization_failed")
  else
    let account = case decode_account_identity(authorization.account_identity) do
      Err(_) -> Err("invalid_link_authorization")
      Ok(value)
    end?
    let credential = case decode_device_credential(authorization.device_credential) do
      Err(_) -> Err("invalid_link_authorization")
      Ok(value)
    end?
    let device = open_pending_device(pending, wrapping_key, request.database_path)?
    let signed = case generate_signed_prekey(device,
      credential,
      mobile_wide("1")?,
      credential.expires_at) do
      Err(_) -> Err("prekey_generation_failed")
      Ok(value)
    end?
    let one_time = case generate_one_time_prekey(mobile_wide("2")?) do
      Err(_) -> Err("prekey_generation_failed")
      Ok(value)
    end?
    let post_quantum = open_pending_post_quantum_prekey(pending,
      wrapping_key,
      request.database_path)?
    let bundle = case build_hybrid_prekey_bundle(credential, signed, one_time, post_quantum) do
      Err(_) -> Err("prekey_bundle_failed")
      Ok(value)
    end?
    let entry = DirectoryEntry {
      version: 1,
      username: authorization.username,
      account_identity: authorization.account_identity,
      prekey_bundle: case encode_prekey_bundle(bundle) do
        Err(_) -> Err("prekey_encoding_failed")
        Ok(value)
      end?,
      mailbox_token: random_bytes(32)?
    }
    let profile = encode_client_profile(entry, account.account_id, credential.device_id)?
    let signing_blob = seal_signing(device.signing_private_key,
      wrapping_key,
      context(account.account_id, credential.device_id, "device-signing-key/v1", 7)?)?
    let identity_blob = seal_x25519(device.identity_private_key,
      wrapping_key,
      context(account.account_id, credential.device_id, "device-identity-key/v1", 8)?)?
    let signed_prekey_blob = seal_x25519(signed.private_key,
      wrapping_key,
      context(account.account_id, credential.device_id, "signed-prekey/v1", 9)?)?
    let one_time_label = one_time_prekey_label(one_time.id)
    let one_time_prekey_blob = seal_x25519(one_time.private_key,
      wrapping_key,
      context(account.account_id, credential.device_id, one_time_label, 10)?)?
    let post_quantum_prekey_blob = seal_mlkem(post_quantum.private_key,
      wrapping_key,
      context(account.account_id, credential.device_id, "post-quantum-prekey/v1", 15)?)?
    let profile_blob = seal_local(profile, wrapping_key, local_context("profile/v1")?)?
    let prekey_index_blob = seal_prekey_pool([
        MobileOneTimePrekey { id: one_time.id, public_key: one_time.public_key.bytes }
      ],
      wrapping_key)?
    let prekey_active_blob = seal_active_prekey_pool([one_time.id], wrapping_key)?
    let prekey_next_id_blob = seal_prekey_wide("one-time-prekey-next-id/v1",
      U64.add(one_time.id, mobile_wide("1")?)?,
      wrapping_key)?
    store_new_account(request.database_path,
      [
        "device-signing-key/v1",
        "device-identity-key/v1",
        "signed-prekey/v1",
        one_time_label,
        "post-quantum-prekey/v1",
        "profile/v1",
        "one-time-prekeys/v1",
        "one-time-prekey-active/v1",
        "one-time-prekey-next-id/v1"
      ],
      [
        signing_blob,
        identity_blob,
        signed_prekey_blob,
        one_time_prekey_blob,
        post_quantum_prekey_blob,
        profile_blob,
        prekey_index_blob,
        prekey_active_blob,
        prekey_next_id_blob
      ])?
    Ok(profile)
  end
end

pub fn device_link_sas(input :: Bytes) -> Bytes!String do
  let request = parse_link_request(input)?
  let digest = Crypto.sha256(link_request_bytes(request)?)
  case Bytes.slice(digest, 0, 6) do
    Err(_) -> Err("link_sas_failed")
    Ok(value) -> Ok(Bytes.from_utf8(Bytes.to_hex(value)))
  end
end

fn active_device_rows(profiles :: List<ClientProfile>,
  local_device_id :: Bytes,
  index :: Int,
  rows :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(profiles) do
    Ok(rows)
  else
    let profile = List.get(profiles, index)
    let row = mobile_join([
        mobile_vector(profile.device_id)?,
        mobile_vector(mobile_byte(1)?)?,
        mobile_vector(mobile_byte(if Bytes.secure_equals(profile.device_id, local_device_id) do
          1
        else
          0
        end)?)?
      ],
      0,
      Bytes.empty())?
    active_device_rows(profiles, local_device_id, index + 1, List.append(rows, row))
  end
end

fn revoked_device_rows(values :: List<Bytes>, index :: Int, rows :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(values) do
    Ok(rows)
  else
    let row = mobile_join([
        mobile_vector(List.get(values, index))?,
        mobile_vector(mobile_byte(0)?)?,
        mobile_vector(mobile_byte(0)?)?
      ],
      0,
      Bytes.empty())?
    revoked_device_rows(values, index + 1, List.append(rows, row))
  end
end

pub fn inspect_device_set(request :: MobilePayloadRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let local = decode_client_profile(load_profile(request.database_path)?)?
  let verified = verified_device_set(request.payload)?
  let wrapping_key = platform_key()?
  require_transparency_device_set(request.database_path, wrapping_key, verified)?
  let label = device_set_label(verified.account.account_id)
  let changed = cached_device_set_changed(request.database_path, wrapping_key, verified, label)?
  let sealed = seal_local(verified.wire, wrapping_key, local_context(label)?)?
  store_updated_session(request.database_path, label, sealed)?
  let can_manage = case load_blob(request.database_path, "account-signing-key/v1") do
    Err(error) -> if error == "local_state_not_found" do
      Ok(false)
    else
      Err(error)
    end
    Ok(_) -> Ok(true)
  end?
  let active = active_device_rows(verified.profiles, local.device_id, 0, List.new())?
  let rows = revoked_device_rows(verified.value.revoked_device_ids, 0, active)?
  mobile_join([
      mobile_vector(Bytes.from_utf8(verified.value.username))?,
      mobile_vector(verified.account.account_id)?,
      mobile_vector(mobile_write_u64(verified.value.sequence)?)?,
      mobile_vector(mobile_byte(if changed do
        1
      else
        0
      end)?)?,
      mobile_vector(mobile_byte(if can_manage do
        1
      else
        0
      end)?)?,
      mobile_vector(encode_output_list(rows)?)?
    ],
    0,
    Bytes.empty())
end

pub fn authorize_link_for_set(request :: MobileTriplePayloadRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let local = decode_client_profile(load_profile(request.database_path)?)?
  let devices = verified_device_set(request.first)?
  let wrapping_key = platform_key()?
  require_transparency_device_set(request.database_path, wrapping_key, devices)?
  let requested_device = parse_link_request(request.second)?
  let now = current_time()?
  if !local_device_set(local, devices) || U64.compare(requested_device.created_at, now) > 0 || U64.compare(requested_device.expires_at,
    now) < 0 do
    Err("link_authorization_failed")
  else
    let account = open_account(local, wrapping_key, request.database_path)?
    let authorization = case authorize_device_link(account,
      local.account,
      requested_device,
      local.username,
      U64.add(now, mobile_wide("31536000000")?)?,
      U64.add(devices.value.sequence, mobile_wide("1")?)?) do
      Err(_) -> Err("link_authorization_failed")
      Ok(value)
    end?
    link_authorization_bytes(authorization)
  end
end

pub fn create_device_revocation(request :: MobileTriplePayloadRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let local = decode_client_profile(load_profile(request.database_path)?)?
  let devices = verified_device_set(request.first)?
  let wrapping_key = platform_key()?
  require_transparency_device_set(request.database_path, wrapping_key, devices)?
  let target = request.second
  let allowed = Bytes.length(target) == 16 && local_device_set(local, devices) && List.length(devices.profiles) > 1 && contains_device_id(devices.profiles,
    target,
    0) && !Bytes.secure_equals(local.device_id, target)
  if !allowed do
    Err("invalid_device_revocation")
  else
    let account = open_account(local, wrapping_key, request.database_path)?
    let revocation = case issue_device_revocation(account,
      target,
      U64.add(devices.value.sequence, mobile_wide("1")?)?) do
      Err(_) -> Err("invalid_device_revocation")
      Ok(value)
    end?
    case encode_device_revocation(revocation) do
      Err(_) -> Err("invalid_device_revocation")
      Ok(encoded)
    end
  end
end

## The statement that deletes this account from the directory, signed now.
## Empty on a linked device: only the device that created the account holds the
## account key, so a linked device can erase only its own copy.

pub fn account_deletion(database_path :: String) -> Bytes!String do
  let profile = decode_client_profile(load_profile(database_path)?)?
  case load_blob(database_path, "account-signing-key/v1") do
    Err(error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
    Ok(_) -> do
      let wrapping_key = platform_key()?
      let account = open_account(profile, wrapping_key, database_path)?
      let deletion = case issue_account_deletion(account, current_time()?) do
        Err(_) -> Err("account_deletion_failed")
        Ok(value)
      end?
      case encode_account_deletion(deletion) do
        Err(_) -> Err("account_deletion_failed")
        Ok(encoded)
      end
    end
  end
end

pub fn erase_account(database_path :: String) -> Bytes!String do
  erase_local_state(database_path)?
  Ok(Bytes.empty())
end

## The statement that takes this device out of its account, signed now by the
## device's own key: a linked device sends it before it erases itself, so that
## no one goes on sending to a device that is gone.

pub fn device_departure(database_path :: String) -> Bytes!String do
  let profile = decode_client_profile(load_profile(database_path)?)?
  let wrapping_key = platform_key()?
  let device = open_device(profile, wrapping_key, database_path)?
  let departure = case issue_device_departure(device, profile.account_id, current_time()?) do
    Err(_) -> Err("device_departure_failed")
    Ok(value)
  end?
  case encode_device_departure(departure) do
    Err(_) -> Err("device_departure_failed")
    Ok(encoded)
  end
end

fn proven(result :: Result<Bool, IdentityError>) -> Bool do
  case result do
    Err(_) -> false
    Ok(valid) -> valid
  end
end

fn deletion_proven(profile :: ClientProfile, statement :: Bytes) -> Bool do
  case decode_account_deletion(statement) do
    Err(_) -> false
    Ok(deletion) -> proven(verify_account_deletion(profile.account, deletion))
  end
end

fn revocation_proven(profile :: ClientProfile, statement :: Bytes) -> Bool do
  case decode_device_revocation(statement) do
    Err(_) -> false
    Ok(revocation) -> do
      let this_device = Bytes.secure_equals(revocation.device_id, profile.device_id)
      this_device && proven(verify_device_revocation(profile.account, revocation))
    end
  end
end

fn departure_proven(profile :: ClientProfile, statement :: Bytes) -> Bool do
  case decode_device_departure(statement) do
    Err(_) -> false
    Ok(departure) -> do
      let this_device = Bytes.secure_equals(departure.account_id, profile.account_id) && Bytes.secure_equals(departure.device_id,
        profile.device_id)
      let own_key = profile.credential.signing_public_key
      this_device && proven(verify_device_departure(own_key, departure))
    end
  end
end

## What a statement proves about this device: 1 its account was deleted with the
## account key, 2 the account key removed this device, 3 this device left on its
## own key. 0 when it proves none of them.

fn removal_kind(profile :: ClientProfile, statement :: Bytes) -> Int do
  if deletion_proven(profile, statement) do
    1
  else if revocation_proven(profile, statement) do
    2
  else if departure_proven(profile, statement) do
    3
  else
    0
  end
end

## Erases this device's copy of its account when the directory says the device
## no longer belongs to it, but only on signed proof, and answers which one. A
## claim that does not verify against the keys this device knows changes nothing.

pub fn forget_on_proof(request :: MobilePayloadRequest) -> Bytes!String do
  let profile = decode_client_profile(load_profile(request.database_path)?)?
  let kind = removal_kind(profile, request.payload)
  if kind == 0 do
    Err("unproven_removal")
  else
    erase_local_state(request.database_path)?
    mobile_byte(kind)
  end
end

pub fn import_contact(input :: Bytes) -> Bytes!String do
  let entry = case decode_directory_entry(input) do
    Err(_) -> Err("invalid_directory_entry")
    Ok(value)
  end?
  let account = case decode_account_identity(entry.account_identity) do
    Err(_) -> Err("invalid_directory_entry")
    Ok(value)
  end?
  let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
    Err(_) -> Err("invalid_directory_entry")
    Ok(value)
  end?
  let credential = case decode_device_credential(bundle.device_credential) do
    Err(_) -> Err("invalid_directory_entry")
    Ok(value)
  end?
  let profile = encode_client_profile(entry, account.account_id, credential.device_id)?
  decode_client_profile(profile)?
  Ok(profile)
end

pub fn directory_entry_for(database_path :: String) -> Bytes!String do
  let profile = decode_client_profile(load_profile(database_path)?)?
  directory_bytes(profile.entry)
end

pub fn directory_lookup(input :: Bytes) -> Bytes!String do
  let username = mobile_utf8(input, "invalid_username")?
  case encode_directory_lookup(username) do
    Err(_) -> Err("invalid_username")
    Ok(encoded)
  end
end

## A fresh fetch statement signed by this device. The same frame authorizes the
## mailbox stream; the published mailbox address alone authorizes neither.

pub fn mailbox_fetch(database_path :: String) -> Bytes!String do
  let profile = decode_client_profile(load_profile(database_path)?)?
  let wrapping_key = platform_key()?
  let device = open_device(profile, wrapping_key, database_path)?
  # Past whatever the current pass has set aside, so that it cannot hold up the
  # envelopes behind it; zero otherwise.
  case sign_mailbox_fetch(device.signing_private_key,
    Crypto.sha256(profile.entry.mailbox_token),
    load_fetch_cursor(database_path, wrapping_key)?,
    current_time()?) do
    Err(_) -> Err("mailbox_fetch_encoding_failed")
    Ok(encoded)
  end
end
