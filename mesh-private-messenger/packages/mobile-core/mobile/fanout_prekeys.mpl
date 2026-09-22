from Mobile.Codec import current_time, encode_output_list, mobile_wide, random_bytes
from Mobile.DeviceSet import local_device_set, verified_device_set
from Mobile.Platform import stamped_request
from Mobile.Profile import load_profile
from Mobile.Sessions import device_needs_prekey, load_session_ids
from Mobile.Transparency import require_transparency_device_set
from Mobile.Types import (
  MobileClaimedPrekey,
  MobileFanoutPrekeyReservationRequest,
  MobileFanoutPrepareRequest,
  MobileFanoutTargetsRequest,
  MobileVerifiedDeviceSet
)
from Prekeys.Bundle import PrekeyError, normalize_prekey_bundle, verify_prekey_bundle
from Prekeys.Pool import PrekeyClaimRequest, decode_prekey_claim, encode_prekey_claim
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import AccountIdentity, DeviceCredential, DeviceSet, DirectoryEntry, PrekeyBundle
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import local_context, open_local, platform_key, seal_local
from Storage.Records import store_updated_blobs
from Transport.Packet import ClientProfile, decode_client_profile, encode_client_profile

##! Mobile.FanoutPrekeys implementation.

fn fanout_base_profiles(profiles :: List < ClientProfile >, index :: Int) -> Bool do
  if index >= List.length(profiles) do
    true
  else
    let profile = List.get(profiles, index)
    case normalize_prekey_bundle(profile.bundle) do
      Err(_) -> false
      Ok(normalized) -> case encode_prekey_bundle(normalized) do
        Err(_) -> false
        Ok(encoded) -> Bytes.secure_equals(encoded, profile.entry.prekey_bundle) && fanout_base_profiles(profiles,
        index + 1)
      end
    end
  end
end

pub fn invalid_fanout_sets(local :: ClientProfile,
peers :: MobileVerifiedDeviceSet,
local_devices :: MobileVerifiedDeviceSet) -> Bool do
  !local_device_set(local, local_devices) || Bytes.secure_equals(local.account_id,
  peers.account.account_id) || List.length(peers.profiles) == 0 || !fanout_base_profiles(peers.profiles,
  0) || !fanout_base_profiles(local_devices.profiles, 0)
end

fn append_missing_prekey_claims(database_path :: String,
wrapping_key :: borrow StorageKey,
session_ids :: List < Bytes >,
profiles :: List < ClientProfile >,
local_device_id :: Bytes,
skip_local_device :: Bool,
now :: U64,
index :: Int,
claims :: List < Bytes >) -> List < Bytes > ! String do
  if index >= List.length(profiles) do
    Ok(claims)
  else
    let profile = List.get(profiles, index)
    if skip_local_device && Bytes.secure_equals(profile.device_id, local_device_id) do
      append_missing_prekey_claims(database_path,
      wrapping_key,
      session_ids,
      profiles,
      local_device_id,
      skip_local_device,
      now,
      index + 1,
      claims)
    else
      if !(device_needs_prekey(database_path, wrapping_key, session_ids, profile) ?) do
        append_missing_prekey_claims(database_path,
        wrapping_key,
        session_ids,
        profiles,
        local_device_id,
        skip_local_device,
        now,
        index + 1,
        claims)
      else
        case load_fanout_prekey_reservation(database_path, wrapping_key, profile, now) do
          Err(error) -> Err(error)
          Ok(Some(_)) -> append_missing_prekey_claims(database_path,
          wrapping_key,
          session_ids,
          profiles,
          local_device_id,
          skip_local_device,
          now,
          index + 1,
          claims)
          Ok(None) -> do
            let claim = case load_fanout_prekey_claim(database_path, wrapping_key, profile) do
              Err(error) -> Err(error)
              Ok(Some(value)) -> Ok(value)
              Ok(None) -> create_fanout_prekey_claim(database_path, wrapping_key, profile)
            end ?
            append_missing_prekey_claims(database_path,
            wrapping_key,
            session_ids,
            profiles,
            local_device_id,
            skip_local_device,
            now,
            index + 1,
            List.append(claims, claim))
          end
        end
      end
    end
  end
end

fn fanout_prekey_claim_values(request :: MobileFanoutTargetsRequest) -> List < Bytes > ! String do
  ensure_schema(request.database_path) ?
  let local = decode_client_profile(load_profile(request.database_path) ?) ?
  let peers = verified_device_set(request.peer_device_set) ?
  let local_devices = verified_device_set(request.local_device_set) ?
  if invalid_fanout_sets(local, peers, local_devices) do
    Err("invalid_fanout_device_set")
  else
    let wrapping_key = platform_key() ?
    let _ = require_transparency_device_set(request.database_path, wrapping_key, peers) ?
    let _ = require_transparency_device_set(request.database_path, wrapping_key, local_devices) ?
    let session_ids = load_session_ids(request.database_path, wrapping_key) ?
    let now = current_time() ?
    let peer_claims = append_missing_prekey_claims(request.database_path,
    wrapping_key,
    session_ids,
    peers.profiles,
    local.device_id,
    false,
    now,
    0,
    List.new()) ?
    append_missing_prekey_claims(request.database_path,
    wrapping_key,
    session_ids,
    local_devices.profiles,
    local.device_id,
    true,
    now,
    0,
    peer_claims)
  end
end

pub fn fanout_prekey_claims(request :: MobileFanoutTargetsRequest) -> Bytes ! String do
  encode_output_list(fanout_prekey_claim_values(request) ?)
end

fn fanout_prekey_bundle(input :: Bytes) -> PrekeyBundle ! String do
  case decode_prekey_bundle(input) do
    Err(_) -> Err("invalid_fanout_prekeys")
    Ok(bundle) -> case encode_prekey_bundle(bundle) do
      Err(_) -> Err("invalid_fanout_prekeys")
      Ok(encoded) -> if Bytes.secure_equals(encoded, input) do
        Ok(bundle)
      else
        Err("invalid_fanout_prekeys")
      end
    end
  end
end

fn fanout_prekey_base(bundle :: PrekeyBundle) -> Bytes ! String do
  let normalized = case normalize_prekey_bundle(bundle) do
    Err(_) -> Err("invalid_fanout_prekeys")
    Ok(value) -> Ok(value)
  end ?
  case encode_prekey_bundle(normalized) do
    Err(_) -> Err("invalid_fanout_prekeys")
    Ok(value) -> Ok(value)
  end
end

pub fn fanout_prekey_reservation_label(profile :: ClientProfile) -> String do
  "fanout-prekey-reservation/v1/#{Bytes.to_hex(profile.account_id)}/#{Bytes.to_hex(profile.device_id)}"
end

pub fn fanout_prekey_claim_label(profile :: ClientProfile) -> String do
  "fanout-prekey-claim/v1/#{Bytes.to_hex(profile.account_id)}/#{Bytes.to_hex(profile.device_id)}"
end

pub fn matching_fanout_prekey_state_labels(database_path :: String,
wrapping_key :: borrow StorageKey,
profile :: ClientProfile,
accepted_suite :: Int) -> List < String > ! String do
  let reservation_label = fanout_prekey_reservation_label(profile)
  case load_blob(database_path, reservation_label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(List.new())
    else
      Err(error)
    end
    Ok(blob) -> do
      let reserved = fanout_prekey_bundle(open_local(blob,
      wrapping_key,
      local_context(reservation_label) ?) ?) ?
      if accepted_suite >= reserved.suite && Bytes.secure_equals(fanout_prekey_base(reserved) ?,
      fanout_prekey_base(profile.bundle) ?) do
        Ok([reservation_label, fanout_prekey_claim_label(profile)])
      else
        Ok(List.new())
      end
    end
  end
end

fn load_fanout_prekey_claim(database_path :: String,
wrapping_key :: borrow StorageKey,
profile :: ClientProfile) -> Option < Bytes > ! String do
  let label = fanout_prekey_claim_label(profile)
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(None)
    else
      Err(error)
    end
    Ok(blob) -> do
      let input = open_local(blob, wrapping_key, local_context(label) ?) ?
      let claim = case decode_prekey_claim(input) do
        Err(_) -> Err("invalid_fanout_prekeys")
        Ok(value) -> Ok(value)
      end ?
      if !Bytes.secure_equals(claim.account_id, profile.account_id) || !Bytes.secure_equals(claim.device_id,
      profile.device_id) do
        Err("invalid_fanout_prekeys")
      else if !Bytes.secure_equals(claim.base_bundle_hash,
      Crypto.sha256(profile.entry.prekey_bundle)) do
        Ok(None)
      else
        Ok(Some(input))
      end
    end
  end
end

fn create_fanout_prekey_claim(database_path :: String,
wrapping_key :: borrow StorageKey,
profile :: ClientProfile) -> Bytes ! String do
  let claim = encode_prekey_claim(PrekeyClaimRequest {
    account_id : profile.account_id,
    device_id : profile.device_id,
    base_bundle_hash : Crypto.sha256(profile.entry.prekey_bundle),
    reservation_id : random_bytes(16) ?
  }) ?
  let label = fanout_prekey_claim_label(profile)
  store_updated_blobs(database_path,
  [label],
  [seal_local(claim, wrapping_key, local_context(label) ?) ?]) ?
  Ok(claim)
end

pub fn load_fanout_prekey_reservation(database_path :: String,
wrapping_key :: borrow StorageKey,
profile :: ClientProfile,
now :: U64) -> Option < MobileClaimedPrekey > ! String do
  let label = fanout_prekey_reservation_label(profile)
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(None)
    else
      Err(error)
    end
    Ok(blob) -> do
      let input = open_local(blob, wrapping_key, local_context(label) ?) ?
      let bundle = fanout_prekey_bundle(input) ?
      if !Bytes.secure_equals(fanout_prekey_base(bundle) ?, profile.entry.prekey_bundle) do
        Ok(None)
      else
        Ok(Some(validate_claimed_prekey(input, [profile], List.new(), Bytes.empty(), now) ?))
      end
    end
  end
end

fn store_fanout_prekey_reservation(database_path :: String,
wrapping_key :: borrow StorageKey,
claim :: MobileClaimedPrekey,
now :: U64) -> Result <(), String > do
  let profile = claim.profile
  let label = fanout_prekey_reservation_label(profile)
  case load_fanout_prekey_reservation(database_path, wrapping_key, profile, now) do
    Err(error) -> Err(error)
    Ok(Some(existing)) -> if Bytes.secure_equals(existing.profile.entry.prekey_bundle,
    claim.profile.entry.prekey_bundle) do
      Ok(nil)
    else
      Err("prekey_reservation_exists")
    end
    Ok(None) -> store_updated_blobs(database_path,
    [label],
    [seal_local(claim.profile.entry.prekey_bundle, wrapping_key, local_context(label) ?) ?])
  end
end

fn store_fanout_prekey_reservations(database_path :: String,
wrapping_key :: borrow StorageKey,
claims :: List < MobileClaimedPrekey >,
now :: U64,
index :: Int) -> Result <(), String > do
  if index >= List.length(claims) do
    Ok(nil)
  else
    store_fanout_prekey_reservation(database_path, wrapping_key, List.get(claims, index), now) ?
    store_fanout_prekey_reservations(database_path, wrapping_key, claims, now, index + 1)
  end
end

pub fn fanout_prekey_reservation_labels(claims :: List < MobileClaimedPrekey >,
index :: Int,
labels :: List < String >) -> List < String > do
  if index >= List.length(claims) do
    labels
  else
    let profile = List.get(claims, index).profile
    fanout_prekey_reservation_labels(claims,
    index + 1,
    List.append(List.append(labels, fanout_prekey_reservation_label(profile)),
    fanout_prekey_claim_label(profile)))
  end
end

fn count_prekey_targets(profiles :: List < ClientProfile >,
base_bundle :: Bytes,
local_device_id :: Bytes,
skip_local_device :: Bool,
index :: Int,
count :: Int) -> Int do
  if index >= List.length(profiles) do
    count
  else
    let profile = List.get(profiles, index)
    let matches = !(skip_local_device && Bytes.secure_equals(profile.device_id, local_device_id)) && Bytes.secure_equals(profile.entry.prekey_bundle,
    base_bundle)
    count_prekey_targets(profiles,
    base_bundle,
    local_device_id,
    skip_local_device,
    index + 1,
    if matches do
      count + 1
    else
      count
    end)
  end
end

fn find_prekey_target(profiles :: List < ClientProfile >,
base_bundle :: Bytes,
local_device_id :: Bytes,
skip_local_device :: Bool,
index :: Int) -> ClientProfile ! String do
  if index >= List.length(profiles) do
    Err("invalid_fanout_prekeys")
  else
    let profile = List.get(profiles, index)
    if !(skip_local_device && Bytes.secure_equals(profile.device_id, local_device_id)) && Bytes.secure_equals(profile.entry.prekey_bundle,
    base_bundle) do
      Ok(profile)
    else
      find_prekey_target(profiles, base_bundle, local_device_id, skip_local_device, index + 1)
    end
  end
end

fn claimed_prekey_exists(claims :: List < MobileClaimedPrekey >, base_bundle :: Bytes, index :: Int) -> Bool do
  if index >= List.length(claims) do
    false
  else if Bytes.secure_equals(List.get(claims, index).base_bundle, base_bundle) do
    true
  else
    claimed_prekey_exists(claims, base_bundle, index + 1)
  end
end

pub fn claimed_prekey_profile(claims :: List < MobileClaimedPrekey >,
base_bundle :: Bytes,
index :: Int) -> ClientProfile ! String do
  if index >= List.length(claims) do
    Err("invalid_fanout_prekeys")
  else
    let claim = List.get(claims, index)
    if Bytes.secure_equals(claim.base_bundle, base_bundle) do
      Ok(claim.profile)
    else
      claimed_prekey_profile(claims, base_bundle, index + 1)
    end
  end
end

fn validate_claimed_prekey(input :: Bytes,
peers :: List < ClientProfile >,
local_devices :: List < ClientProfile >,
local_device_id :: Bytes,
now :: U64) -> MobileClaimedPrekey ! String do
  let bundle = fanout_prekey_bundle(input) ?
  if U64.compare(bundle.one_time_prekey_id, mobile_wide("0") ?) <= 0 || Bytes.length(bundle.one_time_prekey) != 32 do
    Err("invalid_fanout_prekeys")
  else
    let base_bundle = fanout_prekey_base(bundle) ?
    let peer_count = count_prekey_targets(peers, base_bundle, local_device_id, false, 0, 0)
    let local_count = count_prekey_targets(local_devices, base_bundle, local_device_id, true, 0, 0)
    if peer_count + local_count != 1 do
      Err("invalid_fanout_prekeys")
    else
      let target = if peer_count == 1 do
        find_prekey_target(peers, base_bundle, local_device_id, false, 0) ?
      else
        find_prekey_target(local_devices, base_bundle, local_device_id, true, 0) ?
      end
      let valid = case verify_prekey_bundle(target.account,
      bundle,
      1,
      now,
      target.account.directory_sequence) do
        Err(_) -> false
        Ok(value) -> value
      end
      if !valid do
        Err("invalid_fanout_prekeys")
      else
        let claimed_entry = % {target.entry | prekey_bundle : input }
        let encoded_profile = case encode_client_profile(claimed_entry,
        target.account_id,
        target.device_id) do
          Err(_) -> Err("invalid_fanout_prekeys")
          Ok(value) -> Ok(value)
        end ?
        let claimed_profile = case decode_client_profile(encoded_profile) do
          Err(_) -> Err("invalid_fanout_prekeys")
          Ok(value) -> Ok(value)
        end ?
        Ok(MobileClaimedPrekey {
          base_bundle : base_bundle,
          profile : claimed_profile
        })
      end
    end
  end
end

fn validate_claimed_prekeys(inputs :: List < Bytes >,
peers :: List < ClientProfile >,
local_devices :: List < ClientProfile >,
local_device_id :: Bytes,
now :: U64,
index :: Int,
claims :: List < MobileClaimedPrekey >) -> List < MobileClaimedPrekey > ! String do
  if index >= List.length(inputs) do
    Ok(claims)
  else
    let claim = validate_claimed_prekey(List.get(inputs, index),
    peers,
    local_devices,
    local_device_id,
    now) ?
    if claimed_prekey_exists(claims, claim.base_bundle, 0) do
      Err("invalid_fanout_prekeys")
    else
      validate_claimed_prekeys(inputs,
      peers,
      local_devices,
      local_device_id,
      now,
      index + 1,
      List.append(claims, claim))
    end
  end
end

fn require_claimed_prekeys_needed(database_path :: String,
wrapping_key :: borrow StorageKey,
session_ids :: List < Bytes >,
claims :: List < MobileClaimedPrekey >,
index :: Int) -> Result <(), String > do
  if index >= List.length(claims) do
    Ok(nil)
  else
    let profile = List.get(claims, index).profile
    if device_needs_prekey(database_path, wrapping_key, session_ids, profile) ? do
      require_claimed_prekeys_needed(database_path, wrapping_key, session_ids, claims, index + 1)
    else
      Err("invalid_fanout_prekeys")
    end
  end
end

pub fn reserve_fanout_prekey(request :: MobileFanoutPrekeyReservationRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local = decode_client_profile(load_profile(request.database_path) ?) ?
  let peers = verified_device_set(request.peer_device_set) ?
  let local_devices = verified_device_set(request.local_device_set) ?
  if invalid_fanout_sets(local, peers, local_devices) do
    Err("invalid_fanout_device_set")
  else
    let wrapping_key = platform_key() ?
    let _ = require_transparency_device_set(request.database_path, wrapping_key, peers) ?
    let _ = require_transparency_device_set(request.database_path, wrapping_key, local_devices) ?
    let now = current_time() ?
    let claims = validate_claimed_prekeys([request.claimed_prekey],
    peers.profiles,
    local_devices.profiles,
    local.device_id,
    now,
    0,
    List.new()) ?
    require_claimed_prekeys_needed(request.database_path,
    wrapping_key,
    load_session_ids(request.database_path, wrapping_key) ?,
    claims,
    0) ?
    store_fanout_prekey_reservations(request.database_path, wrapping_key, claims, now, 0) ?
    Ok(Bytes.empty())
  end
end

fn fetch_fanout_prekey(directory_url :: String, claim :: Bytes) -> Bytes ! String do
  let stamped = stamped_request("mesh-msg/v1/work/prekey-claim", claim) ?
  let response = case (Http.build(:post, directory_url <> "/v1/prekeys/bundle")
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Cache-Control", "no-store")
    |> Http.body_bytes(stamped)
    |> Http.timeout(8000)
    |> Http.max_response_bytes(19312)
    |> Http.max_redirects(0)
    |> Http.send()) do
    Err(error) -> if String.contains(error, "RESPONSE_TOO_LARGE") do
      Err("prekey_claim_too_large")
    else
      Err("prekey_claim_failed")
    end
    Ok(value) -> Ok(value)
  end ?
  if response.status != 200 do
    Err("prekey_claim_failed")
  else if Map.get(response.headers, "cache-control") != "no-store" do
    Err("prekey_claim_cache_policy_invalid")
  else
    Ok(response.body_bytes)
  end
end

fn prepare_fanout_prekey_claims(request :: MobileFanoutPrepareRequest,
claims :: List < Bytes >,
index :: Int) -> Result <(), String > do
  if index >= List.length(claims) do
    Ok(nil)
  else
    let claimed_prekey = fetch_fanout_prekey(request.directory_url, List.get(claims, index)) ?
    let _ = reserve_fanout_prekey(MobileFanoutPrekeyReservationRequest {
      database_path : request.database_path,
      peer_device_set : request.peer_device_set,
      local_device_set : request.local_device_set,
      claimed_prekey : claimed_prekey
    }) ?
    prepare_fanout_prekey_claims(request, claims, index + 1)
  end
end

pub fn prepare_fanout_prekeys(request :: MobileFanoutPrepareRequest) -> Bytes ! String do
  let claims = fanout_prekey_claim_values(MobileFanoutTargetsRequest {
    database_path : request.database_path,
    peer_device_set : request.peer_device_set,
    local_device_set : request.local_device_set
  }) ?
  prepare_fanout_prekey_claims(request, claims, 0) ?
  Ok(Bytes.empty())
end
