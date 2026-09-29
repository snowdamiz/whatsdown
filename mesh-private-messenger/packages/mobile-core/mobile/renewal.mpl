from Identity.Device import VerificationPolicy, issue_renewed_device_credential
from Mobile.Codec import (
  current_time,
  mobile_byte,
  mobile_join,
  mobile_read_byte,
  mobile_read_u32,
  mobile_read_u64,
  mobile_vector,
  mobile_wide,
  mobile_write_u64,
  mobile_zeroes
)
from Mobile.DeviceSet import account_device_profiles, bundle_lapses_at, local_device_set, verified_device_set
from Mobile.Platform import stamped_request
from Mobile.Profile import directory_bytes, load_profile, open_account, open_device, open_post_quantum_prekey
from Mobile.Transparency import require_transparency_device_set
from Mobile.Types import MobileOneTimePrekey, MobilePayloadRequest
from Prekeys.Bundle import (
  OneTimePrekeySecrets,
  PostQuantumPrekeySecrets,
  SignedPrekeySecrets,
  generate_post_quantum_prekey,
  normalize_prekey_bundle
)
from Prekeys.Renewal import (
  RenewalRequest,
  bundle_renewal_request,
  bundle_with_renewal_request,
  decode_renewal_request,
  encode_renewal_request,
  generate_renewal_signed_prekey,
  issue_renewal_request,
  renewed_prekey_bundle,
  verify_renewal_request
)
from Mobile.Codec import encode_output_list
from Protocol.IdentityWire import decode_device_credential
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import PrekeyBundle
from Session.Handshake import initial_message_uses_bundle
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import (
  context,
  local_context,
  one_time_prekey_context,
  one_time_prekey_label,
  open_local,
  open_mlkem,
  open_x25519,
  platform_key,
  seal_local,
  seal_mlkem,
  seal_x25519
)
from Storage.Records import store_record_changes
from Transport.Packet import ClientProfile, decode_client_profile, encode_client_profile

##! Mobile.Renewal: renewing this device's credential, signed prekey and ML-KEM
##! prekey before they expire, and answering linked devices that ask.
##!
##! All three live in the logged device set, so every renewal is a logged
##! transition, and this device only ever takes on what the verified set shows.
##! Until then a renewal is pending: offered to the directory again on every
##! pass, and already able to open mail. A replaced bundle is kept, secrets and
##! all, until 35 days after the directory showed its successor, because a first
##! message sealed to it can wait up to 31 days in a mailbox.

fn credential_lifetime() -> U64!String do
  mobile_wide("31536000000")
end

# Renew once fewer than 275 days are left: ninety days into a one-year
# credential, which leaves nine months for a device that is seldom opened.

fn renewal_margin() -> U64!String do
  mobile_wide("23760000000")
end

fn retirement_grace() -> U64!String do
  mobile_wide("3024000000")
end

fn signed_prekey_label(id :: U64) -> String do
  "signed-prekey/v1/#{U64.to_string(id)}"
end

fn post_quantum_prekey_label(id :: U64) -> String do
  "post-quantum-prekey/v1/#{U64.to_string(id)}"
end

# A bundle this device published besides the one its profile names: one the
# directory has not shown yet (pending), or one it has replaced (retired),
# kept until confirmed_at plus the grace period.

struct KeptBundle do
  pending :: Bool
  confirmed_at :: U64
  bundle :: Bytes
end

fn encode_kept(values :: List<KeptBundle>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(values) do
    Ok(output)
  else
    let value = List.get(values, index)
    let state = if value.pending do
      1
    else
      0
    end
    encode_kept(values,
      index + 1,
      mobile_join([
          output,
          mobile_byte(state)?,
          mobile_write_u64(value.confirmed_at)?,
          mobile_vector(value.bundle)?
        ],
        0,
        Bytes.empty())?)
  end
end

fn decode_kept(input :: Bytes, offset :: Int, output :: List<KeptBundle>) -> List<KeptBundle>!String do
  if offset >= Bytes.length(input) do
    Ok(output)
  else
    let state = mobile_read_byte(Bytes.slice(input, offset, 1)?)?
    let confirmed_at = mobile_read_u64(Bytes.slice(input, offset + 1, 8)?)?
    let length = mobile_read_u32(Bytes.slice(input, offset + 9, 4)?)?
    if state > 1 || length <= 0 || length > 19312 do
      Err("invalid_kept_prekey_bundles")
    else
      decode_kept(input,
        offset + 13 + length,
        List.append(output,
          KeptBundle {
            pending: state == 1,
            confirmed_at: confirmed_at,
            bundle: Bytes.slice(input, offset + 13, length)?
          }))
    end
  end
end

fn sealed_state(path :: String, wrapping_key :: borrow StorageKey, label :: String) -> Option<Bytes>!String do
  case load_blob(path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(None)
    else
      Err(error)
    end
    Ok(blob) -> Ok(Some(open_local(blob, wrapping_key, local_context(label)?)?))
  end
end

fn load_kept(path :: String, wrapping_key :: borrow StorageKey) -> List<KeptBundle>!String do
  case sealed_state(path, wrapping_key, "prekey-bundles/v1")? do
    None -> Ok(List.new())
    Some(encoded) -> decode_kept(encoded, 0, List.new())
  end
end

fn kept_blob(values :: List<KeptBundle>, wrapping_key :: borrow StorageKey) -> Bytes!String do
  seal_local(encode_kept(values, 0, Bytes.empty())?,
    wrapping_key,
    local_context("prekey-bundles/v1")?)
end

# What a linked device asked the account key for, until it is answered.

fn load_request(path :: String, wrapping_key :: borrow StorageKey) -> Option<RenewalRequest>!String do
  case sealed_state(path, wrapping_key, "renewal-request/v1")? do
    None -> Ok(None)
    Some(encoded) -> case decode_renewal_request(encoded) do
      Err(_) -> Err("invalid_renewal_request")
      Ok(value) -> Ok(Some(value))
    end
  end
end

fn prekey_bundle(input :: Bytes) -> PrekeyBundle!String do
  case decode_prekey_bundle(input) do
    Err(_) -> Err("invalid_prekey_bundle")
    Ok(value)
  end
end

fn bundle_bytes(value :: PrekeyBundle) -> Bytes!String do
  case encode_prekey_bundle(value) do
    Err(_) -> Err("invalid_prekey_bundle")
    Ok(encoded)
  end
end

fn normalized(value :: PrekeyBundle) -> PrekeyBundle!String do
  case normalize_prekey_bundle(value) do
    Err(_) -> Err("invalid_prekey_bundle")
    Ok(output)
  end
end

fn normalized_bytes(value :: PrekeyBundle) -> Bytes!String do
  bundle_bytes(normalized(value)?)
end

fn holds_account_key(path :: String) -> Bool!String do
  case load_blob(path, "account-signing-key/v1") do
    Err(error) -> if error == "local_state_not_found" do
      Ok(false)
    else
      Err(error)
    end
    Ok(_) -> Ok(true)
  end
end

# Secrets. Those of the bundle a profile names were first stored under fixed
# labels; every other generation is stored by its signed-prekey identifier,
# which also names its ML-KEM prekey.

fn open_signed_secret(profile :: ClientProfile,
  wrapping_key :: borrow StorageKey,
  path :: String,
  id :: U64) -> X25519PrivateKey!String do
  let label = signed_prekey_label(id)
  case load_blob(path, label) do
    Ok(blob) -> open_x25519(blob, wrapping_key, context(profile.account_id, profile.device_id, label, 9)?)
    Err(error) -> if error == "local_state_not_found" && U64.compare(id,
      profile.bundle.signed_prekey_id) == 0 do
      open_x25519(load_blob(path, "signed-prekey/v1")?,
        wrapping_key,
        context(profile.account_id, profile.device_id, "signed-prekey/v1", 9)?)
    else
      Err(error)
    end
  end
end

fn open_bundle_post_quantum(profile :: ClientProfile,
  wrapping_key :: borrow StorageKey,
  path :: String,
  bundle :: PrekeyBundle) -> PostQuantumPrekeySecrets!String do
  let label = post_quantum_prekey_label(bundle.signed_prekey_id)
  case load_blob(path, label) do
    Ok(blob) -> do
      let private_key = open_mlkem(blob,
        wrapping_key,
        context(profile.account_id, profile.device_id, label, 15)?)?
      Ok(PostQuantumPrekeySecrets {
        private_key: private_key,
        public_key: MlKemPublicKey { bytes: bundle.post_quantum_prekey }
      })
    end
    Err(error) -> if error != "local_state_not_found" do
      Err(error)
    else if U64.compare(bundle.signed_prekey_id, profile.bundle.signed_prekey_id) == 0 do
      open_post_quantum_prekey(profile, wrapping_key, path)
    else if bundle.suite == 1 do
      # A classical bundle has no ML-KEM prekey; the handshake never uses this.
      case generate_post_quantum_prekey() do
        Err(_) -> Err("post_quantum_prekey_generation_failed")
        Ok(value)
      end
    else
      Err(error)
    end
  end
end

fn reject_bundle_open(signed_private :: consume X25519PrivateKey, error :: String) -> Result<(SignedPrekeySecrets, OneTimePrekeySecrets, PostQuantumPrekeySecrets), String> do
  Err(error)
end

fn reject_bundle_post_quantum(signed_private :: consume X25519PrivateKey,
  one_time_private :: consume X25519PrivateKey,
  error :: String) -> Result<(SignedPrekeySecrets, OneTimePrekeySecrets, PostQuantumPrekeySecrets), String> do
  Err(error)
end

## The secrets behind a bundle this device published, with the one-time prekey
## a first message names.

pub fn open_bundle_prekeys(profile :: ClientProfile,
  wrapping_key :: borrow StorageKey,
  path :: String,
  bundle :: PrekeyBundle,
  selected :: MobileOneTimePrekey) -> Result<(SignedPrekeySecrets, OneTimePrekeySecrets, PostQuantumPrekeySecrets), String> do
  let one_time_blob = load_blob(path, one_time_prekey_label(selected.id))?
  let one_time_context = one_time_prekey_context(profile, selected.id)?
  case open_signed_secret(profile, wrapping_key, path, bundle.signed_prekey_id) do
    Err(error)
    Ok(signed_private) -> case open_x25519(one_time_blob, wrapping_key, one_time_context) do
      Err(error) -> reject_bundle_open(signed_private, error)
      Ok(one_time_private) -> case open_bundle_post_quantum(profile, wrapping_key, path, bundle) do
        Err(error) -> reject_bundle_post_quantum(signed_private, one_time_private, error)
        Ok(post_quantum) -> Ok((SignedPrekeySecrets {
            id: bundle.signed_prekey_id,
            private_key: signed_private,
            public_key: X25519PublicKey { bytes: bundle.signed_prekey },
            signature: Signature { bytes: bundle.signed_prekey_signature },
            expires_at: bundle.expires_at
          },
          OneTimePrekeySecrets {
            id: selected.id,
            private_key: one_time_private,
            public_key: X25519PublicKey { bytes: selected.public_key }
          },
          post_quantum))
      end
    end
  end
end

fn with_prekey(bundle :: PrekeyBundle, selected :: MobileOneTimePrekey) -> PrekeyBundle do
  %{bundle | one_time_prekey_id: selected.id, one_time_prekey: selected.public_key}
end

fn matching_bundle(candidates :: List<PrekeyBundle>,
  selected :: MobileOneTimePrekey,
  strongest_suite :: Int,
  message :: Bytes,
  index :: Int) -> Option<PrekeyBundle> do
  if index >= List.length(candidates) do
    None
  else
    let candidate = with_prekey(List.get(candidates, index), selected)
    if initial_message_uses_bundle(candidate, strongest_suite, message) do
      Some(candidate)
    else
      matching_bundle(candidates, selected, strongest_suite, message, index + 1)
    end
  end
end

fn kept_prekey_bundles(values :: List<KeptBundle>, index :: Int, output :: List<PrekeyBundle>) -> List<PrekeyBundle>!String do
  if index >= List.length(values) do
    Ok(output)
  else
    kept_prekey_bundles(values,
      index + 1,
      List.append(output, prekey_bundle(List.get(values, index).bundle)?))
  end
end

## The bundle a first message was sealed to: the one the profile names, one
## still pending, or one replaced recently enough that its mail may still come.
## A message that matches none is tried against the current bundle and fails
## there as before.

pub fn responder_prekey_bundle(path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  selected :: MobileOneTimePrekey,
  strongest_suite :: Int,
  message :: Bytes) -> PrekeyBundle!String do
  let current = normalized(local.bundle)?
  let candidates = List.concat([current],
    kept_prekey_bundles(load_kept(path, wrapping_key)?, 0, List.new())?)
  case matching_bundle(candidates, selected, strongest_suite, message, 0) do
    Some(found) -> Ok(found)
    None -> Ok(with_prekey(current, selected))
  end
end

## This device checks its own bundle as of when it was still valid: mail sealed
## just before a bundle ran out may arrive after.

pub fn own_bundle_policy(local :: ClientProfile, bundle :: PrekeyBundle, now :: U64) -> VerificationPolicy do
  let lapse = case decode_device_credential(bundle.device_credential) do
    Err(_) -> now
    Ok(credential) -> bundle_lapses_at(bundle, credential)
  end
  VerificationPolicy {
    current_time: if U64.compare(lapse, now) < 0 do
      lapse
    else
      now
    end,
    minimum_directory_sequence: local.account.directory_sequence
  }
end

fn find_own(profiles :: List<ClientProfile>, device_id :: Bytes, index :: Int) -> ClientProfile!String do
  if index >= List.length(profiles) do
    Err("renewal_device_missing")
  else if Bytes.secure_equals(List.get(profiles, index).device_id, device_id) do
    Ok(List.get(profiles, index))
  else
    find_own(profiles, device_id, index + 1)
  end
end

# The signed and ML-KEM public keys this device holds secrets for under one
# signed-prekey identifier.

struct HeldKeys do
  signed_prekey :: Bytes
  post_quantum_prekey :: Bytes
end

fn kept_generation(values :: List<KeptBundle>, id :: U64, index :: Int) -> Option<HeldKeys>!String do
  if index >= List.length(values) do
    Ok(None)
  else
    let candidate = prekey_bundle(List.get(values, index).bundle)?
    if U64.compare(candidate.signed_prekey_id, id) == 0 do
      Ok(Some(HeldKeys {
        signed_prekey: candidate.signed_prekey,
        post_quantum_prekey: candidate.post_quantum_prekey
      }))
    else
      kept_generation(values, id, index + 1)
    end
  end
end

fn requested_generation(asked :: Option<RenewalRequest>, id :: U64) -> Option<HeldKeys> do
  case asked do
    Some(request) -> if U64.compare(request.signed_prekey_id, id) == 0 do
      Some(HeldKeys {
        signed_prekey: request.signed_prekey,
        post_quantum_prekey: request.post_quantum_prekey
      })
    else
      None
    end
    None
  end
end

fn known_generation(local :: ClientProfile,
  kept :: List<KeptBundle>,
  asked :: Option<RenewalRequest>,
  id :: U64) -> Option<HeldKeys>!String do
  if U64.compare(id, local.bundle.signed_prekey_id) == 0 do
    Ok(Some(HeldKeys {
      signed_prekey: local.bundle.signed_prekey,
      post_quantum_prekey: local.bundle.post_quantum_prekey
    }))
  else
    case kept_generation(kept, id, 0)? do
      Some(found) -> Ok(Some(found))
      None -> Ok(requested_generation(asked, id))
    end
  end
end

fn holds_keys_of(held :: Option<HeldKeys>, bundle :: PrekeyBundle) -> Bool do
  case held do
    None -> false
    Some(keys) -> Bytes.secure_equals(keys.signed_prekey, bundle.signed_prekey) && (bundle.suite != 2 || Bytes.secure_equals(keys.post_quantum_prekey,
      bundle.post_quantum_prekey))
  end
end

fn request_signed_prekey_id(bundle :: PrekeyBundle) -> Option<U64> do
  case bundle_renewal_request(bundle) do
    Ok(Some(request)) -> Some(request.signed_prekey_id)
    _ -> None
  end
end

# Whether the directory's entry for this device is newer than the one its
# profile names: a newer credential, or under the same credential a (newer)
# renewal request. An older one is a rollback, never taken on.

fn newer_entry(local :: ClientProfile, logged :: ClientProfile) -> Bool do
  let order = U64.compare(logged.credential.directory_sequence, local.credential.directory_sequence)
  if order != 0 do
    order > 0
  else if !Bytes.secure_equals(logged.bundle.device_credential, local.bundle.device_credential) do
    false
  else
    case request_signed_prekey_id(logged.bundle) do
      None -> false
      Some(asked) -> case request_signed_prekey_id(local.bundle) do
        None -> true
        Some(previous) -> U64.compare(asked, previous) > 0
      end
    end
  end
end

fn kept_signed_prekey_ids(values :: List<KeptBundle>, index :: Int, output :: List<U64>) -> List<U64>!String do
  if index >= List.length(values) do
    Ok(output)
  else
    let bundle = prekey_bundle(List.get(values, index).bundle)?
    kept_signed_prekey_ids(values, index + 1, List.append(output, bundle.signed_prekey_id))
  end
end

fn signed_prekey_ids_in_use(local :: ClientProfile,
  kept :: List<KeptBundle>,
  asked :: Option<RenewalRequest>) -> List<U64>!String do
  let kept_ids = kept_signed_prekey_ids(kept, 0, List.new())?
  let with_current = List.append(kept_ids, local.bundle.signed_prekey_id)
  case asked do
    None -> Ok(with_current)
    Some(request) -> Ok(List.append(with_current, request.signed_prekey_id))
  end
end

fn contains_id(values :: List<U64>, id :: U64, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else if U64.compare(List.get(values, index), id) == 0 do
    true
  else
    contains_id(values, id, index + 1)
  end
end

fn secret_labels(ids :: List<U64>, in_use :: List<U64>, index :: Int, output :: List<String>) -> List<String> do
  if index >= List.length(ids) do
    output
  else
    let id = List.get(ids, index)
    if contains_id(in_use, id, 0) do
      secret_labels(ids, in_use, index + 1, output)
    else
      secret_labels(ids,
        in_use,
        index + 1,
        List.append(List.append(output, signed_prekey_label(id)), post_quantum_prekey_label(id)))
    end
  end
end

fn contains_bundle(values :: List<KeptBundle>, bundle :: Bytes, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else if Bytes.secure_equals(List.get(values, index).bundle, bundle) do
    true
  else
    contains_bundle(values, bundle, index + 1)
  end
end

fn past_grace(value :: KeptBundle, clock :: U64) -> Bool!String do
  if value.pending do
    Ok(false)
  else
    Ok(U64.compare(clock, U64.add(value.confirmed_at, retirement_grace()?)?) >= 0)
  end
end

# Replaced bundles whose grace has run out go, with every secret no remaining
# bundle or request needs. At most sixteen are kept; the oldest go first.

fn settled(local :: ClientProfile,
  kept :: List<KeptBundle>,
  asked :: Option<RenewalRequest>,
  clock :: U64) -> Result<(List<KeptBundle>, List<String>), String> do
  let remaining = List.filter(kept,
    fn (value) do
      case past_grace(value, clock) do
        Err(_) -> false
        Ok(expired) -> !expired
      end
    end)
  let bounded = if List.length(remaining) > 16 do
    List.drop(remaining, List.length(remaining) - 16)
  else
    remaining
  end
  let dropped = List.filter(kept, fn (value) do !contains_bundle(bounded, value.bundle, 0) end)
  let dropped_ids = kept_signed_prekey_ids(dropped, 0, List.new())?
  let in_use = signed_prekey_ids_in_use(local, bounded, asked)?
  Ok((bounded, secret_labels(dropped_ids, in_use, 0, List.new())))
end

fn settle(path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  kept :: List<KeptBundle>,
  asked :: Option<RenewalRequest>,
  clock :: U64) -> Result<(), String> do
  let (remaining, removed) = settled(local, kept, asked, clock)?
  if List.length(remaining) == List.length(kept) do
    Ok(nil)
  else
    store_record_changes(path, ["prekey-bundles/v1"], [kept_blob(remaining, wrapping_key)?], removed)
  end
end

# The secrets of the bundle a profile named before its first renewal sit under
# fixed labels. Before the profile moves on they move to labels by identifier.

fn legacy_secret_moves(local :: ClientProfile,
  wrapping_key :: borrow StorageKey,
  path :: String) -> Result<(List<String>, List<Bytes>, List<String>), String> do
  let id = local.bundle.signed_prekey_id
  let (signed_labels, signed_blobs, signed_removed) = case load_blob(path, "signed-prekey/v1") do
    Err(error) -> if error == "local_state_not_found" do
      Ok((List.new(), List.new(), List.new()))
    else
      Err(error)
    end
    Ok(blob) -> do
      let secret = open_x25519(blob,
        wrapping_key,
        context(local.account_id, local.device_id, "signed-prekey/v1", 9)?)?
      let label = signed_prekey_label(id)
      Ok(([label],
        [seal_x25519(secret, wrapping_key, context(local.account_id, local.device_id, label, 9)?)?],
        ["signed-prekey/v1"]))
    end
  end?
  case load_blob(path, "post-quantum-prekey/v1") do
    Err(error) -> if error == "local_state_not_found" do
      Ok((signed_labels, signed_blobs, signed_removed))
    else
      Err(error)
    end
    Ok(blob) -> do
      let secret = open_mlkem(blob,
        wrapping_key,
        context(local.account_id, local.device_id, "post-quantum-prekey/v1", 15)?)?
      let label = post_quantum_prekey_label(id)
      Ok((List.append(signed_labels, label),
        List.append(signed_blobs,
          seal_mlkem(secret, wrapping_key, context(local.account_id, local.device_id, label, 15)?)?),
        List.append(signed_removed, "post-quantum-prekey/v1")))
    end
  end
end

# A pending bundle may have been live before the one the directory now shows,
# so it is kept like any replaced bundle.

fn retire_pending(values :: List<KeptBundle>, now :: U64, index :: Int, output :: List<KeptBundle>) -> List<KeptBundle> do
  if index >= List.length(values) do
    output
  else
    let value = List.get(values, index)
    let kept = KeptBundle {
      pending: false,
      confirmed_at: if value.pending do
        now
      else
        value.confirmed_at
      end,
      bundle: value.bundle
    }
    retire_pending(values, now, index + 1, List.append(output, kept))
  end
end

# The directory now shows a newer entry for this device, built on keys it holds.
# The profile takes it; the bundle it named, and any other that may have been
# live, start their grace now.

fn adopt(path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  logged :: ClientProfile,
  kept :: List<KeptBundle>,
  asked :: Option<RenewalRequest>,
  now :: U64,
  clock :: U64) -> ClientProfile!String do
  let logged_bytes = normalized_bytes(logged.bundle)?
  let others = List.filter(kept, fn (value) do !Bytes.secure_equals(value.bundle, logged_bytes) end)
  let retired = retire_pending(others, now, 0, List.new())
  let with_previous = List.append(retired,
    KeptBundle {
      pending: false,
      confirmed_at: now,
      bundle: normalized_bytes(local.bundle)?
    })
  # A request the entry now answers is done with.
  let outstanding = case asked do
    None
    Some(request) -> if U64.compare(logged.bundle.signed_prekey_id, request.signed_prekey_id) >= 0 do
      None
    else
      Some(request)
    end
  end
  let profile_bytes = encode_client_profile(logged.entry, local.account_id, local.device_id)?
  let profile = decode_client_profile(profile_bytes)?
  let (moved_labels, moved_blobs, moved_removed) = legacy_secret_moves(local, wrapping_key, path)?
  let (remaining, destroyed) = settled(profile, with_previous, outstanding, clock)?
  let request_removed = case asked do
    None -> List.new()
    Some(_) -> case outstanding do
      None -> ["renewal-request/v1"]
      Some(_) -> List.new()
    end
  end
  store_record_changes(path,
    List.concat(moved_labels, ["profile/v1", "prekey-bundles/v1"]),
    List.concat(moved_blobs,
      [
        seal_local(profile_bytes, wrapping_key, local_context("profile/v1")?)?,
        kept_blob(remaining, wrapping_key)?
      ]),
    List.concat(List.concat(moved_removed, request_removed), destroyed))?
  Ok(profile)
end

fn reconcile(path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  logged :: ClientProfile,
  now :: U64,
  clock :: U64) -> ClientProfile!String do
  let kept = load_kept(path, wrapping_key)?
  let asked = load_request(path, wrapping_key)?
  if Bytes.secure_equals(normalized_bytes(local.bundle)?, normalized_bytes(logged.bundle)?) do
    settle(path, wrapping_key, local, kept, asked, clock)?
    Ok(local)
  else
    let same_keys = Bytes.secure_equals(logged.credential.signing_public_key,
      local.credential.signing_public_key) && Bytes.secure_equals(logged.credential.dh_public_key,
      local.credential.dh_public_key)
    let held = holds_keys_of(known_generation(local, kept, asked, logged.bundle.signed_prekey_id)?,
      logged.bundle)
    if !same_keys || !held || !newer_entry(local, logged) do
      Err("unrecognized_device_entry")
    else
      adopt(path, wrapping_key, local, logged, kept, asked, now, clock)
    end
  end
end

fn renewal_due(local :: ClientProfile, clock :: U64) -> Bool!String do
  Ok(U64.compare(bundle_lapses_at(local.bundle, local.credential), U64.add(clock, renewal_margin()?)?) < 0)
end

fn next_signed_prekey_id(local :: ClientProfile,
  kept :: List<KeptBundle>,
  asked :: Option<RenewalRequest>) -> U64!String do
  let ids = signed_prekey_ids_in_use(local, kept, asked)?
  let highest = List.reduce(ids,
    local.bundle.signed_prekey_id,
    fn (best, id) do
      if U64.compare(id, best) > 0 do
        id
      else
        best
      end
    end)
  U64.add(highest, mobile_wide("1")?)
end

fn pending_bundle(values :: List<KeptBundle>, index :: Int) -> Option<PrekeyBundle>!String do
  if index >= List.length(values) do
    Ok(None)
  else if List.get(values, index).pending do
    Ok(Some(prekey_bundle(List.get(values, index).bundle)?))
  else
    pending_bundle(values, index + 1)
  end
end

# One pending renewal at a time: a new one replaces any other.

fn with_pending(values :: List<KeptBundle>, bundle :: Bytes) -> List<KeptBundle>!String do
  let settled_values = List.filter(values, fn (value) do !value.pending end)
  Ok(List.append(settled_values,
    KeptBundle {
      pending: true,
      confirmed_at: mobile_wide("0")?,
      bundle: bundle
    }))
end

fn own_request_from(bundle :: PrekeyBundle) -> RenewalRequest!String do
  let credential = case decode_device_credential(bundle.device_credential) do
    Err(_) -> Err("invalid_prekey_bundle")
    Ok(value)
  end?
  Ok(RenewalRequest {
    version: 1,
    account_id: credential.account_id,
    device_id: credential.device_id,
    signed_prekey_id: bundle.signed_prekey_id,
    signed_prekey: bundle.signed_prekey,
    expires_at: bundle.expires_at,
    signed_prekey_signature: bundle.signed_prekey_signature,
    post_quantum_prekey: bundle.post_quantum_prekey,
    signature: mobile_zeroes(64)?
  })
end

fn renewed_entry(local :: ClientProfile, bundle :: PrekeyBundle) -> Bytes!String do
  directory_bytes(%{local.entry | prekey_bundle: bundle_bytes(bundle)?})
end

fn credential_answer(path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  previous :: ClientProfile,
  request :: RenewalRequest,
  now :: U64,
  sequence :: U64) -> PrekeyBundle!String do
  let account = open_account(local, wrapping_key, path)?
  let credential = case issue_renewed_device_credential(account,
    previous.credential,
    request.post_quantum_prekey,
    now,
    U64.add(now, credential_lifetime()?)?,
    sequence) do
    Err(_) -> Err("credential_renewal_failed")
    Ok(value)
  end?
  case renewed_prekey_bundle(credential, request) do
    Err(_) -> Err("credential_renewal_failed")
    Ok(value)
  end
end

# The device holding the account key renews itself in one transition. A
# renewal the directory has not shown yet is offered again, with a credential
# for the sequence the directory is at now.

fn own_account_renewal(path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  now :: U64,
  clock :: U64,
  sequence :: U64) -> Option<Bytes>!String do
  let kept = load_kept(path, wrapping_key)?
  case pending_bundle(kept, 0)? do
    Some(pending) -> do
      let pending_credential = case decode_device_credential(pending.device_credential) do
        Err(_) -> Err("invalid_prekey_bundle")
        Ok(value)
      end?
      if U64.compare(pending_credential.directory_sequence, sequence) == 0 do
        Ok(Some(renewed_entry(local, pending)?))
      else
        let rebased = credential_answer(path,
          wrapping_key,
          local,
          local,
          own_request_from(pending)?,
          now,
          sequence)?
        store_record_changes(path,
          ["prekey-bundles/v1"],
          [kept_blob(with_pending(kept, bundle_bytes(rebased)?)?, wrapping_key)?],
          List.new())?
        Ok(Some(renewed_entry(local, rebased)?))
      end
    end
    None -> if !(renewal_due(local, clock)?) do
      Ok(None)
    else
      let id = next_signed_prekey_id(local, kept, None)?
      let device = open_device(local, wrapping_key, path)?
      let signed = case generate_renewal_signed_prekey(device,
        local.credential,
        id,
        U64.add(now, credential_lifetime()?)?) do
        Err(_) -> Err("prekey_generation_failed")
        Ok(value)
      end?
      let post_quantum = case generate_post_quantum_prekey() do
        Err(_) -> Err("post_quantum_prekey_generation_failed")
        Ok(value)
      end?
      let request = case issue_renewal_request(device, local.credential, signed, post_quantum) do
        Err(_) -> Err("renewal_request_failed")
        Ok(value)
      end?
      let bundle = credential_answer(path, wrapping_key, local, local, request, now, sequence)?
      let signed_label = signed_prekey_label(id)
      let post_quantum_label = post_quantum_prekey_label(id)
      store_record_changes(path,
        [signed_label, post_quantum_label, "prekey-bundles/v1"],
        [
          seal_x25519(signed.private_key,
            wrapping_key,
            context(local.account_id, local.device_id, signed_label, 9)?)?,
          seal_mlkem(post_quantum.private_key,
            wrapping_key,
            context(local.account_id, local.device_id, post_quantum_label, 15)?)?,
          kept_blob(with_pending(kept, bundle_bytes(bundle)?)?, wrapping_key)?
        ],
        List.new())?
      Ok(Some(renewed_entry(local, bundle)?))
    end
  end
end

# A linked device asks in its own bundle, under the credential it has, for the
# signed prekey and ML-KEM prekey it has made for next time, and then waits for
# the account key to answer. Until the directory shows the request it is
# offered again.

fn linked_renewal(path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  now :: U64,
  clock :: U64) -> Option<Bytes>!String do
  let kept = load_kept(path, wrapping_key)?
  case load_request(path, wrapping_key)? do
    Some(asked) -> case request_signed_prekey_id(local.bundle) do
      Some(published) -> if U64.compare(published, asked.signed_prekey_id) == 0 do
        Ok(None)
      else
        ask_again(path, wrapping_key, local, kept, asked)
      end
      None -> ask_again(path, wrapping_key, local, kept, asked)
    end
    None -> if !(renewal_due(local, clock)?) do
      Ok(None)
    else
      let id = next_signed_prekey_id(local, kept, None)?
      let device = open_device(local, wrapping_key, path)?
      let signed = case generate_renewal_signed_prekey(device,
        local.credential,
        id,
        U64.add(now, credential_lifetime()?)?) do
        Err(_) -> Err("prekey_generation_failed")
        Ok(value)
      end?
      let post_quantum = case generate_post_quantum_prekey() do
        Err(_) -> Err("post_quantum_prekey_generation_failed")
        Ok(value)
      end?
      let request = case issue_renewal_request(device, local.credential, signed, post_quantum) do
        Err(_) -> Err("renewal_request_failed")
        Ok(value)
      end?
      let request_bytes = case encode_renewal_request(request) do
        Err(_) -> Err("renewal_request_failed")
        Ok(value)
      end?
      let asking = case bundle_with_renewal_request(normalized(local.bundle)?, request) do
        Err(_) -> Err("renewal_request_failed")
        Ok(value)
      end?
      let signed_label = signed_prekey_label(id)
      let post_quantum_label = post_quantum_prekey_label(id)
      store_record_changes(path,
        [signed_label, post_quantum_label, "renewal-request/v1", "prekey-bundles/v1"],
        [
          seal_x25519(signed.private_key,
            wrapping_key,
            context(local.account_id, local.device_id, signed_label, 9)?)?,
          seal_mlkem(post_quantum.private_key,
            wrapping_key,
            context(local.account_id, local.device_id, post_quantum_label, 15)?)?,
          seal_local(request_bytes, wrapping_key, local_context("renewal-request/v1")?)?,
          kept_blob(with_pending(kept, bundle_bytes(asking)?)?, wrapping_key)?
        ],
        List.new())?
      Ok(Some(renewed_entry(local, asking)?))
    end
  end
end

fn ask_again(path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  kept :: List<KeptBundle>,
  asked :: RenewalRequest) -> Option<Bytes>!String do
  if U64.compare(asked.signed_prekey_id, local.bundle.signed_prekey_id) <= 0 do
    # Answered already; the record outlived its answer.
    store_record_changes(path, List.new(), List.new(), ["renewal-request/v1"])?
    Ok(None)
  else
    let asking = case bundle_with_renewal_request(normalized(local.bundle)?, asked) do
      Err(_) -> Err("renewal_request_failed")
      Ok(value)
    end?
    let asking_bytes = bundle_bytes(asking)?
    let unchanged = case pending_bundle(kept, 0)? do
      Some(pending) -> Bytes.secure_equals(bundle_bytes(pending)?, asking_bytes)
      None -> false
    end
    if !unchanged do
      store_record_changes(path,
        ["prekey-bundles/v1"],
        [kept_blob(with_pending(kept, asking_bytes)?, wrapping_key)?],
        List.new())
    else
      Ok(nil)
    end?
    Ok(Some(renewed_entry(local, asking)?))
  end
end

# The account key answers each device that asks: a credential for exactly the
# keys it asked for, each at the next sequence.

fn answer_requests(path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  profiles :: List<ClientProfile>,
  now :: U64,
  sequence :: U64,
  index :: Int,
  output :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(profiles) do
    Ok(output)
  else
    let device = List.get(profiles, index)
    let request = if Bytes.secure_equals(device.device_id, local.device_id) do
      None
    else
      case bundle_renewal_request(device.bundle) do
        Ok(Some(value)) -> if verify_renewal_request(device.credential, value) && U64.compare(value.signed_prekey_id,
          device.bundle.signed_prekey_id) > 0 do
          Some(value)
        else
          None
        end
        _ -> None
      end
    end
    case request do
      None -> answer_requests(path, wrapping_key, local, profiles, now, sequence, index + 1, output)
      Some(value) -> do
        let bundle = credential_answer(path, wrapping_key, local, device, value, now, sequence)?
        answer_requests(path,
          wrapping_key,
          local,
          profiles,
          now,
          U64.add(sequence, mobile_wide("1")?)?,
          index + 1,
          List.append(output, directory_bytes(%{device.entry | prekey_bundle: bundle_bytes(bundle)?})?))
      end
    end
  end
end

fn option_list(value :: Option<Bytes>) -> List<Bytes> do
  case value do
    None -> List.new()
    Some(entry) -> [entry]
  end
end

fn wide_count(value :: Int) -> U64!String do
  mobile_wide(Int.to_string(value))
end

## The registrations this device should make now, in order, given its account's
## device set as the directory just showed it, with evidence. Takes on what the
## set shows of this device first. `age` moves the renewal clock forward for
## tests; it never moves the times written into credentials.

pub fn renew_devices_at(path :: String, device_set :: Bytes, age :: U64) -> List<Bytes>!String do
  ensure_schema(path)?
  let stored = decode_client_profile(load_profile(path)?)?
  let devices = verified_device_set(device_set)?
  let wrapping_key = platform_key()?
  require_transparency_device_set(path, wrapping_key, devices)?
  if !local_device_set(stored, devices) do
    Err("renewal_device_set_mismatch")
  else
    let now = current_time()?
    let clock = U64.add(now, age)?
    let logged = find_own(account_device_profiles(devices), stored.device_id, 0)?
    let local = reconcile(path, wrapping_key, stored, logged, now, clock)?
    let sequence = U64.add(devices.value.sequence, mobile_wide("1")?)?
    if holds_account_key(path)? do
      let own = own_account_renewal(path, wrapping_key, local, now, clock, sequence)?
      let first = option_list(own)
      answer_requests(path,
        wrapping_key,
        local,
        account_device_profiles(devices),
        now,
        U64.add(sequence, wide_count(List.length(first))?)?,
        0,
        first)
    else
      Ok(option_list(linked_renewal(path, wrapping_key, local, now, clock)?))
    end
  end
end

fn stamped_registrations(entries :: List<Bytes>, index :: Int, output :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(entries) do
    Ok(output)
  else
    stamped_registrations(entries,
      index + 1,
      List.append(output, stamped_request("mesh-msg/v1/work/register", List.get(entries, index))?))
  end
end

## The export: each registration wrapped in proof of work for the anonymous
## register endpoint, to be sent in order until one is refused.

pub fn renew_devices(request :: MobilePayloadRequest) -> Bytes!String do
  let entries = renew_devices_at(request.database_path, request.payload, mobile_wide("0")?)?
  encode_output_list(stamped_registrations(entries, 0, List.new())?)
end
