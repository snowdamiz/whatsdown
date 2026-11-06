##! Inactive native OHTTP transport context. No direct mode or route activation.
from Mobile.Codec import current_time, mobile_write_u64, mobile_read_u64
from Mobile.OhttpPins import MobileOhttpPins, MobileOhttpKey, decode_ohttp_pins
from Mobile.OhttpPrekeys import fetch_ohttp_prekey
from Mobile.OhttpLookups import fetch_lookup
from Ohttp.LookupPolicy import OhttpLookupOperation, OhttpLookupResult
from Mobile.Platform import decode_native_security_config
from Storage.AccountGuard import (
  AccountBasis,
  load_account_basis,
  commit_account_changes,
  load_account_basis_bounded_with_key,
  require_account_basis_bounded_with_key
)
from Storage.Blobs import put_blob_bounded_with_key
from Storage.Keys import platform_key, open_local, seal_local, local_context
from Transport.Packet import decode_client_profile

pub struct NativeOhttpContext do
  basis :: AccountBasis
  pins :: MobileOhttpPins
  network_frame :: Bytes
  security_frame :: Bytes
  companion_frame :: Bytes
  started_at :: U64
  selected_key :: Option<MobileOhttpKey>
end

struct NativeOhttpFrames do
  network :: Bytes
  security :: Bytes
  companion :: Bytes
end

struct DerivedOhttpContext do
  pins :: MobileOhttpPins
  selected :: Option<MobileOhttpKey>
end

fn fence_label() -> String do
  "ohttp-revision/v1"
end

fn native_frame(selector :: String, maximum :: Int) -> Bytes!String do
  let frame = case Host.push_get_token(Bytes.from_utf8(selector)) do
    Err(_) -> return Err("ohttp_configuration_required")
    Ok(value) -> value
  end
  if Bytes.length(frame) < 1 || Bytes.length(frame) > maximum do
    Err("invalid_ohttp_configuration")
  else
    Ok(frame)
  end
end

fn native_frames() -> NativeOhttpFrames!String do
  Ok(NativeOhttpFrames {
    network: native_frame("messenger/network/v1", 8244)?,
    security: native_frame("messenger/config/v1", 8192)?,
    companion: native_frame("messenger/ohttp/v1", 600)?
  })
end

fn selected_key(pins :: MobileOhttpPins, now :: U64) -> Option<MobileOhttpKey>!String do
  if !pins.required do
    return Ok(None)
  end
  for key in pins.keys do
    if U64.compare(now, key.not_before_ms) >= 0 && U64.compare(now, key.not_after_ms) < 0 do
      return Ok(Some(key))
    end
  end
  Err("ohttp_no_active_key")
end

# Pure time predicate for bounded clock fixtures. Native callers below always
# obtain their own wall clock; this helper grants no transport or storage access.
pub fn require_ohttp_completion_time(started :: U64,
  selected :: Option<MobileOhttpKey>,
  now :: U64) -> Result<(), String> do
  if U64.compare(now, started) < 0 do
    return Err("ohttp_clock_rollback")
  end
  case selected do
    None -> Ok(nil)
    Some(key) -> if U64.compare(now, key.not_before_ms) < 0
      || U64.compare(now, key.not_after_ms) >= 0 do
      Err("ohttp_key_expired")
    else
      Ok(nil)
    end
  end
end

fn revision_record(before :: AccountBasis,
  key :: borrow StorageKey,
  pins :: MobileOhttpPins) -> Option<Bytes>!String do
  let account = decode_client_profile(open_local(before.profile,
    key,
    local_context("profile/v1")?)?)?.account_id
  let previous = List.get(before.records, 0)
  if Bytes.length(previous) > 0 do
    let payload = case open_local(previous, key, local_context(fence_label())?) do
      Err(_) -> return Err("invalid_ohttp_revision_state")
      Ok(value) -> value
    end
    if Bytes.length(payload) != 76
      || !Bytes.secure_equals(Bytes.slice(payload, 0, 4)?, Bytes.from_utf8("MOR1")) do
      return Err("invalid_ohttp_revision_state")
    end
    let revision = mobile_read_u64(Bytes.slice(payload, 36, 8)?)?
    if U64.to_string(revision) == "0" do
      return Err("invalid_ohttp_revision_state")
    end
    if Bytes.secure_equals(Bytes.slice(payload, 4, 32)?, account) do
      let comparison = U64.compare(pins.revision, revision)
      if comparison < 0 do
        return Err("ohttp_revision_rollback")
      end
      if comparison == 0 do
        if !Bytes.secure_equals(Bytes.slice(payload, 44, 32)?, pins.identity) do
          return Err("ohttp_revision_rebind")
        end
        return Ok(None)
      end
    end
    # An authenticated other-account row starts a fresh current account scope.
    # The original current profile and old fence are still checked by the CAS.
  end
  let payload = case Bytes.concat_many([
      Bytes.from_utf8("MOR1"),
      account,
      mobile_write_u64(pins.revision)?,
      pins.identity
    ],
    76) do
    Err(_) -> return Err("invalid_ohttp_revision_state")
    Ok(value) -> value
  end
  Ok(Some(seal_local(payload, key, local_context(fence_label())?)?))
end

fn same_key(left :: MobileOhttpKey, right :: MobileOhttpKey) -> Bool do
  left.config.key_id == right.config.key_id
    && Bytes.secure_equals(left.config.public_key.bytes, right.config.public_key.bytes)
    && U64.compare(left.not_before_ms, right.not_before_ms) == 0
    && U64.compare(left.not_after_ms, right.not_after_ms) == 0
end

fn same_keys(left :: List<MobileOhttpKey>, right :: List<MobileOhttpKey>, index :: Int) -> Bool do
  if List.length(left) != List.length(right) do
    false
  else if index >= List.length(left) do
    true
  else
    same_key(List.get(left, index), List.get(right, index)) && same_keys(left, right, index + 1)
  end
end

fn same_pins(left :: MobileOhttpPins, right :: MobileOhttpPins) -> Bool do
  Bytes.secure_equals(left.identity, right.identity)
    && U64.compare(left.revision, right.revision) == 0
    && left.required == right.required
    && left.network.development == right.network.development
    && left.network.core_origin == right.network.core_origin
    && left.network.edge_origin == right.network.edge_origin
    && left.network.object_origin == right.network.object_origin
    && left.network.stream_url == right.network.stream_url
    && left.network.object_work_difficulty == right.network.object_work_difficulty
    && same_keys(left.keys, right.keys, 0)
end

fn same_selected(left :: Option<MobileOhttpKey>, right :: Option<MobileOhttpKey>) -> Bool do
  case (left, right) do
    (None, None) -> true
    (Some(a), Some(b)) -> same_key(a, b)
    _ -> false
  end
end

fn require_frames(frames :: NativeOhttpFrames) -> Result<(), String> do
  let current = case native_frames() do
    Err(_) -> return Err("account_state_changed")
    Ok(value) -> value
  end
  if !Bytes.secure_equals(current.network, frames.network)
    || !Bytes.secure_equals(current.security, frames.security)
    || !Bytes.secure_equals(current.companion, frames.companion) do
    Err("account_state_changed")
  else
    Ok(nil)
  end
end

fn require_fence_basis_shape(context :: NativeOhttpContext) -> Result<(), String> do
  if context.basis.labels != [fence_label()]
    || List.length(context.basis.records) != 1
    || Bytes.length(context.basis.profile) == 0
    || Bytes.length(List.head(context.basis.records)) == 0 do
    return Err("invalid_ohttp_context")
  end
  Ok(nil)
end

# Ordinary records are not authority tokens: require the expected shape and
# authenticate both custody and revision payloads with the retained owner.
fn authenticate_fence_with_key(context :: NativeOhttpContext,
  pins :: MobileOhttpPins,
  key :: borrow StorageKey) -> Result<(), String> do
  let profile = case open_local(context.basis.profile, key, local_context("profile/v1")?) do
    Err(_) -> return Err("invalid_ohttp_context")
    Ok(value) -> value
  end
  let account = case decode_client_profile(profile) do
    Err(_) -> return Err("invalid_ohttp_context")
    Ok(value) -> value.account_id
  end
  let payload = case open_local(List.head(context.basis.records),
    key,
    local_context(fence_label())?) do
    Err(_) -> return Err("invalid_ohttp_context")
    Ok(value) -> value
  end
  if Bytes.length(payload) != 76
    || !Bytes.secure_equals(Bytes.slice(payload, 0, 4)?, Bytes.from_utf8("MOR1"))
    || !Bytes.secure_equals(Bytes.slice(payload, 4, 32)?, account)
    || U64.compare(mobile_read_u64(Bytes.slice(payload, 36, 8)?)?, pins.revision) != 0
    || !Bytes.secure_equals(Bytes.slice(payload, 44, 32)?, pins.identity) do
    Err("invalid_ohttp_context")
  else
    Ok(nil)
  end
end

fn authenticate_fence(context :: NativeOhttpContext,
  pins :: MobileOhttpPins) -> Result<(), String> do
  require_fence_basis_shape(context)?
  let key = platform_key()?
  let result = authenticate_fence_with_key(context, pins, key)
  Secret.destroy(key)
  result
end

fn derive_context_pins(context :: NativeOhttpContext) -> DerivedOhttpContext!String do
  let security = case decode_native_security_config(context.security_frame) do
    Err(_) -> return Err("invalid_ohttp_context")
    Ok(value) -> value
  end
  let pins = case decode_ohttp_pins(context.companion_frame, context.network_frame, security) do
    Err(_) -> return Err("invalid_ohttp_context")
    Ok(value) -> value
  end
  let selected = case selected_key(pins, context.started_at) do
    Err(_) -> return Err("invalid_ohttp_context")
    Ok(value) -> value
  end
  if !same_pins(context.pins, pins) || !same_selected(context.selected_key, selected) do
    return Err("invalid_ohttp_context")
  end
  Ok(DerivedOhttpContext { pins: pins, selected: selected })
end

fn derive_context(context :: NativeOhttpContext) -> DerivedOhttpContext!String do
  let derived = derive_context_pins(context)?
  authenticate_fence(context, derived.pins)?
  Ok(derived)
end

fn derive_context_with_key(context :: NativeOhttpContext,
  key :: borrow StorageKey) -> DerivedOhttpContext!String do
  let derived = derive_context_pins(context)?
  authenticate_fence_with_key(context, derived.pins, key)?
  Ok(derived)
end

fn validated_current(path :: String, context :: NativeOhttpContext) -> DerivedOhttpContext!String do
  let derived = derive_context(context)?
  require_frames(NativeOhttpFrames {
    network: context.network_frame,
    security: context.security_frame,
    companion: context.companion_frame
  })?
  require_ohttp_completion_time(context.started_at, derived.selected, current_time()?)?
  # Writer-lock CAS checks exact original profile AND fence ciphertexts.
  # No transaction survives cryptographic preparation or HTTP.
  commit_account_changes(path, context.basis, [], [], [])?
  Ok(derived)
end

pub fn require_current_ohttp_context(path :: String,
  context :: NativeOhttpContext) -> Result<(), String> do
  validated_current(path, context)?
  Ok(nil)
end

pub fn capture_native_ohttp_context(path :: String,
  expected_profile :: Bytes) -> NativeOhttpContext!String do
  let before = load_account_basis(path, [fence_label()])?
  if !Bytes.secure_equals(before.profile, expected_profile) do
    return Err("account_state_changed")
  end
  let frames = native_frames()?
  let security = decode_native_security_config(frames.security)?
  let pins = decode_ohttp_pins(frames.companion, frames.network, security)?
  let started = current_time()?
  let selected = selected_key(pins, started)?
  let key = platform_key()?
  let next = revision_record(before, key, pins)?
  Secret.destroy(key)
  # Preparation may have taken time: never advance a fence for changed raw pins.
  require_frames(frames)?
  let basis = case next do
    None -> do
      commit_account_changes(path, before, [], [], [])?
      before
    end
    Some(sealed) -> do
      commit_account_changes(path, before, [fence_label()], [sealed], [])?
      AccountBasis { profile: before.profile, labels: before.labels, records: [sealed] }
    end
  end
  let context = NativeOhttpContext {
    basis: basis,
    pins: pins,
    network_frame: frames.network,
    security_frame: frames.security,
    companion_frame: frames.companion,
    started_at: started,
    selected_key: selected
  }
  require_current_ohttp_context(path, context)?
  Ok(context)
end

fn require_bounded_capture_request(path :: String,
  expected_profile :: Bytes) -> Result<(), String> do
  if String.length(path) == 0
    || String.length(path) > 4096
    || Bytes.length(expected_profile) == 0 do
    return Err("invalid_ohttp_context")
  end
  if Bytes.length(expected_profile) > 40000 do
    Err("account_source_limit")
  else
    Ok(nil)
  end
end

fn require_bounded_context_request(path :: String,
  context :: NativeOhttpContext) -> Result<(), String> do
  require_bounded_capture_request(path, context.basis.profile)?
  require_fence_basis_shape(context)?
  if Bytes.length(List.head(context.basis.records)) > 1024 do
    Err("account_source_limit")
  else
    Ok(nil)
  end
end

fn bounded_context_change_on(database :: SqliteConn,
  key :: borrow StorageKey,
  before :: AccountBasis,
  value :: Option<Bytes>) -> Result<(), String> do
  require_account_basis_bounded_with_key(database, key, before, 40000, 1024, 41024)?
  case value do
    None -> Ok(nil)
    Some(blob) -> put_blob_bounded_with_key(database, key, fence_label(), blob, 1024)
  end
end

## Direct writer arguments retain the borrowed owner without a resource capture
## in a closure. All comparisons and any revision write use this connection.
fn bounded_context_change(path :: String,
  key :: borrow StorageKey,
  before :: AccountBasis,
  value :: Option<Bytes>) -> Result<(), String> do
  case value do
    Some(blob) -> if Bytes.length(blob) == 0 || Bytes.length(blob) > 1024 do
      return Err("account_source_limit")
    end
    None -> nil
  end
  let database = Sqlite.open(path)?
  let started = case Sqlite.execute(database, "PRAGMA busy_timeout = 1000", []) do
    Err(error)
    Ok(_) -> Sqlite.execute(database, "BEGIN IMMEDIATE", [])
  end
  let result = case started do
    Err(_) -> Err("database_write_failed")
    Ok(_) -> case bounded_context_change_on(database, key, before, value) do
      Err(error)
      Ok(_) -> case Sqlite.commit(database) do
        Err(_) -> Err("database_write_failed")
        Ok(_) -> Ok(nil)
      end
    end
  end
  case result do
    Err(_) -> do
      Sqlite.rollback(database)
      nil
    end
    Ok(_) -> nil
  end
  Sqlite.close(database)
  result
end

fn validated_current_bounded_with_key(path :: String,
  context :: NativeOhttpContext,
  key :: borrow StorageKey) -> DerivedOhttpContext!String do
  let derived = derive_context_with_key(context, key)?
  require_frames(NativeOhttpFrames {
    network: context.network_frame,
    security: context.security_frame,
    companion: context.companion_frame
  })?
  require_ohttp_completion_time(context.started_at, derived.selected, current_time()?)?
  bounded_context_change(path, key, context.basis, None)?
  Ok(derived)
end

fn capture_bounded_with_key(path :: String,
  expected_profile :: Bytes,
  key :: borrow StorageKey) -> NativeOhttpContext!String do
  let before = load_account_basis_bounded_with_key(path, key, [fence_label()], 40000, 1024, 41024)?
  if !Bytes.secure_equals(before.profile, expected_profile) do
    return Err("account_state_changed")
  end
  let frames = native_frames()?
  let security = decode_native_security_config(frames.security)?
  let pins = decode_ohttp_pins(frames.companion, frames.network, security)?
  let started = current_time()?
  let selected = selected_key(pins, started)?
  let next = revision_record(before, key, pins)?
  require_frames(frames)?
  let basis = case next do
    None -> do
      bounded_context_change(path, key, before, None)?
      before
    end
    Some(sealed) -> do
      bounded_context_change(path, key, before, Some(sealed))?
      AccountBasis { profile: before.profile, labels: before.labels, records: [sealed] }
    end
  end
  let context = NativeOhttpContext {
    basis: basis,
    pins: pins,
    network_frame: frames.network,
    security_frame: frames.security,
    companion_frame: frames.companion,
    started_at: started,
    selected_key: selected
  }
  require_bounded_context_request(path, context)?
  validated_current_bounded_with_key(path, context, key)?
  Ok(context)
end

pub fn capture_native_ohttp_context_bounded_with_key(path :: String,
  expected_profile :: Bytes,
  key :: borrow StorageKey) -> NativeOhttpContext!String do
  require_bounded_capture_request(path, expected_profile)?
  capture_bounded_with_key(path, expected_profile, key)
end

pub fn capture_native_ohttp_context_bounded(path :: String,
  expected_profile :: Bytes) -> NativeOhttpContext!String do
  require_bounded_capture_request(path, expected_profile)?
  let key = platform_key()?
  let result = capture_bounded_with_key(path, expected_profile, key)
  Secret.destroy(key)
  result
end

pub fn require_current_ohttp_context_bounded_with_key(path :: String,
  context :: NativeOhttpContext,
  key :: borrow StorageKey) -> Result<(), String> do
  require_bounded_context_request(path, context)?
  validated_current_bounded_with_key(path, context, key)?
  Ok(nil)
end

pub fn require_current_ohttp_context_bounded(path :: String,
  context :: NativeOhttpContext) -> Result<(), String> do
  require_bounded_context_request(path, context)?
  let key = platform_key()?
  let result = validated_current_bounded_with_key(path, context, key)
  Secret.destroy(key)
  result?
  Ok(nil)
end

pub fn fetch_guarded_ohttp_prekey(path :: String,
  context :: NativeOhttpContext,
  stamped :: Bytes,
  timeout :: Int) -> Bytes!String do
  # Caller preflight before the unchanged bounded HTTP helper. All authority is
  # rederived; no caller-mutated cache can steer a key, mode or destination.
  let derived = validated_current(path, context)?
  let selected = case derived.selected do
    None -> return Err("ohttp_required")
    Some(value) -> value
  end
  if !derived.pins.required do
    return Err("ohttp_required")
  end
  # Keep the actual operation-start clock and used key LOCAL across the call.
  # The ordinary input context is not a trusted clock or opaque capability.
  let started = current_time()?
  require_ohttp_completion_time(context.started_at, Some(selected), started)?
  let result = fetch_ohttp_prekey(%{derived.pins | keys: [selected]}, stamped, started, timeout)
  # Completion guard: both success and failure must still own their sources.
  let completed = validated_current(path, context)?
  require_ohttp_completion_time(started, Some(selected), current_time()?)?
  # Assert semantic cache equality again; neither completion nor another overlap
  # key may replace the exact key/context used for the outgoing request.
  if !same_pins(completed.pins, derived.pins)
    || !same_selected(completed.selected, Some(selected)) do
    return Err("account_state_changed")
  end
  commit_account_changes(path, context.basis, [], [], [])?
  # SQLite may have waited for another writer; sample native time after it returns.
  require_ohttp_completion_time(started, Some(selected), current_time()?)?
  result
end

## Native lookup transport selects only explicit validated off or required mode.
## The exact used key and native start stay local through both result branches.
pub fn fetch_guarded_ohttp_lookup(path :: String,
  context :: NativeOhttpContext,
  operation :: OhttpLookupOperation,
  body :: Bytes,
  timeout :: Int) -> OhttpLookupResult!String do
  fetch_guarded_ohttp_lookup_at_origin(path,
    context,
    operation,
    body,
    context.pins.network.core_origin,
    timeout)
end

# Independent proof reads historically use their authenticated stored origin in
# explicit-off mode. Required mode accepts only the derived configured origin.
pub fn fetch_guarded_ohttp_lookup_at_origin(path :: String,
  context :: NativeOhttpContext,
  operation :: OhttpLookupOperation,
  body :: Bytes,
  origin :: String,
  timeout :: Int) -> OhttpLookupResult!String do
  let derived = validated_current(path, context)?
  if derived.pins.required && origin != derived.pins.network.core_origin do
    return Err("transparency_origin_mismatch")
  end
  let started = current_time()?
  require_ohttp_completion_time(context.started_at, derived.selected, started)?
  let pins = case derived.selected do
    None -> derived.pins
    Some(key) -> %{derived.pins | keys: [key]}
  end
  let transport_pins = if derived.pins.required do
    pins
  else
    %{pins | network: %{pins.network | core_origin: origin}}
  end
  let result = fetch_lookup(transport_pins, operation, body, started, timeout)
  let completed = validated_current(path, context)?
  require_ohttp_completion_time(started, derived.selected, current_time()?)?
  if !same_pins(completed.pins, derived.pins)
    || !same_selected(completed.selected, derived.selected) do
    return Err("account_state_changed")
  end
  commit_account_changes(path, context.basis, [], [], [])?
  require_ohttp_completion_time(started, derived.selected, current_time()?)?
  result
end
