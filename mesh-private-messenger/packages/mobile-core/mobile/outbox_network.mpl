from Mobile.Codec import (
  canonical_outer,
  current_time,
  mobile_read_byte,
  mobile_byte,
  mobile_write_u16,
  mobile_write_u64
)
from Mobile.CreditState import pack_credit_parts, unpack_credit_parts
from Mobile.NetworkPins import native_network_pins
from Mobile.Platform import native_security_config, privacy_submission
from Mobile.Profile import load_profile
from Mobile.Outbox import (
  outbox_basis,
  ids_from_basis,
  load_outbox_entry,
  optional_outbox_blob,
  settle_ordinary_outbox
)
from Mobile.PostageQueue import postage_owned_ids
from Mobile.Types import MobilePayloadRequest
from Storage.Blobs import put_blob, load_blob
from Storage.Keys import platform_key, open_local, seal_local, local_context
from Storage.Records import with_record_transaction
from Storage.OutboxGuard import OutboxBasis, require_outbox_basis, record_matches
from Transparency.Config import encode_security_config

pub struct OutboxFailure do
  status :: Int
  queued_at :: U64
end

pub struct OutboxDrainResult do
  status :: Int
  accepted :: Int
  remaining :: Int
  postage :: List<Bytes>
  failures :: List<OutboxFailure>
end

struct Pauses do
  previous :: Bytes
  mailboxes :: List<Bytes>
end

struct DrainIdentity do
  profile :: Bytes
  public_profile :: Bytes
  security :: Bytes
  origin :: String
end

fn pause_label() -> String do
  "outbox-postage-pauses/v1"
end

fn load_pauses(path :: String, key :: borrow StorageKey) -> Pauses!String do
  let previous = optional_outbox_blob(path, pause_label())?
  if Bytes.length(previous) == 0 do
    return Ok(Pauses { previous: previous, mailboxes: [] })
  end
  let encoded = open_local(previous, key, local_context(pause_label())?)?
  let mailboxes = unpack_credit_parts(encoded, 256, 32)?
  for index in 0..List.length(mailboxes) do
    if Bytes.length(List.get(mailboxes, index)) != 32 do
      return Err("invalid_outbox_pause")
    end
    for prior in 0..index do
      if Bytes.secure_equals(List.get(mailboxes, prior), List.get(mailboxes, index)) do
        return Err("invalid_outbox_pause")
      end
    end
  end
  Ok(Pauses { previous: previous, mailboxes: mailboxes })
end

fn store_pauses(path :: String,
  key :: borrow StorageKey,
  basis :: OutboxBasis,
  before :: Pauses,
  mailboxes :: List<Bytes>) -> Result<(), String> do
  if List.length(mailboxes) > 256 do
    return Err("outbox_pause_capacity")
  end
  let value = seal_local(pack_credit_parts(mailboxes)?, key, local_context(pause_label())?)?
  with_record_transaction(path,
    fn(database) do
      require_outbox_basis(database, basis)?
      if !record_matches(database, pause_label(), before.previous)? do
        return Err("outbox_state_changed")
      end
      put_blob(database, pause_label(), value)
    end)
end

fn current(path :: String, who :: DrainIdentity) -> Bool do
  let profile = case load_blob(path, "profile/v1") do
    Err(_) -> return false
    Ok(value) -> value
  end
  let pins = case native_network_pins() do
    Err(_) -> return false
    Ok(value) -> value
  end
  let config = case native_security_config() do
    Err(_) -> return false
    Ok(value) -> value
  end
  let security = case encode_security_config(config) do
    Err(_) -> return false
    Ok(value) -> value
  end
  pins.edge_origin == who.origin
    && Bytes.secure_equals(profile, who.profile)
    && Bytes.secure_equals(security, who.security)
end

fn clear_pauses(path :: String,
  key :: borrow StorageKey,
  profile :: Bytes,
  attempt :: Int) -> Result<(), String> do
  let basis = outbox_basis(path, key, profile)?
  let pauses = load_pauses(path, key)?
  case store_pauses(path, key, basis, pauses, []) do
    Err("outbox_state_changed") -> if attempt < 3 do
      clear_pauses(path, key, profile, attempt + 1)
    else
      Err("outbox_state_changed")
    end
    Ok(value)
    Err(error)
  end
end

fn remember_postage(path :: String,
  key :: borrow StorageKey,
  profile :: Bytes,
  id :: Bytes,
  mailbox :: Bytes,
  attempt :: Int) -> Bool!String do
  let basis = outbox_basis(path, key, profile)?
  if !List.contains(ids_from_basis(basis, key)?, id)
    || List.contains(postage_owned_ids(path, key)?, id) do
    return Ok(false)
  end
  let before = load_pauses(path, key)?
  if List.contains(before.mailboxes, mailbox) do
    return Ok(true)
  end
  let kept = if List.length(before.mailboxes) < 256 do
    before.mailboxes
  else
    # A full history may discard only recipients with no queued frames. Live
    # paused mailboxes are never evicted to make an unapproved free retry.
    let live = for current_id in ids_from_basis(basis, key)? do
      canonical_outer(load_outbox_entry(path, key, current_id)?)?.mailbox_token
    end
    List.filter(before.mailboxes, fn(value) -> List.contains(live, value) end)
  end
  case store_pauses(path, key, basis, before, kept ++ [mailbox]) do
    Ok(_) -> Ok(true)
    Err("outbox_state_changed") -> if attempt < 3 do
      remember_postage(path, key, profile, id, mailbox, attempt + 1)
    else
      Err("outbox_state_changed")
    end
    Err(error)
  end
end

fn queued_at(expiration :: U64) -> U64!String do
  let lifetime = U64.parse("2592000000")?
  if U64.compare(expiration, lifetime) < 0 do
    U64.parse("0")
  else
    U64.subtract(expiration, lifetime)
  end
end

fn result(path :: String,
  key :: borrow StorageKey,
  profile :: Bytes,
  status :: Int,
  accepted :: Int,
  postage :: List<Bytes>,
  failures :: List<OutboxFailure>) -> OutboxDrainResult!String do
  let basis = outbox_basis(path, key, profile)?
  let owned = postage_owned_ids(path, key)?
  let remaining = List.length(List.filter(ids_from_basis(basis, key)?,
    fn(id) -> !List.contains(owned, id) end))
  Ok(OutboxDrainResult {
    status: status,
    accepted: accepted,
    remaining: remaining,
    postage: postage,
    failures: failures
  })
end

fn remaining(started :: Int) -> Int!String do
  Ok(30000 - Monotonic.elapsed(started, Monotonic.now_nanos())? / 1000000)
end

## Ordinary delivery selects and authenticates saved frames internally. A known
## 402 is sealed before returning; only the explicit free-retry mode clears it.
## Paid-owned IDs remain suppressed without requiring spending to be enabled.
pub fn drain_outbox(path :: String, retry_free :: Bool) -> OutboxDrainResult!String do
  let key = platform_key()?
  let pins = native_network_pins()?
  let profile = load_blob(path, "profile/v1")?
  let public_profile = load_profile(path)?
  let security = encode_security_config(native_security_config()?)?
  let who = DrainIdentity {
    profile: profile,
    public_profile: public_profile,
    security: security,
    origin: pins.edge_origin
  }
  if !current(path, who) do
    return Err("outbox_identity_changed")
  end
  if retry_free do
    clear_pauses(path, key, public_profile, 0)?
  end
  let basis = outbox_basis(path, key, public_profile)?
  let initial = ids_from_basis(basis, key)?
  let started = Monotonic.now_nanos()
  walk(path,
    key,
    who,
    initial,
    0,
    started,
    DrainProgress { status: 0, accepted: 0, postage: [], failures: [], waiting: [] })
end

struct DrainProgress do
  status :: Int
  accepted :: Int
  postage :: List<Bytes>
  failures :: List<OutboxFailure>
  waiting :: List<Bytes>
end

fn done(path :: String,
  key :: borrow StorageKey,
  who :: DrainIdentity,
  state :: DrainProgress) -> OutboxDrainResult!String do
  if !current(path, who) do
    return Err("outbox_identity_changed")
  end
  result(path, key, who.public_profile, state.status, state.accepted, state.postage, state.failures)
end

fn walk(path :: String,
  key :: borrow StorageKey,
  who :: DrainIdentity,
  ids :: List<Bytes>,
  index :: Int,
  started :: Int,
  state :: DrainProgress) -> OutboxDrainResult!String do
  if index >= List.length(ids) || state.status >= 2 do
    return done(path, key, who, state)
  end
  if remaining(started)? <= 0 do
    return done(path, key, who, %{state | status: 3})
  end
  if !current(path, who) do
    return Err("outbox_identity_changed")
  end
  let id = List.get(ids, index)
  let basis = outbox_basis(path, key, who.public_profile)?
  if !List.contains(ids_from_basis(basis, key)?, id)
    || List.contains(postage_owned_ids(path, key)?, id) do
    return walk(path, key, who, ids, index + 1, started, state)
  end
  let wire = load_outbox_entry(path, key, id)?
  let envelope = canonical_outer(wire)?
  let paused = load_pauses(path, key)?
  if List.contains(paused.mailboxes, envelope.mailbox_token)
    && U64.compare(current_time()?, envelope.expiration) < 0 do
    return walk(path, key, who, ids, index + 1, started, %{state | postage: state.postage ++ [id]})
  end
  if List.contains(state.waiting, envelope.mailbox_token) do
    return walk(path, key, who, ids, index + 1, started, state)
  end
  let next = send_saved(path, key, who, wire, started, state)?
  walk(path, key, who, ids, index + 1, started, next)
end

fn send_saved(path :: String,
  key :: borrow StorageKey,
  who :: DrainIdentity,
  wire :: Bytes,
  started :: Int,
  state :: DrainProgress) -> DrainProgress!String do
  let envelope = canonical_outer(wire)?
  let budget = remaining(started)?
  if budget <= 0 do
    return Ok(%{state | status: 3})
  end
  let submission = privacy_submission(wire)?
  if !current(path, who) do
    return Err("outbox_identity_changed")
  end
  # Ownership is checked after proof work as well as after the response. A
  # concurrent ownership commit cannot acknowledge this ordinary attempt.
  if List.contains(postage_owned_ids(path, key)?, envelope.envelope_id) do
    return Ok(state)
  end
  let budget = remaining(started)?
  if budget <= 0 do
    return Ok(%{state | status: 3})
  end
  let response = case Http.build(:post, who.origin <> "/v1/envelopes/batch")
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Cache-Control", "no-store")
    |> Http.body_bytes(submission)
    |> Http.timeout(if budget < 8000 do
      budget
    else
      8000
    end)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(1024)
    |> Http.send() do
    Err(_) -> do
      if !current(path, who) do
        return Err("outbox_identity_changed")
      end
      return Ok(%{state | status: 2})
    end
    Ok(value) -> value
  end
  if !current(path, who) do
    return Err("outbox_identity_changed")
  end
  if response.status == 402 do
    if remember_postage(path,
      key,
      who.public_profile,
      envelope.envelope_id,
      envelope.mailbox_token,
      0)? do
      Ok(%{state | postage: state.postage ++ [envelope.envelope_id]})
    else
      Ok(state)
    end
  else if response.status == 429 do
    Ok(%{state | waiting: state.waiting ++ [envelope.mailbox_token], status: 1})
  else if response.status == 410
    || (response.status == 400 && U64.compare(current_time()?, envelope.expiration) >= 0) do
    case settle_ordinary_outbox(MobilePayloadRequest { database_path: path, payload: wire },
      who.public_profile,
      false) do
      Ok(changed) -> if changed do
        Ok(%{state |
          failures: state.failures
            ++ [
              OutboxFailure { status: response.status, queued_at: queued_at(envelope.expiration)? }
            ]
        })
      else
        Ok(state)
      end
      Err("outbox_postage_owned") -> Ok(state)
      Err(error)
    end
  else if response.status >= 200 && response.status < 300 do
    case settle_ordinary_outbox(MobilePayloadRequest { database_path: path, payload: wire },
      who.public_profile,
      true) do
      Ok(changed) -> if changed do
        Ok(%{state | accepted: state.accepted + 1})
      else
        Ok(state)
      end
      Err("outbox_postage_owned") -> Ok(state)
      Err(error)
    end
  else
    Ok(%{state | status: 2})
  end
end

from Mobile.Codec import mobile_reader, mobile_finish, take_vector, mobile_utf8

pub fn native_outbox_drain(input :: Bytes) -> Bytes!String do
  let state = mobile_reader(input, 4105, "invalid_outbox_request")?
  let path = take_vector(state, 4096)?
  let mode = take_vector(path.state, 1)?
  mobile_finish(mode.state, "invalid_outbox_request")?
  let database = mobile_utf8(path.value, "invalid_database_path")?
  let selected = mobile_read_byte(mode.value)?
  if Bytes.length(path.value) == 0 || String.contains(database, "\0") || selected > 1 do
    return Err("invalid_outbox_request")
  end
  let value = drain_outbox(database, selected == 1)?
  let failures = for failure in value.failures do
    Bytes.concat(mobile_write_u16(failure.status)?, mobile_write_u64(failure.queued_at)?)?
  end
  pack_credit_parts([
    Bytes.from_hex("014f4258")?,
    mobile_byte(value.status)?,
    mobile_write_u16(value.accepted)?,
    mobile_write_u16(value.remaining)?,
    pack_credit_parts(value.postage)?,
    pack_credit_parts(failures)?
  ])
end
