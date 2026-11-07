from Mobile.Codec import (
  mobile_reader,
  mobile_finish,
  take_fixed,
  take_vector,
  mobile_read_u64,
  mobile_write_u64,
  mobile_join,
  mobile_vector,
  random_bytes
)
from Mobile.Types import MobileReadBytes
from Binary.Reader import BinaryReader
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local, seal_local
from Storage.Records import compare_and_swap_blobs

pub struct AnchorSchedule do
  config_id :: Bytes
  next_daily :: U64
  next_allowed :: U64
  last_started :: U64
  last_completed :: U64
  active_token :: Bytes
  last_result :: Bytes
end

pub struct AnchorClaim do
  config_id :: Bytes
  token :: Bytes
  started_at :: U64
end

struct StoredSchedule do
  state :: AnchorSchedule
  ciphertext :: Bytes
end

fn label() -> String do
  "anchor-schedule/v1"
end

fn initial(identity :: Bytes) -> AnchorSchedule!String do
  let zero = U64.parse("0")?
  Ok(AnchorSchedule {
    config_id: identity,
    next_daily: zero,
    next_allowed: zero,
    last_started: zero,
    last_completed: zero,
    active_token: Bytes.empty(),
    last_result: Bytes.empty()
  })
end

fn load_record(path :: String, key :: borrow StorageKey) -> StoredSchedule!String do
  let blob = case load_blob(path, label()) do
    Err(error) -> if error == "local_state_not_found" do
      return Ok(StoredSchedule { state: initial(Bytes.empty())?, ciphertext: Bytes.empty() })
    else
      return Err(error)
    end
    Ok(value) -> value
  end
  let bytes = open_local(blob, key, local_context(label())?)?
  let input = mobile_reader(bytes, 4188, "invalid_anchor_schedule")?
  let magic = take_fixed(input, 4)?
  let identity = take_fixed(magic.state, 32)?
  let daily = take_fixed(identity.state, 8)?
  let allowed = take_fixed(daily.state, 8)?
  let started = take_fixed(allowed.state, 8)?
  let completed = take_fixed(started.state, 8)?
  let token = take_vector(completed.state, 16)?
  let result = take_vector(token.state, 4096)?
  mobile_finish(result.state, "invalid_anchor_schedule")?
  if !Bytes.secure_equals(magic.value, Bytes.from_utf8("ASC1"))
    || (Bytes.length(token.value) != 0 && Bytes.length(token.value) != 16) do
    return Err("invalid_anchor_schedule")
  end
  Ok(StoredSchedule {
    ciphertext: blob,
    state: AnchorSchedule {
      config_id: identity.value,
      next_daily: mobile_read_u64(daily.value)?,
      next_allowed: mobile_read_u64(allowed.value)?,
      last_started: mobile_read_u64(started.value)?,
      last_completed: mobile_read_u64(completed.value)?,
      active_token: token.value,
      last_result: result.value
    }
  })
end

fn seal_schedule(state :: AnchorSchedule, key :: borrow StorageKey) -> Bytes!String do
  if Bytes.length(state.config_id) != 32 || Bytes.length(state.last_result) > 4096 do
    return Err("invalid_anchor_schedule")
  end
  let bytes = mobile_join([
      Bytes.from_utf8("ASC1"),
      state.config_id,
      mobile_write_u64(state.next_daily)?,
      mobile_write_u64(state.next_allowed)?,
      mobile_write_u64(state.last_started)?,
      mobile_write_u64(state.last_completed)?,
      mobile_vector(state.active_token)?,
      mobile_vector(state.last_result)?
    ],
    0,
    Bytes.empty())?
  seal_local(bytes, key, local_context(label())?)
end

pub fn load_anchor_schedule(path :: String,
  key :: borrow StorageKey,
  identity :: Bytes) -> AnchorSchedule!String do
  if Bytes.length(identity) != 32 do
    return Err("invalid_anchor_identity")
  end
  let stored = load_record(path, key)?
  if Bytes.secure_equals(identity, stored.state.config_id) do
    Ok(stored.state)
  else
    initial(identity)
  end
end

# Commit the rate-limit reservation before any network request. An encrypted
# compare-and-swap also fences simultaneous foreground/background invocations.
# A crashed attempt consumes its hour; a later attempt gets a new token.
pub fn claim_anchor_check(path :: String,
  key :: borrow StorageKey,
  identity :: Bytes,
  now :: U64,
  key_changed :: Bool) -> Option<AnchorClaim>!String do
  if Bytes.length(identity) != 32 do
    return Err("invalid_anchor_identity")
  end
  let stored = load_record(path, key)?
  let previous = if Bytes.secure_equals(identity, stored.state.config_id) do
    stored.state
  else
    initial(identity)?
  end
  if U64.compare(now, previous.next_allowed) < 0
    || (!key_changed && U64.compare(now, previous.next_daily) < 0) do
    return Ok(None)
  end
  let token = random_bytes(16)?
  let reserved = %{previous |
    last_started: now,
    active_token: token,
    next_allowed: U64.add(now, U64.parse("3600000")?)?
  }
  let ciphertext = seal_schedule(reserved, key)?
  case compare_and_swap_blobs(path, [label()], [ciphertext], stored.ciphertext) do
    Err(error) -> if error == "local_state_changed" do
      return Ok(None)
    else
      return Err(error)
    end
    Ok(_) -> nil
  end
  Ok(Some(AnchorClaim { config_id: identity, token: token, started_at: now }))
end

# Retryable clock/RPC failures become due after the reserved hour. A completed
# observation starts the next daily interval. Completion never releases the
# hourly key-change limit or overwrites a newer claim/native configuration.
pub fn finish_anchor_check(path :: String,
  key :: borrow StorageKey,
  claim :: AnchorClaim,
  now :: U64,
  retry :: Bool,
  result :: Bytes) -> Result<(), String> do
  finish_anchor_check_with_blobs(path, key, claim, now, retry, result, [], [])
end

# Evidence and a new refusal commit in the same fenced transaction. Callers
# supply sealed companion records; none may overwrite the scheduler itself.
pub fn finish_anchor_check_with_blobs(path :: String,
  key :: borrow StorageKey,
  claim :: AnchorClaim,
  now :: U64,
  retry :: Bool,
  result :: Bytes,
  labels :: List<String>,
  blobs :: List<Bytes>) -> Result<(), String> do
  if List.length(labels) != List.length(blobs)
    || List.length(labels) > 3
    || List.any(labels, fn(value) do value == label() end) do
    return Err("invalid_anchor_completion")
  end
  let stored = load_record(path, key)?
  let state = stored.state
  if Bytes.length(claim.token) != 16
    || !Bytes.secure_equals(claim.config_id, state.config_id)
    || !Bytes.secure_equals(claim.token, state.active_token)
    || U64.compare(claim.started_at, state.last_started) != 0 do
    return Err("anchor_claim_superseded")
  end
  if U64.compare(now, claim.started_at) < 0 do
    return Err("invalid_anchor_clock")
  end
  let daily = if retry do
    now
  else
    U64.add(now, U64.parse("86400000")?)?
  end
  let completed = %{state |
    next_daily: daily,
    last_completed: now,
    active_token: Bytes.empty(),
    last_result: result
  }
  case compare_and_swap_blobs(path,
    [label()] ++ labels,
    [seal_schedule(completed, key)?] ++ blobs,
    stored.ciphertext) do
    Err(error) -> if error == "local_state_changed" do
      Err("anchor_claim_superseded")
    else
      Err(error)
    end
    Ok(_) -> Ok(nil)
  end
end
