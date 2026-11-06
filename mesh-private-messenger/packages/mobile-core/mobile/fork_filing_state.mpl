from Mobile.Codec import (
  mobile_reader,
  mobile_finish,
  take_fixed,
  take_vector,
  mobile_join,
  mobile_vector,
  mobile_byte,
  mobile_write_u64,
  mobile_read_u64,
  random_bytes
)
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local, seal_local
from Storage.Records import compare_and_swap_blobs

pub struct FilingObservation do
  status :: String
  context_slot :: U64
  finder :: Bytes
  units :: U64
  morse_units :: U64
  receipt_format :: Int
  receipt_binding :: Bytes
end

pub struct FilingState do
  identity :: Bytes
  target_hash :: Bytes
  next_attempt :: U64
  started_at :: U64
  checked_at :: U64
  tier :: Int
  targets :: Int
  accepted :: Int
  token :: Bytes
  observation :: FilingObservation
end

pub struct FilingClaim do
  identity :: Bytes
  target_hash :: Bytes
  token :: Bytes
  started_at :: U64
  targets :: Int
  minimum_slot :: U64
end

struct StoredFiling do
  state :: FilingState
  ciphertext :: Bytes
end

fn label() -> String do
  "fork-filing/v1"
end

fn statuses() -> List<String> do
  ["pending", "rpc_unavailable", "rpc_disagree", "settled", "prepared"]
end

pub fn filing_pending(slot :: U64) -> FilingObservation!String do
  Ok(FilingObservation {
    status: "pending",
    context_slot: slot,
    finder: Bytes.empty(),
    units: U64.parse("0")?,
    morse_units: U64.parse("0")?,
    receipt_format: 0,
    receipt_binding: Bytes.empty()
  })
end

fn initial(identity :: Bytes) -> FilingState!String do
  let zero = U64.parse("0")?
  Ok(FilingState {
    identity: identity,
    target_hash: Bytes.empty(),
    next_attempt: zero,
    started_at: zero,
    checked_at: zero,
    tier: 0,
    targets: 0,
    accepted: 0,
    token: Bytes.empty(),
    observation: filing_pending(zero)?
  })
end

fn status_code(value :: String) -> Int!String do
  for index in 0..List.length(statuses()) do
    if List.get(statuses(), index) == value do
      return Ok(index)
    end
  end
  Err("invalid_filing_state")
end

fn valid(state :: FilingState) -> Result<(), String> do
  let observation = state.observation
  let binding_length = Bytes.length(observation.receipt_binding)
  let zero = U64.parse("0")?
  status_code(observation.status)?
  if Bytes.length(state.identity) != 32
    || Bytes.length(state.target_hash) != 32
    || state.tier < 1
    || state.tier > 5
    || state.targets < 0
    || state.targets > 8
    || state.accepted < 0
    || state.accepted > state.targets
    || (binding_length != 0 && binding_length != 32)
    || (Bytes.length(state.token) != 0 && Bytes.length(state.token) != 16)
    || U64.compare(state.next_attempt, state.started_at) <= 0 do
    return Err("invalid_filing_state")
  end
  if observation.status == "settled" || observation.status == "prepared" do
    if Bytes.length(observation.finder) != 32
      || Bytes.to_hex(observation.finder) == String.repeat("00", 32)
      || (observation.receipt_format == 2 && binding_length != 32) do
      return Err("invalid_filing_state")
    end
    if observation.status == "prepared" do
      if observation.receipt_format != 2
        || observation.units != zero
        || observation.morse_units != zero do
        return Err("invalid_filing_state")
      end
    else if (observation.receipt_format != 1 && observation.receipt_format != 2)
      || (observation.receipt_format == 1 && observation.morse_units != zero) do
      return Err("invalid_filing_state")
    end
  else if Bytes.length(observation.finder) != 0
    || observation.units != zero
    || observation.morse_units != zero
    || binding_length != 0
    || observation.receipt_format != 0 do
    return Err("invalid_filing_state")
  end
  Ok(nil)
end

fn seal(state :: FilingState, key :: borrow StorageKey) -> Bytes!String do
  valid(state)?
  let bytes = mobile_join([
      Bytes.from_utf8("FFS2"),
      state.identity,
      state.target_hash,
      mobile_write_u64(state.next_attempt)?,
      mobile_write_u64(state.started_at)?,
      mobile_write_u64(state.checked_at)?,
      mobile_byte(state.tier)?,
      mobile_byte(state.targets)?,
      mobile_byte(state.accepted)?,
      mobile_byte(status_code(state.observation.status)?)?,
      mobile_write_u64(state.observation.context_slot)?,
      mobile_write_u64(state.observation.units)?,
      mobile_write_u64(state.observation.morse_units)?,
      mobile_byte(state.observation.receipt_format)?,
      mobile_vector(state.token)?,
      mobile_vector(state.observation.finder)?,
      mobile_vector(state.observation.receipt_binding)?
    ],
    0,
    Bytes.empty())?
  seal_local(bytes, key, local_context(label())?)
end

fn load_record(path :: String, key :: borrow StorageKey) -> StoredFiling!String do
  let blob = case load_blob(path, label()) do
    Err(error) -> if error == "local_state_not_found" do
      return Ok(StoredFiling { state: initial(Bytes.empty())?, ciphertext: Bytes.empty() })
    else
      return Err(error)
    end
    Ok(value) -> value
  end
  let bytes = open_local(blob, key, local_context(label())?)?
  let input = mobile_reader(bytes, 213, "invalid_filing_state")?
  let magic = take_fixed(input, 4)?
  let legacy = Bytes.secure_equals(magic.value, Bytes.from_utf8("FFS1"))
  if !legacy && !Bytes.secure_equals(magic.value, Bytes.from_utf8("FFS2")) do
    return Err("invalid_filing_state")
  end
  let identity = take_fixed(magic.state, 32)?
  let targets = take_fixed(identity.state, 32)?
  let next = take_fixed(targets.state, 8)?
  let started = take_fixed(next.state, 8)?
  let checked = take_fixed(started.state, 8)?
  let flags = take_fixed(checked.state, 4)?
  let code = Bytes.get(flags.value, 3)?
  if code >= List.length(statuses()) || (legacy && code >= 4) do
    return Err("invalid_filing_state")
  end
  let slot = take_fixed(flags.state, 8)?
  let units = take_fixed(slot.state, 8)?
  # FFS1 has no receipt format, MORSE or binding; its settled status means MPR1.
  # The storage label/context stays at v1 so existing encrypted records reopen.
  let (morse_units, receipt_format, remainder) = if legacy do
    (U64.parse("0")?,
      if code == 3 do
        1
      else
        0
      end,
      units.state)
  else
    let morse = take_fixed(units.state, 8)?
    let format = take_fixed(morse.state, 1)?
    (mobile_read_u64(morse.value)?, Bytes.get(format.value, 0)?, format.state)
  end
  let token = take_vector(remainder, 16)?
  let finder = take_vector(token.state, 32)?
  let (receipt_binding, tail) = if legacy do
    (Bytes.empty(), finder.state)
  else
    let binding = take_vector(finder.state, 32)?
    (binding.value, binding.state)
  end
  mobile_finish(tail, "invalid_filing_state")?
  let state = FilingState {
    identity: identity.value,
    target_hash: targets.value,
    next_attempt: mobile_read_u64(next.value)?,
    started_at: mobile_read_u64(started.value)?,
    checked_at: mobile_read_u64(checked.value)?,
    tier: Bytes.get(flags.value, 0)?,
    targets: Bytes.get(flags.value, 1)?,
    accepted: Bytes.get(flags.value, 2)?,
    token: token.value,
    observation: FilingObservation {
      status: List.get(statuses(), code),
      context_slot: mobile_read_u64(slot.value)?,
      units: mobile_read_u64(units.value)?,
      morse_units: morse_units,
      receipt_format: receipt_format,
      receipt_binding: receipt_binding,
      finder: finder.value
    }
  }
  valid(state)?
  Ok(StoredFiling { state: state, ciphertext: blob })
end

pub fn load_filing(path :: String,
  key :: borrow StorageKey,
  identity :: Bytes) -> FilingState!String do
  if Bytes.length(identity) != 32 do
    return Err("invalid_filing_identity")
  end
  let stored = load_record(path, key)?
  if Bytes.secure_equals(identity, stored.state.identity) do
    Ok(stored.state)
  else
    initial(identity)
  end
end

# The encrypted CAS commits the retry budget before any HTTP or RPC. All wakes
# share it. URL/policy rotation must reuse the stable judge/proof identity.
pub fn claim_filing(path :: String,
  key :: borrow StorageKey,
  identity :: Bytes,
  target_hash :: Bytes,
  targets :: Int,
  now :: U64) -> Option<FilingClaim>!String do
  if Bytes.length(identity) != 32
    || Bytes.length(target_hash) != 32
    || targets < 0
    || targets > 8 do
    return Err("invalid_filing_identity")
  end
  let stored = load_record(path, key)?
  let state = if Bytes.secure_equals(identity, stored.state.identity) do
    stored.state
  else
    initial(identity)?
  end
  if state.observation.status == "settled" || U64.compare(now, state.next_attempt) < 0 do
    return Ok(None)
  end
  let tier = if state.tier >= 5 do
    5
  else
    state.tier + 1
  end
  let interval = U64.parse(List.get(["60000", "300000", "900000", "3600000", "21600000"],
    tier - 1))?
  let token = random_bytes(16)?
  let reserved = %{state |
    target_hash: target_hash,
    targets: targets,
    accepted: if Bytes.secure_equals(state.target_hash, target_hash) do
      state.accepted
    else
      0
    end,
    token: token,
    tier: tier,
    started_at: now,
    next_attempt: U64.add(now, interval)?
  }
  let blob = seal(reserved, key)?
  case compare_and_swap_blobs(path, [label()], [blob], stored.ciphertext) do
    Err(error) -> if error == "local_state_changed" do
      return Ok(None)
    else
      return Err(error)
    end
    Ok(_) -> nil
  end
  Ok(Some(FilingClaim {
    identity: identity,
    target_hash: target_hash,
    token: token,
    started_at: now,
    targets: targets,
    minimum_slot: state.observation.context_slot
  }))
end

# Only the worker's independently authenticated receipt observation can supply
# a settled result. Relay acknowledgments affect accepted count alone.
pub fn finish_filing(path :: String,
  key :: borrow StorageKey,
  claim :: FilingClaim,
  now :: U64,
  accepted :: Int,
  observation :: FilingObservation) -> Result<(), String> do
  let stored = load_record(path, key)?
  let state = stored.state
  if Bytes.length(claim.token) != 16
    || !Bytes.secure_equals(claim.identity, state.identity)
    || !Bytes.secure_equals(claim.token, state.token)
    || !Bytes.secure_equals(claim.target_hash, state.target_hash)
    || claim.started_at != state.started_at
    || claim.targets != state.targets do
    return Err("filing_claim_superseded")
  end
  if U64.compare(now, claim.started_at) < 0 do
    return Err("invalid_filing_clock")
  end
  if U64.compare(observation.context_slot, state.observation.context_slot) < 0 do
    return Err("filing_context_regressed")
  end
  let next = %{state |
    checked_at: now,
    accepted: accepted,
    token: Bytes.empty(),
    observation: observation
  }
  let blob = seal(next, key)?
  case compare_and_swap_blobs(path, [label()], [blob], stored.ciphertext) do
    Err(error) -> if error == "local_state_changed" do
      Err("filing_claim_superseded")
    else
      Err(error)
    end
    Ok(_) -> Ok(nil)
  end
end
