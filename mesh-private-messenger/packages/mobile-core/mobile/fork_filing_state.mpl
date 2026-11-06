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
from Mobile.Types import MobileReadBytes
from Binary.Reader import BinaryReader
from Storage.Keys import local_context, open_local, seal_local
from Storage.Records import compare_and_swap_blobs

pub struct FilingObservation do
  status :: String
  context_slot :: U64
  finder :: Bytes
  units :: U64
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
  ["pending", "rpc_unavailable", "rpc_disagree", "settled"]
end

pub fn filing_pending(slot :: U64) -> FilingObservation!String do
  Ok(FilingObservation {
    status: "pending",
    context_slot: slot,
    finder: Bytes.empty(),
    units: U64.parse("0")?
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
  status_code(observation.status)?
  if Bytes.length(state.identity) != 32
    || Bytes.length(state.target_hash) != 32
    || state.tier < 1
    || state.tier > 5
    || state.targets < 0
    || state.targets > 8
    || state.accepted < 0
    || state.accepted > state.targets
    || (Bytes.length(state.token) != 0 && Bytes.length(state.token) != 16)
    || U64.compare(state.next_attempt, state.started_at) <= 0 do
    return Err("invalid_filing_state")
  end
  if observation.status == "settled" do
    if Bytes.length(observation.finder) != 32
      || Bytes.to_hex(observation.finder) == String.repeat("00", 32) do
      return Err("invalid_filing_state")
    end
  else if Bytes.length(observation.finder) != 0 || observation.units != U64.parse("0")? do
    return Err("invalid_filing_state")
  end
  Ok(nil)
end

fn seal(state :: FilingState, key :: borrow StorageKey) -> Bytes!String do
  valid(state)?
  let bytes = mobile_join([
      Bytes.from_utf8("FFS1"),
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
      mobile_vector(state.token)?,
      mobile_vector(state.observation.finder)?
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
  let input = mobile_reader(bytes, 192, "invalid_filing_state")?
  let magic = take_fixed(input, 4)?
  let identity = take_fixed(magic.state, 32)?
  let targets = take_fixed(identity.state, 32)?
  let next = take_fixed(targets.state, 8)?
  let started = take_fixed(next.state, 8)?
  let checked = take_fixed(started.state, 8)?
  let flags = take_fixed(checked.state, 4)?
  let slot = take_fixed(flags.state, 8)?
  let units = take_fixed(slot.state, 8)?
  let token = take_vector(units.state, 16)?
  let finder = take_vector(token.state, 32)?
  mobile_finish(finder.state, "invalid_filing_state")?
  let code = Bytes.get(flags.value, 3)?
  if !Bytes.secure_equals(magic.value, Bytes.from_utf8("FFS1"))
    || code >= List.length(statuses()) do
    return Err("invalid_filing_state")
  end
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
