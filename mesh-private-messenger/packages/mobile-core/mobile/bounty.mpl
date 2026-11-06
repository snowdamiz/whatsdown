from Mobile.Codec import (
  mobile_reader,
  mobile_finish,
  take_fixed,
  take_vector,
  mobile_join,
  mobile_vector,
  mobile_byte,
  mobile_zeroes,
  mobile_read_u64,
  mobile_write_u64
)
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local, seal_local
from Storage.Records import compare_and_swap_blobs
from Transparency.Fork import decode_fork, encode_fork

# Status: 0 no proof, 1 awaiting wallet, 2 declined at detection, 3 selected,
# 4 wallet unavailable, 5 frozen legacy. Preference changes affect future forks.
pub struct BountyState do
  enabled :: Bool
  status :: Int
  proof_identity :: Bytes
  finder :: Bytes
  index :: U64
end

struct StoredBounty do
  state :: BountyState
  ciphertext :: Bytes
end

fn label() -> String do
  "fork-bounty/v1"
end

fn proof_label() -> String do
  "transparency-fork/v1"
end

fn initial() -> BountyState!String do
  Ok(BountyState {
    enabled: false,
    status: 0,
    proof_identity: Bytes.empty(),
    finder: Bytes.empty(),
    index: U64.parse("0")?
  })
end

fn valid(state :: BountyState) -> Result<(), String> do
  if state.status < 0 || state.status > 5 do
    return Err("invalid_bounty_state")
  end
  if state.status == 0 do
    if Bytes.length(state.proof_identity) != 0 || Bytes.length(state.finder) != 0 do
      return Err("invalid_bounty_state")
    end
  else if Bytes.length(state.proof_identity) != 32 do
    return Err("invalid_bounty_state")
  end
  if state.status == 1 do
    if Bytes.length(state.finder) != 0 do
      return Err("invalid_bounty_state")
    end
  else if state.status >= 2 && Bytes.length(state.finder) != 32 do
    return Err("invalid_bounty_state")
  end
  if state.status == 3 do
    if U64.compare(state.index, U64.parse("2147483648")?) >= 0
      || Bytes.secure_equals(state.finder, mobile_zeroes(32)?) do
      return Err("invalid_bounty_state")
    end
  else if state.index != U64.parse("0")? do
    return Err("invalid_bounty_state")
  end
  if (state.status == 2 || state.status == 4)
    && !Bytes.secure_equals(state.finder, mobile_zeroes(32)?) do
    return Err("invalid_bounty_state")
  end
  Ok(nil)
end

fn seal(state :: BountyState, key :: borrow StorageKey) -> Bytes!String do
  valid(state)?
  let wire = mobile_join([
      Bytes.from_utf8("BNY1"),
      mobile_byte(if state.enabled do
        1
      else
        0
      end)?,
      mobile_byte(state.status)?,
      mobile_write_u64(state.index)?,
      mobile_vector(state.proof_identity)?,
      mobile_vector(state.finder)?
    ],
    0,
    Bytes.empty())?
  seal_local(wire, key, local_context(label())?)
end

fn read_stored(path :: String, key :: borrow StorageKey) -> StoredBounty!String do
  let blob = case load_blob(path, label()) do
    Err(error) -> if error == "local_state_not_found" do
      return Ok(StoredBounty { state: initial()?, ciphertext: Bytes.empty() })
    else
      return Err(error)
    end
    Ok(value) -> value
  end
  let wire = open_local(blob, key, local_context(label())?)?
  let magic = take_fixed(mobile_reader(wire, 86, "invalid_bounty_state")?, 4)?
  let flags = take_fixed(magic.state, 2)?
  let index = take_fixed(flags.state, 8)?
  let identity = take_vector(index.state, 32)?
  let finder = take_vector(identity.state, 32)?
  mobile_finish(finder.state, "invalid_bounty_state")?
  let enabled = Bytes.get(flags.value, 0)?
  if !Bytes.secure_equals(magic.value, Bytes.from_utf8("BNY1")) || enabled > 1 do
    return Err("invalid_bounty_state")
  end
  let state = BountyState {
    enabled: enabled == 1,
    status: Bytes.get(flags.value, 1)?,
    proof_identity: identity.value,
    finder: finder.value,
    index: mobile_read_u64(index.value)?
  }
  valid(state)?
  Ok(StoredBounty { state: state, ciphertext: blob })
end

fn raw_proof(path :: String, key :: borrow StorageKey) -> Bytes!String do
  case load_blob(path, proof_label()) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
    Ok(blob) -> open_local(blob, key, local_context(proof_label())?)
  end
end

fn current(path :: String, key :: borrow StorageKey, retries :: Int) -> StoredBounty!String do
  if retries > 6 do
    return Err("local_state_changed")
  end
  let stored = read_stored(path, key)?
  let proof = raw_proof(path, key)?
  if Bytes.length(proof) == 0 do
    if stored.state.status != 0 do
      return Err("invalid_bounty_state")
    end
    return Ok(stored)
  end
  let identity = Crypto.sha256(proof)
  if stored.state.status != 0 do
    if !Bytes.secure_equals(identity, stored.state.proof_identity) do
      return Err("invalid_bounty_state")
    end
    return Ok(stored)
  end
  # Earlier builds may already have exported/filed this exact wire.
  let migrated = %{stored.state |
    status: 5,
    proof_identity: identity,
    finder: decode_fork(proof)?.finder
  }
  let blob = seal(migrated, key)?
  case compare_and_swap_blobs(path, [label()], [blob], stored.ciphertext) do
    Err(error) -> if error == "local_state_changed" do
      current(path, key, retries + 1)
    else
      Err(error)
    end
    Ok(_) -> Ok(StoredBounty { state: migrated, ciphertext: blob })
  end
end

pub fn bounty_state(path :: String, key :: borrow StorageKey) -> BountyState!String do
  Ok(current(path, key, 0)?.state)
end

pub fn set_bounty_enabled(path :: String,
  key :: borrow StorageKey,
  enabled :: Bool) -> BountyState!String do
  let stored = current(path, key, 0)?
  if stored.state.enabled == enabled do
    return Ok(stored.state)
  end
  let next = %{stored.state | enabled: enabled}
  compare_and_swap_blobs(path, [label()], [seal(next, key)?], stored.ciphertext)?
  Ok(next)
end

fn retain(path :: String,
  key :: borrow StorageKey,
  proof :: Bytes,
  retries :: Int) -> Result<(), String> do
  if retries > 6 do
    return Err("local_state_changed")
  end
  let stored = current(path, key, 0)?
  if stored.state.status != 0 do
    return Ok(nil)
  end
  let next = %{stored.state |
    status: if stored.state.enabled do
      1
    else
      2
    end,
    proof_identity: Crypto.sha256(proof),
    finder: if stored.state.enabled do
      Bytes.empty()
    else
      mobile_zeroes(32)?
    end
  }
  # The preference and first proof share one CAS. Concurrent detections cannot
  # replace the winner; a preference change cannot split the choice from it.
  case compare_and_swap_blobs(path,
    [label(), proof_label()],
    [seal(next, key)?, seal_local(proof, key, local_context(proof_label())?)?],
    stored.ciphertext) do
    Err(error) -> if error == "local_state_changed" do
      retain(path, key, proof, retries + 1)
    else
      Err(error)
    end
    Ok(_) -> Ok(nil)
  end
end

# Called after native policy verifies the proof. An incoming finder is not
# wallet authority; only the native SDK may supply this phone's finder.
pub fn retain_bounty_fork(path :: String,
  key :: borrow StorageKey,
  proof :: Bytes) -> Result<(), String> do
  let decoded = decode_fork(proof)?
  retain(path, key, encode_fork(%{decoded | finder: mobile_zeroes(32)?})?, 0)
end

pub fn commit_bounty_address(path :: String,
  key :: borrow StorageKey,
  identity :: Bytes,
  reservation :: Bytes) -> BountyState!String do
  if Bytes.length(identity) != 32 || Bytes.length(reservation) != 40 do
    return Err("invalid_bounty_reservation")
  end
  let index = case Bytes.read_u64_le(reservation, 0) do
    Err(_) -> return Err("invalid_bounty_reservation")
    Ok(value) -> value
  end
  let finder = Bytes.slice(reservation, 8, 32)?
  let stored = current(path, key, 0)?
  let state = stored.state
  if !Bytes.secure_equals(identity, state.proof_identity) do
    return Err("bounty_proof_changed")
  end
  let next = %{state | status: 3, finder: finder, index: index}
  valid(next)?
  if state.status == 3 && state.index == index && Bytes.secure_equals(state.finder, finder) do
    return Ok(state)
  end
  if state.status != 1 do
    return Err("bounty_selection_frozen")
  end
  compare_and_swap_blobs(path, [label()], [seal(next, key)?], stored.ciphertext)?
  Ok(next)
end

pub fn abandon_bounty_address(path :: String,
  key :: borrow StorageKey,
  identity :: Bytes) -> BountyState!String do
  let stored = current(path, key, 0)?
  let state = stored.state
  if Bytes.length(identity) != 32 || !Bytes.secure_equals(identity, state.proof_identity) do
    return Err("bounty_proof_changed")
  end
  if state.status == 4 do
    return Ok(state)
  end
  if state.status != 1 do
    return Err("bounty_selection_frozen")
  end
  let next = %{state | status: 4, finder: mobile_zeroes(32)?}
  compare_and_swap_blobs(path, [label()], [seal(next, key)?], stored.ciphertext)?
  Ok(next)
end

pub fn disclosable_fork(path :: String, key :: borrow StorageKey) -> Bytes!String do
  let stored = current(path, key, 0)?
  if stored.state.status == 0 do
    return Ok(Bytes.empty())
  end
  if stored.state.status == 1 do
    return Err("bounty_selection_pending")
  end
  let proof = raw_proof(path, key)?
  if !Bytes.secure_equals(Crypto.sha256(proof), stored.state.proof_identity) do
    return Err("bounty_proof_changed")
  end
  encode_fork(%{decode_fork(proof)? | finder: stored.state.finder})
end
