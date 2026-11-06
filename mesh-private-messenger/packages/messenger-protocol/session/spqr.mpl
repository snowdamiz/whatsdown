##! Inactive affine SPQR key consumer. No storage, HE or transport authority.
from Session.BraidResponder import BraidScope
from Session.BraidInitiator import BraidEpochOutput
from Session.SpqrKdf import (
  SpqrError,
  spqr_number,
  spqr_check,
  spqr_join,
  spqr_epoch_bytes,
  spqr_byte,
  spqr_scope,
  spqr_initial_material,
  spqr_add_material,
  spqr_step_material
)

pub struct SpqrSlot do
  epoch :: U64
  send_present :: Bool
  send_count :: U64
  receive_present :: Bool
  receive_count :: U64
end

pub resource struct SpqrState do
  scope :: BraidScope
  # Initial handshake direction; not the alternating Braid role.
  direction :: Int
  epoch :: U64
  knowledge :: U64
  slots :: List<SpqrSlot>
  chains :: SecretMap
  skipped :: SecretMap
  # Sorted sixteen-byte epoch/number pairs, at most64; no key plaintext.
  skipped_index :: Bytes
end

pub type SpqrEpochAdmission do
  SpqrEpochAccepted(state :: SpqrState)
  SpqrEpochRefused(state :: SpqrState, error :: SpqrError)
end

pub type SpqrKeyAdmission do
  SpqrKeyAccepted(state :: SpqrState, key :: SecretBytes, number :: U64)
  SpqrKeyRefused(state :: SpqrState, error :: SpqrError)
end

fn next(value :: U64) -> U64!SpqrError do
  case U64.add(value, spqr_number("1")?) do
    Ok(v)
    Err(_) -> Err(SpqrCounterOverflow)
  end
end

fn difference(value :: U64, base :: U64) -> U64!SpqrError do
  case U64.subtract(value, base) do
    Ok(v)
    Err(_) -> Err(SpqrInvalidState)
  end
end

fn first_epoch(knowledge :: U64) -> U64!SpqrError do
  if U64.compare(knowledge, spqr_number("0")?) == 0 do
    Ok(knowledge)
  else
    difference(knowledge, spqr_number("1")?)
  end
end

fn key_name(epoch :: U64, direction :: Int) -> Bytes!SpqrError do
  spqr_join([spqr_byte(1)?, spqr_epoch_bytes(epoch)?, spqr_byte(direction)?], 10)
end

fn index_name(epoch :: U64, number :: U64) -> Bytes!SpqrError do
  spqr_join([spqr_epoch_bytes(epoch)?, spqr_epoch_bytes(number)?], 16)
end

fn skip_name(epoch :: U64, number :: U64) -> Bytes!SpqrError do
  spqr_join([spqr_byte(2)?, index_name(epoch, number)?], 17)
end

fn read_number(bytes :: Bytes, offset :: Int) -> U64!SpqrError do
  case Bytes.read_u64_be(bytes, offset) do
    Ok(v)
    Err(_) -> Err(SpqrInvalidState)
  end
end

fn index_count(bytes :: Bytes) -> Int!SpqrError do
  let count = Bytes.length(bytes) / 16
  spqr_check(count <= 64 && count * 16 == Bytes.length(bytes))?
  Ok(count)
end

fn earlier(e :: U64, n :: U64, other_e :: U64, other_n :: U64) -> Bool do
  U64.compare(e, other_e) < 0 || (U64.compare(e, other_e) == 0 && U64.compare(n, other_n) < 0)
end

fn selected(slots :: List<SpqrSlot>, epoch :: U64) -> Int!SpqrError do
  for i in 0..List.length(slots) do
    if U64.compare(List.get(slots, i).epoch, epoch) == 0 do
      return Ok(i)
    end
  end
  Err(SpqrRetired)
end

fn validate(state :: borrow SpqrState) -> Result<(), SpqrError> do
  spqr_scope(state.scope)?
  spqr_check(state.direction == 0 || state.direction == 1)?
  spqr_check(U64.compare(state.knowledge, state.epoch) <= 0)?
  let gap = difference(state.epoch, state.knowledge)?
  spqr_check(U64.compare(gap, spqr_number("1")?) <= 0)?
  let minimum = first_epoch(state.knowledge)?
  let size = difference(state.epoch, minimum)?
  let size = case U64.to_int(size) do
    Ok(v) -> v
    Err(_) -> return Err(SpqrInvalidState)
  end
  spqr_check(size <= 2
    && List.length(state.slots) == size + 1
    && SecretMap.contains(state.chains, spqr_byte(0)?))?
  for i in 0..List.length(state.slots) do
    let slot = List.get(state.slots, i)
    let expected = case U64.add(minimum, spqr_number(Int.to_string(i))?) do
      Ok(v) -> v
      Err(_) -> return Err(SpqrInvalidState)
    end
    spqr_check(U64.compare(slot.epoch, expected) == 0 && slot.receive_present)?
    if U64.compare(slot.epoch, state.knowledge) > 0 do
      spqr_check(U64.compare(slot.send_count, spqr_number("0")?) == 0
        && U64.compare(slot.receive_count, spqr_number("0")?) == 0)?
    end
    spqr_check(slot.send_present
      || (U64.compare(slot.epoch, state.knowledge) < 0
        && U64.compare(slot.send_count, spqr_number("0")?) == 0))?
    spqr_check(SecretMap.contains(state.chains,
      key_name(slot.epoch, state.direction)?) == slot.send_present
      && SecretMap.contains(state.chains, key_name(slot.epoch, 1 - state.direction)?))?
  end
  let zero = spqr_number("0")?
  spqr_check(List.length(List.filter(state.slots,
    fn(slot) -> slot.send_present && U64.compare(slot.send_count, zero) > 0 end)) <= 1)?
  let count = index_count(state.skipped_index)?
  for i in 0..count do
    let e = read_number(state.skipped_index, i * 16)?
    let n = read_number(state.skipped_index, i * 16 + 8)?
    spqr_check(U64.compare(n, spqr_number("0")?) > 0
      && U64.compare(e, minimum) >= 0
      && U64.compare(e, state.epoch) <= 0)?
    if i > 0 do
      spqr_check(earlier(read_number(state.skipped_index, (i - 1) * 16)?,
        read_number(state.skipped_index, (i - 1) * 16 + 8)?,
        e,
        n))?
    end
    let slot = List.get(state.slots, selected(state.slots, e)?)
    spqr_check(U64.compare(n, slot.receive_count) < 0
      && SecretMap.contains(state.skipped, skip_name(e, n)?))?
  end
  Ok(nil)
end

fn replace(map :: borrow SecretMap,
  name :: Bytes,
  key :: consume SecretBytes) -> Result<(), SpqrError> do
  if SecretMap.contains(map, name) do
    SecretMap.delete(map, name)?
  end
  SecretMap.insert(map, name, key)?
  Ok(nil)
end

fn make_state(old :: borrow SpqrState,
  slots :: List<SpqrSlot>,
  chains :: consume SecretMap,
  skipped :: consume SecretMap,
  index :: Bytes,
  epoch :: U64,
  knowledge :: U64) -> SpqrState do
  SpqrState {
    scope: old.scope,
    direction: old.direction,
    epoch: epoch,
    knowledge: knowledge,
    slots: slots,
    chains: chains,
    skipped: skipped,
    skipped_index: index
  }
end

pub fn initialize_spqr(scope :: BraidScope,
  direction :: Int,
  seed :: borrow SecretBytes) -> SpqrState!SpqrError do
  spqr_check(direction == 0 || direction == 1)?
  let (root, forward, reverse) = spqr_initial_material(scope, seed)?
  let chains = SecretMap.new(7)?
  let zero = spqr_number("0")?
  SecretMap.insert(chains, spqr_byte(0)?, root)?
  SecretMap.insert(chains, key_name(zero, 0)?, forward)?
  SecretMap.insert(chains, key_name(zero, 1)?, reverse)?
  Ok(SpqrState {
    scope: scope,
    direction: direction,
    epoch: zero,
    knowledge: zero,
    slots: [
      SpqrSlot {
        epoch: zero,
        send_present: true,
        send_count: zero,
        receive_present: true,
        receive_count: zero
      }
    ],
    chains: chains,
    skipped: SecretMap.new(64)?,
    skipped_index: Bytes.empty()
  })
end

fn add_epoch(state :: borrow SpqrState, output :: borrow BraidEpochOutput) -> SpqrState!SpqrError do
  validate(state)?
  let successor = next(state.epoch)?
  if U64.compare(output.epoch, successor) != 0 || U64.compare(state.epoch, state.knowledge) != 0 do
    return Err(SpqrEpochOrder)
  end
  let old_root = SecretMap.copy(state.chains, spqr_byte(0)?)?
  let (root, forward, reverse) = spqr_add_material(state.scope, old_root, output.key, output.epoch)?
  Secret.destroy(old_root)
  let chains = SecretMap.fork(state.chains)?
  let skipped = SecretMap.fork(state.skipped)?
  replace(chains, spqr_byte(0)?, root)?
  SecretMap.insert(chains, key_name(output.epoch, 0)?, forward)?
  SecretMap.insert(chains, key_name(output.epoch, 1)?, reverse)?
  let zero = spqr_number("0")?
  let slots = List.append(state.slots,
    SpqrSlot {
      epoch: output.epoch,
      send_present: true,
      send_count: zero,
      receive_present: true,
      receive_count: zero
    })
  Ok(make_state(state, slots, chains, skipped, state.skipped_index, output.epoch, state.knowledge))
end

## The actual scoped kernel call belongs to the consuming coordinator. No output journal.
pub fn incorporate_spqr_epoch(state :: consume SpqrState,
  output :: consume BraidEpochOutput) -> SpqrEpochAdmission do
  case add_epoch(state, output) do
    Ok(v) -> SpqrEpochAccepted(v)
    Err(error) -> SpqrEpochRefused(state, error)
  end
end

fn pruned_index(index :: Bytes, minimum :: U64) -> Bytes!SpqrError do
  let records = for i in 0..index_count(index)? do
    let e = read_number(index, i * 16)?
    let n = read_number(index, i * 16 + 8)?
    if U64.compare(e, minimum) >= 0 do
      index_name(e, n)?
    else
      Bytes.empty()
    end
  end
  spqr_join(records, 1024)
end

fn prune(state :: borrow SpqrState,
  chains :: borrow SecretMap,
  skipped :: borrow SecretMap,
  minimum :: U64) -> List<SpqrSlot>!SpqrError do
  for slot in state.slots do
    if U64.compare(slot.epoch, minimum) < 0 do
      for direction in [0, 1] do
        let name = key_name(slot.epoch, direction)?
        if SecretMap.contains(chains, name) do
          SecretMap.delete(chains, name)?
        end
      end
    end
  end
  for i in 0..index_count(state.skipped_index)? do
    let e = read_number(state.skipped_index, i * 16)?
    let n = read_number(state.skipped_index, i * 16 + 8)?
    if U64.compare(e, minimum) < 0 do
      SecretMap.delete(skipped, skip_name(e, n)?)?
    end
  end
  Ok(List.filter(state.slots, fn(slot) -> U64.compare(slot.epoch, minimum) >= 0 end))
end

fn send_key(state :: borrow SpqrState,
  knowledge :: U64) -> (SpqrState, SecretBytes, U64)!SpqrError do
  validate(state)?
  if U64.compare(knowledge, state.knowledge) < 0 do
    return Err(SpqrRetired)
  end
  if U64.compare(knowledge, state.epoch) > 0 do
    return Err(SpqrEpochOrder)
  end
  let slot = List.get(state.slots, selected(state.slots, knowledge)?)
  if !slot.send_present do
    return Err(SpqrRetired)
  end
  let n = next(slot.send_count)?
  let chain = SecretMap.copy(state.chains, key_name(knowledge, state.direction)?)?
  let (next_chain, key) = spqr_step_material(state.scope, chain, state.direction, knowledge, n)?
  Secret.destroy(chain)
  let minimum = first_epoch(knowledge)?
  let chains = SecretMap.fork(state.chains)?
  let skipped = SecretMap.fork(state.skipped)?
  let slots = prune(state, chains, skipped, minimum)?
  let updated = for old in slots do
    if U64.compare(old.epoch, knowledge) < 0 && old.send_present do
      SecretMap.delete(chains, key_name(old.epoch, state.direction)?)?
      %{old | send_present: false, send_count: spqr_number("0")?}
    else if U64.compare(old.epoch, knowledge) == 0 do
      %{old | send_count: n}
    else
      old
    end
  end
  replace(chains, key_name(knowledge, state.direction)?, next_chain)?
  Ok((make_state(state,
      updated,
      chains,
      skipped,
      pruned_index(state.skipped_index, minimum)?,
      state.epoch,
      knowledge),
    key,
    n))
end

pub fn spqr_send_key(state :: consume SpqrState, knowledge :: U64) -> SpqrKeyAdmission do
  case send_key(state, knowledge) do
    Ok((v, key, n)) -> SpqrKeyAccepted(v, key, n)
    Err(error) -> SpqrKeyRefused(state, error)
  end
end

fn insertion_position(index :: Bytes,
  epoch :: U64,
  number :: U64,
  position :: Int,
  count :: Int) -> Int!SpqrError do
  spqr_check(position >= 0 && position <= count && count <= 64)?
  if position == count do
    return Ok(position)
  end
  if earlier(epoch,
    number,
    read_number(index, position * 16)?,
    read_number(index, position * 16 + 8)?) do
    Ok(position)
  else
    insertion_position(index, epoch, number, position + 1, count)
  end
end

fn part(index :: Bytes, offset :: Int, length :: Int) -> Bytes!SpqrError do
  case Bytes.slice(index, offset, length) do
    Ok(v)
    Err(_) -> Err(SpqrInvalidState)
  end
end

fn insert_index(index :: Bytes, epoch :: U64, number :: U64) -> Bytes!SpqrError do
  let count = index_count(index)?
  spqr_check(count < 64)?
  let offset = insertion_position(index, epoch, number, 0, count)? * 16
  spqr_join([
      part(index, 0, offset)?,
      index_name(epoch, number)?,
      part(index, offset, Bytes.length(index) - offset)?
    ],
    1024)
end

fn indexed(index :: Bytes, epoch :: U64, number :: U64) -> Bool!SpqrError do
  for i in 0..index_count(index)? do
    if U64.compare(read_number(index, i * 16)?, epoch) == 0
      && U64.compare(read_number(index, i * 16 + 8)?, number) == 0 do
      return Ok(true)
    end
  end
  Ok(false)
end

fn remove_index(index :: Bytes, epoch :: U64, number :: U64) -> Bytes!SpqrError do
  let records = for i in 0..index_count(index)? do
    let e = read_number(index, i * 16)?
    let n = read_number(index, i * 16 + 8)?
    if U64.compare(e, epoch) != 0 || U64.compare(n, number) != 0 do
      index_name(e, n)?
    else
      Bytes.empty()
    end
  end
  spqr_join(records, 1024)
end

## remaining is validated before entry: at most64 missing keys and recursion steps.
fn skip_keys(scope :: BraidScope,
  direction :: Int,
  epoch :: U64,
  chains :: borrow SecretMap,
  skipped :: borrow SecretMap,
  index :: Bytes,
  current :: U64,
  remaining :: Int) -> Bytes!SpqrError do
  spqr_check(remaining >= 0 && remaining <= 64)?
  if remaining == 0 do
    return Ok(index)
  end
  let number = next(current)?
  let chain = SecretMap.copy(chains, key_name(epoch, direction)?)?
  let (next_chain, key) = spqr_step_material(scope, chain, direction, epoch, number)?
  Secret.destroy(chain)
  replace(chains, key_name(epoch, direction)?, next_chain)?
  SecretMap.insert(skipped, skip_name(epoch, number)?, key)?
  skip_keys(scope,
    direction,
    epoch,
    chains,
    skipped,
    insert_index(index, epoch, number)?,
    number,
    remaining - 1)
end

fn receive_key(state :: borrow SpqrState,
  knowledge :: U64,
  number :: U64) -> (SpqrState, SecretBytes, U64)!SpqrError do
  validate(state)?
  spqr_check(U64.compare(number, spqr_number("0")?) > 0)?
  if U64.compare(knowledge, first_epoch(state.knowledge)?) < 0 do
    return Err(SpqrRetired)
  end
  if U64.compare(knowledge, state.epoch) > 0 do
    return Err(SpqrEpochOrder)
  end
  let slot = List.get(state.slots, selected(state.slots, knowledge)?)
  let k = if U64.compare(knowledge, state.knowledge) > 0 do
    knowledge
  else
    state.knowledge
  end
  let minimum = first_epoch(k)?
  let index = pruned_index(state.skipped_index, minimum)?
  let wanted = skip_name(knowledge, number)?
  if U64.compare(number, slot.receive_count) <= 0 do
    if !indexed(index, knowledge, number)? || !SecretMap.contains(state.skipped, wanted) do
      return Err(SpqrReplay)
    end
    let chains = SecretMap.fork(state.chains)?
    let skipped = SecretMap.fork(state.skipped)?
    let slots = prune(state, chains, skipped, minimum)?
    let key = SecretMap.copy(skipped, wanted)?
    SecretMap.delete(skipped, wanted)?
    Ok((make_state(state,
        slots,
        chains,
        skipped,
        remove_index(index, knowledge, number)?,
        state.epoch,
        k),
      key,
      number))
  else
    let gap = difference(number, slot.receive_count)?
    if U64.compare(gap, spqr_number("65")?) > 0 do
      return Err(SpqrSkipLimit)
    end
    let gap = case U64.to_int(gap) do
      Ok(v) -> v
      Err(_) -> return Err(SpqrSkipLimit)
    end
    if index_count(index)? + gap - 1 > 64 do
      return Err(SpqrSkipLimit)
    end
    let chains = SecretMap.fork(state.chains)?
    let skipped = SecretMap.fork(state.skipped)?
    let slots = prune(state, chains, skipped, minimum)?
    let index = skip_keys(state.scope,
      1 - state.direction,
      knowledge,
      chains,
      skipped,
      index,
      slot.receive_count,
      gap - 1)?
    let chain = SecretMap.copy(chains, key_name(knowledge, 1 - state.direction)?)?
    let (next_chain, key) = spqr_step_material(state.scope,
      chain,
      1 - state.direction,
      knowledge,
      number)?
    Secret.destroy(chain)
    replace(chains, key_name(knowledge, 1 - state.direction)?, next_chain)?
    let updated = for old in slots do
      if U64.compare(old.epoch, knowledge) == 0 do
        %{old | receive_count: number}
      else
        old
      end
    end
    Ok((make_state(state, updated, chains, skipped, index, state.epoch, k), key, number))
  end
end

pub fn spqr_receive_key(state :: consume SpqrState,
  knowledge :: U64,
  number :: U64) -> SpqrKeyAdmission do
  case receive_key(state, knowledge, number) do
    Ok((v, key, n)) -> SpqrKeyAccepted(v, key, n)
    Err(error) -> SpqrKeyRefused(state, error)
  end
end
