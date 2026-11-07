##! Typed two-map SPQR persistence. No output journal or generic storage fallback.
from Session.BraidResponder import BraidScope, braid_valid_scope
from Session.Spqr import SpqrState, SpqrSlot

pub struct SpqrStoreIdentity do
  revision :: U64
  transition :: Bytes
  descriptor :: Bytes
end

pub struct SpqrSaved do
  scope :: BraidScope
  direction :: Int
  epoch :: U64
  knowledge :: U64
  slots :: List<SpqrSlot>
  skipped_index :: Bytes
  revision :: U64
  transition :: Bytes
  descriptor :: Bytes
  chains :: Bytes
  skipped :: Bytes
end

fn check(value :: Bool) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err("invalid_spqr_storage_metadata")
  end
end

fn number(value :: String) -> U64!String do
  U64.parse(value)
end

fn byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Ok(v)
    Err(_) -> Err("invalid_spqr_storage_metadata")
  end
end

fn short(value :: Int) -> Bytes!String do
  case Bytes.write_u16_be(value) do
    Ok(v)
    Err(_) -> Err("invalid_spqr_storage_metadata")
  end
end

fn wide(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Ok(v)
    Err(_) -> Err("invalid_spqr_storage_metadata")
  end
end

fn read_wide(value :: Bytes, offset :: Int) -> U64!String do
  case Bytes.read_u64_be(value, offset) do
    Ok(v)
    Err(_) -> Err("invalid_spqr_storage_metadata")
  end
end

fn join(parts :: List<Bytes>) -> Bytes!String do
  case Bytes.concat_many(parts, 1309) do
    Ok(v)
    Err(_) -> Err("invalid_spqr_storage_metadata")
  end
end

fn flag(value :: Bool) -> Bytes!String do
  byte(if value do
    1
  else
    0
  end)
end

fn validate(value :: SpqrSaved) -> Result<(), String> do
  let zero = number("0")?
  check(braid_valid_scope(value.scope, number("1")?)
    && (value.direction == 0 || value.direction == 1)
    && U64.compare(value.revision, zero) > 0
    && Bytes.length(value.transition) == 32
    && Bytes.length(value.descriptor) == 32
    && U64.compare(value.knowledge, value.epoch) <= 0)?
  let gap = U64.subtract(value.epoch, value.knowledge)?
  check(U64.compare(gap, number("1")?) <= 0)?
  let first = if U64.compare(value.knowledge, zero) == 0 do
    zero
  else
    U64.subtract(value.knowledge, number("1")?)?
  end
  let count = U64.to_int(U64.subtract(value.epoch, first)?)?
  check(count <= 2 && List.length(value.slots) == count + 1)?
  for i in 0..List.length(value.slots) do
    let s = List.get(value.slots, i)
    check(U64.compare(s.epoch, U64.add(first, number(Int.to_string(i))?)?) == 0
      && s.receive_present)?
    if U64.compare(s.epoch, value.knowledge) > 0 do
      check(U64.compare(s.send_count, zero) == 0 && U64.compare(s.receive_count, zero) == 0)?
    end
    check(s.send_present
      || (U64.compare(s.epoch, value.knowledge) < 0 && U64.compare(s.send_count, zero) == 0))?
  end
  check(List.length(List.filter(value.slots,
    fn(s) -> s.send_present && U64.compare(s.send_count, zero) > 0 end)) <= 1)?
  let n = Bytes.length(value.skipped_index) / 16
  check(n <= 64 && n * 16 == Bytes.length(value.skipped_index))?
  for i in 0..n do
    let e = read_wide(value.skipped_index, i * 16)?
    let k = read_wide(value.skipped_index, i * 16 + 8)?
    check(U64.compare(e, first) >= 0
      && U64.compare(e, value.epoch) <= 0
      && U64.compare(k, zero) > 0)?
    let offset = U64.to_int(U64.subtract(e, first)?)?
    check(U64.compare(k, List.get(value.slots, offset).receive_count) < 0)?
    if i > 0 do
      let old_e = read_wide(value.skipped_index, (i - 1) * 16)?
      let old_k = read_wide(value.skipped_index, (i - 1) * 16 + 8)?
      check(U64.compare(old_e, e) < 0 || (U64.compare(old_e, e) == 0 && U64.compare(old_k, k) < 0))?
    end
  end
  Ok(nil)
end

fn scope_bytes(scope :: BraidScope) -> Bytes!String do
  join([
    byte(Bytes.length(scope.protocol_info))?,
    scope.protocol_info,
    scope.configuration,
    scope.account_id,
    scope.device_id,
    scope.peer_account_id,
    scope.peer_device_id,
    scope.session_id
  ])
end

pub fn spqr_storage_context(value :: SpqrSaved, purpose :: Int) -> Bytes!String do
  validate(value)?
  check(purpose == 24 || purpose == 25)?
  let component = if purpose == 24 do
    "chains"
  else
    "skipped"
  end
  let object = Crypto.sha256(join([
    Bytes.from_utf8("mesh/spqr/storage/v1/" <> component),
    byte(0)?,
    scope_bytes(value.scope)?,
    byte(value.direction)?,
    wide(value.revision)?,
    value.transition,
    value.descriptor
  ])?)
  let slots = for s in value.slots do
    join([
      wide(s.epoch)?,
      flag(s.send_present)?,
      wide(s.send_count)?,
      flag(s.receive_present)?,
      wide(s.receive_count)?
    ])?
  end
  join([
    byte(1)?,
    value.scope.account_id,
    value.scope.device_id,
    value.scope.session_id,
    object,
    short(purpose)?,
    wide(value.revision)?,
    byte(1)?,
    byte(value.direction)?,
    wide(value.epoch)?,
    wide(value.knowledge)?,
    value.transition,
    value.descriptor,
    byte(List.length(value.slots))?
  ]
    ++ slots
    ++ [byte(Bytes.length(value.skipped_index) / 16)?, value.skipped_index])
end

## Borrowing preserves the owner if either typed seal fails. Every call reseals both maps.
pub fn seal_spqr(state :: borrow SpqrState,
  key :: borrow StorageKey,
  identity :: SpqrStoreIdentity) -> SpqrSaved!String do
  let value = SpqrSaved {
    scope: state.scope,
    direction: state.direction,
    epoch: state.epoch,
    knowledge: state.knowledge,
    slots: state.slots,
    skipped_index: state.skipped_index,
    revision: identity.revision,
    transition: identity.transition,
    descriptor: identity.descriptor,
    chains: Bytes.empty(),
    skipped: Bytes.empty()
  }
  let chains = case SecretMap.seal_for_storage(state.chains,
    key,
    spqr_storage_context(value, 24)?) do
    Ok(v) -> v
    Err(_) -> return Err("spqr_storage_failed")
  end
  let skipped = case SecretMap.seal_for_storage(state.skipped,
    key,
    spqr_storage_context(value, 25)?) do
    Ok(v) -> v
    Err(_) -> return Err("spqr_storage_failed")
  end
  Ok(%{value | chains: chains, skipped: skipped})
end

## Only typed roles publish maps; a failed second open drops the first candidate.
pub fn restore_spqr(value :: SpqrSaved,
  expected :: SpqrSaved,
  key :: borrow StorageKey) -> SpqrState!String do
  let c = spqr_storage_context(value, 24)?
  let s = spqr_storage_context(value, 25)?
  check(Bytes.secure_equals(c, spqr_storage_context(expected, 24)?)
    && Bytes.secure_equals(s, spqr_storage_context(expected, 25)?))?
  let chains = case SecretMap.unseal_from_storage(value.chains, key, c) do
    Ok(v) -> v
    Err(_) -> return Err("spqr_storage_failed")
  end
  let skipped = case SecretMap.unseal_from_storage(value.skipped, key, s) do
    Ok(v) -> v
    Err(_) -> return Err("spqr_storage_failed")
  end
  Ok(SpqrState {
    scope: value.scope,
    direction: value.direction,
    epoch: value.epoch,
    knowledge: value.knowledge,
    slots: value.slots,
    skipped_index: value.skipped_index,
    chains: chains,
    skipped: skipped
  })
end
