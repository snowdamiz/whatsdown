##! Typed inactive C1 persistence; storage purpose22 is new, continuation21 is unchanged.
from Session.BraidResponder import (
  BraidError,
  BraidScope,
  BraidAwaitHeader,
  BraidHeaderReady,
  BraidCt1Ready,
  braid_join,
  braid_epoch_bytes,
  braid_valid_scope
)

pub struct BraidSaved do
  scope :: BraidScope
  epoch :: U64
  revision :: U64
  transition :: Bytes
  phase :: Int
  header :: Bytes
  first :: Bytes
  secrets :: Bytes
  continuation :: Bytes
end

fn byte(value :: Int) -> Bytes!BraidError do
  case Bytes.from_list([value]) do
    Ok(v)
    Err(_) -> Err(BraidInvalidState)
  end
end

fn purpose(value :: Int) -> Bytes!BraidError do
  case Bytes.write_u16_be(value) do
    Ok(v)
    Err(_) -> Err(BraidInvalidState)
  end
end

pub fn braid_saved_shape(value :: BraidSaved) -> Bool do
  let zero = case U64.parse("0") do
    Ok(v) -> v
    Err(_) -> return false
  end
  braid_valid_scope(value.scope, value.epoch)
    && U64.compare(value.revision, zero) > 0
    && Bytes.length(value.transition) == 32
    && ((value.phase == 0 && Bytes.length(value.header) == 0 && Bytes.length(value.first) == 0)
      || (value.phase == 1 && Bytes.length(value.header) == 64 && Bytes.length(value.first) == 0)
      || (value.phase == 2 && Bytes.length(value.header) == 64 && Bytes.length(value.first) == 960))
end

fn object(value :: BraidSaved, role :: String) -> Bytes!BraidError do
  Ok(Crypto.sha256(braid_join([
    Bytes.from_utf8("morse/c1/braid-responder/storage/v1/" <> role),
    value.scope.configuration,
    purpose(Bytes.length(value.scope.protocol_info))?,
    value.scope.protocol_info,
    value.scope.account_id,
    value.scope.device_id,
    value.scope.peer_account_id,
    value.scope.peer_device_id,
    value.scope.session_id,
    braid_epoch_bytes(value.epoch)?,
    byte(value.phase)?,
    braid_epoch_bytes(value.revision)?,
    value.transition,
    value.header,
    value.first
  ])?))
end

pub fn braid_storage_context(value :: BraidSaved, role :: Int) -> Bytes!BraidError do
  if !braid_saved_shape(value) || (role != 21 && role != 22) do
    return Err(BraidInvalidState)
  end
  if role == 21 && value.phase != 2 do
    return Err(BraidInvalidState)
  end
  let common = braid_join([
    byte(1)?,
    value.scope.account_id,
    value.scope.device_id,
    value.scope.session_id,
    object(value,
      if role == 22 do
        "secrets"
      else
        "continuation"
      end)?,
    purpose(role)?,
    braid_epoch_bytes(value.revision)?
  ])?
  if role == 22 do
    braid_join([common, byte(value.phase)?])
  else
    Ok(common)
  end
end

fn seal_secrets(value :: BraidSaved,
  secrets :: borrow SecretMap,
  key :: borrow StorageKey) -> BraidSaved!BraidError do
  let blob = case SecretMap.seal_for_storage(secrets, key, braid_storage_context(value, 22)?) do
    Ok(v) -> v
    Err(error) -> return Err(BraidCryptoFailure(error))
  end
  Ok(%{value | secrets: blob})
end

pub fn seal_await(state :: borrow BraidAwaitHeader,
  key :: borrow StorageKey,
  revision :: U64,
  transition :: Bytes) -> BraidSaved!BraidError do
  seal_secrets(BraidSaved {
      scope: state.scope,
      epoch: state.epoch,
      revision: revision,
      transition: transition,
      phase: 0,
      header: Bytes.empty(),
      first: Bytes.empty(),
      secrets: Bytes.empty(),
      continuation: Bytes.empty()
    },
    state.secrets,
    key)
end

pub fn seal_header(state :: borrow BraidHeaderReady,
  key :: borrow StorageKey,
  revision :: U64,
  transition :: Bytes) -> BraidSaved!BraidError do
  seal_secrets(BraidSaved {
      scope: state.scope,
      epoch: state.epoch,
      revision: revision,
      transition: transition,
      phase: 1,
      header: state.header,
      first: Bytes.empty(),
      secrets: Bytes.empty(),
      continuation: Bytes.empty()
    },
    state.secrets,
    key)
end

pub fn seal_ct1(state :: borrow BraidCt1Ready,
  key :: borrow StorageKey,
  revision :: U64,
  transition :: Bytes) -> BraidSaved!BraidError do
  seal_ct1_fault(state, key, revision, transition, fn() -> Ok(nil) end)
end

## Inactive fixture fault seam after the first encrypted component exists but
## before any result or second component is published. It takes no secret.
pub fn seal_ct1_fault(state :: borrow BraidCt1Ready,
  key :: borrow StorageKey,
  revision :: U64,
  transition :: Bytes,
  after_map :: Fun() -> Result<(), BraidError>) -> BraidSaved!BraidError do
  let value = seal_secrets(BraidSaved {
      scope: state.scope,
      epoch: state.epoch,
      revision: revision,
      transition: transition,
      phase: 2,
      header: state.header,
      first: state.first.bytes,
      secrets: Bytes.empty(),
      continuation: Bytes.empty()
    },
    state.secrets,
    key)?
  after_map()?
  let blob = case MlKemEncapsulationState.seal_for_storage(state.continuation,
    key,
    braid_storage_context(value, 21)?) do
    Ok(v) -> v
    Err(error) -> return Err(BraidCryptoFailure(error))
  end
  Ok(%{value | continuation: blob})
end

fn restored_secrets(value :: BraidSaved, key :: borrow StorageKey) -> SecretMap!BraidError do
  case SecretMap.unseal_from_storage(value.secrets, key, braid_storage_context(value, 22)?) do
    Ok(v)
    Err(error) -> Err(BraidCryptoFailure(error))
  end
end

pub fn restore_await(value :: BraidSaved,
  key :: borrow StorageKey) -> BraidAwaitHeader!BraidError do
  if value.phase != 0 || Bytes.length(value.continuation) != 0 do
    return Err(BraidInvalidState)
  end
  Ok(BraidAwaitHeader {
    scope: value.scope,
    epoch: value.epoch,
    secrets: restored_secrets(value, key)?
  })
end

pub fn restore_header(value :: BraidSaved,
  key :: borrow StorageKey) -> BraidHeaderReady!BraidError do
  if value.phase != 1 || Bytes.length(value.continuation) != 0 do
    return Err(BraidInvalidState)
  end
  Ok(BraidHeaderReady {
    scope: value.scope,
    epoch: value.epoch,
    header: value.header,
    secrets: restored_secrets(value, key)?
  })
end

pub fn restore_ct1(value :: BraidSaved, key :: borrow StorageKey) -> BraidCt1Ready!BraidError do
  if value.phase != 2 do
    return Err(BraidInvalidState)
  end
  let slots = restored_secrets(value, key)?
  let continuation = case MlKemEncapsulationState.unseal_from_storage(value.continuation,
    key,
    braid_storage_context(value, 21)?) do
    Ok(v) -> v
    Err(error) -> return Err(BraidCryptoFailure(error))
  end
  Ok(BraidCt1Ready {
    scope: value.scope,
    epoch: value.epoch,
    header: value.header,
    first: MlKemCiphertext1_960 { bytes: value.first },
    secrets: slots,
    continuation: continuation
  })
end
