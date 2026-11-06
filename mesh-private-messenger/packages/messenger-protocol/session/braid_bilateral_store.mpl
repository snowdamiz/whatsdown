##! New complete-kernel storage record. Old BraidSaved/Journal stay unchanged.
##! New committed snapshots contain root/mac only; never re-emit epoch output.
from Session.BraidResponder import (
  BraidError,
  BraidScope,
  braid_join,
  braid_epoch_bytes,
  braid_valid_scope
)
from Session.BraidInitiator import (
  BraidAliceIdle,
  BraidAliceHeaderSent,
  BraidAliceEkSent,
  BraidAliceCt1Received
)
from Session.BraidComplete import (
  BraidBobCt1Sent,
  BraidBobEkReceived,
  BraidBobCt2Sent
)

pub struct BraidBilateralSaved do
  scope :: BraidScope
  role :: Int
  substate :: Int
  epoch :: U64
  revision :: U64
  transition :: Bytes
  output_epoch :: U64
  header :: Bytes
  vector :: Bytes
  first :: Bytes
  wire :: Bytes
  secrets :: Bytes
  epoch_key :: Bytes
  continuation :: Bytes
end

fn byte(value :: Int) -> Bytes!BraidError do
  case Bytes.from_list([value]) do
    Ok(v)
    Err(_) -> Err(BraidInvalidState)
  end
end

fn short(value :: Int) -> Bytes!BraidError do
  case Bytes.write_u16_be(value) do
    Ok(v)
    Err(_) -> Err(BraidInvalidState)
  end
end

fn number(text :: String) -> U64!BraidError do
  case U64.parse(text) do
    Ok(v)
    Err(_) -> Err(BraidInvalidState)
  end
end

fn output_epoch(role :: Int, epoch :: U64) -> U64!BraidError do
  if role == 2 do
    return Ok(epoch)
  end
  case U64.subtract(epoch, number("1")?) do
    Ok(v)
    Err(_) -> Err(BraidInvalidState)
  end
end

pub fn bilateral_saved_metadata(value :: BraidBilateralSaved) -> Bool do
  let zero = case number("0") do
    Ok(v) -> v
    Err(_) -> return false
  end
  let output = case output_epoch(value.role, value.epoch) do
    Ok(v) -> v
    Err(_) -> return false
  end
  let h = Bytes.length(value.header)
  let v = Bytes.length(value.vector)
  let c = Bytes.length(value.first)
  let w = Bytes.length(value.wire)
  braid_valid_scope(value.scope, value.epoch)
    && U64.compare(value.revision, zero) > 0
    && U64.compare(value.output_epoch, output) == 0
    && Bytes.length(value.transition) == 32
    && ((value.role == 1
      && ((value.substate == 0 && h == 0 && v == 0 && c == 0 && w == 0)
        || ((value.substate == 1 || value.substate == 2)
          && h == 64
          && v == 1152
          && c == 0
          && w == 0)
        || (value.substate == 3 && h == 64 && v == 1152 && c == 960 && w == 0)))
      || (value.role == 2
        && ((value.substate == 1 && h == 64 && v == 0 && c == 960 && w == 0)
          || (value.substate == 2 && h == 64 && v == 1152 && c == 960 && w == 0)
          || (value.substate == 3 && h == 64 && v == 1152 && c == 960 && w == 160))))
end

## Structural complete-carrier bound, distinct from the local output high-watermark.
## E becomes knowable to the peer only with the complete Ct2 carrier. This does
## not attest delivery or authorize a message/root-mixing action by itself.
pub fn bilateral_carrier_epoch(value :: BraidBilateralSaved) -> U64!BraidError do
  if !bilateral_saved_metadata(value) do
    return Err(BraidInvalidState)
  end
  if value.role == 2 && value.substate == 3 do
    return Ok(value.epoch)
  end
  case U64.subtract(value.epoch, number("1")?) do
    Ok(v)
    Err(_) -> Err(BraidInvalidState)
  end
end

pub fn bilateral_saved_shape(value :: BraidBilateralSaved) -> Bool do
  bilateral_saved_metadata(value)
    && Bytes.length(value.secrets) == 154
    && Bytes.length(value.epoch_key) == (if value.role == 1 && value.substate > 0 do
        131
      else
        0
      end)
    && Bytes.length(value.continuation) == (if value.role == 2 && value.substate < 3 do
        167
      else
        0
      end)
end

fn object(value :: BraidBilateralSaved, component :: String) -> Bytes!BraidError do
  if !bilateral_saved_metadata(value) do
    return Err(BraidInvalidState)
  end
  Ok(Crypto.sha256(braid_join([
    Bytes.from_utf8("morse/c1/bilateral/storage/v1/" <> component),
    value.scope.configuration,
    short(Bytes.length(value.scope.protocol_info))?,
    value.scope.protocol_info,
    value.scope.account_id,
    value.scope.device_id,
    value.scope.peer_account_id,
    value.scope.peer_device_id,
    value.scope.session_id,
    byte(value.role)?,
    byte(value.substate)?,
    braid_epoch_bytes(value.epoch)?,
    braid_epoch_bytes(value.revision)?,
    braid_epoch_bytes(value.output_epoch)?,
    value.transition,
    value.header,
    value.vector,
    value.first,
    value.wire
  ])?))
end

pub fn bilateral_storage_context(value :: BraidBilateralSaved,
  purpose :: Int) -> Bytes!BraidError do
  if !bilateral_saved_metadata(value) || (purpose != 21 && purpose != 22 && purpose != 23) do
    return Err(BraidInvalidState)
  end
  if purpose == 23 && (value.role != 1 || value.substate == 0) do
    return Err(BraidInvalidState)
  end
  if purpose == 21 && (value.role != 2 || value.substate == 3) do
    return Err(BraidInvalidState)
  end
  let component = if purpose == 22 do
    "authenticator"
  else if purpose == 23 do
    "epoch-private"
  else
    "continuation"
  end
  let common = braid_join([
    byte(1)?,
    value.scope.account_id,
    value.scope.device_id,
    value.scope.session_id,
    object(value, component)?,
    short(purpose)?,
    braid_epoch_bytes(value.revision)?
  ])?
  if purpose == 22 do
    braid_join([common, byte(0)?])
  else
    Ok(common)
  end
end

fn base(scope :: BraidScope,
  epoch :: U64,
  revision :: U64,
  transition :: Bytes,
  role :: Int,
  substate :: Int,
  header :: Bytes,
  vector :: Bytes,
  first :: Bytes,
  wire :: Bytes) -> BraidBilateralSaved!BraidError do
  let value = BraidBilateralSaved {
    scope: scope,
    role: role,
    substate: substate,
    epoch: epoch,
    revision: revision,
    transition: transition,
    output_epoch: output_epoch(role, epoch)?,
    header: header,
    vector: vector,
    first: first,
    wire: wire,
    secrets: Bytes.empty(),
    epoch_key: Bytes.empty(),
    continuation: Bytes.empty()
  }
  if !bilateral_saved_metadata(value) do
    return Err(BraidInvalidState)
  end
  Ok(value)
end

fn save_auth(value :: BraidBilateralSaved,
  auth :: borrow SecretMap,
  key :: borrow StorageKey) -> BraidBilateralSaved!BraidError do
  if SecretMap.contains(auth, Bytes.from_utf8("output")) do
    return Err(BraidInvalidState)
  end
  let blob = SecretMap.seal_for_storage(auth, key, bilateral_storage_context(value, 22)?)?
  Ok(%{value | secrets: blob})
end

fn save_epoch(value :: BraidBilateralSaved,
  private_key :: borrow MlKemPrivateKey,
  key :: borrow StorageKey) -> BraidBilateralSaved!BraidError do
  let (header, vector) = Crypto.mlkem_public_parts(private_key)?
  if !Bytes.secure_equals(header.bytes, value.header)
    || !Bytes.secure_equals(vector.bytes, value.vector) do
    return Err(BraidInvalidState)
  end
  let blob = MlKemPrivateKey.seal_for_storage(private_key,
    key,
    bilateral_storage_context(value, 23)?)?
  Ok(%{value | epoch_key: blob})
end

## `expected` must come from the caller's exact trusted guarded-journal basis.
## Passing self-described metadata as expected does not supply antirollback.
fn checked(value :: BraidBilateralSaved,
  expected :: BraidBilateralSaved,
  role :: Int,
  substate :: Int) -> Result<(), BraidError> do
  if !bilateral_saved_shape(value)
    || !bilateral_saved_metadata(expected)
    || value.role != role
    || value.substate != substate
    || !Bytes.secure_equals(object(value, "identity")?, object(expected, "identity")?) do
    return Err(BraidInvalidState)
  end
  Ok(nil)
end

fn load_auth(value :: BraidBilateralSaved, key :: borrow StorageKey) -> SecretMap!BraidError do
  case SecretMap.unseal_from_storage(value.secrets, key, bilateral_storage_context(value, 22)?) do
    Ok(v)
    Err(error) -> Err(BraidCryptoFailure(error))
  end
end

fn load_epoch(value :: BraidBilateralSaved,
  key :: borrow StorageKey) -> MlKemPrivateKey!BraidError do
  let private_key = MlKemPrivateKey.unseal_from_storage(value.epoch_key,
    key,
    bilateral_storage_context(value, 23)?)?
  let (header, vector) = Crypto.mlkem_public_parts(private_key)?
  if !Bytes.secure_equals(header.bytes, value.header)
    || !Bytes.secure_equals(vector.bytes, value.vector) do
    return Err(BraidInvalidState)
  end
  Ok(private_key)
end

pub fn save_alice_idle(state :: borrow BraidAliceIdle,
  key :: borrow StorageKey,
  revision :: U64,
  transition :: Bytes) -> BraidBilateralSaved!BraidError do
  let value = save_auth(base(state.scope,
      state.epoch,
      revision,
      transition,
      1,
      0,
      Bytes.empty(),
      Bytes.empty(),
      Bytes.empty(),
      Bytes.empty())?,
    state.secrets,
    key)?
  Ok(value)
end

pub fn restore_alice_idle(value :: BraidBilateralSaved,
  expected :: BraidBilateralSaved,
  key :: borrow StorageKey) -> BraidAliceIdle!BraidError do
  checked(value, expected, 1, 0)?
  Ok(BraidAliceIdle { scope: value.scope, epoch: value.epoch, secrets: load_auth(value, key)? })
end

pub fn save_alice_header(state :: borrow BraidAliceHeaderSent,
  key :: borrow StorageKey,
  revision :: U64,
  transition :: Bytes) -> BraidBilateralSaved!BraidError do
  let value = save_auth(base(state.scope,
      state.epoch,
      revision,
      transition,
      1,
      1,
      state.header.bytes,
      state.vector.bytes,
      Bytes.empty(),
      Bytes.empty())?,
    state.secrets,
    key)?
  save_epoch(value, state.private_key, key)
end

pub fn restore_alice_header(value :: BraidBilateralSaved,
  expected :: BraidBilateralSaved,
  key :: borrow StorageKey) -> BraidAliceHeaderSent!BraidError do
  checked(value, expected, 1, 1)?
  Ok(BraidAliceHeaderSent {
    scope: value.scope,
    epoch: value.epoch,
    header: MlKemHeader64 { bytes: value.header },
    vector: MlKemPublicVector1152 { bytes: value.vector },
    private_key: load_epoch(value, key)?,
    secrets: load_auth(value, key)?
  })
end

pub fn save_alice_ek(state :: borrow BraidAliceEkSent,
  key :: borrow StorageKey,
  revision :: U64,
  transition :: Bytes) -> BraidBilateralSaved!BraidError do
  let value = save_auth(base(state.scope,
      state.epoch,
      revision,
      transition,
      1,
      2,
      state.header.bytes,
      state.vector.bytes,
      Bytes.empty(),
      Bytes.empty())?,
    state.secrets,
    key)?
  save_epoch(value, state.private_key, key)
end

pub fn restore_alice_ek(value :: BraidBilateralSaved,
  expected :: BraidBilateralSaved,
  key :: borrow StorageKey) -> BraidAliceEkSent!BraidError do
  checked(value, expected, 1, 2)?
  Ok(BraidAliceEkSent {
    scope: value.scope,
    epoch: value.epoch,
    header: MlKemHeader64 { bytes: value.header },
    vector: MlKemPublicVector1152 { bytes: value.vector },
    private_key: load_epoch(value, key)?,
    secrets: load_auth(value, key)?
  })
end

pub fn save_alice_first(state :: borrow BraidAliceCt1Received,
  key :: borrow StorageKey,
  revision :: U64,
  transition :: Bytes) -> BraidBilateralSaved!BraidError do
  let value = save_auth(base(state.scope,
      state.epoch,
      revision,
      transition,
      1,
      3,
      state.header.bytes,
      state.vector.bytes,
      state.first.bytes,
      Bytes.empty())?,
    state.secrets,
    key)?
  save_epoch(value, state.private_key, key)
end

pub fn restore_alice_first(value :: BraidBilateralSaved,
  expected :: BraidBilateralSaved,
  key :: borrow StorageKey) -> BraidAliceCt1Received!BraidError do
  checked(value, expected, 1, 3)?
  Ok(BraidAliceCt1Received {
    scope: value.scope,
    epoch: value.epoch,
    header: MlKemHeader64 { bytes: value.header },
    vector: MlKemPublicVector1152 { bytes: value.vector },
    first: MlKemCiphertext1_960 { bytes: value.first },
    private_key: load_epoch(value, key)?,
    secrets: load_auth(value, key)?
  })
end

pub fn save_bob_first(state :: borrow BraidBobCt1Sent,
  key :: borrow StorageKey,
  revision :: U64,
  transition :: Bytes) -> BraidBilateralSaved!BraidError do
  let value = save_auth(base(state.scope,
      state.epoch,
      revision,
      transition,
      2,
      1,
      state.header.bytes,
      Bytes.empty(),
      state.first.bytes,
      Bytes.empty())?,
    state.secrets,
    key)?
  let blob = MlKemEncapsulationState.seal_for_storage(state.continuation,
    key,
    bilateral_storage_context(value, 21)?)?
  Ok(%{value | continuation: blob})
end

pub fn restore_bob_first(value :: BraidBilateralSaved,
  expected :: BraidBilateralSaved,
  key :: borrow StorageKey) -> BraidBobCt1Sent!BraidError do
  checked(value, expected, 2, 1)?
  Ok(BraidBobCt1Sent {
    scope: value.scope,
    epoch: value.epoch,
    header: MlKemHeader64 { bytes: value.header },
    first: MlKemCiphertext1_960 { bytes: value.first },
    continuation: MlKemEncapsulationState.unseal_from_storage(value.continuation,
      key,
      bilateral_storage_context(value, 21)?)?,
    secrets: load_auth(value, key)?
  })
end

pub fn save_bob_vector(state :: borrow BraidBobEkReceived,
  key :: borrow StorageKey,
  revision :: U64,
  transition :: Bytes) -> BraidBilateralSaved!BraidError do
  let value = save_auth(base(state.scope,
      state.epoch,
      revision,
      transition,
      2,
      2,
      state.header.bytes,
      state.vector.bytes,
      state.first.bytes,
      Bytes.empty())?,
    state.secrets,
    key)?
  let blob = MlKemEncapsulationState.seal_for_storage(state.continuation,
    key,
    bilateral_storage_context(value, 21)?)?
  Ok(%{value | continuation: blob})
end

pub fn restore_bob_vector(value :: BraidBilateralSaved,
  expected :: BraidBilateralSaved,
  key :: borrow StorageKey) -> BraidBobEkReceived!BraidError do
  checked(value, expected, 2, 2)?
  Ok(BraidBobEkReceived {
    scope: value.scope,
    epoch: value.epoch,
    header: MlKemHeader64 { bytes: value.header },
    vector: MlKemPublicVector1152 { bytes: value.vector },
    first: MlKemCiphertext1_960 { bytes: value.first },
    continuation: MlKemEncapsulationState.unseal_from_storage(value.continuation,
      key,
      bilateral_storage_context(value, 21)?)?,
    secrets: load_auth(value, key)?
  })
end

pub fn save_bob_second(state :: borrow BraidBobCt2Sent,
  key :: borrow StorageKey,
  revision :: U64,
  transition :: Bytes) -> BraidBilateralSaved!BraidError do
  let value = save_auth(base(state.scope,
      state.epoch,
      revision,
      transition,
      2,
      3,
      state.header.bytes,
      state.vector.bytes,
      state.first.bytes,
      state.wire)?,
    state.secrets,
    key)?
  Ok(value)
end

pub fn restore_bob_second(value :: BraidBilateralSaved,
  expected :: BraidBilateralSaved,
  key :: borrow StorageKey) -> BraidBobCt2Sent!BraidError do
  checked(value, expected, 2, 3)?
  Ok(BraidBobCt2Sent {
    scope: value.scope,
    epoch: value.epoch,
    header: MlKemHeader64 { bytes: value.header },
    vector: MlKemPublicVector1152 { bytes: value.vector },
    first: MlKemCiphertext1_960 { bytes: value.first },
    wire: value.wire,
    secrets: load_auth(value, key)?
  })
end
