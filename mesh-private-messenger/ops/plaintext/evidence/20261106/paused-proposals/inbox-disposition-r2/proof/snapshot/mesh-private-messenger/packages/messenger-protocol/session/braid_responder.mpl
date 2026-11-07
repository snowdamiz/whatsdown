##! Inactive C1 responder seam. Complete logical headers only; no wire/fragment
##! parser or Triple Ratchet composition is implemented by this module.

pub type BraidError do
  BraidInvalidState
  BraidInvalidHeader
  BraidWrongEpoch
  BraidAuthenticationRejected
  BraidCryptoFailure(error :: CryptoError)
end

impl From<CryptoError> for BraidError do
  fn from(error :: CryptoError) -> BraidError do
    BraidCryptoFailure(error)
  end
end

pub struct BraidScope do
  protocol_info :: Bytes
  configuration :: Bytes
  account_id :: Bytes
  device_id :: Bytes
  peer_account_id :: Bytes
  peer_device_id :: Bytes
  session_id :: Bytes
end

pub resource struct BraidAwaitHeader do
  scope :: BraidScope
  epoch :: U64
  secrets :: SecretMap
end

pub resource struct BraidHeaderReady do
  scope :: BraidScope
  epoch :: U64
  header :: Bytes
  secrets :: SecretMap
end

pub resource struct BraidCt1Ready do
  scope :: BraidScope
  epoch :: U64
  header :: Bytes
  first :: MlKemCiphertext1_960
  secrets :: SecretMap
  continuation :: MlKemEncapsulationState
end

pub type BraidHeaderAdmission do
  BraidHeaderAccepted(state :: BraidHeaderReady)
  BraidHeaderIgnored(state :: BraidAwaitHeader, error :: BraidError)
  BraidHeaderFatal(error :: BraidError)
end

pub fn braid_join(parts :: List<Bytes>) -> Bytes!BraidError do
  join_at(parts, 0, Bytes.empty())
end

fn join_at(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!BraidError do
  if index >= List.length(parts) do
    Ok(output)
  else
    let next = case Bytes.concat(output, List.get(parts, index)) do
      Ok(value) -> value
      Err(_) -> return Err(BraidInvalidState)
    end
    join_at(parts, index + 1, next)
  end
end

pub fn braid_epoch_bytes(epoch :: U64) -> Bytes!BraidError do
  case Bytes.write_u64_be(epoch) do
    Ok(value)
    Err(_) -> Err(BraidInvalidState)
  end
end

pub fn braid_valid_scope(scope :: BraidScope, epoch :: U64) -> Bool do
  let zero = case U64.parse("0") do
    Ok(value) -> value
    Err(_) -> return false
  end
  let empty_session = case Bytes.repeat(0, 32) do
    Ok(value) -> value
    Err(_) -> return false
  end
  Bytes.length(scope.protocol_info) > 0
    && Bytes.length(scope.protocol_info) <= 128
    && Bytes.length(scope.configuration) == 32
    && Bytes.length(scope.account_id) == 32
    && Bytes.length(scope.device_id) == 16
    && Bytes.length(scope.peer_account_id) == 32
    && Bytes.length(scope.peer_device_id) == 16
    && Bytes.length(scope.session_id) == 32
    && !Bytes.secure_equals(scope.session_id, empty_session)
    && U64.compare(epoch, zero) > 0
end

fn zero_salt() -> Bytes!BraidError do
  case Bytes.repeat(0, 32) do
    Ok(value)
    Err(_) -> Err(BraidInvalidState)
  end
end

fn info(scope :: BraidScope, label :: String, epoch :: U64) -> Bytes!BraidError do
  braid_join([scope.protocol_info, Bytes.from_utf8(label), braid_epoch_bytes(epoch)?])
end

fn auth_map(wide :: consume SecretBytes) -> SecretMap!BraidError do
  let (root, mac) = case Secret.split_at(wide, 32) do
    Ok(value) -> value
    Err(error) -> return Err(BraidCryptoFailure(error))
  end
  let slots = case SecretMap.new(3) do
    Ok(value) -> value
    Err(error) -> return Err(BraidCryptoFailure(error))
  end
  case SecretMap.insert(slots, Bytes.from_utf8("root"), root) do
    Err(error) -> return Err(BraidCryptoFailure(error))
    Ok(_) -> nil
  end
  case SecretMap.insert(slots, Bytes.from_utf8("mac"), mac) do
    Err(error) -> return Err(BraidCryptoFailure(error))
    Ok(_) -> nil
  end
  Ok(slots)
end

## Caller supplies an independently established opaque initializer. This is not
## an HE-root exporter or a production handshake/capability/initializer choice.
pub fn initialize_responder(scope :: BraidScope,
  shared :: borrow SecretBytes) -> BraidAwaitHeader!BraidError do
  let epoch = case U64.parse("1") do
    Ok(v) -> v
    Err(_) -> return Err(BraidInvalidState)
  end
  if !braid_valid_scope(scope, epoch) do
    return Err(BraidInvalidState)
  end
  let wide = case Crypto.hkdf_sha256(shared,
    zero_salt()?,
    info(scope, ":Authenticator Update", epoch)?,
    64) do
    Ok(value) -> value
    Err(error) -> return Err(BraidCryptoFailure(error))
  end
  Ok(BraidAwaitHeader { scope: scope, epoch: epoch, secrets: auth_map(wide)? })
end

fn header_tag(state :: borrow BraidAwaitHeader, header :: Bytes) -> Bytes!BraidError do
  let mac = case SecretMap.copy(state.secrets, Bytes.from_utf8("mac")) do
    Ok(value) -> value
    Err(error) -> return Err(BraidCryptoFailure(error))
  end
  let tag = case Crypto.hmac_sha256_tag(mac,
    braid_join([info(state.scope, ":ekheader", state.epoch)?, header])?) do
    Ok(value)
    Err(error) -> Err(BraidCryptoFailure(error))
  end
  Secret.destroy(mac)
  tag
end

## This pure transition does not authenticate an external envelope or authorize
## durable state. Only the owning HE coordinator may publish its outcome.
pub fn admit_complete_header(state :: consume BraidAwaitHeader,
  epoch :: U64,
  complete :: Bytes) -> BraidHeaderAdmission do
  if !braid_valid_scope(state.scope, state.epoch) do
    return BraidHeaderIgnored(state, BraidInvalidState)
  end
  if U64.compare(epoch, state.epoch) != 0 do
    return BraidHeaderIgnored(state, BraidWrongEpoch)
  end
  if Bytes.length(complete) != 96 do
    return BraidHeaderIgnored(state, BraidInvalidHeader)
  end
  let header = case Bytes.slice(complete, 0, 64) do
    Ok(value) -> value
    Err(_) -> return BraidHeaderIgnored(state, BraidInvalidHeader)
  end
  let supplied = case Bytes.slice(complete, 64, 32) do
    Ok(value) -> value
    Err(_) -> return BraidHeaderIgnored(state, BraidInvalidHeader)
  end
  let expected = case header_tag(state, header) do
    Ok(value) -> value
    Err(error) -> return BraidHeaderIgnored(state, error)
  end
  if !Bytes.secure_equals(expected, supplied) do
    Secret.destroy(state.secrets)
    return BraidHeaderFatal(BraidAuthenticationRejected)
  end
  BraidHeaderAccepted(BraidHeaderReady {
    scope: state.scope,
    epoch: state.epoch,
    header: header,
    secrets: state.secrets
  })
end

## One tentative candidate per call; the borrowed accepted-header state remains
## valid on refusal. Only the final journal CAS emits an application output.
pub fn prepare_ct1(state :: borrow BraidHeaderReady) -> BraidCt1Ready!BraidError do
  if !braid_valid_scope(state.scope, state.epoch) || Bytes.length(state.header) != 64 do
    return Err(BraidInvalidState)
  end
  let root = case SecretMap.copy(state.secrets, Bytes.from_utf8("root")) do
    Ok(value) -> value
    Err(error) -> return Err(BraidCryptoFailure(error))
  end
  let (continuation, first, shared) = case Crypto.mlkem_encapsulate1(MlKemHeader64 {
    bytes: state.header
  }) do
    Ok(value) -> value
    Err(error) -> return Err(BraidCryptoFailure(error))
  end
  let output = case Crypto.hkdf_sha256(shared,
    zero_salt()?,
    info(state.scope, ":SCKA Key", state.epoch)?,
    32) do
    Ok(value) -> value
    Err(error) -> return Err(BraidCryptoFailure(error))
  end
  Secret.destroy(shared)
  let update = case Crypto.hkdf_sha256_secret_salt(output,
    root,
    info(state.scope, ":Authenticator Update", state.epoch)?,
    64) do
    Ok(value) -> value
    Err(error) -> return Err(BraidCryptoFailure(error))
  end
  Secret.destroy(root)
  let slots = auth_map(update)?
  case SecretMap.insert(slots, Bytes.from_utf8("output"), output) do
    Err(error) -> return Err(BraidCryptoFailure(error))
    Ok(_) -> nil
  end
  Ok(BraidCt1Ready {
    scope: state.scope,
    epoch: state.epoch,
    header: state.header,
    first: first,
    secrets: slots,
    continuation: continuation
  })
end
