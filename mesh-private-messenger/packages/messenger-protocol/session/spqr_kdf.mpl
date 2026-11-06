##! Inactive opaque SPQR KDF profile. Not Signal wire interoperability.
from Session.BraidResponder import BraidError, BraidScope, braid_valid_scope

pub type SpqrError do
  SpqrInvalidState
  SpqrEpochOrder
  SpqrRetired
  SpqrReplay
  SpqrSkipLimit
  SpqrCounterOverflow
  SpqrCryptoFailure(error :: CryptoError)
  SpqrKernelFailure(error :: BraidError)
end

impl From<CryptoError> for SpqrError do
  fn from(error :: CryptoError) -> SpqrError do
    SpqrCryptoFailure(error)
  end
end

pub fn spqr_number(text :: String) -> U64!SpqrError do
  case U64.parse(text) do
    Ok(v)
    Err(_) -> Err(SpqrInvalidState)
  end
end

pub fn spqr_check(ok :: Bool) -> Result<(), SpqrError> do
  if ok do
    Ok(nil)
  else
    Err(SpqrInvalidState)
  end
end

pub fn spqr_join(parts :: List<Bytes>, limit :: Int) -> Bytes!SpqrError do
  case Bytes.concat_many(parts, limit) do
    Ok(v)
    Err(_) -> Err(SpqrInvalidState)
  end
end

pub fn spqr_epoch_bytes(epoch :: U64) -> Bytes!SpqrError do
  case Bytes.write_u64_be(epoch) do
    Ok(v)
    Err(_) -> Err(SpqrInvalidState)
  end
end

pub fn spqr_byte(value :: Int) -> Bytes!SpqrError do
  case Bytes.from_list([value]) do
    Ok(v)
    Err(_) -> Err(SpqrInvalidState)
  end
end

pub fn spqr_scope(scope :: BraidScope) -> Result<(), SpqrError> do
  spqr_check(braid_valid_scope(scope, spqr_number("1")?))
end

fn domain(scope :: BraidScope, label :: String, tail :: List<Bytes>) -> Bytes!SpqrError do
  spqr_scope(scope)?
  spqr_join([
      Bytes.from_utf8("mesh-msg/spqr/v1"),
      spqr_byte(0)?,
      scope.configuration,
      scope.session_id,
      spqr_byte(0)?,
      Bytes.from_utf8(label)
    ]
      ++ tail,
    256)
end

fn zero_salt() -> Bytes!SpqrError do
  case Bytes.repeat(0, 32) do
    Ok(v)
    Err(_) -> Err(SpqrInvalidState)
  end
end

fn triple(wide :: consume SecretBytes) -> (SecretBytes, SecretBytes, SecretBytes)!SpqrError do
  let (root, rest) = Secret.split_at(wide, 32)?
  let (forward, reverse) = Secret.split_at(rest, 32)?
  Ok((root, forward, reverse))
end

pub fn spqr_initial_material(scope :: BraidScope,
  seed :: borrow SecretBytes) -> (SecretBytes, SecretBytes, SecretBytes)!SpqrError do
  triple(Crypto.hkdf_sha256(seed, zero_salt()?, domain(scope, "Chain Start", [])?, 96)?)
end

pub fn spqr_add_material(scope :: BraidScope,
  root :: borrow SecretBytes,
  output :: borrow SecretBytes,
  epoch :: U64) -> (SecretBytes, SecretBytes, SecretBytes)!SpqrError do
  spqr_check(U64.compare(epoch, spqr_number("0")?) > 0)?
  triple(Crypto.hkdf_sha256_secret_salt(output,
    root,
    domain(scope, "Chain Add Epoch", [spqr_epoch_bytes(epoch)?])?,
    96)?)
end

pub fn spqr_step_material(scope :: BraidScope,
  chain :: borrow SecretBytes,
  direction :: Int,
  epoch :: U64,
  number :: U64) -> (SecretBytes, SecretBytes)!SpqrError do
  spqr_check((direction == 0 || direction == 1) && U64.compare(number, spqr_number("0")?) > 0)?
  Ok(Secret.split_at(Crypto.hkdf_sha256(chain,
      zero_salt()?,
      domain(scope,
        "Message Key",
        [spqr_epoch_bytes(epoch)?, spqr_byte(direction)?, spqr_epoch_bytes(number)?])?,
      64)?,
    32)?)
end
