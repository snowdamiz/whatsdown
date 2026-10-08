##! The sparse post-quantum ratchet of ratchet message version 4.
##!
##! The two sides take turns running one ML-KEM-768 exchange an epoch. The
##! epoch's owner sends a fresh encapsulation key in 32-byte units carried in the
##! padding its messages have anyway; the other side collects them, encapsulates,
##! and sends the ciphertext the same way. Once the owner has decapsulated, its
##! next sending root step mixes the shared secret into the root key with that
##! step's X25519 output, and every header of that chain says so. The other side
##! mixes the same secret when it takes that chain's root step, then owns the
##! next epoch. A unit is idempotent and says which epoch it belongs to, so loss
##! and reordering only delay an epoch; nothing is mixed until both sides hold
##! the secret, and the side that mixes first announces it in authenticated
##! headers, so the two roots cannot part.
##!
##! Phases: 0 not started, 1 owner sending its key, 2 owner collecting the
##! ciphertext, 3 owner holding the secret until its next sending root step,
##! 4 collecting the owner's key, 5 sending the ciphertext and holding the secret
##! until the owner's mixing chain arrives, 6 owning the next epoch from this
##! side's next sending root step.

from Session.Handshake import RatchetState
from Session.Header import (
  RatchetHeader,
  ratchet_pq_key_pair,
  ratchet_pq_unit_size,
  ratchet_pq_units
)

pub type PqError do
  PqInvalid
  PqCrypto
end

pub struct PqPublic do
  epoch :: Int
  phase :: Int
  cursor :: Int
  own :: Bytes
  peer :: Bytes
  have :: Bytes
end

impl From<CryptoError> for PqError do
  fn from(error :: CryptoError) -> PqError do
    PqCrypto
  end
end

fn secret_id(name :: String) -> Bytes do
  Bytes.from_utf8("mesh-msg/v2/pq/" <> name)
end

pub fn ratchet_pq_public(state :: borrow RatchetState) -> PqPublic do
  PqPublic {
    epoch: state.pq_epoch,
    phase: state.pq_phase,
    cursor: state.pq_cursor,
    own: state.pq_own,
    peer: state.pq_peer,
    have: state.pq_have
  }
end

pub fn ratchet_pq_apply(state :: consume RatchetState,
  secrets :: SecretMap,
  value :: PqPublic) -> RatchetState do
  %{state |
    pq_secrets: secrets,
    pq_epoch: value.epoch,
    pq_phase: value.phase,
    pq_cursor: value.cursor,
    pq_own: value.own,
    pq_peer: value.peer,
    pq_have: value.have
  }
end

fn discard(secret :: SecretBytes, error :: CryptoError) -> Result<(), CryptoError> do
  Err(error)
end

fn replace_secret(secrets :: borrow SecretMap,
  name :: String,
  secret :: SecretBytes) -> Result<(), CryptoError> do
  case SecretMap.delete(secrets, secret_id(name)) do
    Err(error) -> discard(secret, error)
    Ok(_) -> SecretMap.insert(secrets, secret_id(name), secret)
  end
end

fn cleared(epoch :: Int, phase :: Int) -> PqPublic do
  sending(epoch, phase, Bytes.empty())
end

fn sending(epoch :: Int, phase :: Int, own :: Bytes) -> PqPublic do
  PqPublic {
    epoch: epoch,
    phase: phase,
    cursor: 0,
    own: own,
    peer: Bytes.empty(),
    have: Bytes.empty()
  }
end

fn collected(epoch :: Int, phase :: Int, peer :: Bytes, have :: Bytes) -> PqPublic do
  PqPublic { epoch: epoch, phase: phase, cursor: 0, own: Bytes.empty(), peer: peer, have: have }
end

# A new epoch's key: the seed stays until the ciphertext comes back.

fn new_owner_key(secrets :: borrow SecretMap,
  session_id :: Bytes,
  epoch :: Int) -> PqPublic!PqError do
  let seed = Secret.random(32)?
  let pair = ratchet_pq_key_pair(seed, session_id)?
  let key = pair.public_key.bytes
  replace_secret(secrets, "seed", seed)?
  Ok(sending(epoch, 1, key))
end

## What this side's sending root step does to the ratchet, given that step's
## X25519 output: the owner holding a secret mixes it (the step's input becomes
## `dh || secret`, returned with the epoch mixed) and turns to collecting the
## next epoch; a side due to own an epoch starts one. `enabled` says whether the
## session may start the ratchet at all.

pub fn ratchet_pq_send_step(state :: borrow RatchetState,
  dh :: SecretBytes,
  enabled :: Bool) -> Result<(SecretBytes, SecretMap, PqPublic, Int), PqError> do
  let secrets = SecretMap.fork(state.pq_secrets)?
  if state.pq_phase == 3 do
    let secret = SecretMap.copy(secrets, secret_id("secret"))?
    SecretMap.delete(secrets, secret_id("secret"))?
    let shared = Secret.concat(dh, secret)?
    Ok((shared, secrets, cleared(state.pq_epoch + 1, 4), state.pq_epoch))
  else if state.pq_phase == 6 do
    let value = new_owner_key(secrets, state.session_id, state.pq_epoch)?
    Ok((dh, secrets, value, 0))
  else if state.pq_phase == 0 && enabled do
    let value = new_owner_key(secrets, state.session_id, 1)?
    Ok((dh, secrets, value, 0))
  else
    Ok((dh, secrets, ratchet_pq_public(state), 0))
  end
end

## What a received chain's root step does, given its X25519 output and the
## epoch its header says it mixed. Only the side holding that epoch's secret
## as the one who sent the ciphertext can take a mixing step; it then owns the
## next epoch.

pub fn ratchet_pq_receive_step(state :: borrow RatchetState,
  dh :: SecretBytes,
  mix :: Int) -> Result<(SecretBytes, SecretMap, PqPublic), PqError> do
  let secrets = SecretMap.fork(state.pq_secrets)?
  if mix == 0 do
    Ok((dh, secrets, ratchet_pq_public(state)))
  else if state.pq_phase != 5 || state.pq_epoch != mix do
    Err(PqInvalid)
  else
    let secret = SecretMap.copy(secrets, secret_id("secret"))?
    SecretMap.delete(secrets, secret_id("secret"))?
    let shared = Secret.concat(dh, secret)?
    Ok((shared, secrets, cleared(state.pq_epoch + 1, 6)))
  end
end

## The kind of units this side sends now: its key (1) while it owns an epoch
## and has seen no ciphertext, its ciphertext (2) until the owner mixes, or none.

pub fn ratchet_pq_outgoing_kind(state :: borrow RatchetState) -> Int do
  if state.pq_phase == 1 do
    1
  else if state.pq_phase == 5 do
    2
  else
    0
  end
end

fn slice(value :: Bytes, start :: Int, length :: Int) -> Bytes!PqError do
  case Bytes.slice(value, start, length) do
    Err(_) -> Err(PqInvalid)
    Ok(part)
  end
end

## The next run of units, as many as `budget` (at most the whole set), from the
## cursor round past the end. A run that wraps shifts where the next cycle's
## runs fall, so losing every second message cannot lose the same units twice.

pub fn ratchet_pq_take(own :: Bytes,
  cursor :: Int,
  budget :: Int,
  kind :: Int) -> Result<(Int, Bytes, Int), PqError> do
  let total = ratchet_pq_units(kind)
  let size = ratchet_pq_unit_size()
  if total == 0 || Bytes.length(own) != total * size || cursor < 0 || cursor >= total do
    Ok((0, Bytes.empty(), 0))
  else
    let count = if budget < total do
      budget
    else
      total
    end
    let head = if cursor + count > total do
      total - cursor
    else
      count
    end
    let units = join([
        slice(own, cursor * size, head * size)?,
        slice(own, 0, (count - head) * size)?
      ],
      0,
      Bytes.empty())?
    Ok((cursor, units, (cursor + count) % total))
  end
end

fn join(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!PqError do
  if index >= List.length(parts) do
    Ok(output)
  else
    case Bytes.concat(output, List.get(parts, index)) do
      Err(_) -> Err(PqInvalid)
      Ok(next) -> join(parts, index + 1, next)
    end
  end
end

fn repeated(value :: Int, length :: Int) -> Bytes!PqError do
  case Bytes.repeat(value, length) do
    Err(_) -> Err(PqInvalid)
    Ok(bytes)
  end
end

# One contiguous run [first, first + count) into the buffer and its marks.

fn store_run(buffer :: Bytes,
  marks :: Bytes,
  total :: Int,
  first :: Int,
  units :: Bytes) -> Result<(Bytes, Bytes), PqError> do
  let size = ratchet_pq_unit_size()
  let count = Bytes.length(units) / size
  if count == 0 do
    Ok((buffer, marks))
  else
    let stored = join([
        slice(buffer, 0, first * size)?,
        units,
        slice(buffer, (first + count) * size, (total - first - count) * size)?
      ],
      0,
      Bytes.empty())?
    let marked = join([
        slice(marks, 0, first)?,
        repeated(1, count)?,
        slice(marks, first + count, total - first - count)?
      ],
      0,
      Bytes.empty())?
    Ok((stored, marked))
  end
end

fn store_units(peer :: Bytes,
  have :: Bytes,
  kind :: Int,
  first :: Int,
  units :: Bytes) -> Result<(Bytes, Bytes), PqError> do
  let total = ratchet_pq_units(kind)
  let size = ratchet_pq_unit_size()
  let count = Bytes.length(units) / size
  let buffer = if Bytes.length(peer) == total * size do
    Ok(peer)
  else
    repeated(0, total * size)
  end?
  let marks = if Bytes.length(have) == total do
    Ok(have)
  else
    repeated(0, total)
  end?
  if first < 0 || first >= total || count > total do
    Err(PqInvalid)
  else
    let head = if first + count > total do
      total - first
    else
      count
    end
    let (buffer, marks) = store_run(buffer, marks, total, first, slice(units, 0, head * size)?)?
    store_run(buffer, marks, total, 0, slice(units, head * size, (count - head) * size)?)
  end
end

fn complete(have :: Bytes, kind :: Int) -> Bool do
  case Bytes.repeat(1, ratchet_pq_units(kind)) do
    Err(_) -> false
    Ok(all) -> Bytes.secure_equals(have, all)
  end
end

# The collector's whole key has arrived: encapsulate to it.

fn encapsulated(secrets :: borrow SecretMap,
  epoch :: Int,
  key :: Bytes) -> Result<(SecretMap, PqPublic), PqError> do
  let (ciphertext, secret) = case Crypto.mlkem_encapsulate(MlKemPublicKey { bytes: key }) do
    Err(InvalidPublicKey) -> Err(PqInvalid)
    Err(_) -> Err(PqCrypto)
    Ok(value)
  end?
  let next = SecretMap.fork(secrets)?
  replace_secret(next, "secret", secret)?
  Ok((next, sending(epoch, 5, ciphertext.bytes)))
end

# The owner's whole ciphertext has arrived: decapsulate with the epoch's seed.

fn decapsulated(secrets :: borrow SecretMap,
  session_id :: Bytes,
  epoch :: Int,
  ciphertext :: Bytes) -> Result<(SecretMap, PqPublic), PqError> do
  let next = SecretMap.fork(secrets)?
  let seed = SecretMap.copy(next, secret_id("seed"))?
  let pair = ratchet_pq_key_pair(seed, session_id)?
  let secret = case Crypto.mlkem_decapsulate(pair.private_key,
    MlKemCiphertext { bytes: ciphertext }) do
    Err(_) -> Err(PqCrypto)
    Ok(value)
  end?
  SecretMap.delete(next, secret_id("seed"))?
  replace_secret(next, "secret", secret)?
  Ok((next, cleared(epoch, 3)))
end

fn unchanged(secrets :: borrow SecretMap,
  value :: PqPublic) -> Result<(SecretMap, PqPublic), PqError> do
  Ok((SecretMap.fork(secrets)?, value))
end

fn ingest_key(value :: PqPublic,
  secrets :: borrow SecretMap,
  suite :: Int,
  header :: RatchetHeader) -> Result<(SecretMap, PqPublic), PqError> do
  let starting = value.phase == 0 && header.pq_epoch == 1 && suite == 2
  let collecting = value.phase == 4 && header.pq_epoch == value.epoch
  if !(starting || collecting) do
    unchanged(secrets, value)
  else
    let (peer, have) = store_units(value.peer, value.have, 1, header.pq_first, header.pq_units)?
    if complete(have, 1) do
      encapsulated(secrets, header.pq_epoch, peer)
    else
      unchanged(secrets, collected(header.pq_epoch, 4, peer, have))
    end
  end
end

fn ingest_ciphertext(value :: PqPublic,
  secrets :: borrow SecretMap,
  session_id :: Bytes,
  header :: RatchetHeader) -> Result<(SecretMap, PqPublic), PqError> do
  let owning = (value.phase == 1 || value.phase == 2) && header.pq_epoch == value.epoch
  if !owning do
    unchanged(secrets, value)
  else
    let (peer, have) = store_units(value.peer, value.have, 2, header.pq_first, header.pq_units)?
    if complete(have, 2) do
      decapsulated(secrets, session_id, header.pq_epoch, peer)
    else
      unchanged(secrets, collected(header.pq_epoch, 2, peer, have))
    end
  end
end

## Takes in the units of an authenticated message, given the ratchet's public
## state and secrets as they are after this message's root step: the new public
## state and a new secret map. Units of another epoch, or of a kind this side is
## not collecting, are left alone: they are late copies.

pub fn ratchet_pq_ingest(value :: PqPublic,
  secrets :: borrow SecretMap,
  suite :: Int,
  session_id :: Bytes,
  header :: RatchetHeader) -> Result<(SecretMap, PqPublic), PqError> do
  if header.pq_kind == 1 do
    ingest_key(value, secrets, suite, header)
  else if header.pq_kind == 2 do
    ingest_ciphertext(value, secrets, session_id, header)
  else
    unchanged(secrets, value)
  end
end
