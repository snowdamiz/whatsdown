##! Ratchet message version 4: the encrypted header, its key schedule, and the
##! wire of the sparse post-quantum ratchet (`protocol/ratchet-message-v2.md`).
##!
##! Everything here is pure: codecs over public bytes, and derivations that
##! borrow or consume secrets. `Session.Ratchet` owns the state machine.

from Binary.Reader import BinaryReader
from Protocol.V1 import ProtocolError
from Protocol.WirePrimitives import (
  protocol_as_int,
  protocol_byte,
  protocol_join,
  protocol_open,
  protocol_require_end,
  protocol_take_fixed,
  protocol_take_u16,
  protocol_take_u32,
  protocol_take_u8,
  protocol_write_length,
  protocol_write_u16
)

## What a peer says it can do, one bit a feature, in the session-features
## inner-envelope extension (`ratchet_session_features_extension`).

pub fn ratchet_feature_header_encryption() -> Int do
  1
end

pub fn ratchet_feature_post_quantum() -> Int do
  2
end

pub fn ratchet_feature_session_reset() -> Int do
  4
end

## Reads deniable group messages: inner message type 9 (a sender's `GSA`
## announcement) and group message version 6 (`protocol/mls-groups-v1.md`).

pub fn ratchet_feature_deniable_groups() -> Int do
  8
end

pub fn ratchet_session_features_extension() -> Int do
  3
end

pub fn ratchet_has_feature(features :: Int, feature :: Int) -> Bool do
  features >= 0 && feature > 0 && features / feature % 2 == 1
end

fn union_bits(first :: Int, second :: Int, bit :: Int, output :: Int) -> Int do
  if bit > 128 do
    output
  else
    let present = ratchet_has_feature(first, bit) || ratchet_has_feature(second, bit)
    union_bits(first,
      second,
      bit * 2,
      if present do
        output + bit
      else
        output
      end)
  end
end

## A peer's features only grow: a session never goes back to a weaker format.

pub fn ratchet_feature_union(first :: Int, second :: Int) -> Int do
  union_bits(first, second, 1, 0)
end

## The post-quantum ratchet moves an ML-KEM-768 encapsulation key (kind 1,
## 1,184 bytes) or ciphertext (kind 2, 1,088 bytes) in 32-byte units. A run of
## units starts at `pq_first` and wraps past the last unit to the first.

pub fn ratchet_pq_unit_size() -> Int do
  32
end

pub fn ratchet_pq_units(kind :: Int) -> Int do
  if kind == 1 do
    37
  else if kind == 2 do
    34
  else
    0
  end
end

## Bytes the recipient-sealed transport adds around a sealed ratchet message:
## 52 for `RCP`, 4 for its length prefix, 13 for the `M8P` ratchet packet.

fn transport_overhead() -> Int do
  69
end

## Bytes of a version 4 message around its plaintext and header units: magic,
## header vector (nonce, tag, 85 fixed header bytes), nonce, ciphertext vector
## and tag.

fn message_overhead() -> Int do
  153
end

fn bucket(length :: Int, candidate :: Int) -> Int do
  if length <= candidate || candidate >= 65536 do
    candidate
  else
    bucket(length, candidate * 2)
  end
end

## How many units fit in the padding a message would carry anyway: a unit
## never moves a message into a larger bucket.

pub fn ratchet_pq_unit_budget(plaintext_length :: Int) -> Int do
  let used = transport_overhead() + message_overhead() + plaintext_length
  let slack = bucket(used, 256) - used
  if slack <= 0 do
    0
  else
    slack / ratchet_pq_unit_size()
  end
end

pub fn ratchet_v4_plaintext_limit() -> Int do
  65536 - transport_overhead() - message_overhead()
end

pub struct RatchetHeader do
  suite :: Int
  session_id :: Bytes
  ratchet_public_key :: X25519PublicKey
  previous_chain_length :: Int
  message_number :: Int
  pq_mix :: Int
  pq_epoch :: Int
  pq_kind :: Int
  pq_first :: Int
  pq_units :: Bytes
end

fn write_u32(value :: Int) -> Bytes!ProtocolError do
  protocol_write_length(value)
end

fn valid_units(value :: RatchetHeader) -> Bool do
  let size = ratchet_pq_unit_size()
  let count = Bytes.length(value.pq_units) / size
  if value.pq_kind == 0 do
    value.pq_epoch == 0 && value.pq_first == 0 && Bytes.length(value.pq_units) == 0
  else
    let total = ratchet_pq_units(value.pq_kind)
    total > 0
      && value.pq_epoch >= 1
      && Bytes.length(value.pq_units) % size == 0
      && value.pq_first >= 0
      && value.pq_first < total
      && count <= total
  end
end

fn valid_header(value :: RatchetHeader) -> Bool do
  (value.suite == 1 || value.suite == 2)
    && Bytes.length(value.session_id) == 32
    && Bytes.length(value.ratchet_public_key.bytes) == 32
    && value.previous_chain_length >= 0
    && value.previous_chain_length <= 4294967295
    && value.message_number >= 0
    && value.message_number <= 4294967295
    && value.pq_mix >= 0
    && value.pq_mix <= 4294967295
    && value.pq_epoch <= 4294967295
    && valid_units(value)
end

pub fn ratchet_header_encode(value :: RatchetHeader) -> Bytes!ProtocolError do
  if !valid_header(value) do
    Err(MalformedEncoding)
  else
    protocol_join([
        protocol_write_u16(value.suite)?,
        value.session_id,
        value.ratchet_public_key.bytes,
        write_u32(value.previous_chain_length)?,
        write_u32(value.message_number)?,
        write_u32(value.pq_mix)?,
        write_u32(value.pq_epoch)?,
        protocol_byte(value.pq_kind)?,
        protocol_byte(value.pq_first)?,
        protocol_byte(Bytes.length(value.pq_units) / ratchet_pq_unit_size())?,
        value.pq_units
      ],
      0,
      Bytes.empty())
  end
end

struct ReadCount do
  state :: BinaryReader
  value :: Int
end

fn take_count(state :: BinaryReader) -> ReadCount!ProtocolError do
  let wide = protocol_take_u32(state)?
  Ok(ReadCount { state: wide.state, value: protocol_as_int(wide.value)? })
end

pub fn ratchet_header_decode(input :: Bytes) -> RatchetHeader!ProtocolError do
  let suite = protocol_take_u16(protocol_open(input, 85 + 37 * 32)?)?
  let session_id = protocol_take_fixed(suite.state, 32)?
  let ratchet_public_key = protocol_take_fixed(session_id.state, 32)?
  let previous_chain_length = take_count(ratchet_public_key.state)?
  let message_number = take_count(previous_chain_length.state)?
  let pq_mix = take_count(message_number.state)?
  let pq_epoch = take_count(pq_mix.state)?
  let pq_kind = protocol_take_u8(pq_epoch.state)?
  let pq_first = protocol_take_u8(pq_kind.state)?
  let pq_count = protocol_take_u8(pq_first.state)?
  let pq_units = protocol_take_fixed(pq_count.state, pq_count.value * ratchet_pq_unit_size())?
  protocol_require_end(pq_units.state)?
  let value = RatchetHeader {
    suite: suite.value,
    session_id: session_id.value,
    ratchet_public_key: X25519PublicKey { bytes: ratchet_public_key.value },
    previous_chain_length: previous_chain_length.value,
    message_number: message_number.value,
    pq_mix: pq_mix.value,
    pq_epoch: pq_epoch.value,
    pq_kind: pq_kind.value,
    pq_first: pq_first.value,
    pq_units: pq_units.value
  }
  if valid_header(value) do
    Ok(value)
  else
    Err(MalformedEncoding)
  end
end

# The header key seals nothing itself: each use derives the AEAD key, so the
# stored key stays a plain 32-byte secret like the chain keys.

fn header_aead_key(header_key :: borrow SecretBytes) -> AeadKey!CryptoError do
  let material = Crypto.hkdf_sha256(header_key,
    Bytes.empty(),
    Bytes.from_utf8("mesh-msg/v2/header-seal"),
    32)?
  Crypto.aead_key(material)
end

fn header_aad() -> Bytes do
  Bytes.from_utf8("mesh-msg/v2/ratchet-header")
end

## `nonce || ChaCha20-Poly1305(header)`. Only tests pass a nonce; senders use
## `ratchet_header_seal`.

pub fn ratchet_header_seal_with_nonce(header_key :: borrow SecretBytes,
  nonce :: Bytes,
  plaintext :: Bytes) -> Bytes!CryptoError do
  let key = header_aead_key(header_key)?
  let sealed = Crypto.aead_seal(key, nonce, header_aad(), plaintext)?
  case Bytes.concat(nonce, sealed) do
    Err(_) -> Err(InvalidKey)
    Ok(value)
  end
end

pub fn ratchet_header_seal(header_key :: borrow SecretBytes,
  plaintext :: Bytes) -> Bytes!CryptoError do
  ratchet_header_seal_with_nonce(header_key, Crypto.random_bytes(12)?, plaintext)
end

pub fn ratchet_header_open(header_key :: borrow SecretBytes, blob :: Bytes) -> Bytes!CryptoError do
  if Bytes.length(blob) < 28 do
    Err(AuthenticationFailed)
  else
    let key = header_aead_key(header_key)?
    let nonce = case Bytes.slice(blob, 0, 12) do
      Err(_) -> Err(AuthenticationFailed)
      Ok(value)
    end?
    let sealed = case Bytes.slice(blob, 12, Bytes.length(blob) - 12) do
      Err(_) -> Err(AuthenticationFailed)
      Ok(value)
    end?
    Crypto.aead_open(key, nonce, header_aad(), sealed)
  end
end

fn labelled(label :: String, tail :: Bytes) -> Bytes!CryptoError do
  case Bytes.concat(Bytes.from_utf8(label), tail) do
    Err(_) -> Err(InvalidKey)
    Ok(value)
  end
end

fn epoch_bytes(epoch :: Int) -> Bytes!CryptoError do
  case write_u32(epoch) do
    Err(_) -> Err(InvalidKey)
    Ok(value)
  end
end

## One step of the version 4 root chain. `shared` is the X25519 output, or the
## X25519 output followed by the ML-KEM secret when this step mixes the
## post-quantum epoch `mix_epoch` (0 when it mixes none). Returns the next root
## key, the new chain key, and the header key of the chain after next.

pub fn ratchet_root_v2(root_key :: borrow SecretBytes,
  shared :: SecretBytes,
  session_id :: Bytes,
  ratchet_public_key :: X25519PublicKey,
  mix_epoch :: Int) -> Result<(SecretBytes, SecretBytes, SecretBytes), CryptoError> do
  let old_material = Crypto.hkdf_sha256(root_key,
    session_id,
    labelled("mesh-msg/v2/root-mix", ratchet_public_key.bytes)?,
    32)?
  let combined = Secret.concat(old_material, shared)?
  let suffix = case Bytes.concat(ratchet_public_key.bytes, epoch_bytes(mix_epoch)?) do
    Err(_) -> Err(InvalidKey)
    Ok(value)
  end?
  let next_root = Crypto.hkdf_sha256(combined,
    session_id,
    labelled("mesh-msg/v2/ratchet-root", suffix)?,
    32)?
  let chain = Crypto.hkdf_sha256(combined,
    session_id,
    labelled("mesh-msg/v2/ratchet-chain", suffix)?,
    32)?
  let next_header_key = Crypto.hkdf_sha256(combined,
    session_id,
    labelled("mesh-msg/v2/header-key", suffix)?,
    32)?
  Secret.destroy(combined)
  Ok((next_root, chain, next_header_key))
end

## The two header keys an upgrade starts from, both from the root key the two
## sides share when the upgrading side begins its chain: `first` seals that
## chain, `second` the other side's next one.

pub fn ratchet_upgrade_header_keys(root_key :: borrow SecretBytes,
  session_id :: Bytes) -> Result<(SecretBytes, SecretBytes), CryptoError> do
  let first = Crypto.hkdf_sha256(root_key,
    session_id,
    Bytes.from_utf8("mesh-msg/v2/header-key/upgrade/first"),
    32)?
  let second = Crypto.hkdf_sha256(root_key,
    session_id,
    Bytes.from_utf8("mesh-msg/v2/header-key/upgrade/second"),
    32)?
  Ok((first, second))
end

## The ML-KEM-768 key pair an epoch's owner sends, from a 32-byte seed kept in
## the session until the ciphertext arrives.

pub fn ratchet_pq_key_pair(seed :: borrow SecretBytes,
  session_id :: Bytes) -> MlKemKeyPair!CryptoError do
  let material = Crypto.hkdf_sha256(seed,
    session_id,
    Bytes.from_utf8("mesh-msg/v2/pq-ratchet-key"),
    64)?
  Crypto.mlkem_from_secret(material)
end

## Where each header key lives in a session's header-key map: `send`,
## `next-send`, `receive`, `next-receive`. None is 32 bytes long, so none can
## collide with an earlier receiving chain's ratchet key.

pub fn ratchet_header_role(role :: String) -> Bytes do
  Bytes.from_utf8("mesh-msg/v2/header-key/" <> role)
end
