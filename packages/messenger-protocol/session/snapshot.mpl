from Binary.Reader import (
  BinaryReader,
  finish,
  read_fixed,
  read_u16_be,
  read_u8,
  read_vector,
  reader
)
from Session.Handshake import RatchetState
from Session.Header import ratchet_header_role

pub type SnapshotError do
  CryptoFailure(error :: CryptoError)
  InvalidSnapshot
  RollbackRejected
end

pub type SnapshotOutcome do
  SnapshotSealed(state :: RatchetState, blob :: Bytes)
  SnapshotRejected(state :: RatchetState, error :: SnapshotError)
end

pub type ReplacementOutcome do
  SessionReplaced(state :: RatchetState)
  ReplacementRejected(state :: RatchetState, error :: SnapshotError)
end

struct ReadInt do
  state :: BinaryReader
  value :: Int
end

struct ReadBytes do
  state :: BinaryReader
  value :: Bytes
end

struct ReadWide do
  state :: BinaryReader
  value :: U64
end

struct ParsedSnapshot do
  format :: Int
  suite :: Int
  session_id :: Bytes
  snapshot_version :: U64
  local_ratchet_public :: Bytes
  remote_ratchet_public :: Bytes
  previous_chain_length :: Int
  sent_count :: Int
  received_count :: Int
  pending_send_ratchet :: Bool
  receive_generation :: Int
  skipped_index :: Bytes
  root_key :: Bytes
  sending_chain_key :: Bytes
  receiving_chain_key :: Bytes
  local_ratchet_private :: Bytes
  skipped_keys :: Bytes
  extension :: SnapshotExtension
  header_send :: Bytes
  header_next_send :: Bytes
  header_receive :: Bytes
  header_next_receive :: Bytes
  earlier_header_keys :: Bytes
  pq_secrets :: Bytes
end

# What version 3 adds to the authenticated header: the peer's features, whether
# sends encrypt their headers, the earlier chains whose header keys are kept,
# and the public half of the post-quantum ratchet.

struct SnapshotExtension do
  peer_features :: Int
  header_encrypted :: Bool
  header_key_owners :: Bytes
  pq_epoch :: Int
  pq_phase :: Int
  pq_cursor :: Int
  pq_send_mix :: Int
  pq_own :: Bytes
  pq_peer :: Bytes
  pq_have :: Bytes
end

fn append(left :: Bytes, right :: Bytes) -> Bytes!SnapshotError do
  case Bytes.concat(left, right) do
    Err(_) -> Err(InvalidSnapshot)
    Ok(value)
  end
end

fn join(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!SnapshotError do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, append(output, List.get(parts, index))?)
  end
end

fn byte(value :: Int) -> Bytes!SnapshotError do
  case Bytes.from_list([value]) do
    Err(_) -> Err(InvalidSnapshot)
    Ok(encoded)
  end
end

fn write_u16(value :: Int) -> Bytes!SnapshotError do
  case Bytes.write_u16_be(value) do
    Err(_) -> Err(InvalidSnapshot)
    Ok(encoded)
  end
end

fn write_u32(value :: Int) -> Bytes!SnapshotError do
  case U64.parse(Int.to_string(value)) do
    Err(_) -> Err(InvalidSnapshot)
    Ok(wide) -> case Bytes.write_u32_be(wide) do
      Err(_) -> Err(InvalidSnapshot)
      Ok(encoded)
    end
  end
end

fn write_u64(value :: U64) -> Bytes!SnapshotError do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err(InvalidSnapshot)
    Ok(encoded)
  end
end

fn vector(value :: Bytes) -> Bytes!SnapshotError do
  append(write_u32(Bytes.length(value))?, value)
end

fn zero() -> U64!SnapshotError do
  case U64.parse("0") do
    Err(_) -> Err(InvalidSnapshot)
    Ok(value)
  end
end

# Version 2 adds what the ratchet needs to age its skipped keys: the number of
# receiving chains seen, and the list of kept keys, 40 bytes each and at most
# 64. Both are in the header, so every sealed part is bound to them.

fn valid_index(index :: Bytes) -> Bool do
  Bytes.length(index) <= 2560 && Bytes.length(index) % 40 == 0
end

fn valid_pq_bytes(value :: Bytes) -> Bool do
  Bytes.length(value) == 0 || Bytes.length(value) == 1184 || Bytes.length(value) == 1088
end

fn valid_extension(value :: SnapshotExtension) -> Bool do
  value.peer_features >= 0
    && value.peer_features <= 255
    && Bytes.length(value.header_key_owners) <= 256
    && Bytes.length(value.header_key_owners) % 32 == 0
    && value.pq_epoch >= 0
    && value.pq_phase >= 0
    && value.pq_phase <= 6
    && value.pq_cursor >= 0
    && value.pq_cursor < 37
    && value.pq_send_mix >= 0
    && valid_pq_bytes(value.pq_own)
    && valid_pq_bytes(value.pq_peer)
    && Bytes.length(value.pq_have) <= 37
end

fn state_extension(state :: borrow RatchetState) -> SnapshotExtension do
  SnapshotExtension {
    peer_features: state.peer_features,
    header_encrypted: state.header_encrypted,
    header_key_owners: state.header_key_owners,
    pq_epoch: state.pq_epoch,
    pq_phase: state.pq_phase,
    pq_cursor: state.pq_cursor,
    pq_send_mix: state.pq_send_mix,
    pq_own: state.pq_own,
    pq_peer: state.pq_peer,
    pq_have: state.pq_have
  }
end

fn encode_extension(value :: SnapshotExtension) -> Bytes!SnapshotError do
  if !valid_extension(value) do
    Err(InvalidSnapshot)
  else
    join([
        byte(value.peer_features)?,
        byte(if value.header_encrypted do
          1
        else
          0
        end)?,
        vector(value.header_key_owners)?,
        write_u32(value.pq_epoch)?,
        byte(value.pq_phase)?,
        write_u32(value.pq_cursor)?,
        write_u32(value.pq_send_mix)?,
        vector(value.pq_own)?,
        vector(value.pq_peer)?,
        vector(value.pq_have)?
      ],
      0,
      Bytes.empty())
  end
end

fn encode_header(state :: borrow RatchetState, snapshot_version :: U64) -> Bytes!SnapshotError do
  let valid_suite = state.suite == 1 || state.suite == 2
  let valid = state.version == 1
    && valid_suite
    && Bytes.length(state.session_id) == 32
    && Bytes.length(state.local_ratchet_public.bytes) == 32
    && Bytes.length(state.remote_ratchet_public.bytes) == 32
    && state.previous_chain_length >= 0
    && state.sent_count >= 0
    && state.received_count >= 0
    && state.receive_generation >= 0
    && valid_index(state.skipped_index)
    && U64.compare(snapshot_version, zero()?) > 0
  if !valid do
    Err(InvalidSnapshot)
  else
    let pending = if state.pending_send_ratchet do
      1
    else
      0
    end
    join([
        byte(3)?,
        Bytes.from_utf8("RST"),
        write_u16(state.suite)?,
        state.session_id,
        write_u64(snapshot_version)?,
        state.local_ratchet_public.bytes,
        state.remote_ratchet_public.bytes,
        write_u32(state.previous_chain_length)?,
        write_u32(state.sent_count)?,
        write_u32(state.received_count)?,
        byte(pending)?,
        write_u32(state.receive_generation)?,
        vector(state.skipped_index)?,
        encode_extension(state_extension(state))?
      ],
      0,
      Bytes.empty())
  end
end

fn storage_object(header :: Bytes, purpose :: Int) -> Bytes!SnapshotError do
  let input = join([
      Bytes.from_utf8("mesh-msg/v1/ratchet-snapshot-object"),
      header,
      write_u16(purpose)?
    ],
    0,
    Bytes.empty())?
  Ok(Crypto.sha256(input))
end

# Parts version 3 added are named by a slot, so two parts sealed for the same
# purpose (the four header keys, the two extra maps) never share a context.

fn slot_object(header :: Bytes, purpose :: Int, slot :: String) -> Bytes!SnapshotError do
  let input = join([
      Bytes.from_utf8("mesh-msg/v2/ratchet-snapshot-object/" <> slot),
      header,
      write_u16(purpose)?
    ],
    0,
    Bytes.empty())?
  Ok(Crypto.sha256(input))
end

fn object_for(header :: Bytes, purpose :: Int, slot :: String) -> Bytes!SnapshotError do
  if slot == "" do
    storage_object(header, purpose)
  else
    slot_object(header, purpose, slot)
  end
end

fn storage_context(account_id :: Bytes,
  device_id :: Bytes,
  session_id :: Bytes,
  header :: Bytes,
  purpose :: Int,
  snapshot_version :: U64) -> Bytes!SnapshotError do
  slot_context(account_id, device_id, session_id, header, purpose, "", snapshot_version)
end

fn slot_context(account_id :: Bytes,
  device_id :: Bytes,
  session_id :: Bytes,
  header :: Bytes,
  purpose :: Int,
  slot :: String,
  snapshot_version :: U64) -> Bytes!SnapshotError do
  let supported = purpose == 1
    || purpose == 2
    || purpose == 3
    || purpose == 4
    || purpose == 12
    || purpose == 13
  if Bytes.length(account_id) != 32
    || Bytes.length(device_id) != 16
    || Bytes.length(session_id) != 32
    || !supported do
    Err(InvalidSnapshot)
  else
    join([
        byte(1)?,
        account_id,
        device_id,
        session_id,
        object_for(header, purpose, slot)?,
        write_u16(purpose)?,
        write_u64(snapshot_version)?
      ],
      0,
      Bytes.empty())
  end
end

fn seal_secret(secret :: borrow SecretBytes,
  wrapping_key :: borrow StorageKey,
  context :: Bytes) -> Bytes!SnapshotError do
  case Secret.seal_for_storage(secret, wrapping_key, context) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(blob)
  end
end

fn seal_private(secret :: borrow X25519PrivateKey,
  wrapping_key :: borrow StorageKey,
  context :: Bytes) -> Bytes!SnapshotError do
  case X25519PrivateKey.seal_for_storage(secret, wrapping_key, context) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(blob)
  end
end

fn seal_map(secret :: borrow SecretMap,
  wrapping_key :: borrow StorageKey,
  context :: Bytes) -> Bytes!SnapshotError do
  case SecretMap.seal_for_storage(secret, wrapping_key, context) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(blob)
  end
end

fn header_roles() -> List<String> do
  ["send", "next-send", "receive", "next-receive"]
end

# A header key the session does not hold yet is an empty part.

fn seal_header_role(keys :: borrow SecretMap,
  role :: String,
  wrapping_key :: borrow StorageKey,
  context :: Bytes) -> Bytes!SnapshotError do
  let id = ratchet_header_role(role)
  if !SecretMap.contains(keys, id) do
    Ok(Bytes.empty())
  else
    case SecretMap.copy(keys, id) do
      Err(error) -> Err(CryptoFailure(error))
      Ok(key) -> seal_secret(key, wrapping_key, context)
    end
  end
end

fn drop_roles(keys :: borrow SecretMap,
  roles :: List<String>,
  index :: Int) -> Result<(), SnapshotError> do
  if index >= List.length(roles) do
    Ok(nil)
  else
    case SecretMap.delete(keys, ratchet_header_role(List.get(roles, index))) do
      Err(error) -> Err(CryptoFailure(error))
      Ok(_) -> drop_roles(keys, roles, index + 1)
    end
  end
end

# The header keys of earlier chains, without the four sealed on their own.

fn seal_earlier_header_keys(keys :: borrow SecretMap,
  wrapping_key :: borrow StorageKey,
  context :: Bytes) -> Bytes!SnapshotError do
  case SecretMap.fork(keys) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(earlier) -> do
      drop_roles(earlier, header_roles(), 0)?
      seal_map(earlier, wrapping_key, context)
    end
  end
end

struct SealedExtension do
  header_send :: Bytes
  header_next_send :: Bytes
  header_receive :: Bytes
  header_next_receive :: Bytes
  earlier_header_keys :: Bytes
  pq_secrets :: Bytes
end

fn seal_extension(state :: borrow RatchetState,
  wrapping_key :: borrow StorageKey,
  account_id :: Bytes,
  device_id :: Bytes,
  header :: Bytes,
  snapshot_version :: U64) -> SealedExtension!SnapshotError do
  let session_id = state.session_id
  Ok(SealedExtension {
    header_send: seal_header_role(state.header_keys,
      "send",
      wrapping_key,
      slot_context(account_id, device_id, session_id, header, 4, "send", snapshot_version)?)?,
    header_next_send: seal_header_role(state.header_keys,
      "next-send",
      wrapping_key,
      slot_context(account_id, device_id, session_id, header, 4, "next-send", snapshot_version)?)?,
    header_receive: seal_header_role(state.header_keys,
      "receive",
      wrapping_key,
      slot_context(account_id, device_id, session_id, header, 4, "receive", snapshot_version)?)?,
    header_next_receive: seal_header_role(state.header_keys,
      "next-receive",
      wrapping_key,
      slot_context(account_id,
        device_id,
        session_id,
        header,
        4,
        "next-receive",
        snapshot_version)?)?,
    earlier_header_keys: seal_earlier_header_keys(state.header_keys,
      wrapping_key,
      slot_context(account_id,
        device_id,
        session_id,
        header,
        12,
        "header-keys",
        snapshot_version)?)?,
    pq_secrets: seal_map(state.pq_secrets,
      wrapping_key,
      slot_context(account_id, device_id, session_id, header, 12, "pq", snapshot_version)?)?
  })
end

fn seal_snapshot(state :: borrow RatchetState,
  wrapping_key :: borrow StorageKey,
  account_id :: Bytes,
  device_id :: Bytes,
  snapshot_version :: U64) -> Bytes!SnapshotError do
  let header = encode_header(state, snapshot_version)?
  let root_key = seal_secret(state.root_key,
    wrapping_key,
    storage_context(account_id, device_id, state.session_id, header, 1, snapshot_version)?)?
  let sending_chain_key = seal_secret(state.sending_chain_key,
    wrapping_key,
    storage_context(account_id, device_id, state.session_id, header, 2, snapshot_version)?)?
  let receiving_chain_key = seal_secret(state.receiving_chain_key,
    wrapping_key,
    storage_context(account_id, device_id, state.session_id, header, 3, snapshot_version)?)?
  let local_ratchet_private = seal_private(state.local_ratchet_private,
    wrapping_key,
    storage_context(account_id, device_id, state.session_id, header, 13, snapshot_version)?)?
  let skipped_keys = seal_map(state.skipped_keys,
    wrapping_key,
    storage_context(account_id, device_id, state.session_id, header, 12, snapshot_version)?)?
  let extension = seal_extension(state,
    wrapping_key,
    account_id,
    device_id,
    header,
    snapshot_version)?
  join([
      header,
      vector(root_key)?,
      vector(sending_chain_key)?,
      vector(receiving_chain_key)?,
      vector(local_ratchet_private)?,
      vector(skipped_keys)?,
      vector(extension.header_send)?,
      vector(extension.header_next_send)?,
      vector(extension.header_receive)?,
      vector(extension.header_next_receive)?,
      vector(extension.earlier_header_keys)?,
      vector(extension.pq_secrets)?
    ],
    0,
    Bytes.empty())
end

pub fn snapshot(state :: consume RatchetState,
  wrapping_key :: borrow StorageKey,
  account_id :: Bytes,
  device_id :: Bytes,
  snapshot_version :: U64) -> SnapshotOutcome do
  if U64.compare(snapshot_version, state.snapshot_version) <= 0 do
    SnapshotRejected(state, RollbackRejected)
  else
    case seal_snapshot(state, wrapping_key, account_id, device_id, snapshot_version) do
      Err(error) -> SnapshotRejected(state, error)
      Ok(blob) -> SnapshotSealed(%{state | snapshot_version: snapshot_version}, blob)
    end
  end
end

fn open_reader(input :: Bytes) -> BinaryReader!SnapshotError do
  case reader(input, 68900) do
    Err(_) -> Err(InvalidSnapshot)
    Ok(state)
  end
end

fn take_u8(state :: BinaryReader) -> ReadInt!SnapshotError do
  case read_u8(state) do
    Err(_) -> Err(InvalidSnapshot)
    Ok(value) -> do
      let (next, number) = value
      Ok(ReadInt { state: next, value: number })
    end
  end
end

fn take_u16(state :: BinaryReader) -> ReadInt!SnapshotError do
  case read_u16_be(state) do
    Err(_) -> Err(InvalidSnapshot)
    Ok(value) -> do
      let (next, number) = value
      Ok(ReadInt { state: next, value: number })
    end
  end
end

fn take_fixed(state :: BinaryReader, length :: Int) -> ReadBytes!SnapshotError do
  case read_fixed(state, length) do
    Err(_) -> Err(InvalidSnapshot)
    Ok(value) -> do
      let (next, bytes) = value
      Ok(ReadBytes { state: next, value: bytes })
    end
  end
end

fn take_vector(state :: BinaryReader, maximum :: Int) -> ReadBytes!SnapshotError do
  case read_vector(state, maximum) do
    Err(_) -> Err(InvalidSnapshot)
    Ok(value) -> do
      let (next, bytes) = value
      Ok(ReadBytes { state: next, value: bytes })
    end
  end
end

fn take_u32(state :: BinaryReader) -> ReadInt!SnapshotError do
  let encoded = take_fixed(state, 4)?
  case Bytes.read_u32_be(encoded.value, 0) do
    Err(_) -> Err(InvalidSnapshot)
    Ok(wide) -> case U64.to_int(wide) do
      Err(_) -> Err(InvalidSnapshot)
      Ok(value) -> Ok(ReadInt { state: encoded.state, value: value })
    end
  end
end

fn take_u64(state :: BinaryReader) -> ReadWide!SnapshotError do
  let encoded = take_fixed(state, 8)?
  case Bytes.read_u64_be(encoded.value, 0) do
    Err(_) -> Err(InvalidSnapshot)
    Ok(value) -> Ok(ReadWide { state: encoded.state, value: value })
  end
end

fn require_end(state :: BinaryReader) -> Result<(), SnapshotError> do
  case finish(state) do
    Err(_) -> Err(InvalidSnapshot)
    Ok(_) -> Ok(nil)
  end
end

struct ReadAging do
  state :: BinaryReader
  generation :: Int
  index :: Bytes
end

fn take_aging(state :: BinaryReader, format :: Int) -> ReadAging!SnapshotError do
  if format == 2 || format == 3 do
    let generation = take_u32(state)?
    let index = take_vector(generation.state, 2560)?
    Ok(ReadAging { state: index.state, generation: generation.value, index: index.value })
  else
    Ok(ReadAging { state: state, generation: 0, index: Bytes.empty() })
  end
end

struct ReadExtension do
  state :: BinaryReader
  value :: SnapshotExtension
end

fn empty_extension() -> SnapshotExtension do
  SnapshotExtension {
    peer_features: 0,
    header_encrypted: false,
    header_key_owners: Bytes.empty(),
    pq_epoch: 0,
    pq_phase: 0,
    pq_cursor: 0,
    pq_send_mix: 0,
    pq_own: Bytes.empty(),
    pq_peer: Bytes.empty(),
    pq_have: Bytes.empty()
  }
end

fn take_extension(state :: BinaryReader, format :: Int) -> ReadExtension!SnapshotError do
  if format != 3 do
    Ok(ReadExtension { state: state, value: empty_extension() })
  else
    let features = take_u8(state)?
    let encrypted = take_u8(features.state)?
    let owners = take_vector(encrypted.state, 256)?
    let epoch = take_u32(owners.state)?
    let phase = take_u8(epoch.state)?
    let cursor = take_u32(phase.state)?
    let send_mix = take_u32(cursor.state)?
    let own = take_vector(send_mix.state, 1184)?
    let peer = take_vector(own.state, 1184)?
    let have = take_vector(peer.state, 37)?
    let value = SnapshotExtension {
      peer_features: features.value,
      header_encrypted: encrypted.value == 1,
      header_key_owners: owners.value,
      pq_epoch: epoch.value,
      pq_phase: phase.value,
      pq_cursor: cursor.value,
      pq_send_mix: send_mix.value,
      pq_own: own.value,
      pq_peer: peer.value,
      pq_have: have.value
    }
    if encrypted.value > 1 || !valid_extension(value) do
      Err(InvalidSnapshot)
    else
      Ok(ReadExtension { state: have.state, value: value })
    end
  end
end

struct ReadSealed do
  state :: BinaryReader
  value :: SealedExtension
end

fn take_sealed_extension(state :: BinaryReader, format :: Int) -> ReadSealed!SnapshotError do
  if format != 3 do
    Ok(ReadSealed {
      state: state,
      value: SealedExtension {
        header_send: Bytes.empty(),
        header_next_send: Bytes.empty(),
        header_receive: Bytes.empty(),
        header_next_receive: Bytes.empty(),
        earlier_header_keys: Bytes.empty(),
        pq_secrets: Bytes.empty()
      }
    })
  else
    let header_send = take_vector(state, 99)?
    let header_next_send = take_vector(header_send.state, 99)?
    let header_receive = take_vector(header_next_send.state, 99)?
    let header_next_receive = take_vector(header_receive.state, 99)?
    let earlier = take_vector(header_next_receive.state, 2048)?
    let pq = take_vector(earlier.state, 512)?
    Ok(ReadSealed {
      state: pq.state,
      value: SealedExtension {
        header_send: header_send.value,
        header_next_send: header_next_send.value,
        header_receive: header_receive.value,
        header_next_receive: header_next_receive.value,
        earlier_header_keys: earlier.value,
        pq_secrets: pq.value
      }
    })
  end
end

fn decode_snapshot(input :: Bytes) -> ParsedSnapshot!SnapshotError do
  let version = take_u8(open_reader(input)?)?
  let magic = take_fixed(version.state, 3)?
  let suite = take_u16(magic.state)?
  let session_id = take_fixed(suite.state, 32)?
  let snapshot_version = take_u64(session_id.state)?
  let local_public = take_fixed(snapshot_version.state, 32)?
  let remote_public = take_fixed(local_public.state, 32)?
  let previous_chain_length = take_u32(remote_public.state)?
  let sent_count = take_u32(previous_chain_length.state)?
  let received_count = take_u32(sent_count.state)?
  let pending = take_u8(received_count.state)?
  let aging = take_aging(pending.state, version.value)?
  let extension = take_extension(aging.state, version.value)?
  let root_key = take_vector(extension.state, 99)?
  let sending_chain_key = take_vector(root_key.state, 99)?
  let receiving_chain_key = take_vector(sending_chain_key.state, 99)?
  let local_private = take_vector(receiving_chain_key.state, 99)?
  let skipped_keys = take_vector(local_private.state, 65603)?
  let sealed = take_sealed_extension(skipped_keys.state, version.value)?
  require_end(sealed.state)?
  let valid_suite = suite.value == 1 || suite.value == 2
  let valid = (version.value == 1 || version.value == 2 || version.value == 3)
    && Bytes.secure_equals(magic.value, Bytes.from_utf8("RST"))
    && valid_suite
    && pending.value >= 0
    && pending.value <= 1
    && valid_index(aging.index)
    && U64.compare(snapshot_version.value, zero()?) > 0
  if !valid do
    Err(InvalidSnapshot)
  else
    Ok(ParsedSnapshot {
      format: version.value,
      suite: suite.value,
      session_id: session_id.value,
      snapshot_version: snapshot_version.value,
      local_ratchet_public: local_public.value,
      remote_ratchet_public: remote_public.value,
      previous_chain_length: previous_chain_length.value,
      sent_count: sent_count.value,
      received_count: received_count.value,
      pending_send_ratchet: pending.value == 1,
      receive_generation: aging.generation,
      skipped_index: aging.index,
      root_key: root_key.value,
      sending_chain_key: sending_chain_key.value,
      receiving_chain_key: receiving_chain_key.value,
      local_ratchet_private: local_private.value,
      skipped_keys: skipped_keys.value,
      extension: extension.value,
      header_send: sealed.value.header_send,
      header_next_send: sealed.value.header_next_send,
      header_receive: sealed.value.header_receive,
      header_next_receive: sealed.value.header_next_receive,
      earlier_header_keys: sealed.value.earlier_header_keys,
      pq_secrets: sealed.value.pq_secrets
    })
  end
end

fn parsed_header(value :: ParsedSnapshot) -> Bytes!SnapshotError do
  let pending = if value.pending_send_ratchet do
    1
  else
    0
  end
  let header = join([
      byte(value.format)?,
      Bytes.from_utf8("RST"),
      write_u16(value.suite)?,
      value.session_id,
      write_u64(value.snapshot_version)?,
      value.local_ratchet_public,
      value.remote_ratchet_public,
      write_u32(value.previous_chain_length)?,
      write_u32(value.sent_count)?,
      write_u32(value.received_count)?,
      byte(pending)?
    ],
    0,
    Bytes.empty())?
  if value.format == 1 do
    Ok(header)
  else if value.format == 2 do
    join([header, write_u32(value.receive_generation)?, vector(value.skipped_index)?],
      0,
      Bytes.empty())
  else
    join([
        header,
        write_u32(value.receive_generation)?,
        vector(value.skipped_index)?,
        encode_extension(value.extension)?
      ],
      0,
      Bytes.empty())
  end
end

fn unseal_secret(blob :: Bytes,
  wrapping_key :: borrow StorageKey,
  context :: Bytes) -> SecretBytes!SnapshotError do
  case Secret.unseal_from_storage(blob, wrapping_key, context) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(secret)
  end
end

fn unseal_private(blob :: Bytes,
  wrapping_key :: borrow StorageKey,
  context :: Bytes) -> X25519PrivateKey!SnapshotError do
  case X25519PrivateKey.unseal_from_storage(blob, wrapping_key, context) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(secret)
  end
end

fn unseal_map(blob :: Bytes,
  wrapping_key :: borrow StorageKey,
  context :: Bytes) -> SecretMap!SnapshotError do
  case SecretMap.unseal_from_storage(blob, wrapping_key, context) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(secret)
  end
end

# A version 1 snapshot does not say which skipped keys it holds, so they could
# never be aged out. They are left behind: their messages, if any were still
# coming, are lost, and every key kept from here on is accounted for.

fn restored_skipped_keys(value :: ParsedSnapshot,
  wrapping_key :: borrow StorageKey,
  account_id :: Bytes,
  device_id :: Bytes,
  header :: Bytes) -> SecretMap!SnapshotError do
  if value.format == 1 do
    case SecretMap.new(64) do
      Err(error) -> Err(CryptoFailure(error))
      Ok(empty)
    end
  else
    unseal_map(value.skipped_keys,
      wrapping_key,
      storage_context(account_id, device_id, value.session_id, header, 12, value.snapshot_version)?)
  end
end

fn restore_header_role(keys :: borrow SecretMap,
  blob :: Bytes,
  role :: String,
  wrapping_key :: borrow StorageKey,
  context :: Bytes) -> Result<(), SnapshotError> do
  if Bytes.length(blob) == 0 do
    Ok(nil)
  else
    let key = unseal_secret(blob, wrapping_key, context)?
    case SecretMap.insert(keys, ratchet_header_role(role), key) do
      Err(error) -> Err(CryptoFailure(error))
      Ok(_) -> Ok(nil)
    end
  end
end

fn restored_header_keys(value :: ParsedSnapshot,
  wrapping_key :: borrow StorageKey,
  account_id :: Bytes,
  device_id :: Bytes,
  header :: Bytes) -> SecretMap!SnapshotError do
  if value.format != 3 do
    case SecretMap.new(16) do
      Err(error) -> Err(CryptoFailure(error))
      Ok(empty)
    end
  else
    let session_id = value.session_id
    let version = value.snapshot_version
    let keys = unseal_map(value.earlier_header_keys,
      wrapping_key,
      slot_context(account_id, device_id, session_id, header, 12, "header-keys", version)?)?
    restore_header_role(keys,
      value.header_send,
      "send",
      wrapping_key,
      slot_context(account_id, device_id, session_id, header, 4, "send", version)?)?
    restore_header_role(keys,
      value.header_next_send,
      "next-send",
      wrapping_key,
      slot_context(account_id, device_id, session_id, header, 4, "next-send", version)?)?
    restore_header_role(keys,
      value.header_receive,
      "receive",
      wrapping_key,
      slot_context(account_id, device_id, session_id, header, 4, "receive", version)?)?
    restore_header_role(keys,
      value.header_next_receive,
      "next-receive",
      wrapping_key,
      slot_context(account_id, device_id, session_id, header, 4, "next-receive", version)?)?
    Ok(keys)
  end
end

fn restored_pq_secrets(value :: ParsedSnapshot,
  wrapping_key :: borrow StorageKey,
  account_id :: Bytes,
  device_id :: Bytes,
  header :: Bytes) -> SecretMap!SnapshotError do
  if value.format != 3 do
    case SecretMap.new(2) do
      Err(error) -> Err(CryptoFailure(error))
      Ok(empty)
    end
  else
    unseal_map(value.pq_secrets,
      wrapping_key,
      slot_context(account_id,
        device_id,
        value.session_id,
        header,
        12,
        "pq",
        value.snapshot_version)?)
  end
end

fn restore_parsed(value :: ParsedSnapshot,
  wrapping_key :: borrow StorageKey,
  account_id :: Bytes,
  device_id :: Bytes) -> RatchetState!SnapshotError do
  let header = parsed_header(value)?
  let root_key = unseal_secret(value.root_key,
    wrapping_key,
    storage_context(account_id, device_id, value.session_id, header, 1, value.snapshot_version)?)?
  let sending_chain_key = unseal_secret(value.sending_chain_key,
    wrapping_key,
    storage_context(account_id, device_id, value.session_id, header, 2, value.snapshot_version)?)?
  let receiving_chain_key = unseal_secret(value.receiving_chain_key,
    wrapping_key,
    storage_context(account_id, device_id, value.session_id, header, 3, value.snapshot_version)?)?
  let local_ratchet_private = unseal_private(value.local_ratchet_private,
    wrapping_key,
    storage_context(account_id, device_id, value.session_id, header, 13, value.snapshot_version)?)?
  let skipped_keys = restored_skipped_keys(value, wrapping_key, account_id, device_id, header)?
  let header_keys = restored_header_keys(value, wrapping_key, account_id, device_id, header)?
  let pq_secrets = restored_pq_secrets(value, wrapping_key, account_id, device_id, header)?
  let extension = value.extension
  Ok(RatchetState {
    version: 1,
    suite: value.suite,
    session_id: value.session_id,
    root_key: root_key,
    sending_chain_key: sending_chain_key,
    receiving_chain_key: receiving_chain_key,
    local_ratchet_private: local_ratchet_private,
    local_ratchet_public: X25519PublicKey { bytes: value.local_ratchet_public },
    remote_ratchet_public: X25519PublicKey { bytes: value.remote_ratchet_public },
    previous_chain_length: value.previous_chain_length,
    sent_count: value.sent_count,
    received_count: value.received_count,
    skipped_keys: skipped_keys,
    skipped_index: value.skipped_index,
    receive_generation: value.receive_generation,
    pending_send_ratchet: value.pending_send_ratchet,
    snapshot_version: value.snapshot_version,
    peer_features: extension.peer_features,
    header_encrypted: extension.header_encrypted,
    header_keys: header_keys,
    header_key_owners: extension.header_key_owners,
    pq_epoch: extension.pq_epoch,
    pq_phase: extension.pq_phase,
    pq_cursor: extension.pq_cursor,
    pq_send_mix: extension.pq_send_mix,
    pq_own: extension.pq_own,
    pq_peer: extension.pq_peer,
    pq_have: extension.pq_have,
    pq_secrets: pq_secrets
  })
end

pub fn restore(blob :: Bytes,
  wrapping_key :: borrow StorageKey,
  account_id :: Bytes,
  device_id :: Bytes,
  minimum_version :: U64) -> RatchetState!SnapshotError do
  let value = decode_snapshot(blob)?
  if U64.compare(value.snapshot_version, minimum_version) < 0 do
    Err(RollbackRejected)
  else
    restore_parsed(value, wrapping_key, account_id, device_id)
  end
end

pub fn replace_session(current :: consume RatchetState,
  blob :: Bytes,
  wrapping_key :: borrow StorageKey,
  account_id :: Bytes,
  device_id :: Bytes) -> ReplacementOutcome do
  case decode_snapshot(blob) do
    Err(error) -> ReplacementRejected(current, error)
    Ok(value) -> if U64.compare(value.snapshot_version, current.snapshot_version) <= 0 do
      ReplacementRejected(current, RollbackRejected)
    else
      case restore_parsed(value, wrapping_key, account_id, device_id) do
        Err(error) -> ReplacementRejected(current, error)
        Ok(candidate) -> SessionReplaced(candidate)
      end
    end
  end
end
