from Session.HeaderStore import header_slot_names, checked_header_names, encode_header_names
from Session.State import RatchetError
from Session.State import RatchetState
from Binary.Reader import (
  BinaryReader,
  finish,
  read_fixed,
  read_u16_be,
  read_u8,
  read_vector,
  reader
)

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
  header_names :: Bytes
  header_secrets :: Bytes
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

fn encode_header(state :: borrow RatchetState, snapshot_version :: U64) -> Bytes!SnapshotError do
  let valid_suite = state.suite == 1 || state.suite == 2
  let valid = (state.version == 1 || state.version == 2)
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
    let encoded = join([
        byte(if state.version == 2 do
          3
        else
          2
        end)?,
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
        vector(state.skipped_index)?
      ],
      0,
      Bytes.empty())?
    if state.version == 2 do
      let names = case checked_header_names(state) do
        Err(error) -> Err(header_snapshot_error(error))
        Ok(value)
      end?
      let encoded_names = case encode_header_names(names) do
        Err(error) -> Err(header_snapshot_error(error))
        Ok(value)
      end?
      append(encoded, vector(encoded_names)?)
    else
      Ok(encoded)
    end
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

fn storage_context(account_id :: Bytes,
  device_id :: Bytes,
  session_id :: Bytes,
  header :: Bytes,
  purpose :: Int,
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
        storage_object(header, purpose)?,
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
  let encoded = join([
      header,
      vector(root_key)?,
      vector(sending_chain_key)?,
      vector(receiving_chain_key)?,
      vector(local_ratchet_private)?,
      vector(skipped_keys)?
    ],
    0,
    Bytes.empty())?
  if state.version == 2 do
    let names = case checked_header_names(state) do
      Err(error) -> Err(header_snapshot_error(error))
      Ok(value)
    end?
    let secrets = seal_headers(state,
      wrapping_key,
      account_id,
      device_id,
      header,
      snapshot_version,
      names,
      0,
      Bytes.empty())?
    append(encoded, vector(secrets)?)
  else
    Ok(encoded)
  end
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
  case reader(input, 70100) do
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
  let header_names = if version.value == 3 do
    take_vector(aging.state, 262)?
  else
    ReadBytes { state: aging.state, value: Bytes.empty() }
  end
  let root_key = take_vector(header_names.state, 99)?
  let sending_chain_key = take_vector(root_key.state, 99)?
  let receiving_chain_key = take_vector(sending_chain_key.state, 99)?
  let local_private = take_vector(receiving_chain_key.state, 99)?
  let skipped_keys = take_vector(local_private.state, 65603)?
  let header_secrets = if version.value == 3 do
    take_vector(skipped_keys.state, 927)?
  else
    ReadBytes { state: skipped_keys.state, value: Bytes.empty() }
  end
  require_end(header_secrets.state)?
  let valid_suite = suite.value == 1 || suite.value == 2
  let valid = (version.value == 1 || version.value == 2 || version.value == 3)
    && (version.value == 3 || Bytes.length(input) <= 68900)
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
      header_names: header_names.value,
      header_secrets: header_secrets.value
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
  else
    let encoded = join([header, write_u32(value.receive_generation)?, vector(value.skipped_index)?],
      0,
      Bytes.empty())?
    if value.format == 3 do
      append(encoded, vector(value.header_names)?)
    else
      Ok(encoded)
    end
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
  let header_keys = if value.format == 3 do
    restore_headers(value, wrapping_key, account_id, device_id, header)?
  else
    case SecretMap.new(16) do
      Err(error) -> Err(CryptoFailure(error))
      Ok(value)
    end?
  end
  Ok(RatchetState {
    version: if value.format == 3 do
      2
    else
      1
    end,
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
    header_keys: header_keys
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

# RST3 maximum: prior header2791 + names vector266 + four key vectors412
# + skipped-map vector65607 + nine purpose4 key vectors927 + vector4 =70007.
# 70100 is the new parser ceiling; RST1/2 retain their68900 admission ceiling.
fn header_snapshot_error(error :: RatchetError) -> SnapshotError do
  case error do
    RatchetError.CryptoFailure -> CryptoFailure(InternalFailure)
    _ -> InvalidSnapshot
  end
end

fn seal_headers(state :: borrow RatchetState,
  key :: borrow StorageKey,
  account :: Bytes,
  device :: Bytes,
  header :: Bytes,
  version :: U64,
  names :: List<Bytes>,
  index :: Int,
  output :: Bytes) -> Bytes!SnapshotError do
  if index >= List.length(names) do
    return Ok(output)
  end
  let name = List.get(names, index)
  let material = case SecretMap.copy(state.header_keys, name) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end?
  let role_header = append(header, vector(name)?)?
  let blob = seal_secret(material,
    key,
    storage_context(account, device, state.session_id, role_header, 4, version)?)?
  Secret.destroy(material)
  seal_headers(state,
    key,
    account,
    device,
    header,
    version,
    names,
    index + 1,
    append(output, vector(blob)?)?)
end

fn restore_header_rows(value :: ParsedSnapshot,
  key :: borrow StorageKey,
  account :: Bytes,
  device :: Bytes,
  header :: Bytes,
  names :: List<Bytes>,
  index :: Int,
  headers :: borrow SecretMap) -> Unit!SnapshotError do
  if index >= List.length(names) do
    return Ok(nil)
  end
  let name = List.get(names, index)
  let offset = index * 103
  let length = case Bytes.read_u32_be(value.header_secrets, offset) do
    Err(_) -> Err(InvalidSnapshot)
    Ok(wide) -> case U64.to_int(wide) do
      Err(_) -> Err(InvalidSnapshot)
      Ok(number)
    end
  end?
  if length != 99 do
    return Err(InvalidSnapshot)
  end
  let blob = case Bytes.slice(value.header_secrets, offset + 4, 99) do
    Err(_) -> Err(InvalidSnapshot)
    Ok(value)
  end?
  let material = unseal_secret(blob,
    key,
    storage_context(account,
      device,
      value.session_id,
      append(header, vector(name)?)?,
      4,
      value.snapshot_version)?)?
  case SecretMap.insert(headers, name, material) do
    Err(error) -> return Err(CryptoFailure(error))
    Ok(_) -> nil
  end
  restore_header_rows(value, key, account, device, header, names, index + 1, headers)
end

fn restore_headers(value :: ParsedSnapshot,
  key :: borrow StorageKey,
  account :: Bytes,
  device :: Bytes,
  header :: Bytes) -> SecretMap!SnapshotError do
  let names = case header_slot_names(value.skipped_index,
    value.remote_ratchet_public,
    value.receive_generation) do
    Err(error) -> Err(header_snapshot_error(error))
    Ok(value)
  end?
  let canonical = case encode_header_names(names) do
    Err(error) -> Err(header_snapshot_error(error))
    Ok(value)
  end?
  if !Bytes.secure_equals(canonical, value.header_names)
    || Bytes.length(value.header_secrets) != List.length(names) * 103 do
    return Err(InvalidSnapshot)
  end
  let headers = case SecretMap.new(16) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end?
  restore_header_rows(value, key, account, device, header, names, 0, headers)?
  Ok(headers)
end
