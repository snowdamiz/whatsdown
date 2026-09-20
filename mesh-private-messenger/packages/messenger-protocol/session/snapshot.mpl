from Binary.Reader import BinaryReader, finish, read_fixed, read_u16_be, read_u8, read_vector, reader
from Session.Handshake import RatchetState

pub type SnapshotError do
  CryptoFailure( error :: CryptoError)

  InvalidSnapshot

  RollbackRejected
end

pub type SnapshotOutcome do
  SnapshotSealed( state :: RatchetState, blob :: Bytes)

  SnapshotRejected( state :: RatchetState, error :: SnapshotError)
end

pub type ReplacementOutcome do
  SessionReplaced( state :: RatchetState)

  ReplacementRejected( state :: RatchetState, error :: SnapshotError)
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
  suite :: Int
  session_id :: Bytes
  snapshot_version :: U64
  local_ratchet_public :: Bytes
  remote_ratchet_public :: Bytes
  previous_chain_length :: Int
  sent_count :: Int
  received_count :: Int
  pending_send_ratchet :: Bool
  root_key :: Bytes
  sending_chain_key :: Bytes
  receiving_chain_key :: Bytes
  local_ratchet_private :: Bytes
  skipped_keys :: Bytes
end

fn append(left :: Bytes, right :: Bytes) -> Bytes ! SnapshotError do
  case Bytes.concat(left, right) do
    Err( _) -> Err(InvalidSnapshot)
    Ok( value) -> Ok(value)
  end
end

fn join(parts :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! SnapshotError do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, append(output, List.get(parts, index)) ?)
  end
end

fn byte(value :: Int) -> Bytes ! SnapshotError do
  case Bytes.from_list([value]) do
    Err( _) -> Err(InvalidSnapshot)
    Ok( encoded) -> Ok(encoded)
  end
end

fn write_u16(value :: Int) -> Bytes ! SnapshotError do
  case Bytes.write_u16_be(value) do
    Err( _) -> Err(InvalidSnapshot)
    Ok( encoded) -> Ok(encoded)
  end
end

fn write_u32(value :: Int) -> Bytes ! SnapshotError do
  case U64.parse(Int.to_string(value)) do
    Err( _) -> Err(InvalidSnapshot)
    Ok( wide) -> case Bytes.write_u32_be(wide) do
      Err( _) -> Err(InvalidSnapshot)
      Ok( encoded) -> Ok(encoded)
    end
  end
end

fn write_u64(value :: U64) -> Bytes ! SnapshotError do
  case Bytes.write_u64_be(value) do
    Err( _) -> Err(InvalidSnapshot)
    Ok( encoded) -> Ok(encoded)
  end
end

fn vector(value :: Bytes) -> Bytes ! SnapshotError do
  append(write_u32(Bytes.length(value)) ?, value)
end

fn zero() -> U64 ! SnapshotError do
  case U64.parse("0") do
    Err( _) -> Err(InvalidSnapshot)
    Ok( value) -> Ok(value)
  end
end

fn encode_header(state :: borrow RatchetState, snapshot_version :: U64) -> Bytes ! SnapshotError do
  let valid_suite = state.suite == 1 || state.suite == 2
  let valid = state.version == 1 && valid_suite && Bytes.length(state.session_id) == 32 && Bytes.length(state.local_ratchet_public.bytes) == 32 && Bytes.length(state.remote_ratchet_public.bytes) == 32 && state.previous_chain_length >= 0 && state.sent_count >= 0 && state.received_count >= 0 && U64.compare(snapshot_version,
  zero() ?) > 0
  if !valid do
    Err(InvalidSnapshot)
  else
    let pending = if state.pending_send_ratchet do
      1
    else
      0
    end
    join([byte(1) ?, Bytes.from_utf8("RST"), write_u16(state.suite) ?, state.session_id, write_u64(snapshot_version) ?, state.local_ratchet_public.bytes, state.remote_ratchet_public.bytes, write_u32(state.previous_chain_length) ?, write_u32(state.sent_count) ?, write_u32(state.received_count) ?, byte(pending) ?],
    0,
    Bytes.empty())
  end
end

fn storage_object(header :: Bytes, purpose :: Int) -> Bytes ! SnapshotError do
  let input = join([Bytes.from_utf8("mesh-msg/v1/ratchet-snapshot-object"), header, write_u16(purpose) ?],
  0,
  Bytes.empty()) ?
  Ok(Crypto.sha256(input))
end

fn storage_context(account_id :: Bytes,
device_id :: Bytes,
session_id :: Bytes,
header :: Bytes,
purpose :: Int,
snapshot_version :: U64) -> Bytes ! SnapshotError do
  let supported = purpose == 1 || purpose == 2 || purpose == 3 || purpose == 12 || purpose == 13
  if Bytes.length(account_id) != 32 || Bytes.length(device_id) != 16 || Bytes.length(session_id) != 32 || !supported do
    Err(InvalidSnapshot)
  else
    join([byte(1) ?, account_id, device_id, session_id, storage_object(header, purpose) ?, write_u16(purpose) ?, write_u64(snapshot_version) ?],
    0,
    Bytes.empty())
  end
end

fn seal_secret(secret :: borrow SecretBytes, wrapping_key :: borrow StorageKey, context :: Bytes) -> Bytes ! SnapshotError do
  case Secret.seal_for_storage(secret, wrapping_key, context) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( blob) -> Ok(blob)
  end
end

fn seal_private(secret :: borrow X25519PrivateKey,
wrapping_key :: borrow StorageKey,
context :: Bytes) -> Bytes ! SnapshotError do
  case X25519PrivateKey.seal_for_storage(secret, wrapping_key, context) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( blob) -> Ok(blob)
  end
end

fn seal_map(secret :: borrow SecretMap, wrapping_key :: borrow StorageKey, context :: Bytes) -> Bytes ! SnapshotError do
  case SecretMap.seal_for_storage(secret, wrapping_key, context) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( blob) -> Ok(blob)
  end
end

fn seal_snapshot(state :: borrow RatchetState,
wrapping_key :: borrow StorageKey,
account_id :: Bytes,
device_id :: Bytes,
snapshot_version :: U64) -> Bytes ! SnapshotError do
  let header = encode_header(state, snapshot_version) ?
  let root_key = seal_secret(state.root_key,
  wrapping_key,
  storage_context(account_id, device_id, state.session_id, header, 1, snapshot_version) ?) ?
  let sending_chain_key = seal_secret(state.sending_chain_key,
  wrapping_key,
  storage_context(account_id, device_id, state.session_id, header, 2, snapshot_version) ?) ?
  let receiving_chain_key = seal_secret(state.receiving_chain_key,
  wrapping_key,
  storage_context(account_id, device_id, state.session_id, header, 3, snapshot_version) ?) ?
  let local_ratchet_private = seal_private(state.local_ratchet_private,
  wrapping_key,
  storage_context(account_id, device_id, state.session_id, header, 13, snapshot_version) ?) ?
  let skipped_keys = seal_map(state.skipped_keys,
  wrapping_key,
  storage_context(account_id, device_id, state.session_id, header, 12, snapshot_version) ?) ?
  join([header, vector(root_key) ?, vector(sending_chain_key) ?, vector(receiving_chain_key) ?, vector(local_ratchet_private) ?, vector(skipped_keys) ?],
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
      Err( error) -> SnapshotRejected(state, error)
      Ok( blob) -> SnapshotSealed(% { state | snapshot_version : snapshot_version }, blob)
    end
  end
end

fn open_reader(input :: Bytes) -> BinaryReader ! SnapshotError do
  case reader(input, 66300) do
    Err( _) -> Err(InvalidSnapshot)
    Ok( state) -> Ok(state)
  end
end

fn take_u8(state :: BinaryReader) -> ReadInt ! SnapshotError do
  case read_u8(state) do
    Err( _) -> Err(InvalidSnapshot)
    Ok( value) -> do
      let ( next, number) = value
      Ok(ReadInt {
        state : next,
        value : number
      })
    end
  end
end

fn take_u16(state :: BinaryReader) -> ReadInt ! SnapshotError do
  case read_u16_be(state) do
    Err( _) -> Err(InvalidSnapshot)
    Ok( value) -> do
      let ( next, number) = value
      Ok(ReadInt {
        state : next,
        value : number
      })
    end
  end
end

fn take_fixed(state :: BinaryReader, length :: Int) -> ReadBytes ! SnapshotError do
  case read_fixed(state, length) do
    Err( _) -> Err(InvalidSnapshot)
    Ok( value) -> do
      let ( next, bytes) = value
      Ok(ReadBytes {
        state : next,
        value : bytes
      })
    end
  end
end

fn take_vector(state :: BinaryReader, maximum :: Int) -> ReadBytes ! SnapshotError do
  case read_vector(state, maximum) do
    Err( _) -> Err(InvalidSnapshot)
    Ok( value) -> do
      let ( next, bytes) = value
      Ok(ReadBytes {
        state : next,
        value : bytes
      })
    end
  end
end

fn take_u32(state :: BinaryReader) -> ReadInt ! SnapshotError do
  let encoded = take_fixed(state, 4) ?
  case Bytes.read_u32_be(encoded.value, 0) do
    Err( _) -> Err(InvalidSnapshot)
    Ok( wide) -> case U64.to_int(wide) do
      Err( _) -> Err(InvalidSnapshot)
      Ok( value) -> Ok(ReadInt {
        state : encoded.state,
        value : value
      })
    end
  end
end

fn take_u64(state :: BinaryReader) -> ReadWide ! SnapshotError do
  let encoded = take_fixed(state, 8) ?
  case Bytes.read_u64_be(encoded.value, 0) do
    Err( _) -> Err(InvalidSnapshot)
    Ok( value) -> Ok(ReadWide {
      state : encoded.state,
      value : value
    })
  end
end

fn require_end(state :: BinaryReader) -> Result <(), SnapshotError > do
  case finish(state) do
    Err( _) -> Err(InvalidSnapshot)
    Ok( _) -> Ok(nil)
  end
end

fn decode_snapshot(input :: Bytes) -> ParsedSnapshot ! SnapshotError do
  let version = take_u8(open_reader(input) ?) ?
  let magic = take_fixed(version.state, 3) ?
  let suite = take_u16(magic.state) ?
  let session_id = take_fixed(suite.state, 32) ?
  let snapshot_version = take_u64(session_id.state) ?
  let local_public = take_fixed(snapshot_version.state, 32) ?
  let remote_public = take_fixed(local_public.state, 32) ?
  let previous_chain_length = take_u32(remote_public.state) ?
  let sent_count = take_u32(previous_chain_length.state) ?
  let received_count = take_u32(sent_count.state) ?
  let pending = take_u8(received_count.state) ?
  let root_key = take_vector(pending.state, 99) ?
  let sending_chain_key = take_vector(root_key.state, 99) ?
  let receiving_chain_key = take_vector(sending_chain_key.state, 99) ?
  let local_private = take_vector(receiving_chain_key.state, 99) ?
  let skipped_keys = take_vector(local_private.state, 65603) ?
  require_end(skipped_keys.state) ?
  let valid_suite = suite.value == 1 || suite.value == 2
  let valid = version.value == 1 && Bytes.secure_equals(magic.value, Bytes.from_utf8("RST")) && valid_suite && pending.value >= 0 && pending.value <= 1 && U64.compare(snapshot_version.value,
  zero() ?) > 0
  if !valid do
    Err(InvalidSnapshot)
  else
    Ok(ParsedSnapshot {
      suite : suite.value,
      session_id : session_id.value,
      snapshot_version : snapshot_version.value,
      local_ratchet_public : local_public.value,
      remote_ratchet_public : remote_public.value,
      previous_chain_length : previous_chain_length.value,
      sent_count : sent_count.value,
      received_count : received_count.value,
      pending_send_ratchet : pending.value == 1,
      root_key : root_key.value,
      sending_chain_key : sending_chain_key.value,
      receiving_chain_key : receiving_chain_key.value,
      local_ratchet_private : local_private.value,
      skipped_keys : skipped_keys.value
    })
  end
end

fn parsed_header(value :: ParsedSnapshot) -> Bytes ! SnapshotError do
  let pending = if value.pending_send_ratchet do
    1
  else
    0
  end
  join([byte(1) ?, Bytes.from_utf8("RST"), write_u16(value.suite) ?, value.session_id, write_u64(value.snapshot_version) ?, value.local_ratchet_public, value.remote_ratchet_public, write_u32(value.previous_chain_length) ?, write_u32(value.sent_count) ?, write_u32(value.received_count) ?, byte(pending) ?],
  0,
  Bytes.empty())
end

fn unseal_secret(blob :: Bytes, wrapping_key :: borrow StorageKey, context :: Bytes) -> SecretBytes ! SnapshotError do
  case Secret.unseal_from_storage(blob, wrapping_key, context) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( secret) -> Ok(secret)
  end
end

fn unseal_private(blob :: Bytes, wrapping_key :: borrow StorageKey, context :: Bytes) -> X25519PrivateKey ! SnapshotError do
  case X25519PrivateKey.unseal_from_storage(blob, wrapping_key, context) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( secret) -> Ok(secret)
  end
end

fn unseal_map(blob :: Bytes, wrapping_key :: borrow StorageKey, context :: Bytes) -> SecretMap ! SnapshotError do
  case SecretMap.unseal_from_storage(blob, wrapping_key, context) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( secret) -> Ok(secret)
  end
end

fn restore_parsed(value :: ParsedSnapshot,
wrapping_key :: borrow StorageKey,
account_id :: Bytes,
device_id :: Bytes) -> RatchetState ! SnapshotError do
  let header = parsed_header(value) ?
  let root_key = unseal_secret(value.root_key,
  wrapping_key,
  storage_context(account_id, device_id, value.session_id, header, 1, value.snapshot_version) ?) ?
  let sending_chain_key = unseal_secret(value.sending_chain_key,
  wrapping_key,
  storage_context(account_id, device_id, value.session_id, header, 2, value.snapshot_version) ?) ?
  let receiving_chain_key = unseal_secret(value.receiving_chain_key,
  wrapping_key,
  storage_context(account_id, device_id, value.session_id, header, 3, value.snapshot_version) ?) ?
  let local_ratchet_private = unseal_private(value.local_ratchet_private,
  wrapping_key,
  storage_context(account_id, device_id, value.session_id, header, 13, value.snapshot_version) ?) ?
  let skipped_keys = unseal_map(value.skipped_keys,
  wrapping_key,
  storage_context(account_id, device_id, value.session_id, header, 12, value.snapshot_version) ?) ?
  Ok(RatchetState {
    version : 1,
    suite : value.suite,
    session_id : value.session_id,
    root_key : root_key,
    sending_chain_key : sending_chain_key,
    receiving_chain_key : receiving_chain_key,
    local_ratchet_private : local_ratchet_private,
    local_ratchet_public : X25519PublicKey { bytes : value.local_ratchet_public },
    remote_ratchet_public : X25519PublicKey { bytes : value.remote_ratchet_public },
    previous_chain_length : value.previous_chain_length,
    sent_count : value.sent_count,
    received_count : value.received_count,
    skipped_keys : skipped_keys,
    pending_send_ratchet : value.pending_send_ratchet,
    snapshot_version : value.snapshot_version
  })
end

pub fn restore(blob :: Bytes,
wrapping_key :: borrow StorageKey,
account_id :: Bytes,
device_id :: Bytes,
minimum_version :: U64) -> RatchetState ! SnapshotError do
  let value = decode_snapshot(blob) ?
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
    Err( error) -> ReplacementRejected(current, error)
    Ok( value) -> if U64.compare(value.snapshot_version, current.snapshot_version) <= 0 do
      ReplacementRejected(current, RollbackRejected)
    else
      case restore_parsed(value, wrapping_key, account_id, device_id) do
        Err( error) -> ReplacementRejected(current, error)
        Ok( candidate) -> SessionReplaced(candidate)
      end
    end
  end
end
