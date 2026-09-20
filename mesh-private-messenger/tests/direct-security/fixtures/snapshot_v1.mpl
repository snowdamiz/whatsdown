# The version 1 ratchet snapshot writer, frozen as it was before version 2, and
# kept only so the migration proof can seal a genuine version 1 snapshot: the
# storage key is never a fixture, so an old blob cannot be one either. Every
# name carries a suffix so that nothing here can be taken for the live writer.

from Session.Handshake import RatchetState

pub type SnapshotErrorV1 do
  CryptoFailureV1( error :: CryptoError)

  InvalidSnapshotV1

  RollbackRejectedV1
end

pub type SnapshotOutcomeV1 do
  SnapshotSealedV1( state :: RatchetState, blob :: Bytes)

  SnapshotRejectedV1( state :: RatchetState, error :: SnapshotErrorV1)
end

fn append_v1(left :: Bytes, right :: Bytes) -> Bytes ! SnapshotErrorV1 do
  case Bytes.concat(left, right) do
    Err( _) -> Err(InvalidSnapshotV1)
    Ok( value) -> Ok(value)
  end
end

fn join_v1(parts :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! SnapshotErrorV1 do
  if index >= List.length(parts) do
    Ok(output)
  else
    join_v1(parts, index + 1, append_v1(output, List.get(parts, index)) ?)
  end
end

fn byte_v1(value :: Int) -> Bytes ! SnapshotErrorV1 do
  case Bytes.from_list([value]) do
    Err( _) -> Err(InvalidSnapshotV1)
    Ok( encoded) -> Ok(encoded)
  end
end

fn write_u16_v1(value :: Int) -> Bytes ! SnapshotErrorV1 do
  case Bytes.write_u16_be(value) do
    Err( _) -> Err(InvalidSnapshotV1)
    Ok( encoded) -> Ok(encoded)
  end
end

fn write_u32_v1(value :: Int) -> Bytes ! SnapshotErrorV1 do
  case U64.parse(Int.to_string(value)) do
    Err( _) -> Err(InvalidSnapshotV1)
    Ok( wide) -> case Bytes.write_u32_be(wide) do
      Err( _) -> Err(InvalidSnapshotV1)
      Ok( encoded) -> Ok(encoded)
    end
  end
end

fn write_u64_v1(value :: U64) -> Bytes ! SnapshotErrorV1 do
  case Bytes.write_u64_be(value) do
    Err( _) -> Err(InvalidSnapshotV1)
    Ok( encoded) -> Ok(encoded)
  end
end

fn vector_v1(value :: Bytes) -> Bytes ! SnapshotErrorV1 do
  append_v1(write_u32_v1(Bytes.length(value)) ?, value)
end

fn zero_v1() -> U64 ! SnapshotErrorV1 do
  case U64.parse("0") do
    Err( _) -> Err(InvalidSnapshotV1)
    Ok( value) -> Ok(value)
  end
end

fn encode_header_v1(state :: borrow RatchetState, snapshot_version :: U64) -> Bytes ! SnapshotErrorV1 do
  let valid_suite = state.suite == 1 || state.suite == 2
  let valid = state.version == 1 && valid_suite && Bytes.length(state.session_id) == 32 && Bytes.length(state.local_ratchet_public.bytes) == 32 && Bytes.length(state.remote_ratchet_public.bytes) == 32 && state.previous_chain_length >= 0 && state.sent_count >= 0 && state.received_count >= 0 && U64.compare(snapshot_version,
  zero_v1() ?) > 0
  if !valid do
    Err(InvalidSnapshotV1)
  else
    let pending = if state.pending_send_ratchet do
      1
    else
      0
    end
    join_v1([byte_v1(1) ?, Bytes.from_utf8("RST"), write_u16_v1(state.suite) ?, state.session_id, write_u64_v1(snapshot_version) ?, state.local_ratchet_public.bytes, state.remote_ratchet_public.bytes, write_u32_v1(state.previous_chain_length) ?, write_u32_v1(state.sent_count) ?, write_u32_v1(state.received_count) ?, byte_v1(pending) ?],
    0,
    Bytes.empty())
  end
end

fn storage_object_v1(header :: Bytes, purpose :: Int) -> Bytes ! SnapshotErrorV1 do
  let input = join_v1([Bytes.from_utf8("mesh-msg/v1/ratchet-snapshot-object"), header, write_u16_v1(purpose) ?],
  0,
  Bytes.empty()) ?
  Ok(Crypto.sha256(input))
end

fn storage_context_v1(account_id :: Bytes,
device_id :: Bytes,
session_id :: Bytes,
header :: Bytes,
purpose :: Int,
snapshot_version :: U64) -> Bytes ! SnapshotErrorV1 do
  let supported = purpose == 1 || purpose == 2 || purpose == 3 || purpose == 12 || purpose == 13
  if Bytes.length(account_id) != 32 || Bytes.length(device_id) != 16 || Bytes.length(session_id) != 32 || !supported do
    Err(InvalidSnapshotV1)
  else
    join_v1([byte_v1(1) ?, account_id, device_id, session_id, storage_object_v1(header, purpose) ?, write_u16_v1(purpose) ?, write_u64_v1(snapshot_version) ?],
    0,
    Bytes.empty())
  end
end

fn seal_secret_v1(secret :: borrow SecretBytes, wrapping_key :: borrow StorageKey, context :: Bytes) -> Bytes ! SnapshotErrorV1 do
  case Secret.seal_for_storage(secret, wrapping_key, context) do
    Err( error) -> Err(CryptoFailureV1(error))
    Ok( blob) -> Ok(blob)
  end
end

fn seal_private_v1(secret :: borrow X25519PrivateKey,
wrapping_key :: borrow StorageKey,
context :: Bytes) -> Bytes ! SnapshotErrorV1 do
  case X25519PrivateKey.seal_for_storage(secret, wrapping_key, context) do
    Err( error) -> Err(CryptoFailureV1(error))
    Ok( blob) -> Ok(blob)
  end
end

fn seal_map_v1(secret :: borrow SecretMap, wrapping_key :: borrow StorageKey, context :: Bytes) -> Bytes ! SnapshotErrorV1 do
  case SecretMap.seal_for_storage(secret, wrapping_key, context) do
    Err( error) -> Err(CryptoFailureV1(error))
    Ok( blob) -> Ok(blob)
  end
end

fn seal_snapshot_v1(state :: borrow RatchetState,
wrapping_key :: borrow StorageKey,
account_id :: Bytes,
device_id :: Bytes,
snapshot_version :: U64) -> Bytes ! SnapshotErrorV1 do
  let header = encode_header_v1(state, snapshot_version) ?
  let root_key = seal_secret_v1(state.root_key,
  wrapping_key,
  storage_context_v1(account_id, device_id, state.session_id, header, 1, snapshot_version) ?) ?
  let sending_chain_key = seal_secret_v1(state.sending_chain_key,
  wrapping_key,
  storage_context_v1(account_id, device_id, state.session_id, header, 2, snapshot_version) ?) ?
  let receiving_chain_key = seal_secret_v1(state.receiving_chain_key,
  wrapping_key,
  storage_context_v1(account_id, device_id, state.session_id, header, 3, snapshot_version) ?) ?
  let local_ratchet_private = seal_private_v1(state.local_ratchet_private,
  wrapping_key,
  storage_context_v1(account_id, device_id, state.session_id, header, 13, snapshot_version) ?) ?
  let skipped_keys = seal_map_v1(state.skipped_keys,
  wrapping_key,
  storage_context_v1(account_id, device_id, state.session_id, header, 12, snapshot_version) ?) ?
  join_v1([header, vector_v1(root_key) ?, vector_v1(sending_chain_key) ?, vector_v1(receiving_chain_key) ?, vector_v1(local_ratchet_private) ?, vector_v1(skipped_keys) ?],
  0,
  Bytes.empty())
end

pub fn snapshot_v1(state :: consume RatchetState,
wrapping_key :: borrow StorageKey,
account_id :: Bytes,
device_id :: Bytes,
snapshot_version :: U64) -> SnapshotOutcomeV1 do
  if U64.compare(snapshot_version, state.snapshot_version) <= 0 do
    SnapshotRejectedV1(state, RollbackRejectedV1)
  else
    case seal_snapshot_v1(state, wrapping_key, account_id, device_id, snapshot_version) do
      Err( error) -> SnapshotRejectedV1(state, error)
      Ok( blob) -> SnapshotSealedV1(% { state | snapshot_version : snapshot_version }, blob)
    end
  end
end
