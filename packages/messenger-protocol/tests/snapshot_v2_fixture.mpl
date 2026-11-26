##! Writes a ratchet snapshot exactly as version 2 did, so the tests can prove
##! that today's reader takes every session a device already has. Frozen copy
##! of the writer that version 3 replaced; never change it.

from Session.Handshake import RatchetState

fn append(left :: Bytes, right :: Bytes) -> Bytes!String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("fixture concat failed")
    Ok(value)
  end
end

fn join(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, append(output, List.get(parts, index))?)
  end
end

fn byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("fixture byte failed")
    Ok(encoded)
  end
end

fn write_u16(value :: Int) -> Bytes!String do
  case Bytes.write_u16_be(value) do
    Err(_) -> Err("fixture u16 failed")
    Ok(encoded)
  end
end

fn write_u32(value :: Int) -> Bytes!String do
  case U64.parse(Int.to_string(value)) do
    Err(_) -> Err("fixture u32 failed")
    Ok(wide) -> case Bytes.write_u32_be(wide) do
      Err(_) -> Err("fixture u32 failed")
      Ok(encoded)
    end
  end
end

fn write_u64(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err("fixture u64 failed")
    Ok(encoded)
  end
end

fn vector(value :: Bytes) -> Bytes!String do
  append(write_u32(Bytes.length(value))?, value)
end

fn header(state :: borrow RatchetState, snapshot_version :: U64) -> Bytes!String do
  join([
      byte(2)?,
      Bytes.from_utf8("RST"),
      write_u16(state.suite)?,
      state.session_id,
      write_u64(snapshot_version)?,
      state.local_ratchet_public.bytes,
      state.remote_ratchet_public.bytes,
      write_u32(state.previous_chain_length)?,
      write_u32(state.sent_count)?,
      write_u32(state.received_count)?,
      byte(if state.pending_send_ratchet do
        1
      else
        0
      end)?,
      write_u32(state.receive_generation)?,
      vector(state.skipped_index)?
    ],
    0,
    Bytes.empty())
end

fn context(account_id :: Bytes,
  device_id :: Bytes,
  session_id :: Bytes,
  header_bytes :: Bytes,
  purpose :: Int,
  snapshot_version :: U64) -> Bytes!String do
  let object = Crypto.sha256(join([
      Bytes.from_utf8("mesh-msg/v1/ratchet-snapshot-object"),
      header_bytes,
      write_u16(purpose)?
    ],
    0,
    Bytes.empty())?)
  join([
      byte(1)?,
      account_id,
      device_id,
      session_id,
      object,
      write_u16(purpose)?,
      write_u64(snapshot_version)?
    ],
    0,
    Bytes.empty())
end

fn sealed(result :: Result<Bytes, CryptoError>) -> Bytes!String do
  case result do
    Err(_) -> Err("fixture seal failed")
    Ok(blob)
  end
end

pub fn fixture_snapshot_v2(state :: borrow RatchetState,
  wrapping_key :: borrow StorageKey,
  account_id :: Bytes,
  device_id :: Bytes,
  snapshot_version :: U64) -> Bytes!String do
  let header_bytes = header(state, snapshot_version)?
  let session_id = state.session_id
  let root_key = sealed(Secret.seal_for_storage(state.root_key,
    wrapping_key,
    context(account_id, device_id, session_id, header_bytes, 1, snapshot_version)?))?
  let sending = sealed(Secret.seal_for_storage(state.sending_chain_key,
    wrapping_key,
    context(account_id, device_id, session_id, header_bytes, 2, snapshot_version)?))?
  let receiving = sealed(Secret.seal_for_storage(state.receiving_chain_key,
    wrapping_key,
    context(account_id, device_id, session_id, header_bytes, 3, snapshot_version)?))?
  let private_key = sealed(X25519PrivateKey.seal_for_storage(state.local_ratchet_private,
    wrapping_key,
    context(account_id, device_id, session_id, header_bytes, 13, snapshot_version)?))?
  let skipped = sealed(SecretMap.seal_for_storage(state.skipped_keys,
    wrapping_key,
    context(account_id, device_id, session_id, header_bytes, 12, snapshot_version)?))?
  join([
      header_bytes,
      vector(root_key)?,
      vector(sending)?,
      vector(receiving)?,
      vector(private_key)?,
      vector(skipped)?
    ],
    0,
    Bytes.empty())
end
