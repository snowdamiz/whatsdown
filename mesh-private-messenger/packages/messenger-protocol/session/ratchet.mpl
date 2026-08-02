from Session.Handshake import RatchetState

pub type RatchetError do
  AuthenticationRejected
  CryptoFailure
  ExcessiveJump
  InvalidMessage
  Replay
end

pub struct RatchetMessage do
  version :: Int
  suite :: Int
  session_id :: Bytes
  ratchet_public_key :: X25519PublicKey
  previous_chain_length :: Int
  message_number :: Int
  nonce :: Bytes
  ciphertext :: Bytes
end

pub type DecryptOutcome do
  Opened(state :: RatchetState, plaintext :: Bytes)
  Rejected(state :: RatchetState, error :: RatchetError)
end

fn append(left :: Bytes, right :: Bytes) -> Bytes ! RatchetError do
  case Bytes.concat(left, right) do
    Err(_) -> Err(InvalidMessage)
    Ok(value) -> Ok(value)
  end
end

fn write_u16(value :: Int) -> Bytes ! RatchetError do
  case Bytes.write_u16_be(value) do
    Err(_) -> Err(InvalidMessage)
    Ok(encoded) -> Ok(encoded)
  end
end

fn write_u32(value :: Int) -> Bytes ! RatchetError do
  case U64.parse(Int.to_string(value)) do
    Err(_) -> Err(InvalidMessage)
    Ok(wide) -> case Bytes.write_u32_be(wide) do
        Err(_) -> Err(InvalidMessage)
        Ok(encoded) -> Ok(encoded)
      end
  end
end

fn message_info(ratchet_public_key :: X25519PublicKey,
message_number :: Int) -> Bytes ! RatchetError do
  let value = append(Bytes.from_utf8("mesh-msg/v1/message-key"), ratchet_public_key.bytes) ?
  append(value, write_u32(message_number) ?)
end

fn authenticated_data(session_id :: Bytes,
ratchet_public_key :: X25519PublicKey,
message_number :: Int,
nonce :: Bytes,
caller_data :: Bytes) -> Bytes ! RatchetError do
  let value = append(Bytes.from_utf8("mesh-msg/v1/ratchet-message"), write_u16(1) ?) ?
  let value = append(value, write_u16(1) ?) ?
  let value = append(value, session_id) ?
  let value = append(value, ratchet_public_key.bytes) ?
  let value = append(value, write_u32(message_number) ?) ?
  let value = append(value, nonce) ?
  append(value, caller_data)
end

fn message_key(root_key :: borrow SecretBytes,
session_id :: Bytes,
ratchet_public_key :: X25519PublicKey,
message_number :: Int) -> AeadKey ! RatchetError do
  let info = message_info(ratchet_public_key, message_number) ?
  let material = case Crypto.hkdf_sha256(root_key, session_id, info, 32) do
    Err(_) -> Err(CryptoFailure)
    Ok(value) -> Ok(value)
  end ?
  case Crypto.aead_key(material) do
    Err(_) -> Err(CryptoFailure)
    Ok(value) -> Ok(value)
  end
end

fn reject_key(key :: consume AeadKey,
state :: consume RatchetState,
error :: RatchetError) -> DecryptOutcome do
  Rejected(state, error)
end

fn open_key(key :: consume AeadKey,
state :: consume RatchetState,
plaintext :: Bytes,
next_count :: Int) -> DecryptOutcome do
  let next = %{state | received_count: next_count}
  Opened(next, plaintext)
end

pub fn encrypt(state :: consume RatchetState,
plaintext :: Bytes,
associated_data :: Bytes) -> Result <( RatchetState, RatchetMessage), RatchetError > do
  if state.version != 1 || state.suite != 1 || Bytes.length(plaintext) > 65520 || state.sent_count < 0 do
    Err(InvalidMessage)
  else
    let message_number = state.sent_count
    let next_count = message_number + 1
    let key = message_key(state.root_key,
    state.session_id,
    state.local_ratchet_public,
    message_number) ?
    let nonce = case Crypto.random_bytes(12) do
      Err(_) -> Err(CryptoFailure)
      Ok(value) -> Ok(value)
    end ?
    let authenticated = authenticated_data(state.session_id,
    state.local_ratchet_public,
    message_number,
    nonce,
    associated_data) ?
    let ciphertext = case Crypto.aead_seal(key, nonce, authenticated, plaintext) do
      Err(_) -> Err(CryptoFailure)
      Ok(value) -> Ok(value)
    end ?
    let message = RatchetMessage {
      version: 1,
      suite: 1,
      session_id: state.session_id,
      ratchet_public_key: state.local_ratchet_public,
      previous_chain_length: state.received_count,
      message_number: message_number,
      nonce: nonce,
      ciphertext: ciphertext
    }
    let next = %{state | sent_count: next_count}
    Ok((next, message))
  end
end

pub fn decrypt(state :: consume RatchetState,
message :: RatchetMessage,
associated_data :: Bytes) -> DecryptOutcome do
  let wrong_header = message.version != 1 || message.suite != 1 || !Bytes.secure_equals(message.session_id,
  state.session_id) || !Bytes.secure_equals(message.ratchet_public_key.bytes,
  state.remote_ratchet_public.bytes) || Bytes.length(message.nonce) != 12 || Bytes.length(message.ciphertext) > 65536
  if wrong_header do
    Rejected(state, InvalidMessage)
  else if message.message_number < state.received_count do
    Rejected(state, Replay)
  else if message.message_number - state.received_count > 64 do
    Rejected(state, ExcessiveJump)
  else
    let key = message_key(state.root_key,
    state.session_id,
    message.ratchet_public_key,
    message.message_number)
    case key do
      Err(_) -> Rejected(state, InvalidMessage)
      Ok(value) -> do
        case authenticated_data(state.session_id,
        message.ratchet_public_key,
        message.message_number,
        message.nonce,
        associated_data) do
          Err(_) -> reject_key(value, state, InvalidMessage)
          Ok(data) -> case Crypto.aead_open(value, message.nonce, data, message.ciphertext) do
              Err(_) -> reject_key(value, state, AuthenticationRejected)
              Ok(plaintext) -> do
                let next_count = message.message_number + 1
                open_key(value, state, plaintext, next_count)
              end
            end
        end
      end
    end
  end
end
