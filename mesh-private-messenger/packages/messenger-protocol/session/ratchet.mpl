from Transport.Padding import pad_message, unpad_message
from Binary.Reader import BinaryReader, finish, read_fixed, read_u16_be, read_u8, read_vector, reader
from Session.Handshake import RatchetState

pub type RatchetError do
  AuthenticationRejected

  CryptoFailure

  ExcessiveJump

  InvalidMessage

  Replay
end

pub fn is_retryable_ratchet_error(error :: RatchetError) -> Bool do
  case error do
    CryptoFailure -> true
    ExcessiveJump -> true
    _ -> false
  end
end

pub fn skipped_key_error(error :: CryptoError) -> RatchetError do
  case error do
    InvalidKey -> Replay
    _ -> CryptoFailure
  end
end

pub fn ratchet_open_error(error :: CryptoError) -> RatchetError do
  case error do
    AuthenticationFailed -> AuthenticationRejected
    _ -> CryptoFailure
  end
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

struct ReadInt do
  state :: BinaryReader
  value :: Int
end

struct ReadBytes do
  state :: BinaryReader
  value :: Bytes
end

pub type DecryptOutcome do
  Opened( state :: RatchetState, plaintext :: Bytes)

  Rejected( state :: RatchetState, error :: RatchetError)
end

fn append(left :: Bytes, right :: Bytes) -> Bytes ! RatchetError do
  case Bytes.concat(left, right) do
    Err( _) -> Err(InvalidMessage)
    Ok( value) -> Ok(value)
  end
end

fn write_u16(value :: Int) -> Bytes ! RatchetError do
  case Bytes.write_u16_be(value) do
    Err( _) -> Err(InvalidMessage)
    Ok( encoded) -> Ok(encoded)
  end
end

fn write_u32(value :: Int) -> Bytes ! RatchetError do
  case U64.parse(Int.to_string(value)) do
    Err( _) -> Err(InvalidMessage)
    Ok( wide) -> case Bytes.write_u32_be(wide) do
      Err( _) -> Err(InvalidMessage)
      Ok( encoded) -> Ok(encoded)
    end
  end
end

fn byte(value :: Int) -> Bytes ! RatchetError do
  case Bytes.from_list([value]) do
    Err( _) -> Err(InvalidMessage)
    Ok( encoded) -> Ok(encoded)
  end
end

fn vector(value :: Bytes) -> Bytes ! RatchetError do
  append(write_u32(Bytes.length(value)) ?, value)
end

fn open(input :: Bytes) -> BinaryReader ! RatchetError do
  if Bytes.length(input) > 65630 do
    Err(InvalidMessage)
  else
    case reader(input, 65630) do
      Err( _) -> Err(InvalidMessage)
      Ok( state) -> Ok(state)
    end
  end
end

fn take_u8(state :: BinaryReader) -> ReadInt ! RatchetError do
  case read_u8(state) do
    Err( _) -> Err(InvalidMessage)
    Ok( ( next, value)) -> Ok(ReadInt {
      state : next,
      value : value
    })
    Ok( _) -> Err(InvalidMessage)
  end
end

fn take_u16(state :: BinaryReader) -> ReadInt ! RatchetError do
  case read_u16_be(state) do
    Err( _) -> Err(InvalidMessage)
    Ok( ( next, value)) -> Ok(ReadInt {
      state : next,
      value : value
    })
    Ok( _) -> Err(InvalidMessage)
  end
end

fn take_fixed(state :: BinaryReader, length :: Int) -> ReadBytes ! RatchetError do
  case read_fixed(state, length) do
    Err( _) -> Err(InvalidMessage)
    Ok( ( next, value)) -> Ok(ReadBytes {
      state : next,
      value : value
    })
    Ok( _) -> Err(InvalidMessage)
  end
end

fn take_u32(state :: BinaryReader) -> ReadInt ! RatchetError do
  let bytes = take_fixed(state, 4) ?
  case Bytes.read_u32_be(bytes.value, 0) do
    Err( _) -> Err(InvalidMessage)
    Ok( value) -> case U64.to_int(value) do
      Err( _) -> Err(InvalidMessage)
      Ok( number) -> Ok(ReadInt {
        state : bytes.state,
        value : number
      })
    end
  end
end

fn take_vector(state :: BinaryReader, maximum :: Int) -> ReadBytes ! RatchetError do
  case read_vector(state, maximum) do
    Err( _) -> Err(InvalidMessage)
    Ok( ( next, value)) -> Ok(ReadBytes {
      state : next,
      value : value
    })
    Ok( _) -> Err(InvalidMessage)
  end
end

fn require_end(state :: BinaryReader) -> Result <(), RatchetError > do
  case finish(state) do
    Err( _) -> Err(InvalidMessage)
    Ok( _) -> Ok(nil)
  end
end

fn validate_message(value :: RatchetMessage) -> Result <(), RatchetError > do
  let valid_suite = value.suite == 1 || value.suite == 2
  let valid = (value.version == 1 || value.version == 2) && valid_suite && Bytes.length(value.session_id) == 32 && Bytes.length(value.ratchet_public_key.bytes) == 32 && value.previous_chain_length >= 0 && value.message_number >= 0 && Bytes.length(value.nonce) == 12 && Bytes.length(value.ciphertext) >= 16 && Bytes.length(value.ciphertext) <= 65536
  if valid do
    Ok(nil)
  else
    Err(InvalidMessage)
  end
end

pub fn encode_ratchet_message(value :: RatchetMessage) -> Bytes ! RatchetError do
  validate_message(value) ?
  let output = append(byte(value.version) ?, Bytes.from_utf8("RAT")) ?
  let output = append(output, write_u16(value.suite) ?) ?
  let output = append(output, value.session_id) ?
  let output = append(output, value.ratchet_public_key.bytes) ?
  let output = append(output, write_u32(value.previous_chain_length) ?) ?
  let output = append(output, write_u32(value.message_number) ?) ?
  let output = append(output, value.nonce) ?
  append(output, vector(value.ciphertext) ?)
end

pub fn decode_ratchet_message(input :: Bytes) -> RatchetMessage ! RatchetError do
  let version = take_u8(open(input) ?) ?
  let magic = take_fixed(version.state, 3) ?
  let suite = take_u16(magic.state) ?
  let session_id = take_fixed(suite.state, 32) ?
  let ratchet_public_key = take_fixed(session_id.state, 32) ?
  let previous_chain_length = take_u32(ratchet_public_key.state) ?
  let message_number = take_u32(previous_chain_length.state) ?
  let nonce = take_fixed(message_number.state, 12) ?
  let ciphertext = take_vector(nonce.state, 65536) ?
  require_end(ciphertext.state) ?
  let value = RatchetMessage {
    version : version.value,
    suite : suite.value,
    session_id : session_id.value,
    ratchet_public_key : X25519PublicKey { bytes : ratchet_public_key.value },
    previous_chain_length : previous_chain_length.value,
    message_number : message_number.value,
    nonce : nonce.value,
    ciphertext : ciphertext.value
  }
  if !Bytes.secure_equals(magic.value, Bytes.from_utf8("RAT")) do
    Err(InvalidMessage)
  else
    validate_message(value) ?
    Ok(value)
  end
end

fn keyed_info(label :: String, ratchet_public_key :: X25519PublicKey, message_number :: Int) -> Bytes ! RatchetError do
  let value = append(Bytes.from_utf8(label), ratchet_public_key.bytes) ?
  append(value, write_u32(message_number) ?)
end

fn skipped_key_id(ratchet_public_key :: X25519PublicKey, message_number :: Int) -> Bytes ! RatchetError do
  keyed_info("mesh-msg/v1/skipped-key", ratchet_public_key, message_number)
end

fn authenticated_data(version :: Int,
suite :: Int,
session_id :: Bytes,
ratchet_public_key :: X25519PublicKey,
previous_chain_length :: Int,
message_number :: Int,
nonce :: Bytes,
caller_data :: Bytes) -> Bytes ! RatchetError do
  let value = append(Bytes.from_utf8("mesh-msg/v1/ratchet-message"), write_u16(version) ?) ?
  let value = append(value, write_u16(suite) ?) ?
  let value = append(value, session_id) ?
  let value = append(value, ratchet_public_key.bytes) ?
  let value = append(value, write_u32(previous_chain_length) ?) ?
  let value = append(value, write_u32(message_number) ?) ?
  let value = append(value, nonce) ?
  append(value, caller_data)
end

fn derived_secret(input :: borrow SecretBytes, salt :: Bytes, info :: Bytes) -> SecretBytes ! RatchetError do
  case Crypto.hkdf_sha256(input, salt, info, 32) do
    Err( _) -> Err(CryptoFailure)
    Ok( value) -> Ok(value)
  end
end

fn chain_step(chain_key :: borrow SecretBytes,
session_id :: Bytes,
ratchet_public_key :: X25519PublicKey,
message_number :: Int) -> Result <( SecretBytes, SecretBytes), RatchetError > do
  let next_info = keyed_info("mesh-msg/v1/chain-next", ratchet_public_key, message_number) ?
  let message_info = keyed_info("mesh-msg/v1/message-key", ratchet_public_key, message_number) ?
  let next_chain = derived_secret(chain_key, session_id, next_info) ?
  let message_key = derived_secret(chain_key, session_id, message_info) ?
  Ok((next_chain, message_key))
end

fn ratchet_root(root_key :: borrow SecretBytes,
dh :: SecretBytes,
session_id :: Bytes,
ratchet_public_key :: X25519PublicKey) -> Result <( SecretBytes, SecretBytes), RatchetError > do
  let mix_info = append(Bytes.from_utf8("mesh-msg/v1/root-mix"), ratchet_public_key.bytes) ?
  let old_material = derived_secret(root_key, session_id, mix_info) ?
  let combined = case Secret.concat(old_material, dh) do
    Err( _) -> Err(CryptoFailure)
    Ok( value) -> Ok(value)
  end ?
  let root_info = append(Bytes.from_utf8("mesh-msg/v1/ratchet-root"), ratchet_public_key.bytes) ?
  let chain_info = append(Bytes.from_utf8("mesh-msg/v1/ratchet-chain"), ratchet_public_key.bytes) ?
  let next_root = derived_secret(combined, session_id, root_info) ?
  let next_chain = derived_secret(combined, session_id, chain_info) ?
  Secret.destroy(combined)
  Ok((next_root, next_chain))
end

fn aead_key(material :: SecretBytes) -> AeadKey ! RatchetError do
  case Crypto.aead_key(material) do
    Err( _) -> Err(CryptoFailure)
    Ok( value) -> Ok(value)
  end
end

fn candidate_keys(chain_key :: borrow SecretBytes,
skipped :: borrow SecretMap,
session_id :: Bytes,
ratchet_public_key :: X25519PublicKey,
current :: Int,
target :: Int) -> Result <( SecretBytes, SecretBytes), RatchetError > do
  let ( next_chain, message_key) = chain_step(chain_key, session_id, ratchet_public_key, current) ?
  if current == target do
    Ok((next_chain, message_key))
  else
    let key_id = skipped_key_id(ratchet_public_key, current) ?
    case SecretMap.insert(skipped, key_id, message_key) do
      Err( _) -> Err(CryptoFailure)
      Ok( _) -> do
        let result = candidate_keys(next_chain,
        skipped,
        session_id,
        ratchet_public_key,
        current + 1,
        target)
        Secret.destroy(next_chain)
        result
      end
    end
  end
end

fn skip_until(chain_key :: borrow SecretBytes,
skipped :: borrow SecretMap,
session_id :: Bytes,
ratchet_public_key :: X25519PublicKey,
current :: Int,
target :: Int) -> Int ! RatchetError do
  if current >= target do
    Ok(0)
  else
    let ( next_chain, message_key) = chain_step(chain_key, session_id, ratchet_public_key, current) ?
    let key_id = skipped_key_id(ratchet_public_key, current) ?
    case SecretMap.insert(skipped, key_id, message_key) do
      Err( _) -> Err(CryptoFailure)
      Ok( _) -> do
        let result = skip_until(next_chain,
        skipped,
        session_id,
        ratchet_public_key,
        current + 1,
        target)
        Secret.destroy(next_chain)
        result
      end
    end
  end
end

fn encrypt_active(state :: consume RatchetState, plaintext :: Bytes, associated_data :: Bytes) -> Result <( RatchetState, RatchetMessage), RatchetError > do
  let message_number = state.sent_count
  let ( next_chain, material) = chain_step(state.sending_chain_key,
  state.session_id,
  state.local_ratchet_public,
  message_number) ?
  let key = aead_key(material) ?
  let nonce = case Crypto.random_bytes(12) do
    Err( _) -> Err(CryptoFailure)
    Ok( value) -> Ok(value)
  end ?
  let authenticated = authenticated_data(2,
  state.suite,
  state.session_id,
  state.local_ratchet_public,
  state.previous_chain_length,
  message_number,
  nonce,
  associated_data) ?
  let padded = case pad_message(plaintext, 123) do
    Err( _) -> Err(InvalidMessage)
    Ok( value) -> Ok(value)
  end ?
  let ciphertext = case Crypto.aead_seal(key, nonce, authenticated, padded) do
    Err( _) -> Err(CryptoFailure)
    Ok( value) -> Ok(value)
  end ?
  let message = RatchetMessage {
    version : 2,
    suite : state.suite,
    session_id : state.session_id,
    ratchet_public_key : state.local_ratchet_public,
    previous_chain_length : state.previous_chain_length,
    message_number : message_number,
    nonce : nonce,
    ciphertext : ciphertext
  }
  let next = % { state | sending_chain_key : next_chain, sent_count : message_number + 1 }
  Ok((next, message))
end

fn encrypt_rotated(state :: consume RatchetState, plaintext :: Bytes, associated_data :: Bytes) -> Result <( RatchetState, RatchetMessage), RatchetError > do
  let ratchet = case Crypto.x25519_generate() do
    Err( _) -> Err(CryptoFailure)
    Ok( value) -> Ok(value)
  end ?
  let public_key = ratchet.public_key
  let private_key = ratchet.private_key
  let dh = case Crypto.x25519_shared(private_key, state.remote_ratchet_public) do
    Err( _) -> Err(CryptoFailure)
    Ok( value) -> Ok(value)
  end ?
  let ( root_key, sending_chain_key) = ratchet_root(state.root_key,
  dh,
  state.session_id,
  public_key) ?
  let previous_chain_length = state.sent_count
  let rotated = % { state | root_key : root_key, sending_chain_key : sending_chain_key, local_ratchet_private : private_key, local_ratchet_public : public_key, previous_chain_length : previous_chain_length, sent_count : 0, pending_send_ratchet : false }
  encrypt_active(rotated, plaintext, associated_data)
end

pub fn encrypt(state :: consume RatchetState, plaintext :: Bytes, associated_data :: Bytes) -> Result <( RatchetState, RatchetMessage), RatchetError > do
  if state.version != 1 || !(state.suite == 1 || state.suite == 2) || Bytes.length(plaintext) > 65409 || state.sent_count < 0 do
    Err(InvalidMessage)
  else if state.pending_send_ratchet do
    encrypt_rotated(state, plaintext, associated_data)
  else
    encrypt_active(state, plaintext, associated_data)
  end
end

fn reject_key(key :: consume AeadKey, state :: consume RatchetState, error :: RatchetError) -> DecryptOutcome do
  Rejected(state, error)
end

fn reject_map(candidate :: consume SecretMap, state :: consume RatchetState, error :: RatchetError) -> DecryptOutcome do
  Rejected(state, error)
end

fn reject_map_chain(candidate :: consume SecretMap,
next_chain :: consume SecretBytes,
state :: consume RatchetState,
error :: RatchetError) -> DecryptOutcome do
  Rejected(state, error)
end

fn reject_current_candidate(key :: consume AeadKey,
candidate :: consume SecretMap,
next_chain :: consume SecretBytes,
state :: consume RatchetState,
error :: RatchetError) -> DecryptOutcome do
  Rejected(state, error)
end

fn reject_chain_key(key :: consume AeadKey,
next_chain :: consume SecretBytes,
state :: consume RatchetState,
error :: RatchetError) -> DecryptOutcome do
  Rejected(state, error)
end

fn reject_new_material(candidate :: consume SecretMap,
root_key :: consume SecretBytes,
next_chain :: consume SecretBytes,
state :: consume RatchetState,
error :: RatchetError) -> DecryptOutcome do
  Rejected(state, error)
end

fn reject_new_candidate(key :: consume AeadKey,
candidate :: consume SecretMap,
root_key :: consume SecretBytes,
next_chain :: consume SecretBytes,
state :: consume RatchetState,
error :: RatchetError) -> DecryptOutcome do
  Rejected(state, error)
end

fn reject_new_key_material(key :: consume AeadKey,
root_key :: consume SecretBytes,
next_chain :: consume SecretBytes,
state :: consume RatchetState,
error :: RatchetError) -> DecryptOutcome do
  Rejected(state, error)
end

fn open_message(key :: borrow AeadKey, message :: RatchetMessage, data :: Bytes) -> Bytes ! RatchetError do
  let plaintext = case Crypto.aead_open(key, message.nonce, data, message.ciphertext) do
    Err( error) -> Err(ratchet_open_error(error))
    Ok( value) -> Ok(value)
  end ?
  if message.version == 1 do
    Ok(plaintext)
  else
    case unpad_message(plaintext, 123) do
      Err( _) -> Err(InvalidMessage)
      Ok( value) -> Ok(value)
    end
  end
end

fn commit_skipped(key :: consume AeadKey,
state :: consume RatchetState,
plaintext :: Bytes,
key_id :: Bytes) -> DecryptOutcome do
  case SecretMap.delete(state.skipped_keys, key_id) do
    Err( _) -> Rejected(state, CryptoFailure)
    Ok( _) -> Opened(state, plaintext)
  end
end

fn decrypt_skipped(state :: consume RatchetState,
message :: RatchetMessage,
associated_data :: Bytes,
key_id :: Bytes) -> DecryptOutcome do
  case SecretMap.copy(state.skipped_keys, key_id) do
    Err( error) -> Rejected(state, skipped_key_error(error))
    Ok( material) -> case aead_key(material) do
      Err( error) -> Rejected(state, error)
      Ok( key) -> case authenticated_data(message.version,
      state.suite,
      state.session_id,
      message.ratchet_public_key,
      message.previous_chain_length,
      message.message_number,
      message.nonce,
      associated_data) do
        Err( error) -> reject_key(key, state, error)
        Ok( data) -> case open_message(key, message, data) do
          Err( error) -> reject_key(key, state, error)
          Ok( plaintext) -> commit_skipped(key, state, plaintext, key_id)
        end
      end
    end
  end
end

fn commit_current(key :: consume AeadKey,
state :: consume RatchetState,
candidate :: consume SecretMap,
next_chain :: consume SecretBytes,
plaintext :: Bytes,
message_number :: Int) -> DecryptOutcome do
  case SecretMap.merge(state.skipped_keys, candidate) do
    Err( _) -> reject_chain_key(key, next_chain, state, CryptoFailure)
    Ok( _) -> do
      let next = % { state | receiving_chain_key : next_chain, received_count : message_number + 1 }
      Opened(next, plaintext)
    end
  end
end

fn open_current_candidate(key :: consume AeadKey,
state :: consume RatchetState,
candidate :: consume SecretMap,
next_chain :: consume SecretBytes,
message :: RatchetMessage,
associated_data :: Bytes) -> DecryptOutcome do
  case authenticated_data(message.version,
  state.suite,
  state.session_id,
  message.ratchet_public_key,
  message.previous_chain_length,
  message.message_number,
  message.nonce,
  associated_data) do
    Err( error) -> reject_current_candidate(key, candidate, next_chain, state, error)
    Ok( data) -> case open_message(key, message, data) do
      Err( error) -> reject_current_candidate(key, candidate, next_chain, state, error)
      Ok( plaintext) -> commit_current(key,
      state,
      candidate,
      next_chain,
      plaintext,
      message.message_number)
    end
  end
end

fn decrypt_current(state :: consume RatchetState,
message :: RatchetMessage,
associated_data :: Bytes) -> DecryptOutcome do
  case SecretMap.new(64) do
    Err( _) -> Rejected(state, CryptoFailure)
    Ok( candidate) -> case candidate_keys(state.receiving_chain_key,
    candidate,
    state.session_id,
    message.ratchet_public_key,
    state.received_count,
    message.message_number) do
      Err( error) -> reject_map(candidate, state, error)
      Ok( value) -> do
        let ( next_chain, material) = value
        case aead_key(material) do
          Err( error) -> reject_map_chain(candidate, next_chain, state, error)
          Ok( key) -> open_current_candidate(key,
          state,
          candidate,
          next_chain,
          message,
          associated_data)
        end
      end
    end
  end
end

fn commit_new_chain(key :: consume AeadKey,
state :: consume RatchetState,
candidate :: consume SecretMap,
root_key :: consume SecretBytes,
next_chain :: consume SecretBytes,
plaintext :: Bytes,
message :: RatchetMessage) -> DecryptOutcome do
  case SecretMap.merge(state.skipped_keys, candidate) do
    Err( _) -> reject_new_key_material(key, root_key, next_chain, state, CryptoFailure)
    Ok( _) -> do
      let next = % { state | root_key : root_key, receiving_chain_key : next_chain, remote_ratchet_public : message.ratchet_public_key, received_count : message.message_number + 1, pending_send_ratchet : true }
      Opened(next, plaintext)
    end
  end
end

fn open_new_candidate(key :: consume AeadKey,
state :: consume RatchetState,
candidate :: consume SecretMap,
root_key :: consume SecretBytes,
next_chain :: consume SecretBytes,
message :: RatchetMessage,
associated_data :: Bytes) -> DecryptOutcome do
  case authenticated_data(message.version,
  state.suite,
  state.session_id,
  message.ratchet_public_key,
  message.previous_chain_length,
  message.message_number,
  message.nonce,
  associated_data) do
    Err( error) -> reject_new_candidate(key, candidate, root_key, next_chain, state, error)
    Ok( data) -> case open_message(key, message, data) do
      Err( error) -> reject_new_candidate(key, candidate, root_key, next_chain, state, error)
      Ok( plaintext) -> commit_new_chain(key,
      state,
      candidate,
      root_key,
      next_chain,
      plaintext,
      message)
    end
  end
end

fn open_new_chain(state :: consume RatchetState,
candidate :: consume SecretMap,
root_key :: consume SecretBytes,
receiving_chain_key :: consume SecretBytes,
message :: RatchetMessage,
associated_data :: Bytes) -> DecryptOutcome do
  case candidate_keys(receiving_chain_key,
  candidate,
  state.session_id,
  message.ratchet_public_key,
  0,
  message.message_number) do
    Err( error) -> reject_new_material(candidate, root_key, receiving_chain_key, state, error)
    Ok( key_value) -> do
      let ( next_chain, material) = key_value
      Secret.destroy(receiving_chain_key)
      case aead_key(material) do
        Err( error) -> reject_new_material(candidate, root_key, next_chain, state, error)
        Ok( key) -> open_new_candidate(key,
        state,
        candidate,
        root_key,
        next_chain,
        message,
        associated_data)
      end
    end
  end
end

fn derive_new_chain(state :: consume RatchetState,
candidate :: consume SecretMap,
message :: RatchetMessage,
associated_data :: Bytes) -> DecryptOutcome do
  case Crypto.x25519_shared(state.local_ratchet_private, message.ratchet_public_key) do
    Err( InvalidPublicKey) -> reject_map(candidate, state, InvalidMessage)
    Err( _) -> reject_map(candidate, state, CryptoFailure)
    Ok( dh) -> case ratchet_root(state.root_key, dh, state.session_id, message.ratchet_public_key) do
      Err( error) -> reject_map(candidate, state, error)
      Ok( root_value) -> do
        let ( root_key, receiving_chain_key) = root_value
        open_new_chain(state, candidate, root_key, receiving_chain_key, message, associated_data)
      end
    end
  end
end

fn decrypt_new_chain(state :: consume RatchetState,
message :: RatchetMessage,
associated_data :: Bytes) -> DecryptOutcome do
  let old_gap = message.previous_chain_length - state.received_count
  if old_gap > 64 || message.message_number > 64 do
    Rejected(state, ExcessiveJump)
  else
    case SecretMap.new(64) do
      Err( _) -> Rejected(state, CryptoFailure)
      Ok( candidate) -> case skip_until(state.receiving_chain_key,
      candidate,
      state.session_id,
      state.remote_ratchet_public,
      state.received_count,
      message.previous_chain_length) do
        Err( error) -> reject_map(candidate, state, error)
        Ok( _) -> derive_new_chain(state, candidate, message, associated_data)
      end
    end
  end
end

pub fn decrypt(state :: consume RatchetState, message :: RatchetMessage, associated_data :: Bytes) -> DecryptOutcome do
  let wrong_header = !(message.version == 1 || message.version == 2) || !(state.suite == 1 || state.suite == 2) || message.suite != state.suite || !Bytes.secure_equals(message.session_id,
  state.session_id) || Bytes.length(message.ratchet_public_key.bytes) != 32 || message.previous_chain_length < 0 || message.message_number < 0 || Bytes.length(message.nonce) != 12 || Bytes.length(message.ciphertext) > 65536
  if wrong_header do
    Rejected(state, InvalidMessage)
  else
    case skipped_key_id(message.ratchet_public_key, message.message_number) do
      Err( error) -> Rejected(state, error)
      Ok( key_id) -> if SecretMap.contains(state.skipped_keys, key_id) do
        decrypt_skipped(state, message, associated_data, key_id)
      else
        let same_chain = Bytes.secure_equals(message.ratchet_public_key.bytes,
        state.remote_ratchet_public.bytes)
        if same_chain && message.message_number < state.received_count do
          Rejected(state, Replay)
        else if same_chain && message.message_number - state.received_count > 64 do
          Rejected(state, ExcessiveJump)
        else if same_chain do
          decrypt_current(state, message, associated_data)
        else if state.pending_send_ratchet do
          Rejected(state, InvalidMessage)
        else
          decrypt_new_chain(state, message, associated_data)
        end
      end
    end
  end
end
