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

# A message too far ahead is final, not something to try again. A mailbox hands
# envelopes over in order and a sender never lets one overtake another, so the
# messages in between are never coming. Treating it as temporary would leave it
# unacknowledged at the head of the mailbox, where a few of them, which any
# contact can send, used to be all a device received until they expired.

pub fn is_retryable_ratchet_error(error :: RatchetError) -> Bool do
  case error do
    CryptoFailure -> true
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
  let valid = (value.version == 1 || value.version == 2 || value.version == 3) && valid_suite && Bytes.length(value.session_id) == 32 && Bytes.length(value.ratchet_public_key.bytes) == 32 && value.previous_chain_length >= 0 && value.message_number >= 0 && Bytes.length(value.nonce) == 12 && Bytes.length(value.ciphertext) >= 16 && Bytes.length(value.ciphertext) <= 65536
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

# A key kept for a message that has not come is a key an attacker who held
# that message back could use after taking the device, so none is kept for
# ever. The state lists the keys it keeps, oldest first, with the number of
# receiving chains the session had seen when each was set aside. A key is
# forgotten once its message arrives, once five more chains have begun, or
# when 64 newer ones have pushed it out.

fn slice(value :: Bytes, start :: Int, length :: Int) -> Bytes ! RatchetError do
  case Bytes.slice(value, start, length) do
    Err( _) -> Err(CryptoFailure)
    Ok( part) -> Ok(part)
  end
end

fn read_u32(value :: Bytes, offset :: Int) -> Int ! RatchetError do
  case Bytes.read_u32_be(value, offset) do
    Err( _) -> Err(CryptoFailure)
    Ok( wide) -> case U64.to_int(wide) do
      Err( _) -> Err(CryptoFailure)
      Ok( number) -> Ok(number)
    end
  end
end

fn skipped_records(index :: Bytes,
ratchet_public_key :: X25519PublicKey,
current :: Int,
target :: Int,
generation :: Int) -> Bytes ! RatchetError do
  if current >= target do
    Ok(index)
  else
    let record = append(append(ratchet_public_key.bytes, write_u32(current) ?) ?,
    write_u32(generation) ?) ?
    skipped_records(append(index, record) ?, ratchet_public_key, current + 1, target, generation)
  end
end

# A merge that overfills the secret map drops its oldest keys. The list drops
# the same ones, so the two never disagree.

fn newest_records(index :: Bytes) -> Bytes ! RatchetError do
  let excess = Bytes.length(index) - 2560
  if excess <= 0 do
    Ok(index)
  else
    slice(index, excess, 2560)
  end
end

fn index_after_new_chain(index :: Bytes,
previous_public_key :: X25519PublicKey,
received_count :: Int,
generation :: Int,
message :: RatchetMessage) -> Bytes ! RatchetError do
  let previous = skipped_records(index,
  previous_public_key,
  received_count,
  message.previous_chain_length,
  generation) ?
  newest_records(skipped_records(previous,
  message.ratchet_public_key,
  0,
  message.message_number,
  generation + 1) ?)
end

fn without_record(index :: Bytes,
ratchet_public_key :: X25519PublicKey,
message_number :: Int,
offset :: Int) -> Bytes ! RatchetError do
  if offset + 40 > Bytes.length(index) do
    Ok(index)
  else
    let owner = slice(index, offset, 32) ?
    let number = read_u32(index, offset + 32) ?
    if number == message_number && Bytes.secure_equals(owner, ratchet_public_key.bytes) do
      append(slice(index, 0, offset) ?,
      slice(index, offset + 40, Bytes.length(index) - offset - 40) ?)
    else
      without_record(index, ratchet_public_key, message_number, offset + 40)
    end
  end
end

# The list is in the order the keys were set aside, so the ones that are too
# old are at its head.

fn forget_aged(skipped :: borrow SecretMap, index :: Bytes, generation :: Int) -> Bytes ! RatchetError do
  if Bytes.length(index) < 40 do
    Ok(index)
  else
    let set_aside = read_u32(index, 36) ?
    if set_aside > generation - 5 do
      Ok(index)
    else
      let owner = slice(index, 0, 32) ?
      let key_id = skipped_key_id(X25519PublicKey { bytes : owner }, read_u32(index, 32) ?) ?
      case SecretMap.delete(skipped, key_id) do
        Err( _) -> Err(CryptoFailure)
        Ok( _) -> forget_aged(skipped, slice(index, 40, Bytes.length(index) - 40) ?, generation)
      end
    end
  end
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

# Version 2 pads the plaintext because the packet travels bare. Version 3 is
# carried inside the recipient-sealed transport, which pads the whole packet,
# so padding it twice would only double its size bucket.

fn message_plaintext(plaintext :: Bytes, version :: Int) -> Bytes ! RatchetError do
  if version == 3 do
    Ok(plaintext)
  else
    case pad_message(plaintext, 123) do
      Err( _) -> Err(InvalidMessage)
      Ok( value) -> Ok(value)
    end
  end
end

fn encrypt_active(state :: consume RatchetState,
plaintext :: Bytes,
associated_data :: Bytes,
version :: Int) -> Result <( RatchetState, RatchetMessage), RatchetError > do
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
  let authenticated = authenticated_data(version,
  state.suite,
  state.session_id,
  state.local_ratchet_public,
  state.previous_chain_length,
  message_number,
  nonce,
  associated_data) ?
  let padded = message_plaintext(plaintext, version) ?
  let ciphertext = case Crypto.aead_seal(key, nonce, authenticated, padded) do
    Err( _) -> Err(CryptoFailure)
    Ok( value) -> Ok(value)
  end ?
  let message = RatchetMessage {
    version : version,
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

fn encrypt_rotated(state :: consume RatchetState,
plaintext :: Bytes,
associated_data :: Bytes,
version :: Int) -> Result <( RatchetState, RatchetMessage), RatchetError > do
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
  encrypt_active(rotated, plaintext, associated_data, version)
end

fn encrypt_version(state :: consume RatchetState,
plaintext :: Bytes,
associated_data :: Bytes,
version :: Int,
maximum :: Int) -> Result <( RatchetState, RatchetMessage), RatchetError > do
  if state.version != 1 || !(state.suite == 1 || state.suite == 2) || Bytes.length(plaintext) > maximum || state.sent_count < 0 do
    Err(InvalidMessage)
  else if state.pending_send_ratchet do
    encrypt_rotated(state, plaintext, associated_data, version)
  else
    encrypt_active(state, plaintext, associated_data, version)
  end
end

## Version 2: padded, for a packet that travels bare. Retained so queued and
## not-yet-upgraded peers interoperate; new sends use `encrypt_sealed`.

pub fn encrypt(state :: consume RatchetState, plaintext :: Bytes, associated_data :: Bytes) -> Result <( RatchetState, RatchetMessage), RatchetError > do
  encrypt_version(state, plaintext, associated_data, 2, 65409)
end

## Version 3: unpadded, valid only inside the recipient-sealed transport. The
## limit keeps the complete `M8P` packet within that transport's 65,480 bytes.

pub fn encrypt_sealed(state :: consume RatchetState, plaintext :: Bytes, associated_data :: Bytes) -> Result <( RatchetState, RatchetMessage), RatchetError > do
  encrypt_version(state, plaintext, associated_data, 3, 65357)
end

## The version is authenticated, so a sender cannot move a message between
## transports: unpadded version 3 is accepted only sealed, and the bare
## versions are never accepted sealed.

pub fn ratchet_transport_matches(message :: RatchetMessage, sealed :: Bool) -> Bool do
  if sealed do
    message.version == 3
  else
    message.version == 1 || message.version == 2
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
  if message.version == 1 || message.version == 3 do
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
key_id :: Bytes,
message :: RatchetMessage) -> DecryptOutcome do
  case without_record(state.skipped_index, message.ratchet_public_key, message.message_number, 0) do
    Err( error) -> Rejected(state, error)
    Ok( index) -> case SecretMap.delete(state.skipped_keys, key_id) do
      Err( _) -> Rejected(state, CryptoFailure)
      Ok( _) -> Opened(% { state | skipped_index : index }, plaintext)
    end
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
          Ok( plaintext) -> commit_skipped(key, state, plaintext, key_id, message)
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
  case skipped_records(state.skipped_index,
  state.remote_ratchet_public,
  state.received_count,
  message_number,
  state.receive_generation) do
    Err( error) -> reject_current_candidate(key, candidate, next_chain, state, error)
    Ok( listed) -> case newest_records(listed) do
      Err( error) -> reject_current_candidate(key, candidate, next_chain, state, error)
      Ok( index) -> case SecretMap.merge(state.skipped_keys, candidate) do
        Err( _) -> reject_chain_key(key, next_chain, state, CryptoFailure)
        Ok( _) -> do
          let next = % { state | receiving_chain_key : next_chain, received_count : message_number + 1, skipped_index : index }
          Opened(next, plaintext)
        end
      end
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
  let generation = state.receive_generation + 1
  case index_after_new_chain(state.skipped_index,
  state.remote_ratchet_public,
  state.received_count,
  state.receive_generation,
  message) do
    Err( error) -> reject_new_candidate(key, candidate, root_key, next_chain, state, error)
    Ok( listed) -> case SecretMap.merge(state.skipped_keys, candidate) do
      Err( _) -> reject_new_key_material(key, root_key, next_chain, state, CryptoFailure)
      Ok( _) -> case forget_aged(state.skipped_keys, listed, generation) do
        Err( error) -> reject_new_key_material(key, root_key, next_chain, state, error)
        Ok( index) -> do
          let next = % { state | root_key : root_key, receiving_chain_key : next_chain, remote_ratchet_public : message.ratchet_public_key, received_count : message.message_number + 1, skipped_index : index, receive_generation : generation, pending_send_ratchet : true }
          Opened(next, plaintext)
        end
      end
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
  # Both gaps are set aside together, and together they must fit what a
  # session keeps. More is a jump, not a fault to try again.
  let old_gap = message.previous_chain_length - state.received_count
  let too_far = old_gap > 64 || message.message_number > 64 || (old_gap > 0 && old_gap + message.message_number > 64)
  if too_far do
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
  let wrong_header = !(message.version == 1 || message.version == 2 || message.version == 3) || !(state.suite == 1 || state.suite == 2) || message.suite != state.suite || !Bytes.secure_equals(message.session_id,
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
