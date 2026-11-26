from Transport.Padding import pad_message, unpad_message
from Binary.Reader import (
  BinaryReader,
  finish,
  read_fixed,
  read_u16_be,
  read_u8,
  read_vector,
  reader
)
from Protocol.V1 import ProtocolError
from Session.Handshake import RatchetState
from Session.Header import (
  RatchetHeader,
  ratchet_feature_header_encryption,
  ratchet_feature_post_quantum,
  ratchet_feature_union,
  ratchet_has_feature,
  ratchet_header_decode,
  ratchet_header_encode,
  ratchet_header_open,
  ratchet_header_role,
  ratchet_header_seal,
  ratchet_pq_unit_budget,
  ratchet_root_v2,
  ratchet_upgrade_header_keys,
  ratchet_v4_plaintext_limit
)
from Session.PqRatchet import (
  PqError,
  PqPublic,
  ratchet_pq_apply,
  ratchet_pq_ingest,
  ratchet_pq_outgoing_kind,
  ratchet_pq_public,
  ratchet_pq_receive_step,
  ratchet_pq_send_step,
  ratchet_pq_take
)

pub type RatchetError do
  AuthenticationRejected
  CryptoFailure
  ExcessiveJump
  InvalidMessage
  Replay
end

impl From<CryptoError> for RatchetError do
  fn from(error :: CryptoError) -> RatchetError do
    CryptoFailure
  end
end

impl From<ProtocolError> for RatchetError do
  fn from(error :: ProtocolError) -> RatchetError do
    InvalidMessage
  end
end

impl From<PqError> for RatchetError do
  fn from(error :: PqError) -> RatchetError do
    case error do
      PqInvalid -> InvalidMessage
      PqCrypto -> CryptoFailure
    end
  end
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
  # Version 4 only: the sealed header (`Session.Header`). The fields above it
  # are then empty, and filled only once a session opens the header.
  encrypted_header :: Bytes
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
  Opened(state :: RatchetState, plaintext :: Bytes)
  Rejected(state :: RatchetState, error :: RatchetError)
end

fn append(left :: Bytes, right :: Bytes) -> Bytes!RatchetError do
  case Bytes.concat(left, right) do
    Err(_) -> Err(InvalidMessage)
    Ok(value)
  end
end

fn write_u16(value :: Int) -> Bytes!RatchetError do
  case Bytes.write_u16_be(value) do
    Err(_) -> Err(InvalidMessage)
    Ok(encoded)
  end
end

fn write_u32(value :: Int) -> Bytes!RatchetError do
  case U64.parse(Int.to_string(value)) do
    Err(_) -> Err(InvalidMessage)
    Ok(wide) -> case Bytes.write_u32_be(wide) do
      Err(_) -> Err(InvalidMessage)
      Ok(encoded)
    end
  end
end

fn byte(value :: Int) -> Bytes!RatchetError do
  case Bytes.from_list([value]) do
    Err(_) -> Err(InvalidMessage)
    Ok(encoded)
  end
end

fn vector(value :: Bytes) -> Bytes!RatchetError do
  append(write_u32(Bytes.length(value))?, value)
end

fn open(input :: Bytes) -> BinaryReader!RatchetError do
  if Bytes.length(input) > 65630 do
    Err(InvalidMessage)
  else
    case reader(input, 65630) do
      Err(_) -> Err(InvalidMessage)
      Ok(state)
    end
  end
end

fn take_u8(state :: BinaryReader) -> ReadInt!RatchetError do
  case read_u8(state) do
    Err(_) -> Err(InvalidMessage)
    Ok((next, value)) -> Ok(ReadInt { state: next, value: value })
  end
end

fn take_u16(state :: BinaryReader) -> ReadInt!RatchetError do
  case read_u16_be(state) do
    Err(_) -> Err(InvalidMessage)
    Ok((next, value)) -> Ok(ReadInt { state: next, value: value })
  end
end

fn take_fixed(state :: BinaryReader, length :: Int) -> ReadBytes!RatchetError do
  case read_fixed(state, length) do
    Err(_) -> Err(InvalidMessage)
    Ok((next, value)) -> Ok(ReadBytes { state: next, value: value })
  end
end

fn take_u32(state :: BinaryReader) -> ReadInt!RatchetError do
  let bytes = take_fixed(state, 4)?
  case Bytes.read_u32_be(bytes.value, 0) do
    Err(_) -> Err(InvalidMessage)
    Ok(value) -> case U64.to_int(value) do
      Err(_) -> Err(InvalidMessage)
      Ok(number) -> Ok(ReadInt { state: bytes.state, value: number })
    end
  end
end

fn take_vector(state :: BinaryReader, maximum :: Int) -> ReadBytes!RatchetError do
  case read_vector(state, maximum) do
    Err(_) -> Err(InvalidMessage)
    Ok((next, value)) -> Ok(ReadBytes { state: next, value: value })
  end
end

fn require_end(state :: BinaryReader) -> Result<(), RatchetError> do
  case finish(state) do
    Err(_) -> Err(InvalidMessage)
    Ok(_) -> Ok(nil)
  end
end

fn validate_v4_message(value :: RatchetMessage) -> Result<(), RatchetError> do
  let valid = Bytes.length(value.encrypted_header) >= 113
    && Bytes.length(value.encrypted_header) <= 1297
    && Bytes.length(value.nonce) == 12
    && Bytes.length(value.ciphertext) >= 16
    && Bytes.length(value.ciphertext) <= 65536
  if valid do
    Ok(nil)
  else
    Err(InvalidMessage)
  end
end

fn validate_message(value :: RatchetMessage) -> Result<(), RatchetError> do
  let valid_suite = value.suite == 1 || value.suite == 2
  let valid = (value.version == 1 || value.version == 2 || value.version == 3)
    && Bytes.length(value.encrypted_header) == 0
    && valid_suite
    && Bytes.length(value.session_id) == 32
    && Bytes.length(value.ratchet_public_key.bytes) == 32
    && value.previous_chain_length >= 0
    && value.message_number >= 0
    && Bytes.length(value.nonce) == 12
    && Bytes.length(value.ciphertext) >= 16
    && Bytes.length(value.ciphertext) <= 65536
  if valid do
    Ok(nil)
  else
    Err(InvalidMessage)
  end
end

pub fn encode_ratchet_message(value :: RatchetMessage) -> Bytes!RatchetError do
  if value.version == 4 do
    encode_v4_message(value)
  else
    encode_classic_message(value)
  end
end

fn encode_v4_message(value :: RatchetMessage) -> Bytes!RatchetError do
  validate_v4_message(value)?
  let output = append(byte(4)?, Bytes.from_utf8("RAT"))?
  let output = append(output, vector(value.encrypted_header)?)?
  let output = append(output, value.nonce)?
  append(output, vector(value.ciphertext)?)
end

fn encode_classic_message(value :: RatchetMessage) -> Bytes!RatchetError do
  validate_message(value)?
  let output = append(byte(value.version)?, Bytes.from_utf8("RAT"))?
  let output = append(output, write_u16(value.suite)?)?
  let output = append(output, value.session_id)?
  let output = append(output, value.ratchet_public_key.bytes)?
  let output = append(output, write_u32(value.previous_chain_length)?)?
  let output = append(output, write_u32(value.message_number)?)?
  let output = append(output, value.nonce)?
  append(output, vector(value.ciphertext)?)
end

fn decode_v4_message(state :: BinaryReader) -> RatchetMessage!RatchetError do
  let header = take_vector(state, 1297)?
  let nonce = take_fixed(header.state, 12)?
  let ciphertext = take_vector(nonce.state, 65536)?
  require_end(ciphertext.state)?
  let value = RatchetMessage {
    version: 4,
    suite: 0,
    session_id: Bytes.empty(),
    ratchet_public_key: X25519PublicKey { bytes: Bytes.empty() },
    previous_chain_length: 0,
    message_number: 0,
    nonce: nonce.value,
    ciphertext: ciphertext.value,
    encrypted_header: header.value
  }
  validate_v4_message(value)?
  Ok(value)
end

pub fn decode_ratchet_message(input :: Bytes) -> RatchetMessage!RatchetError do
  let version = take_u8(open(input)?)?
  let magic = take_fixed(version.state, 3)?
  if !Bytes.secure_equals(magic.value, Bytes.from_utf8("RAT")) do
    Err(InvalidMessage)
  else if version.value == 4 do
    decode_v4_message(magic.state)
  else
    decode_classic_message(version.value, magic.state)
  end
end

fn decode_classic_message(version :: Int, state :: BinaryReader) -> RatchetMessage!RatchetError do
  let suite = take_u16(state)?
  let session_id = take_fixed(suite.state, 32)?
  let ratchet_public_key = take_fixed(session_id.state, 32)?
  let previous_chain_length = take_u32(ratchet_public_key.state)?
  let message_number = take_u32(previous_chain_length.state)?
  let nonce = take_fixed(message_number.state, 12)?
  let ciphertext = take_vector(nonce.state, 65536)?
  require_end(ciphertext.state)?
  let value = RatchetMessage {
    version: version,
    suite: suite.value,
    session_id: session_id.value,
    ratchet_public_key: X25519PublicKey { bytes: ratchet_public_key.value },
    previous_chain_length: previous_chain_length.value,
    message_number: message_number.value,
    nonce: nonce.value,
    ciphertext: ciphertext.value,
    encrypted_header: Bytes.empty()
  }
  validate_message(value)?
  Ok(value)
end

fn keyed_info(label :: String,
  ratchet_public_key :: X25519PublicKey,
  message_number :: Int) -> Bytes!RatchetError do
  let value = append(Bytes.from_utf8(label), ratchet_public_key.bytes)?
  append(value, write_u32(message_number)?)
end

fn skipped_key_id(ratchet_public_key :: X25519PublicKey,
  message_number :: Int) -> Bytes!RatchetError do
  keyed_info("mesh-msg/v1/skipped-key", ratchet_public_key, message_number)
end

# A key kept for a message that has not come is a key an attacker who held
# that message back could use after taking the device, so none is kept for
# ever. The state lists the keys it keeps, oldest first, with the number of
# receiving chains the session had seen when each was set aside. A key is
# forgotten once its message arrives, once five more chains have begun, or
# when 64 newer ones have pushed it out.

fn slice(value :: Bytes, start :: Int, length :: Int) -> Bytes!RatchetError do
  case Bytes.slice(value, start, length) do
    Err(_) -> Err(CryptoFailure)
    Ok(part)
  end
end

fn read_u32(value :: Bytes, offset :: Int) -> Int!RatchetError do
  case Bytes.read_u32_be(value, offset) do
    Err(_) -> Err(CryptoFailure)
    Ok(wide) -> case U64.to_int(wide) do
      Err(_) -> Err(CryptoFailure)
      Ok(number)
    end
  end
end

fn skipped_records(index :: Bytes,
  ratchet_public_key :: X25519PublicKey,
  current :: Int,
  target :: Int,
  generation :: Int) -> Bytes!RatchetError do
  if current >= target do
    Ok(index)
  else
    let record = append(append(ratchet_public_key.bytes, write_u32(current)?)?,
      write_u32(generation)?)?
    skipped_records(append(index, record)?, ratchet_public_key, current + 1, target, generation)
  end
end

# A merge that overfills the secret map drops its oldest keys. The list drops
# the same ones, so the two never disagree.

fn newest_records(index :: Bytes) -> Bytes!RatchetError do
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
  message :: RatchetMessage) -> Bytes!RatchetError do
  let previous = skipped_records(index,
    previous_public_key,
    received_count,
    message.previous_chain_length,
    generation)?
  newest_records(skipped_records(previous,
    message.ratchet_public_key,
    0,
    message.message_number,
    generation + 1)?)
end

fn without_record(index :: Bytes,
  ratchet_public_key :: X25519PublicKey,
  message_number :: Int,
  offset :: Int) -> Bytes!RatchetError do
  if offset + 40 > Bytes.length(index) do
    Ok(index)
  else
    let owner = slice(index, offset, 32)?
    let number = read_u32(index, offset + 32)?
    if number == message_number && Bytes.secure_equals(owner, ratchet_public_key.bytes) do
      append(slice(index, 0, offset)?,
        slice(index, offset + 40, Bytes.length(index) - offset - 40)?)
    else
      without_record(index, ratchet_public_key, message_number, offset + 40)
    end
  end
end

# The list is in the order the keys were set aside, so the ones that are too
# old are at its head.

fn forget_aged(skipped :: borrow SecretMap,
  index :: Bytes,
  generation :: Int) -> Bytes!RatchetError do
  if Bytes.length(index) < 40 do
    Ok(index)
  else
    let set_aside = read_u32(index, 36)?
    if set_aside > generation - 5 do
      Ok(index)
    else
      let owner = slice(index, 0, 32)?
      let key_id = skipped_key_id(X25519PublicKey { bytes: owner }, read_u32(index, 32)?)?
      case SecretMap.delete(skipped, key_id) do
        Err(_) -> Err(CryptoFailure)
        Ok(_) -> forget_aged(skipped, slice(index, 40, Bytes.length(index) - 40)?, generation)
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
  caller_data :: Bytes) -> Bytes!RatchetError do
  let value = append(Bytes.from_utf8("mesh-msg/v1/ratchet-message"), write_u16(version)?)?
  let value = append(value, write_u16(suite)?)?
  let value = append(value, session_id)?
  let value = append(value, ratchet_public_key.bytes)?
  let value = append(value, write_u32(previous_chain_length)?)?
  let value = append(value, write_u32(message_number)?)?
  let value = append(value, nonce)?
  append(value, caller_data)
end

fn derived_secret(input :: borrow SecretBytes,
  salt :: Bytes,
  info :: Bytes) -> SecretBytes!RatchetError do
  case Crypto.hkdf_sha256(input, salt, info, 32) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end
end

fn chain_step(chain_key :: borrow SecretBytes,
  session_id :: Bytes,
  ratchet_public_key :: X25519PublicKey,
  message_number :: Int) -> Result<(SecretBytes, SecretBytes), RatchetError> do
  let next_info = keyed_info("mesh-msg/v1/chain-next", ratchet_public_key, message_number)?
  let message_info = keyed_info("mesh-msg/v1/message-key", ratchet_public_key, message_number)?
  let next_chain = derived_secret(chain_key, session_id, next_info)?
  let message_key = derived_secret(chain_key, session_id, message_info)?
  Ok((next_chain, message_key))
end

fn ratchet_root(root_key :: borrow SecretBytes,
  dh :: SecretBytes,
  session_id :: Bytes,
  ratchet_public_key :: X25519PublicKey) -> Result<(SecretBytes, SecretBytes), RatchetError> do
  let mix_info = append(Bytes.from_utf8("mesh-msg/v1/root-mix"), ratchet_public_key.bytes)?
  let old_material = derived_secret(root_key, session_id, mix_info)?
  let combined = case Secret.concat(old_material, dh) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end?
  let root_info = append(Bytes.from_utf8("mesh-msg/v1/ratchet-root"), ratchet_public_key.bytes)?
  let chain_info = append(Bytes.from_utf8("mesh-msg/v1/ratchet-chain"), ratchet_public_key.bytes)?
  let next_root = derived_secret(combined, session_id, root_info)?
  let next_chain = derived_secret(combined, session_id, chain_info)?
  Secret.destroy(combined)
  Ok((next_root, next_chain))
end

fn aead_key(material :: SecretBytes) -> AeadKey!RatchetError do
  case Crypto.aead_key(material) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end
end

fn candidate_keys(chain_key :: borrow SecretBytes,
  skipped :: borrow SecretMap,
  session_id :: Bytes,
  ratchet_public_key :: X25519PublicKey,
  current :: Int,
  target :: Int) -> Result<(SecretBytes, SecretBytes), RatchetError> do
  let (next_chain, message_key) = chain_step(chain_key, session_id, ratchet_public_key, current)?
  if current == target do
    Ok((next_chain, message_key))
  else
    let key_id = skipped_key_id(ratchet_public_key, current)?
    case SecretMap.insert(skipped, key_id, message_key) do
      Err(_) -> Err(CryptoFailure)
      Ok(_) -> do
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
  target :: Int) -> Int!RatchetError do
  if current >= target do
    Ok(0)
  else
    let (next_chain, message_key) = chain_step(chain_key, session_id, ratchet_public_key, current)?
    let key_id = skipped_key_id(ratchet_public_key, current)?
    case SecretMap.insert(skipped, key_id, message_key) do
      Err(_) -> Err(CryptoFailure)
      Ok(_) -> do
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

fn message_plaintext(plaintext :: Bytes, version :: Int) -> Bytes!RatchetError do
  if version == 3 do
    Ok(plaintext)
  else
    case pad_message(plaintext, 123) do
      Err(_) -> Err(InvalidMessage)
      Ok(value)
    end
  end
end

fn encrypt_active(state :: consume RatchetState,
  plaintext :: Bytes,
  associated_data :: Bytes,
  version :: Int) -> Result<(RatchetState, RatchetMessage), RatchetError> do
  let message_number = state.sent_count
  let (next_chain, material) = chain_step(state.sending_chain_key,
    state.session_id,
    state.local_ratchet_public,
    message_number)?
  let key = aead_key(material)?
  let nonce = case Crypto.random_bytes(12) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end?
  let authenticated = authenticated_data(version,
    state.suite,
    state.session_id,
    state.local_ratchet_public,
    state.previous_chain_length,
    message_number,
    nonce,
    associated_data)?
  let padded = message_plaintext(plaintext, version)?
  let ciphertext = case Crypto.aead_seal(key, nonce, authenticated, padded) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end?
  let message = RatchetMessage {
    version: version,
    suite: state.suite,
    session_id: state.session_id,
    ratchet_public_key: state.local_ratchet_public,
    previous_chain_length: state.previous_chain_length,
    message_number: message_number,
    nonce: nonce,
    ciphertext: ciphertext,
    encrypted_header: Bytes.empty()
  }
  let next = %{state | sending_chain_key: next_chain, sent_count: message_number + 1}
  Ok((next, message))
end

fn encrypt_rotated(state :: consume RatchetState,
  plaintext :: Bytes,
  associated_data :: Bytes,
  version :: Int) -> Result<(RatchetState, RatchetMessage), RatchetError> do
  let ratchet = case Crypto.x25519_generate() do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end?
  let public_key = ratchet.public_key
  let private_key = ratchet.private_key
  let dh = case Crypto.x25519_shared(private_key, state.remote_ratchet_public) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end?
  let (root_key, sending_chain_key) = ratchet_root(state.root_key,
    dh,
    state.session_id,
    public_key)?
  let previous_chain_length = state.sent_count
  let rotated = %{state |
    root_key: root_key,
    sending_chain_key: sending_chain_key,
    local_ratchet_private: private_key,
    local_ratchet_public: public_key,
    previous_chain_length: previous_chain_length,
    sent_count: 0,
    pending_send_ratchet: false
  }
  encrypt_active(rotated, plaintext, associated_data, version)
end

fn encrypt_version(state :: consume RatchetState,
  plaintext :: Bytes,
  associated_data :: Bytes,
  version :: Int,
  maximum :: Int) -> Result<(RatchetState, RatchetMessage), RatchetError> do
  let upgrade = version == 3
    && state.pending_send_ratchet
    && ratchet_has_feature(state.peer_features, ratchet_feature_header_encryption())
  if state.version != 1
    || !(state.suite == 1 || state.suite == 2)
    || Bytes.length(plaintext) > maximum
    || state.sent_count < 0 do
    Err(InvalidMessage)
  else if version == 3 && (state.header_encrypted || upgrade) do
    encrypt_v4(state, plaintext, associated_data)
  else if state.header_encrypted do
    # A session that encrypts its headers never sends a bare version again.
    Err(InvalidMessage)
  else if state.pending_send_ratchet do
    encrypt_rotated(state, plaintext, associated_data, version)
  else
    encrypt_active(state, plaintext, associated_data, version)
  end
end

## Version 2: padded, for a packet that travels bare. Retained so queued and
## not-yet-upgraded peers interoperate; new sends use `encrypt_sealed`.

pub fn encrypt(state :: consume RatchetState,
  plaintext :: Bytes,
  associated_data :: Bytes) -> Result<(RatchetState, RatchetMessage), RatchetError> do
  encrypt_version(state, plaintext, associated_data, 2, 65409)
end

## Version 3: unpadded, valid only inside the recipient-sealed transport. The
## limit keeps the complete `M8P` packet within that transport's 65,480 bytes.

pub fn encrypt_sealed(state :: consume RatchetState,
  plaintext :: Bytes,
  associated_data :: Bytes) -> Result<(RatchetState, RatchetMessage), RatchetError> do
  encrypt_version(state, plaintext, associated_data, 3, 65357)
end

## The version is authenticated, so a sender cannot move a message between
## transports: unpadded version 3 is accepted only sealed, and the bare
## versions are never accepted sealed.

pub fn ratchet_transport_matches(message :: RatchetMessage, sealed :: Bool) -> Bool do
  if sealed do
    message.version == 3 || message.version == 4
  else
    message.version == 1 || message.version == 2
  end
end

fn reject_key(key :: consume AeadKey,
  state :: consume RatchetState,
  error :: RatchetError) -> DecryptOutcome do
  Rejected(state, error)
end

fn reject_map(candidate :: consume SecretMap,
  state :: consume RatchetState,
  error :: RatchetError) -> DecryptOutcome do
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

fn open_message(key :: borrow AeadKey,
  message :: RatchetMessage,
  data :: Bytes) -> Bytes!RatchetError do
  let plaintext = case Crypto.aead_open(key, message.nonce, data, message.ciphertext) do
    Err(error) -> Err(ratchet_open_error(error))
    Ok(value)
  end?
  if message.version == 1 || message.version == 3 || message.version == 4 do
    Ok(plaintext)
  else
    case unpad_message(plaintext, 123) do
      Err(_) -> Err(InvalidMessage)
      Ok(value)
    end
  end
end

fn commit_skipped(key :: consume AeadKey,
  state :: consume RatchetState,
  plaintext :: Bytes,
  key_id :: Bytes,
  message :: RatchetMessage) -> DecryptOutcome do
  case without_record(state.skipped_index, message.ratchet_public_key, message.message_number, 0) do
    Err(error) -> Rejected(state, error)
    Ok(index) -> case SecretMap.delete(state.skipped_keys, key_id) do
      Err(_) -> Rejected(state, CryptoFailure)
      Ok(_) -> Opened(%{state | skipped_index: index}, plaintext)
    end
  end
end

fn decrypt_skipped(state :: consume RatchetState,
  message :: RatchetMessage,
  associated_data :: Bytes,
  key_id :: Bytes) -> DecryptOutcome do
  case SecretMap.copy(state.skipped_keys, key_id) do
    Err(error) -> Rejected(state, skipped_key_error(error))
    Ok(material) -> case aead_key(material) do
      Err(error) -> Rejected(state, error)
      Ok(key) -> case authenticated_data(message.version,
        state.suite,
        state.session_id,
        message.ratchet_public_key,
        message.previous_chain_length,
        message.message_number,
        message.nonce,
        associated_data) do
        Err(error) -> reject_key(key, state, error)
        Ok(data) -> case open_message(key, message, data) do
          Err(error) -> reject_key(key, state, error)
          Ok(plaintext) -> commit_skipped(key, state, plaintext, key_id, message)
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
    Err(error) -> reject_current_candidate(key, candidate, next_chain, state, error)
    Ok(listed) -> case newest_records(listed) do
      Err(error) -> reject_current_candidate(key, candidate, next_chain, state, error)
      Ok(index) -> case SecretMap.merge(state.skipped_keys, candidate) do
        Err(_) -> reject_chain_key(key, next_chain, state, CryptoFailure)
        Ok(_) -> do
          let next = %{state |
            receiving_chain_key: next_chain,
            received_count: message_number + 1,
            skipped_index: index
          }
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
    Err(error) -> reject_current_candidate(key, candidate, next_chain, state, error)
    Ok(data) -> case open_message(key, message, data) do
      Err(error) -> reject_current_candidate(key, candidate, next_chain, state, error)
      Ok(plaintext) -> commit_current(key,
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
    Err(_) -> Rejected(state, CryptoFailure)
    Ok(candidate) -> case candidate_keys(state.receiving_chain_key,
      candidate,
      state.session_id,
      message.ratchet_public_key,
      state.received_count,
      message.message_number) do
      Err(error) -> reject_map(candidate, state, error)
      Ok(value) -> do
        let (next_chain, material) = value
        case aead_key(material) do
          Err(error) -> reject_map_chain(candidate, next_chain, state, error)
          Ok(key) -> open_current_candidate(key,
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
    Err(error) -> reject_new_candidate(key, candidate, root_key, next_chain, state, error)
    Ok(listed) -> case SecretMap.merge(state.skipped_keys, candidate) do
      Err(_) -> reject_new_key_material(key, root_key, next_chain, state, CryptoFailure)
      Ok(_) -> case forget_aged(state.skipped_keys, listed, generation) do
        Err(error) -> reject_new_key_material(key, root_key, next_chain, state, error)
        Ok(index) -> do
          let next = %{state |
            root_key: root_key,
            receiving_chain_key: next_chain,
            remote_ratchet_public: message.ratchet_public_key,
            received_count: message.message_number + 1,
            skipped_index: index,
            receive_generation: generation,
            pending_send_ratchet: true
          }
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
    Err(error) -> reject_new_candidate(key, candidate, root_key, next_chain, state, error)
    Ok(data) -> case open_message(key, message, data) do
      Err(error) -> reject_new_candidate(key, candidate, root_key, next_chain, state, error)
      Ok(plaintext) -> commit_new_chain(key,
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
    Err(error) -> reject_new_material(candidate, root_key, receiving_chain_key, state, error)
    Ok(key_value) -> do
      let (next_chain, material) = key_value
      Secret.destroy(receiving_chain_key)
      case aead_key(material) do
        Err(error) -> reject_new_material(candidate, root_key, next_chain, state, error)
        Ok(key) -> open_new_candidate(key,
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
    Err(InvalidPublicKey) -> reject_map(candidate, state, InvalidMessage)
    Err(_) -> reject_map(candidate, state, CryptoFailure)
    Ok(dh) -> case ratchet_root(state.root_key, dh, state.session_id, message.ratchet_public_key) do
      Err(error) -> reject_map(candidate, state, error)
      Ok(root_value) -> do
        let (root_key, receiving_chain_key) = root_value
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
  let too_far = old_gap > 64
    || message.message_number > 64
    || (old_gap > 0 && old_gap + message.message_number > 64)
  if too_far do
    Rejected(state, ExcessiveJump)
  else
    case SecretMap.new(64) do
      Err(_) -> Rejected(state, CryptoFailure)
      Ok(candidate) -> case skip_until(state.receiving_chain_key,
        candidate,
        state.session_id,
        state.remote_ratchet_public,
        state.received_count,
        message.previous_chain_length) do
        Err(error) -> reject_map(candidate, state, error)
        Ok(_) -> derive_new_chain(state, candidate, message, associated_data)
      end
    end
  end
end

pub fn decrypt(state :: consume RatchetState,
  message :: RatchetMessage,
  associated_data :: Bytes) -> DecryptOutcome do
  if message.version == 4 do
    decrypt_v4(state, message, associated_data)
  else
    decrypt_classic(state, message, associated_data)
  end
end

# Once a session encrypts headers, a cleartext header may still arrive for a
# chain that began before (the other side had not seen the upgrade yet), never
# for a new one, and never on a chain that itself began encrypted.

fn decrypt_classic(state :: consume RatchetState,
  message :: RatchetMessage,
  associated_data :: Bytes) -> DecryptOutcome do
  let wrong_header = !(message.version == 1 || message.version == 2 || message.version == 3)
    || !(state.suite == 1 || state.suite == 2)
    || message.suite != state.suite
    || !Bytes.secure_equals(message.session_id, state.session_id)
    || Bytes.length(message.ratchet_public_key.bytes) != 32
    || message.previous_chain_length < 0
    || message.message_number < 0
    || Bytes.length(message.nonce) != 12
    || Bytes.length(message.ciphertext) > 65536
  if wrong_header do
    Rejected(state, InvalidMessage)
  else
    case skipped_key_id(message.ratchet_public_key, message.message_number) do
      Err(error) -> Rejected(state, error)
      Ok(key_id) -> if SecretMap.contains(state.skipped_keys, key_id) do
        decrypt_skipped(state, message, associated_data, key_id)
      else
        let same_chain = Bytes.secure_equals(message.ratchet_public_key.bytes,
          state.remote_ratchet_public.bytes)
        let encrypted_chain = SecretMap.contains(state.header_keys, ratchet_header_role("receive"))
        if same_chain && message.message_number < state.received_count do
          Rejected(state, Replay)
        else if same_chain && encrypted_chain do
          Rejected(state, InvalidMessage)
        else if same_chain && message.message_number - state.received_count > 64 do
          Rejected(state, ExcessiveJump)
        else if same_chain do
          decrypt_current(state, message, associated_data)
        else if state.pending_send_ratchet || state.header_encrypted do
          Rejected(state, InvalidMessage)
        else
          decrypt_new_chain(state, message, associated_data)
        end
      end
    end
  end
end

## Version 4 (`protocol/ratchet-message-v2.md`): the header is sealed under a
## header key from the root chain, and the root chain may take in the sparse
## post-quantum ratchet. A session starts sending it at its next sending root
## step once the peer has said it reads it; the other side finds the first such
## chain under a header key both derive from the root key they share then.

## Records what the peer said it supports, from an authenticated message.

pub fn ratchet_note_peer_features(state :: consume RatchetState, features :: Int) -> RatchetState do
  if features < 0 || features > 255 do
    state
  else
    let known = ratchet_feature_union(state.peer_features, features)
    %{state | peer_features: known}
  end
end

fn v4_authenticated_data(header_blob :: Bytes,
  nonce :: Bytes,
  caller_data :: Bytes) -> Bytes!RatchetError do
  let value = append(Bytes.from_utf8("mesh-msg/v2/ratchet-message"), write_u16(4)?)?
  let value = append(value, vector(header_blob)?)?
  let value = append(value, nonce)?
  append(value, caller_data)
end

fn drop_secret(secret :: SecretBytes) -> Result<(), RatchetError> do
  Err(CryptoFailure)
end

fn put_key(keys :: borrow SecretMap,
  id :: Bytes,
  secret :: SecretBytes) -> Result<(), RatchetError> do
  case SecretMap.delete(keys, id) do
    Err(_) -> drop_secret(secret)
    Ok(_) -> case SecretMap.insert(keys, id, secret) do
      Err(_) -> Err(CryptoFailure)
      Ok(_) -> Ok(nil)
    end
  end
end

fn pq_enabled(state :: borrow RatchetState) -> Bool do
  state.suite == 2 && ratchet_has_feature(state.peer_features, ratchet_feature_post_quantum())
end

fn upgrade_keys(state :: borrow RatchetState,
  keys :: borrow SecretMap) -> Result<(), RatchetError> do
  if state.header_encrypted do
    Ok(nil)
  else
    let (first, second) = ratchet_upgrade_header_keys(state.root_key, state.session_id)?
    put_key(keys, ratchet_header_role("next-send"), first)?
    put_key(keys, ratchet_header_role("next-receive"), second)
  end
end

fn rotation_v4(state :: borrow RatchetState) -> Result<(X25519PrivateKey, X25519PublicKey, SecretBytes, SecretBytes, SecretMap, SecretMap, PqPublic, Int), RatchetError> do
  let ratchet = Crypto.x25519_generate()?
  let public_key = ratchet.public_key
  let private_key = ratchet.private_key
  let dh = Crypto.x25519_shared(private_key, state.remote_ratchet_public)?
  let keys = SecretMap.fork(state.header_keys)?
  upgrade_keys(state, keys)?
  let send_key = SecretMap.copy(keys, ratchet_header_role("next-send"))?
  put_key(keys, ratchet_header_role("send"), send_key)?
  let (shared, pq_secrets, pq_public, mix) = ratchet_pq_send_step(state, dh, pq_enabled(state))?
  let (root_key, chain_key, next_header_key) = ratchet_root_v2(state.root_key,
    shared,
    state.session_id,
    public_key,
    mix)?
  put_key(keys, ratchet_header_role("next-send"), next_header_key)?
  Ok((private_key, public_key, root_key, chain_key, keys, pq_secrets, pq_public, mix))
end

fn reject_rotation(state :: consume RatchetState,
  error :: RatchetError) -> RatchetState!RatchetError do
  Err(error)
end

fn rotate_v4(state :: consume RatchetState) -> RatchetState!RatchetError do
  case rotation_v4(state) do
    Err(error) -> reject_rotation(state, error)
    Ok(values) -> do
      let (private_key, public_key, root_key, chain_key, keys, pq_secrets, pq_public, mix) = values
      let previous_chain_length = state.sent_count
      let rotated = %{state |
        root_key: root_key,
        sending_chain_key: chain_key,
        local_ratchet_private: private_key,
        local_ratchet_public: public_key,
        previous_chain_length: previous_chain_length,
        sent_count: 0,
        pending_send_ratchet: false,
        header_encrypted: true,
        header_keys: keys,
        pq_send_mix: mix
      }
      Ok(ratchet_pq_apply(rotated, pq_secrets, pq_public))
    end
  end
end

fn placeholder_key() -> X25519PublicKey do
  X25519PublicKey { bytes: Bytes.empty() }
end

fn sealed_v4(state :: borrow RatchetState,
  plaintext :: Bytes,
  associated_data :: Bytes) -> Result<(SecretBytes, RatchetMessage, Int), RatchetError> do
  let message_number = state.sent_count
  let (next_chain, material) = chain_step(state.sending_chain_key,
    state.session_id,
    state.local_ratchet_public,
    message_number)?
  let kind = ratchet_pq_outgoing_kind(state)
  let (first, units, cursor) = ratchet_pq_take(state.pq_own,
    state.pq_cursor,
    ratchet_pq_unit_budget(Bytes.length(plaintext)),
    kind)?
  let header = RatchetHeader {
    suite: state.suite,
    session_id: state.session_id,
    ratchet_public_key: state.local_ratchet_public,
    previous_chain_length: state.previous_chain_length,
    message_number: message_number,
    pq_mix: state.pq_send_mix,
    pq_epoch: if kind == 0 do
      0
    else
      state.pq_epoch
    end,
    pq_kind: kind,
    pq_first: first,
    pq_units: units
  }
  let send_key = SecretMap.copy(state.header_keys, ratchet_header_role("send"))?
  let blob = ratchet_header_seal(send_key, ratchet_header_encode(header)?)?
  let nonce = Crypto.random_bytes(12)?
  let data = v4_authenticated_data(blob, nonce, associated_data)?
  let key = aead_key(material)?
  let ciphertext = Crypto.aead_seal(key, nonce, data, plaintext)?
  let message = RatchetMessage {
    version: 4,
    suite: 0,
    session_id: Bytes.empty(),
    ratchet_public_key: placeholder_key(),
    previous_chain_length: 0,
    message_number: 0,
    nonce: nonce,
    ciphertext: ciphertext,
    encrypted_header: blob
  }
  Ok((next_chain, message, cursor))
end

fn reject_send(state :: consume RatchetState,
  error :: RatchetError) -> Result<(RatchetState, RatchetMessage), RatchetError> do
  Err(error)
end

fn encrypt_active_v4(state :: consume RatchetState,
  plaintext :: Bytes,
  associated_data :: Bytes) -> Result<(RatchetState, RatchetMessage), RatchetError> do
  case sealed_v4(state, plaintext, associated_data) do
    Err(error) -> reject_send(state, error)
    Ok(values) -> do
      let (next_chain, message, cursor) = values
      let message_number = state.sent_count
      Ok((%{state |
          sending_chain_key: next_chain,
          sent_count: message_number + 1,
          pq_cursor: cursor
        },
        message))
    end
  end
end

fn encrypt_v4(state :: consume RatchetState,
  plaintext :: Bytes,
  associated_data :: Bytes) -> Result<(RatchetState, RatchetMessage), RatchetError> do
  if Bytes.length(plaintext) > ratchet_v4_plaintext_limit() do
    reject_send(state, InvalidMessage)
  else if state.pending_send_ratchet do
    case rotate_v4(state) do
      Err(error)
      Ok(rotated) -> encrypt_active_v4(rotated, plaintext, associated_data)
    end
  else
    encrypt_active_v4(state, plaintext, associated_data)
  end
end

# Which key opened a header: 1 the current receiving chain's, 2 the next
# chain's, 3 an earlier chain's (`owner`), 4 the upgrade key.

struct HeaderMatch do
  source :: Int
  header :: RatchetHeader
  owner :: Bytes
end

fn opened_header(key :: borrow SecretBytes, message :: RatchetMessage) -> Option<RatchetHeader> do
  case ratchet_header_open(key, message.encrypted_header) do
    Err(_) -> None
    Ok(plain) -> case ratchet_header_decode(plain) do
      Err(_) -> None
      Ok(header) -> Some(header)
    end
  end
end

fn header_under(keys :: borrow SecretMap,
  id :: Bytes,
  message :: RatchetMessage) -> Option<RatchetHeader> do
  if !SecretMap.contains(keys, id) do
    None
  else
    case SecretMap.copy(keys, id) do
      Err(_) -> None
      Ok(key) -> opened_header(key, message)
    end
  end
end

fn matched(source :: Int, header :: RatchetHeader, owner :: Bytes) -> HeaderMatch do
  HeaderMatch { source: source, header: header, owner: owner }
end

fn earlier_header(state :: borrow RatchetState,
  message :: RatchetMessage,
  offset :: Int) -> Option<HeaderMatch> do
  if offset + 32 > Bytes.length(state.header_key_owners) do
    None
  else
    case Bytes.slice(state.header_key_owners, offset, 32) do
      Err(_) -> None
      Ok(owner) -> case header_under(state.header_keys, owner, message) do
        Some(header) -> Some(matched(3, header, owner))
        None -> earlier_header(state, message, offset + 32)
      end
    end
  end
end

fn upgrade_header(state :: borrow RatchetState, message :: RatchetMessage) -> Option<HeaderMatch> do
  if state.header_encrypted do
    None
  else
    case ratchet_upgrade_header_keys(state.root_key, state.session_id) do
      Err(_) -> None
      Ok(keys) -> do
        let (first, second) = keys
        Secret.destroy(second)
        case opened_header(first, message) do
          Some(header) -> Some(matched(4, header, Bytes.empty()))
          None
        end
      end
    end
  end
end

fn found_header(state :: borrow RatchetState, message :: RatchetMessage) -> Option<HeaderMatch> do
  case header_under(state.header_keys, ratchet_header_role("receive"), message) do
    Some(header) -> Some(matched(1, header, Bytes.empty()))
    None -> case header_under(state.header_keys, ratchet_header_role("next-receive"), message) do
      Some(header) -> Some(matched(2, header, Bytes.empty()))
      None -> case earlier_header(state, message, 0) do
        None -> upgrade_header(state, message)
        Some(value)
      end
    end
  end
end

fn classify_header(state :: borrow RatchetState,
  message :: RatchetMessage) -> HeaderMatch!RatchetError do
  case found_header(state, message) do
    None -> Err(InvalidMessage)
    Some(found) -> do
      let key = found.header.ratchet_public_key.bytes
      let wrong_chain = (found.source == 1
        && !Bytes.secure_equals(key, state.remote_ratchet_public.bytes))
        || (found.source == 3 && !Bytes.secure_equals(key, found.owner))
      if found.header.suite != state.suite
        || !Bytes.secure_equals(found.header.session_id, state.session_id)
        || wrong_chain do
        Err(InvalidMessage)
      else
        Ok(found)
      end
    end
  end
end

## Whether this session can open the header of a version 4 message, which is
## how a receiver finds the session: the message names none in the clear.

pub fn ratchet_header_matches(state :: borrow RatchetState, message :: RatchetMessage) -> Bool do
  if message.version != 4 do
    false
  else
    case classify_header(state, message) do
      Err(_) -> false
      Ok(_) -> true
    end
  end
end

fn header_view(message :: RatchetMessage, header :: RatchetHeader) -> RatchetMessage do
  %{message |
    suite: header.suite,
    session_id: header.session_id,
    ratchet_public_key: header.ratchet_public_key,
    previous_chain_length: header.previous_chain_length,
    message_number: header.message_number
  }
end

fn open_v4_body(material :: SecretBytes,
  message :: RatchetMessage,
  associated_data :: Bytes) -> Bytes!RatchetError do
  let key = aead_key(material)?
  let data = v4_authenticated_data(message.encrypted_header, message.nonce, associated_data)?
  case Crypto.aead_open(key, message.nonce, data, message.ciphertext) do
    Err(error) -> Err(ratchet_open_error(error))
    Ok(value)
  end
end

fn owner_indexed(index :: Bytes, owner :: Bytes, offset :: Int) -> Bool do
  if offset + 40 > Bytes.length(index) do
    false
  else
    case Bytes.slice(index, offset, 32) do
      Err(_) -> false
      Ok(value) -> Bytes.secure_equals(value, owner) || owner_indexed(index, owner, offset + 40)
    end
  end
end

# An earlier chain's header key goes with that chain's last skipped key.

fn kept_owners(state :: borrow RatchetState, offset :: Int, kept :: Bytes) -> Bytes do
  if offset + 32 > Bytes.length(state.header_key_owners) do
    kept
  else
    case Bytes.slice(state.header_key_owners, offset, 32) do
      Err(_) -> kept
      Ok(owner) -> if owner_indexed(state.skipped_index, owner, 0) && Bytes.length(kept) < 256 do
        case Bytes.concat(kept, owner) do
          Err(_) -> kept_owners(state, offset + 32, kept)
          Ok(next) -> kept_owners(state, offset + 32, next)
        end
      else
        case SecretMap.delete(state.header_keys, owner) do
          _ -> kept_owners(state, offset + 32, kept)
        end
      end
    end
  end
end

fn pruned_header_keys(state :: consume RatchetState) -> RatchetState do
  let kept = kept_owners(state, 0, Bytes.empty())
  %{state | header_key_owners: kept}
end

fn skipped_opened(state :: borrow RatchetState,
  header :: RatchetHeader,
  message :: RatchetMessage,
  associated_data :: Bytes,
  key_id :: Bytes) -> Result<(Bytes, SecretMap, PqPublic), RatchetError> do
  let material = case SecretMap.copy(state.skipped_keys, key_id) do
    Err(error) -> Err(skipped_key_error(error))
    Ok(value)
  end?
  let plaintext = open_v4_body(material, message, associated_data)?
  let (secrets, public) = ratchet_pq_ingest(ratchet_pq_public(state),
    state.pq_secrets,
    state.suite,
    state.session_id,
    header)?
  Ok((plaintext, secrets, public))
end

fn commit_skipped_v4(state :: consume RatchetState,
  plaintext :: Bytes,
  key_id :: Bytes,
  message :: RatchetMessage) -> DecryptOutcome do
  case without_record(state.skipped_index, message.ratchet_public_key, message.message_number, 0) do
    Err(error) -> Rejected(state, error)
    Ok(index) -> case SecretMap.delete(state.skipped_keys, key_id) do
      Err(_) -> Rejected(state, CryptoFailure)
      Ok(_) -> Opened(pruned_header_keys(%{state | skipped_index: index}), plaintext)
    end
  end
end

fn decrypt_skipped_v4(state :: consume RatchetState,
  header :: RatchetHeader,
  message :: RatchetMessage,
  associated_data :: Bytes,
  key_id :: Bytes) -> DecryptOutcome do
  case skipped_opened(state, header, message, associated_data, key_id) do
    Err(error) -> Rejected(state, error)
    Ok(values) -> do
      let (plaintext, secrets, public) = values
      commit_skipped_v4(ratchet_pq_apply(state, secrets, public), plaintext, key_id, message)
    end
  end
end

fn current_opened(state :: borrow RatchetState,
  header :: RatchetHeader,
  message :: RatchetMessage,
  associated_data :: Bytes) -> Result<(Bytes, SecretMap, SecretBytes, SecretMap, PqPublic), RatchetError> do
  let candidate = SecretMap.new(64)?
  let (next_chain, material) = candidate_keys(state.receiving_chain_key,
    candidate,
    state.session_id,
    message.ratchet_public_key,
    state.received_count,
    message.message_number)?
  let plaintext = open_v4_body(material, message, associated_data)?
  let (secrets, public) = ratchet_pq_ingest(ratchet_pq_public(state),
    state.pq_secrets,
    state.suite,
    state.session_id,
    header)?
  Ok((plaintext, candidate, next_chain, secrets, public))
end

fn current_index(state :: borrow RatchetState, message_number :: Int) -> Bytes!RatchetError do
  newest_records(skipped_records(state.skipped_index,
    state.remote_ratchet_public,
    state.received_count,
    message_number,
    state.receive_generation)?)
end

fn reject_next_chain(next_chain :: consume SecretBytes,
  state :: consume RatchetState,
  error :: RatchetError) -> DecryptOutcome do
  Rejected(state, error)
end

fn commit_current_v4(state :: consume RatchetState,
  candidate :: consume SecretMap,
  next_chain :: consume SecretBytes,
  plaintext :: Bytes,
  message_number :: Int) -> DecryptOutcome do
  case current_index(state, message_number) do
    Err(error) -> reject_map_chain(candidate, next_chain, state, error)
    Ok(index) -> case SecretMap.merge(state.skipped_keys, candidate) do
      Err(_) -> reject_next_chain(next_chain, state, CryptoFailure)
      Ok(_) -> do
        let next = %{state |
          receiving_chain_key: next_chain,
          received_count: message_number + 1,
          skipped_index: index
        }
        Opened(pruned_header_keys(next), plaintext)
      end
    end
  end
end

fn decrypt_current_v4(state :: consume RatchetState,
  header :: RatchetHeader,
  message :: RatchetMessage,
  associated_data :: Bytes) -> DecryptOutcome do
  case current_opened(state, header, message, associated_data) do
    Err(error) -> Rejected(state, error)
    Ok(values) -> do
      let (plaintext, candidate, next_chain, secrets, public) = values
      commit_current_v4(ratchet_pq_apply(state, secrets, public),
        candidate,
        next_chain,
        plaintext,
        message.message_number)
    end
  end
end

fn this_chain_header_key(state :: borrow RatchetState,
  keys :: borrow SecretMap,
  upgrade :: Bool) -> SecretBytes!RatchetError do
  if upgrade do
    let (first, second) = ratchet_upgrade_header_keys(state.root_key, state.session_id)?
    put_key(keys, ratchet_header_role("next-send"), second)?
    Ok(first)
  else
    Ok(SecretMap.copy(keys, ratchet_header_role("next-receive"))?)
  end
end

fn keep_earlier_header_key(state :: borrow RatchetState,
  keys :: borrow SecretMap) -> Bytes!RatchetError do
  let current = ratchet_header_role("receive")
  if !SecretMap.contains(keys, current) do
    Ok(state.header_key_owners)
  else
    let key = SecretMap.copy(keys, current)?
    put_key(keys, state.remote_ratchet_public.bytes, key)?
    append(state.header_key_owners, state.remote_ratchet_public.bytes)
  end
end

# The chain being left keeps its header key while skipped keys remain; the
# key that opened this header becomes the receiving chain's, and the new root
# step's header key waits for the chain after next.

fn received_header_keys(state :: borrow RatchetState,
  keys :: borrow SecretMap,
  upgrade :: Bool,
  next_header_key :: SecretBytes) -> Bytes!RatchetError do
  let this_chain = this_chain_header_key(state, keys, upgrade)?
  let owners = keep_earlier_header_key(state, keys)?
  put_key(keys, ratchet_header_role("receive"), this_chain)?
  put_key(keys, ratchet_header_role("next-receive"), next_header_key)?
  Ok(owners)
end

fn new_chain_opened(state :: borrow RatchetState,
  found :: HeaderMatch,
  message :: RatchetMessage,
  associated_data :: Bytes) -> Result<(Bytes, SecretMap, SecretBytes, SecretBytes, SecretMap, Bytes, SecretMap, PqPublic), RatchetError> do
  let header = found.header
  let candidate = SecretMap.new(64)?
  skip_until(state.receiving_chain_key,
    candidate,
    state.session_id,
    state.remote_ratchet_public,
    state.received_count,
    message.previous_chain_length)?
  let dh = case Crypto.x25519_shared(state.local_ratchet_private, message.ratchet_public_key) do
    Err(InvalidPublicKey) -> Err(InvalidMessage)
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end?
  let (shared, stepped_secrets, stepped) = ratchet_pq_receive_step(state, dh, header.pq_mix)?
  let (root_key, chain_key, next_header_key) = ratchet_root_v2(state.root_key,
    shared,
    state.session_id,
    message.ratchet_public_key,
    header.pq_mix)?
  let (next_chain, material) = candidate_keys(chain_key,
    candidate,
    state.session_id,
    message.ratchet_public_key,
    0,
    message.message_number)?
  Secret.destroy(chain_key)
  let plaintext = open_v4_body(material, message, associated_data)?
  let (secrets, public) = ratchet_pq_ingest(stepped,
    stepped_secrets,
    state.suite,
    state.session_id,
    header)?
  let keys = SecretMap.fork(state.header_keys)?
  let owners = received_header_keys(state, keys, found.source == 4, next_header_key)?
  Ok((plaintext, candidate, root_key, next_chain, keys, owners, secrets, public))
end

fn reject_new_v4(candidate :: consume SecretMap,
  root_key :: consume SecretBytes,
  next_chain :: consume SecretBytes,
  keys :: consume SecretMap,
  secrets :: consume SecretMap,
  state :: consume RatchetState,
  error :: RatchetError) -> DecryptOutcome do
  Rejected(state, error)
end

fn reject_merged_v4(root_key :: consume SecretBytes,
  next_chain :: consume SecretBytes,
  keys :: consume SecretMap,
  secrets :: consume SecretMap,
  state :: consume RatchetState,
  error :: RatchetError) -> DecryptOutcome do
  Rejected(state, error)
end

fn commit_new_chain_v4(state :: consume RatchetState,
  candidate :: consume SecretMap,
  root_key :: consume SecretBytes,
  next_chain :: consume SecretBytes,
  keys :: consume SecretMap,
  owners :: Bytes,
  secrets :: consume SecretMap,
  public :: PqPublic,
  plaintext :: Bytes,
  message :: RatchetMessage) -> DecryptOutcome do
  let generation = state.receive_generation + 1
  case index_after_new_chain(state.skipped_index,
    state.remote_ratchet_public,
    state.received_count,
    state.receive_generation,
    message) do
    Err(error) -> reject_new_v4(candidate, root_key, next_chain, keys, secrets, state, error)
    Ok(listed) -> case SecretMap.merge(state.skipped_keys, candidate) do
      Err(_) -> reject_merged_v4(root_key, next_chain, keys, secrets, state, CryptoFailure)
      Ok(_) -> case forget_aged(state.skipped_keys, listed, generation) do
        Err(error) -> reject_merged_v4(root_key, next_chain, keys, secrets, state, error)
        Ok(index) -> do
          let next = %{state |
            root_key: root_key,
            receiving_chain_key: next_chain,
            remote_ratchet_public: message.ratchet_public_key,
            received_count: message.message_number + 1,
            skipped_index: index,
            receive_generation: generation,
            pending_send_ratchet: true,
            header_encrypted: true,
            header_keys: keys,
            header_key_owners: owners
          }
          Opened(pruned_header_keys(ratchet_pq_apply(next, secrets, public)), plaintext)
        end
      end
    end
  end
end

fn decrypt_new_chain_v4(state :: consume RatchetState,
  found :: HeaderMatch,
  message :: RatchetMessage,
  associated_data :: Bytes) -> DecryptOutcome do
  let old_gap = message.previous_chain_length - state.received_count
  let too_far = old_gap > 64
    || message.message_number > 64
    || (old_gap > 0 && old_gap + message.message_number > 64)
  if too_far do
    Rejected(state, ExcessiveJump)
  else
    case new_chain_opened(state, found, message, associated_data) do
      Err(error) -> Rejected(state, error)
      Ok(values) -> do
        let (plaintext, candidate, root_key, next_chain, keys, owners, secrets, public) = values
        commit_new_chain_v4(state,
          candidate,
          root_key,
          next_chain,
          keys,
          owners,
          secrets,
          public,
          plaintext,
          message)
      end
    end
  end
end

fn decrypt_found(state :: consume RatchetState,
  found :: HeaderMatch,
  message :: RatchetMessage,
  associated_data :: Bytes) -> DecryptOutcome do
  let known_chain = found.source == 1 || found.source == 3
  case skipped_key_id(message.ratchet_public_key, message.message_number) do
    Err(error) -> Rejected(state, error)
    Ok(key_id) -> if known_chain && SecretMap.contains(state.skipped_keys, key_id) do
      decrypt_skipped_v4(state, found.header, message, associated_data, key_id)
    else if found.source == 3
      || (found.source == 1 && message.message_number < state.received_count) do
      Rejected(state, Replay)
    else if found.source == 1 && message.message_number - state.received_count > 64 do
      Rejected(state, ExcessiveJump)
    else if found.source == 1 do
      decrypt_current_v4(state, found.header, message, associated_data)
    else if state.pending_send_ratchet do
      Rejected(state, InvalidMessage)
    else
      decrypt_new_chain_v4(state, found, message, associated_data)
    end
  end
end

fn decrypt_v4(state :: consume RatchetState,
  message :: RatchetMessage,
  associated_data :: Bytes) -> DecryptOutcome do
  if !(state.suite == 1 || state.suite == 2) do
    Rejected(state, InvalidMessage)
  else
    case classify_header(state, message) do
      Err(error) -> Rejected(state, error)
      Ok(found) -> decrypt_found(state, found, header_view(message, found.header), associated_data)
    end
  end
end

## Session healing: whether a message refused as too far ahead is genuine, by
## deriving its key without keeping any of the keys in between (at most 16,384
## ahead). A version 4 header is already authenticated; a cleartext one is not,
## so only a message that opens may make the receiver ask for a new session.

pub fn ratchet_jump_limit() -> Int do
  16384
end

fn walk_chain(chain :: SecretBytes,
  session_id :: Bytes,
  ratchet_public_key :: X25519PublicKey,
  current :: Int,
  target :: Int) -> SecretBytes!RatchetError do
  let (next_chain, material) = chain_step(chain, session_id, ratchet_public_key, current)?
  Secret.destroy(chain)
  if current >= target do
    Secret.destroy(next_chain)
    Ok(material)
  else
    Secret.destroy(material)
    walk_chain(next_chain, session_id, ratchet_public_key, current + 1, target)
  end
end

fn key_at(chain :: borrow SecretBytes,
  session_id :: Bytes,
  ratchet_public_key :: X25519PublicKey,
  current :: Int,
  target :: Int) -> SecretBytes!RatchetError do
  if target < current || target - current > ratchet_jump_limit() do
    Err(ExcessiveJump)
  else
    let (next_chain, material) = chain_step(chain, session_id, ratchet_public_key, current)?
    if current >= target do
      Secret.destroy(next_chain)
      Ok(material)
    else
      Secret.destroy(material)
      walk_chain(next_chain, session_id, ratchet_public_key, current + 1, target)
    end
  end
end

fn opened_with(material :: SecretBytes,
  state :: borrow RatchetState,
  message :: RatchetMessage,
  associated_data :: Bytes) -> Bytes!RatchetError do
  if message.version == 4 do
    open_v4_body(material, message, associated_data)
  else
    let key = aead_key(material)?
    let data = authenticated_data(message.version,
      state.suite,
      state.session_id,
      message.ratchet_public_key,
      message.previous_chain_length,
      message.message_number,
      message.nonce,
      associated_data)?
    open_message(key, message, data)
  end
end

fn jump_chain_key(state :: borrow RatchetState,
  message :: RatchetMessage,
  mix :: Int) -> SecretBytes!RatchetError do
  let dh = case Crypto.x25519_shared(state.local_ratchet_private, message.ratchet_public_key) do
    Err(_) -> Err(InvalidMessage)
    Ok(value)
  end?
  if message.version == 4 do
    let (shared, secrets, public) = ratchet_pq_receive_step(state, dh, mix)?
    let (root_key, chain_key, next_header_key) = ratchet_root_v2(state.root_key,
      shared,
      state.session_id,
      message.ratchet_public_key,
      mix)?
    Ok(chain_key)
  else
    let (root_key, chain_key) = ratchet_root(state.root_key,
      dh,
      state.session_id,
      message.ratchet_public_key)?
    Ok(chain_key)
  end
end

fn jump_opened(state :: borrow RatchetState,
  message :: RatchetMessage,
  new_chain :: Bool,
  mix :: Int,
  associated_data :: Bytes) -> Bytes!RatchetError do
  if new_chain do
    let chain_key = jump_chain_key(state, message, mix)?
    let material = key_at(chain_key,
      state.session_id,
      message.ratchet_public_key,
      0,
      message.message_number)?
    opened_with(material, state, message, associated_data)
  else
    let material = key_at(state.receiving_chain_key,
      state.session_id,
      message.ratchet_public_key,
      state.received_count,
      message.message_number)?
    opened_with(material, state, message, associated_data)
  end
end

## The plaintext of a message refused as too far ahead, if it is genuine,
## derived without keeping any key and without changing the session. A
## receiver uses it to read a peer's session reset request that is itself
## beyond the skip limit.

pub fn ratchet_jump_open(state :: borrow RatchetState,
  message :: RatchetMessage,
  associated_data :: Bytes) -> Bytes!RatchetError do
  if message.version == 4 do
    let found = classify_header(state, message)?
    let view = header_view(message, found.header)
    if found.source == 3 do
      Err(InvalidMessage)
    else
      jump_opened(state, view, found.source != 1, found.header.pq_mix, associated_data)
    end
  else if message.suite != state.suite
    || !Bytes.secure_equals(message.session_id, state.session_id) do
    Err(InvalidMessage)
  else
    let same_chain = Bytes.secure_equals(message.ratchet_public_key.bytes,
      state.remote_ratchet_public.bytes)
    jump_opened(state, message, !same_chain, 0, associated_data)
  end
end

pub fn ratchet_jump_authentic(state :: borrow RatchetState,
  message :: RatchetMessage,
  associated_data :: Bytes) -> Bool do
  case ratchet_jump_open(state, message, associated_data) do
    Err(_) -> false
    Ok(_) -> true
  end
end
