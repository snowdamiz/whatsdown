##! Double Ratchet HE: next-key authentication drives the DH ratchet; commit only after body authentication.
from Session.State import RatchetState, RatchetMessage, RatchetError, DecryptOutcome
from Session.HeaderWire import (
  OpenedHeader,
  decode_header,
  encode_header,
  he_body_aad,
  he_decode_message,
  he_encode_message,
  he_header_aad,
  he_join,
  he_read_u32,
  he_slice,
  he_u32
)
from Session.Spqr import SpqrState, SpqrKeyAdmission, spqr_send_key, spqr_receive_key
from Session.SpqrKdf import SpqrError, spqr_scope
from Session.BraidFragment import BraidFragment, encode_braid_fragment
from Session.TripleWire import (
  TripleHeader,
  TripleMessage,
  encode_triple_header,
  decode_triple_header,
  encode_triple_message,
  triple_header_aad,
  triple_body_aad
)
from Session.TripleKdf import triple_message_material

# Inactive complete hybrid profile. Tentative resources and finalizers stay private.
pub type HybridError do
  HybridInvalidState
  HybridInvalidMessage
  HybridAuthenticationRejected
  HybridReplay
  HybridExcessiveJump
  HybridRetired
  HybridSkipLimit
  HybridCounterOverflow
  HybridCryptoFailure
end

pub type HybridSendOutcome do
  HybridSealed(he :: RatchetState, pq :: SpqrState, message :: TripleMessage)
  HybridSealRefused(he :: RatchetState, pq :: SpqrState, error :: HybridError)
end

pub type HybridReceiveOutcome do
  HybridOpened(he :: RatchetState, pq :: SpqrState, header :: TripleHeader, plaintext :: Bytes)
  HybridOpenRefused(he :: RatchetState, pq :: SpqrState, error :: HybridError)
end

resource struct SkippedReceivePrepared do
  id :: Bytes
  material :: SecretBytes
end

resource struct CurrentReceivePrepared do
  chain :: SecretBytes
  material :: SecretBytes
  candidate :: SecretMap
end

resource struct NextReceivePrepared do
  receive_root :: SecretBytes
  chain :: SecretBytes
  material :: SecretBytes
  next_receiving :: SecretBytes
  candidate :: SecretMap
  has_receiving :: Bool
end

struct HybridHeaderMatch do
  header :: TripleHeader
  next :: Bool
  old :: Bool
end

type HybridReceiveCandidate do
  HybridCachedCandidate(commit :: SkippedCommit, pq :: SpqrState, header :: TripleHeader)
  HybridCurrentCandidate(commit :: CurrentCommit, pq :: SpqrState, header :: TripleHeader)
  HybridNextCandidate(commit :: NewCommit, pq :: SpqrState, header :: TripleHeader)
end

struct HeaderMatch do
  header :: OpenedHeader
  next :: Bool
  old :: Bool
end

resource struct CurrentCommit do
  chain :: SecretBytes
  skipped :: SecretMap
  headers :: SecretMap
  index :: Bytes
  plaintext :: Bytes
end

resource struct SkippedCommit do
  skipped :: SecretMap
  headers :: SecretMap
  index :: Bytes
  plaintext :: Bytes
end

resource struct NewCommit do
  root :: SecretBytes
  sending :: SecretBytes
  receiving :: SecretBytes
  private_key :: X25519PrivateKey
  public_key :: X25519PublicKey
  skipped :: SecretMap
  headers :: SecretMap
  index :: Bytes
  generation :: Int
  plaintext :: Bytes
end

pub fn he_empty_headers() -> SecretMap!RatchetError do
  case SecretMap.new(16) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end
end

fn derive(secret :: borrow SecretBytes,
  salt :: Bytes,
  domain :: Bytes) -> SecretBytes!RatchetError do
  case Crypto.hkdf_sha256(secret, salt, domain, 32) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end
end

pub fn he_root_step(root :: borrow SecretBytes,
  dh :: consume SecretBytes,
  session :: Bytes,
  public_key :: X25519PublicKey) -> Result<(SecretBytes, SecretBytes, SecretBytes), RatchetError> do
  # Retain Morse's opaque-secret root mix; every output has a separate new HE domain.
  let previous = derive(root,
    session,
    he_join([Bytes.from_utf8("mesh-msg/v2/he-root-mix"), public_key.bytes])?)?
  let combined = case Secret.concat(previous, dh) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end?
  let next_root = derive(combined,
    session,
    he_join([Bytes.from_utf8("mesh-msg/v2/he-root"), public_key.bytes])?)?
  let chain = derive(combined,
    session,
    he_join([Bytes.from_utf8("mesh-msg/v2/he-chain"), public_key.bytes])?)?
  let next_header = derive(combined,
    session,
    he_join([Bytes.from_utf8("mesh-msg/v2/he-next-header"), public_key.bytes])?)?
  Secret.destroy(combined)
  Ok((next_root, chain, next_header))
end

pub fn he_replace_header(headers :: borrow SecretMap,
  name :: Bytes,
  key :: consume SecretBytes) -> Unit!RatchetError do
  if SecretMap.contains(headers, name) do
    case SecretMap.delete(headers, name) do
      Err(_) -> return Err(CryptoFailure)
      Ok(_) -> nil
    end
  end
  case SecretMap.insert(headers, name, key) do
    Err(_) -> Err(CryptoFailure)
    Ok(_) -> Ok(nil)
  end
end

fn copied(headers :: borrow SecretMap, name :: Bytes) -> SecretBytes!RatchetError do
  case SecretMap.copy(headers, name) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end
end

fn forked(headers :: borrow SecretMap) -> SecretMap!RatchetError do
  case SecretMap.fork(headers) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end
end

fn old_id(public_key :: Bytes) -> Bytes!RatchetError do
  he_join([Bytes.from_utf8("old/"), public_key])
end

fn key_id(public_key :: Bytes, number :: Int) -> Bytes!RatchetError do
  Ok(Crypto.sha256(he_join([
    Bytes.from_utf8("mesh-msg/v2/he-skipped"),
    public_key,
    he_u32(number)?
  ])?))
end

fn chain_step(chain :: borrow SecretBytes,
  session :: Bytes,
  public_key :: X25519PublicKey,
  number :: Int) -> Result<(SecretBytes, SecretBytes), RatchetError> do
  let next = derive(chain,
    session,
    he_join([Bytes.from_utf8("mesh-msg/v2/he-chain-next"), public_key.bytes, he_u32(number)?])?)?
  let message = derive(chain,
    session,
    he_join([Bytes.from_utf8("mesh-msg/v2/he-message-key"), public_key.bytes, he_u32(number)?])?)?
  Ok((next, message))
end

fn aead(material :: consume SecretBytes) -> AeadKey!RatchetError do
  case Crypto.aead_key(material) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end
end

pub fn he_encrypt(state :: consume RatchetState,
  plaintext :: Bytes,
  associated_data :: Bytes) -> Result<(RatchetState, RatchetMessage), RatchetError> do
  let oversized = declassify(Bytes.length(plaintext) > 65317,
    "HE ratchet admission exposes only whether plaintext exceeds the fixed recipient transport bound; content remains private")
  if state.version != 2
    || oversized
    || state.sent_count < 0
    || state.sent_count >= 4294967295
    || !SecretMap.contains(state.header_keys, Bytes.from_utf8("sending")) do
    return Err(InvalidMessage)
  end
  let header = OpenedHeader {
    suite: state.suite,
    session_id: state.session_id,
    ratchet_public_key: state.local_ratchet_public,
    previous_chain_length: state.previous_chain_length,
    message_number: state.sent_count
  }
  let header_nonce = case Crypto.random_bytes(24) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end?
  let header_key = aead(copied(state.header_keys, Bytes.from_utf8("sending"))?)?
  let encrypted_header = case Crypto.xchacha20poly1305_seal(header_key,
    header_nonce,
    he_header_aad(associated_data)?,
    encode_header(header)?) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end?
  let (next_chain, material) = chain_step(state.sending_chain_key,
    state.session_id,
    state.local_ratchet_public,
    state.sent_count)?
  let key = aead(material)?
  let nonce = case Crypto.random_bytes(12) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end?
  let framed = RatchetMessage {
    version: 4,
    suite: 0,
    session_id: Bytes.empty(),
    ratchet_public_key: X25519PublicKey { bytes: Bytes.empty() },
    previous_chain_length: 0,
    message_number: 0,
    header_nonce: header_nonce,
    encrypted_header: encrypted_header,
    nonce: nonce,
    ciphertext: Bytes.empty()
  }
  let sealed = declassify_discriminant(Crypto.aead_seal(key,
      nonce,
      he_body_aad(framed, associated_data)?,
      plaintext),
    "HE body encryption discloses only success or failure; plaintext, error payloads and unrelated private control remain private")
  let ciphertext = case sealed do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end?
  let output = %{framed | ciphertext: ciphertext}
  he_encode_message(output)?
  let sent_count = state.sent_count + 1
  Ok((%{state | sending_chain_key: next_chain, sent_count: sent_count}, output))
end

fn probe(state :: borrow RatchetState,
  message :: RatchetMessage,
  caller :: Bytes,
  name :: Bytes) -> Option<OpenedHeader>!RatchetError do
  if !SecretMap.contains(state.header_keys, name) do
    return Ok(None)
  end
  let key = aead(copied(state.header_keys, name)?)?
  case Crypto.xchacha20poly1305_open(key,
    message.header_nonce,
    he_header_aad(caller)?,
    message.encrypted_header) do
    Err(AuthenticationFailed) -> Ok(None)
    Err(_) -> Err(CryptoFailure)
    Ok(clear) -> do
      let header = decode_header(clear)?
      if header.suite != state.suite || !Bytes.secure_equals(header.session_id, state.session_id) do
        Err(InvalidMessage)
      else
        Ok(Some(header))
      end
    end
  end
end

fn old_header(state :: borrow RatchetState,
  message :: RatchetMessage,
  caller :: Bytes,
  index :: Int,
  seen :: List<Bytes>) -> HeaderMatch!RatchetError do
  if index >= Bytes.length(state.skipped_index) do
    return Err(AuthenticationRejected)
  end
  let public_key = he_slice(state.skipped_index, index, 32)?
  if List.any(seen, fn(value) do Bytes.secure_equals(value, public_key) end) do
    return old_header(state, message, caller, index + 40, seen)
  end
  case probe(state, message, caller, old_id(public_key)?)? do
    None -> old_header(state, message, caller, index + 40, List.append(seen, public_key))
    Some(header) -> if !Bytes.secure_equals(public_key, header.ratchet_public_key.bytes) do
      Err(InvalidMessage)
    else
      Ok(HeaderMatch { header: header, next: false, old: true })
    end
  end
end

fn find_header(state :: borrow RatchetState,
  message :: RatchetMessage,
  caller :: Bytes) -> HeaderMatch!RatchetError do
  case probe(state, message, caller, Bytes.from_utf8("receiving"))? do
    Some(header) -> if !Bytes.secure_equals(header.ratchet_public_key.bytes,
      state.remote_ratchet_public.bytes) do
      Err(InvalidMessage)
    else
      Ok(HeaderMatch { header: header, next: false, old: false })
    end
    None -> case probe(state, message, caller, Bytes.from_utf8("next-receiving"))? do
      Some(header) -> if Bytes.secure_equals(header.ratchet_public_key.bytes,
        state.remote_ratchet_public.bytes) do
        Err(InvalidMessage)
      else
        Ok(HeaderMatch { header: header, next: true, old: false })
      end
      None -> old_header(state, message, caller, 0, List.new())
    end
  end
end

## Bounded local session selection uses only authenticated header matches, never clear hints.
pub fn he_header_matches(state :: borrow RatchetState,
  message :: RatchetMessage,
  caller :: Bytes) -> Bool!RatchetError do
  if state.version != 2 || message.version != 4 do
    return Ok(false)
  end
  case find_header(state, message, caller) do
    Ok(_) -> Ok(true)
    Err(AuthenticationRejected) -> Ok(false)
    Err(InvalidMessage) -> Ok(false)
    Err(error)
  end
end

fn body_open(material :: consume SecretBytes,
  message :: RatchetMessage,
  caller :: Bytes) -> Bytes!RatchetError do
  let key = aead(material)?
  case Crypto.aead_open(key, message.nonce, he_body_aad(message, caller)?, message.ciphertext) do
    Err(AuthenticationFailed) -> Err(AuthenticationRejected)
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end
end

fn record(index :: Bytes,
  public_key :: Bytes,
  number :: Int,
  generation :: Int) -> Bytes!RatchetError do
  he_join([index, public_key, he_u32(number)?, he_u32(generation)?])
end

fn newest(index :: Bytes) -> Bytes!RatchetError do
  if Bytes.length(index) <= 2560 do
    Ok(index)
  else
    he_slice(index, Bytes.length(index) - 2560, 2560)
  end
end

fn key_records(index :: Bytes,
  public_key :: Bytes,
  current :: Int,
  target :: Int,
  generation :: Int) -> Bytes!RatchetError do
  if current >= target do
    Ok(index)
  else
    key_records(record(index, public_key, current, generation)?,
      public_key,
      current + 1,
      target,
      generation)
  end
end

fn has_chain(index :: Bytes, public_key :: Bytes, offset :: Int) -> Bool!RatchetError do
  if offset >= Bytes.length(index) do
    Ok(false)
  else if Bytes.secure_equals(he_slice(index, offset, 32)?, public_key) do
    Ok(true)
  else
    has_chain(index, public_key, offset + 40)
  end
end

fn prune(headers :: borrow SecretMap,
  before :: Bytes,
  remaining :: Bytes,
  offset :: Int) -> Unit!RatchetError do
  if offset >= Bytes.length(before) do
    return Ok(nil)
  end
  let public_key = he_slice(before, offset, 32)?
  if !has_chain(remaining, public_key, 0)? do
    case SecretMap.delete(headers, old_id(public_key)?) do
      Err(_) -> return Err(CryptoFailure)
      Ok(_) -> nil
    end
  end
  prune(headers, before, remaining, offset + 40)
end

fn age(skipped :: borrow SecretMap, index :: Bytes, generation :: Int) -> Bytes!RatchetError do
  if Bytes.length(index) < 40 do
    return Ok(index)
  end
  let kept = he_read_u32(index, 36)?
  if kept > generation - 5 do
    return Ok(index)
  end
  let id = key_id(he_slice(index, 0, 32)?, he_read_u32(index, 32)?)?
  case SecretMap.delete(skipped, id) do
    Err(_) -> return Err(CryptoFailure)
    Ok(_) -> nil
  end
  age(skipped, he_slice(index, 40, Bytes.length(index) - 40)?, generation)
end

fn without(index :: Bytes,
  public_key :: Bytes,
  number :: Int,
  offset :: Int) -> Bytes!RatchetError do
  if offset >= Bytes.length(index) do
    return Ok(index)
  end
  if Bytes.secure_equals(he_slice(index, offset, 32)?, public_key)
    && he_read_u32(index, offset + 32)? == number do
    he_join([
      he_slice(index, 0, offset)?,
      he_slice(index, offset + 40, Bytes.length(index) - offset - 40)?
    ])
  else
    without(index, public_key, number, offset + 40)
  end
end

fn skipped_receive_prepare(state :: borrow RatchetState,
  header :: OpenedHeader) -> SkippedReceivePrepared!RatchetError do
  let id = key_id(header.ratchet_public_key.bytes, header.message_number)?
  let material = copied(state.skipped_keys, id)?
  Ok(SkippedReceivePrepared { id: id, material: material })
end

fn skipped_receive_finalize(state :: borrow RatchetState,
  header :: OpenedHeader,
  id :: Bytes,
  clear :: Bytes) -> SkippedCommit!RatchetError do
  let skipped = forked(state.skipped_keys)?
  case SecretMap.delete(skipped, id) do
    Err(_) -> return Err(CryptoFailure)
    Ok(_) -> nil
  end
  let index = without(state.skipped_index,
    header.ratchet_public_key.bytes,
    header.message_number,
    0)?
  let headers = forked(state.header_keys)?
  prune(headers, state.skipped_index, index, 0)?
  Ok(SkippedCommit { skipped: skipped, headers: headers, index: index, plaintext: clear })
end

fn skipped_commit(state :: borrow RatchetState,
  header :: OpenedHeader,
  message :: RatchetMessage,
  caller :: Bytes) -> SkippedCommit!RatchetError do
  let SkippedReceivePrepared { id, material } = skipped_receive_prepare(state, header)?
  let clear = body_open(material, message, caller)?
  skipped_receive_finalize(state, header, id, clear)
end

fn candidate_chain(chain :: borrow SecretBytes,
  skipped :: borrow SecretMap,
  session :: Bytes,
  public_key :: X25519PublicKey,
  current :: Int,
  target :: Int) -> Result<(SecretBytes, SecretBytes), RatchetError> do
  let (next, material) = chain_step(chain, session, public_key, current)?
  if current == target do
    return Ok((next, material))
  end
  case SecretMap.insert(skipped, key_id(public_key.bytes, current)?, material) do
    Err(_) -> return Err(CryptoFailure)
    Ok(_) -> nil
  end
  let result = candidate_chain(next, skipped, session, public_key, current + 1, target)
  Secret.destroy(next)
  result
end

fn skip_chain(chain :: borrow SecretBytes,
  skipped :: borrow SecretMap,
  session :: Bytes,
  public_key :: X25519PublicKey,
  current :: Int,
  target :: Int) -> Unit!RatchetError do
  if current >= target do
    return Ok(nil)
  end
  let (next, material) = chain_step(chain, session, public_key, current)?
  case SecretMap.insert(skipped, key_id(public_key.bytes, current)?, material) do
    Err(_) -> return Err(CryptoFailure)
    Ok(_) -> nil
  end
  let result = skip_chain(next, skipped, session, public_key, current + 1, target)
  Secret.destroy(next)
  result
end

fn merged(state :: borrow RatchetState, candidate :: consume SecretMap) -> SecretMap!RatchetError do
  let skipped = forked(state.skipped_keys)?
  case SecretMap.merge(skipped, candidate) do
    Err(_) -> Err(CryptoFailure)
    Ok(_) -> Ok(skipped)
  end
end

fn current_receive_prepare(state :: borrow RatchetState,
  header :: OpenedHeader) -> CurrentReceivePrepared!RatchetError do
  let candidate = case SecretMap.new(64) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end?
  let (next, material) = candidate_chain(state.receiving_chain_key,
    candidate,
    state.session_id,
    state.remote_ratchet_public,
    state.received_count,
    header.message_number)?
  Ok(CurrentReceivePrepared { chain: next, material: material, candidate: candidate })
end

fn current_receive_finalize(state :: borrow RatchetState,
  header :: OpenedHeader,
  next :: consume SecretBytes,
  candidate :: consume SecretMap,
  clear :: Bytes) -> CurrentCommit!RatchetError do
  let before = key_records(state.skipped_index,
    state.remote_ratchet_public.bytes,
    state.received_count,
    header.message_number,
    state.receive_generation)?
  let skipped = merged(state, candidate)?
  let index = age(skipped, newest(before)?, state.receive_generation)?
  let headers = forked(state.header_keys)?
  prune(headers, before, index, 0)?
  Ok(CurrentCommit {
    chain: next,
    skipped: skipped,
    headers: headers,
    index: index,
    plaintext: clear
  })
end

fn current_commit(state :: borrow RatchetState,
  header :: OpenedHeader,
  message :: RatchetMessage,
  caller :: Bytes) -> CurrentCommit!RatchetError do
  let CurrentReceivePrepared { chain, material, candidate } = current_receive_prepare(state,
    header)?
  let clear = body_open(material, message, caller)?
  current_receive_finalize(state, header, chain, candidate, clear)
end

fn next_receive_prepare(state :: borrow RatchetState,
  header :: OpenedHeader) -> NextReceivePrepared!RatchetError do
  let candidate = case SecretMap.new(64) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end?
  let has_receiving = SecretMap.contains(state.header_keys, Bytes.from_utf8("receiving"))
  if !has_receiving && header.previous_chain_length != 0 do
    return Err(InvalidMessage)
  end
  if has_receiving do
    skip_chain(state.receiving_chain_key,
      candidate,
      state.session_id,
      state.remote_ratchet_public,
      state.received_count,
      header.previous_chain_length)?
  end
  let dh = case Crypto.x25519_shared(state.local_ratchet_private, header.ratchet_public_key) do
    Err(InvalidPublicKey) -> Err(InvalidMessage)
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end?
  let (receive_root, receive_chain, next_receiving) = he_root_step(state.root_key,
    dh,
    state.session_id,
    header.ratchet_public_key)?
  let (next_chain, material) = candidate_chain(receive_chain,
    candidate,
    state.session_id,
    header.ratchet_public_key,
    0,
    header.message_number)?
  Secret.destroy(receive_chain)
  Ok(NextReceivePrepared {
    receive_root: receive_root,
    chain: next_chain,
    material: material,
    next_receiving: next_receiving,
    candidate: candidate,
    has_receiving: has_receiving
  })
end

fn next_receive_finalize(state :: borrow RatchetState,
  header :: OpenedHeader,
  receive_root :: consume SecretBytes,
  next_chain :: consume SecretBytes,
  next_receiving :: consume SecretBytes,
  candidate :: consume SecretMap,
  has_receiving :: Bool,
  clear :: Bytes) -> NewCommit!RatchetError do
  # Generate/promote the sending half only after body authentication.
  let local = case Crypto.x25519_generate() do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end?
  let send_dh = case Crypto.x25519_shared(local.private_key, header.ratchet_public_key) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end?
  let (root, sending, next_sending) = he_root_step(receive_root,
    send_dh,
    state.session_id,
    local.public_key)?
  Secret.destroy(receive_root)
  let generation = state.receive_generation + 1
  let before = key_records(state.skipped_index,
    state.remote_ratchet_public.bytes,
    state.received_count,
    header.previous_chain_length,
    state.receive_generation)?
  let before = key_records(before,
    header.ratchet_public_key.bytes,
    0,
    header.message_number,
    generation)?
  let skipped = merged(state, candidate)?
  let index = age(skipped, newest(before)?, generation)?
  let headers = forked(state.header_keys)?
  if has_receiving && has_chain(index, state.remote_ratchet_public.bytes, 0)? do
    he_replace_header(headers,
      old_id(state.remote_ratchet_public.bytes)?,
      copied(headers, Bytes.from_utf8("receiving"))?)?
  end
  let receiving = copied(headers, Bytes.from_utf8("next-receiving"))?
  let sender = copied(headers, Bytes.from_utf8("next-sending"))?
  he_replace_header(headers, Bytes.from_utf8("receiving"), receiving)?
  he_replace_header(headers, Bytes.from_utf8("sending"), sender)?
  he_replace_header(headers, Bytes.from_utf8("next-receiving"), next_receiving)?
  he_replace_header(headers, Bytes.from_utf8("next-sending"), next_sending)?
  prune(headers, before, index, 0)?
  Ok(NewCommit {
    root: root,
    sending: sending,
    receiving: next_chain,
    public_key: local.public_key,
    private_key: local.private_key,
    skipped: skipped,
    headers: headers,
    index: index,
    generation: generation,
    plaintext: clear
  })
end

fn new_commit(state :: borrow RatchetState,
  header :: OpenedHeader,
  message :: RatchetMessage,
  caller :: Bytes) -> NewCommit!RatchetError do
  let NextReceivePrepared {
    receive_root,
    chain,
    material,
    next_receiving,
    candidate,
    has_receiving
  } = next_receive_prepare(state, header)?
  let clear = body_open(material, message, caller)?
  next_receive_finalize(state,
    header,
    receive_root,
    chain,
    next_receiving,
    candidate,
    has_receiving,
    clear)
end

pub fn he_decrypt(state :: consume RatchetState,
  message :: RatchetMessage,
  caller :: Bytes) -> DecryptOutcome do
  if state.version != 2 || message.version != 4 do
    return Rejected(state, InvalidMessage)
  end
  let found = case find_header(state, message, caller) do
    Err(error) -> return Rejected(state, error)
    Ok(value) -> value
  end
  let header = found.header
  let id = case key_id(header.ratchet_public_key.bytes, header.message_number) do
    Err(error) -> return Rejected(state, error)
    Ok(value) -> value
  end
  if SecretMap.contains(state.skipped_keys, id) do
    return case skipped_commit(state, header, message, caller) do
      Err(error) -> Rejected(state, error)
      Ok(commit) -> do
        let SkippedCommit { skipped, headers, index, plaintext } = commit
        Opened(%{state | skipped_keys: skipped, header_keys: headers, skipped_index: index},
          plaintext)
      end
    end
  end
  if found.old || (!found.next && header.message_number < state.received_count) do
    return Rejected(state, Replay)
  end
  if header.message_number >= 4294967295
    || (found.next && state.receive_generation >= 4294967295) do
    return Rejected(state, InvalidMessage)
  end
  let old_gap = header.previous_chain_length - state.received_count
  let excessive = if found.next do
    old_gap > 64
      || header.message_number > 64
      || (old_gap > 0 && old_gap + header.message_number > 64)
  else
    header.message_number - state.received_count > 64
  end
  if excessive do
    return Rejected(state, ExcessiveJump)
  end
  if found.next do
    case new_commit(state, header, message, caller) do
      Err(error) -> Rejected(state, error)
      Ok(commit) -> do
        let NewCommit {
          root,
          sending,
          receiving,
          private_key,
          public_key,
          skipped,
          headers,
          index,
          generation,
          plaintext
        } = commit
        let previous = state.sent_count
        Opened(%{state |
            root_key: root,
            sending_chain_key: sending,
            receiving_chain_key: receiving,
            local_ratchet_private: private_key,
            local_ratchet_public: public_key,
            remote_ratchet_public: header.ratchet_public_key,
            previous_chain_length: previous,
            sent_count: 0,
            received_count: header.message_number + 1,
            skipped_keys: skipped,
            header_keys: headers,
            skipped_index: index,
            receive_generation: generation,
            pending_send_ratchet: false
          },
          plaintext)
      end
    end
  else
    case current_commit(state, header, message, caller) do
      Err(error) -> Rejected(state, error)
      Ok(commit) -> do
        let CurrentCommit { chain, skipped, headers, index, plaintext } = commit
        Opened(%{state |
            receiving_chain_key: chain,
            received_count: header.message_number + 1,
            skipped_keys: skipped,
            header_keys: headers,
            skipped_index: index
          },
          plaintext)
      end
    end
  end
end

# These complete operations retain both originals until every candidate succeeds.
fn hybrid_ratchet_error(error :: RatchetError) -> HybridError do
  case error do
    InvalidMessage -> HybridInvalidMessage
    AuthenticationRejected -> HybridAuthenticationRejected
    Replay -> HybridReplay
    ExcessiveJump -> HybridExcessiveJump
    CryptoFailure -> HybridCryptoFailure
  end
end

fn hybrid_spqr_error(error :: SpqrError) -> HybridError do
  case error do
    SpqrInvalidState -> HybridInvalidState
    SpqrEpochOrder -> HybridInvalidState
    SpqrRetired -> HybridRetired
    SpqrReplay -> HybridReplay
    SpqrSkipLimit -> HybridSkipLimit
    SpqrCounterOverflow -> HybridCounterOverflow
    SpqrCryptoFailure(_) -> HybridCryptoFailure
    SpqrKernelFailure(_) -> HybridCryptoFailure
  end
end

fn hybrid_pair(he :: borrow RatchetState, pq :: borrow SpqrState) -> Unit!HybridError do
  if he.version != 2
    || he.suite != 2
    || Bytes.length(he.session_id) != 32
    || !Bytes.secure_equals(he.session_id, pq.scope.session_id)
    || he.sent_count < 0
    || he.sent_count > 4294967295
    || he.received_count < 0
    || he.received_count > 4294967295
    || he.previous_chain_length < 0
    || he.previous_chain_length > 4294967295
    || he.receive_generation < 0
    || he.receive_generation > 4294967295
    || Bytes.length(he.skipped_index) > 2560
    || Bytes.length(he.skipped_index) / 40 * 40 != Bytes.length(he.skipped_index) do
    return Err(HybridInvalidState)
  end
  case spqr_scope(pq.scope) do
    Err(_) -> Err(HybridInvalidState)
    Ok(_) -> Ok(nil)
  end
end

fn hybrid_fork_pq(pq :: borrow SpqrState) -> SpqrState!HybridError do
  let chains = case SecretMap.fork(pq.chains) do
    Err(_) -> return Err(HybridCryptoFailure)
    Ok(value) -> value
  end
  let skipped = case SecretMap.fork(pq.skipped) do
    Err(_) -> return Err(HybridCryptoFailure)
    Ok(value) -> value
  end
  Ok(SpqrState {
    scope: pq.scope,
    direction: pq.direction,
    epoch: pq.epoch,
    knowledge: pq.knowledge,
    slots: pq.slots,
    chains: chains,
    skipped: skipped,
    skipped_index: pq.skipped_index
  })
end

fn hybrid_discard_pq(pq :: consume SpqrState) do
  nil
end

fn hybrid_epoch(fragment :: BraidFragment) -> U64!HybridError do
  let one = case U64.parse("1") do
    Err(_) -> return Err(HybridInvalidMessage)
    Ok(value) -> value
  end
  case U64.subtract(fragment.epoch, one) do
    Err(_) -> Err(HybridInvalidMessage)
    Ok(value)
  end
end

fn hybrid_zeros(count :: Int) -> Bytes!HybridError do
  case Bytes.repeat(0, count) do
    Err(_) -> Err(HybridInvalidMessage)
    Ok(value)
  end
end

fn hybrid_body_key(he :: borrow RatchetState,
  pq :: borrow SpqrState,
  ec :: consume SecretBytes,
  quantum :: consume SecretBytes) -> AeadKey!HybridError do
  let material = case triple_message_material(pq.scope.configuration, he.session_id, ec, quantum) do
    Err(error) -> return Err(hybrid_ratchet_error(error))
    Ok(value) -> value
  end
  case aead(material) do
    Err(error) -> Err(hybrid_ratchet_error(error))
    Ok(value)
  end
end

fn hybrid_seal_candidate(he :: borrow RatchetState,
  pq :: borrow SpqrState,
  plaintext :: Bytes,
  fragment :: BraidFragment,
  caller :: Bytes) -> (SecretBytes, SpqrState, TripleMessage)!HybridError do
  hybrid_pair(he, pq)?
  let oversized = declassify(Bytes.length(plaintext) > 65152,
    "Hybrid HE ratchet admission exposes only whether plaintext exceeds the fixed recipient transport bound; content remains private")
  if oversized do
    return Err(HybridInvalidMessage)
  end
  if he.sent_count >= 4294967295 do
    return Err(HybridCounterOverflow)
  end
  if !SecretMap.contains(he.header_keys, Bytes.from_utf8("sending")) do
    return Err(HybridInvalidState)
  end
  if !Bytes.secure_equals(fragment.configuration, pq.scope.configuration)
    || !Bytes.secure_equals(fragment.session, he.session_id) do
    return Err(HybridInvalidMessage)
  end
  case encode_braid_fragment(fragment) do
    Err(_) -> return Err(HybridInvalidMessage)
    Ok(_) -> nil
  end
  let epoch = hybrid_epoch(fragment)?
  let one = case U64.parse("1") do
    Err(_) -> return Err(HybridInvalidMessage)
    Ok(value) -> value
  end
  let provisional = TripleHeader {
    ec: OpenedHeader {
      suite: he.suite,
      session_id: he.session_id,
      ratchet_public_key: he.local_ratchet_public,
      previous_chain_length: he.previous_chain_length,
      message_number: he.sent_count
    },
    pq_message_number: one,
    fragment: fragment
  }
  let header_size = case encode_triple_header(provisional) do
    Err(_) -> return Err(HybridInvalidMessage)
    Ok(value) -> Bytes.length(value) + 16
  end
  let header_aad = case triple_header_aad(pq.scope.configuration,
    he.session_id,
    header_size,
    caller) do
    Err(_) -> return Err(HybridInvalidMessage)
    Ok(value) -> value
  end
  let bounded = TripleMessage {
    header_nonce: hybrid_zeros(24)?,
    encrypted_header: hybrid_zeros(header_size)?,
    nonce: hybrid_zeros(12)?,
    ciphertext: Bytes.empty()
  }
  case triple_body_aad(pq.scope.configuration, he.session_id, bounded, caller) do
    Err(_) -> return Err(HybridInvalidMessage)
    Ok(_) -> nil
  end
  let shadow = hybrid_fork_pq(pq)?
  let (candidate, quantum, number) = case spqr_send_key(shadow, epoch) do
    SpqrKeyRefused(_, error) -> return Err(hybrid_spqr_error(error))
    SpqrKeyAccepted(state, key, number) -> (state, key, number)
  end
  let header = %{provisional | pq_message_number: number}
  let clear_header = case encode_triple_header(header) do
    Err(_) -> return Err(HybridInvalidMessage)
    Ok(value) -> value
  end
  let header_nonce = case Crypto.random_bytes(24) do
    Err(_) -> return Err(HybridCryptoFailure)
    Ok(value) -> value
  end
  let header_key = case aead(case copied(he.header_keys, Bytes.from_utf8("sending")) do
    Err(error) -> return Err(hybrid_ratchet_error(error))
    Ok(value) -> value
  end) do
    Err(error) -> return Err(hybrid_ratchet_error(error))
    Ok(value) -> value
  end
  let encrypted_header = case Crypto.xchacha20poly1305_seal(header_key,
    header_nonce,
    header_aad,
    clear_header) do
    Err(_) -> return Err(HybridCryptoFailure)
    Ok(value) -> value
  end
  let (next_chain, ec) = case chain_step(he.sending_chain_key,
    he.session_id,
    he.local_ratchet_public,
    he.sent_count) do
    Err(error) -> return Err(hybrid_ratchet_error(error))
    Ok(value) -> value
  end
  let key = hybrid_body_key(he, pq, ec, quantum)?
  let nonce = case Crypto.random_bytes(12) do
    Err(_) -> return Err(HybridCryptoFailure)
    Ok(value) -> value
  end
  let framed = TripleMessage {
    header_nonce: header_nonce,
    encrypted_header: encrypted_header,
    nonce: nonce,
    ciphertext: Bytes.empty()
  }
  let body_aad = case triple_body_aad(pq.scope.configuration, he.session_id, framed, caller) do
    Err(_) -> return Err(HybridInvalidMessage)
    Ok(value) -> value
  end
  let sealed = declassify_discriminant(Crypto.aead_seal(key, nonce, body_aad, plaintext),
    "Hybrid HE body encryption discloses only success or failure; plaintext, error payloads and unrelated private control remain private")
  let ciphertext = case sealed do
    Err(_) -> return Err(HybridCryptoFailure)
    Ok(value) -> value
  end
  let output = %{framed | ciphertext: ciphertext}
  case encode_triple_message(output) do
    Err(_) -> return Err(HybridInvalidMessage)
    Ok(_) -> nil
  end
  Ok((next_chain, candidate, output))
end

pub fn he_encrypt_hybrid(he :: consume RatchetState,
  pq :: consume SpqrState,
  plaintext :: Bytes,
  fragment :: BraidFragment,
  caller :: Bytes) -> HybridSendOutcome do
  case hybrid_seal_candidate(he, pq, plaintext, fragment, caller) do
    Err(error) -> HybridSealRefused(he, pq, error)
    Ok((next_chain, candidate, message)) -> do
      let sent_count = he.sent_count + 1
      hybrid_discard_pq(pq)
      HybridSealed(%{he | sending_chain_key: next_chain, sent_count: sent_count},
        candidate,
        message)
    end
  end
end

fn hybrid_probe(he :: borrow RatchetState,
  pq :: borrow SpqrState,
  message :: TripleMessage,
  header_aad :: Bytes,
  name :: Bytes) -> Option<TripleHeader>!HybridError do
  if !SecretMap.contains(he.header_keys, name) do
    return Ok(None)
  end
  let material = case copied(he.header_keys, name) do
    Err(error) -> return Err(hybrid_ratchet_error(error))
    Ok(value) -> value
  end
  let key = case aead(material) do
    Err(error) -> return Err(hybrid_ratchet_error(error))
    Ok(value) -> value
  end
  case Crypto.xchacha20poly1305_open(key,
    message.header_nonce,
    header_aad,
    message.encrypted_header) do
    Err(AuthenticationFailed) -> Ok(None)
    Err(_) -> Err(HybridCryptoFailure)
    Ok(clear) -> case decode_triple_header(clear, pq.scope.configuration, he.session_id) do
      Err(_) -> Err(HybridInvalidMessage)
      Ok(value) -> Ok(Some(value))
    end
  end
end

fn hybrid_old_header(he :: borrow RatchetState,
  pq :: borrow SpqrState,
  message :: TripleMessage,
  header_aad :: Bytes,
  index :: Int,
  seen :: List<Bytes>) -> HybridHeaderMatch!HybridError do
  if index >= Bytes.length(he.skipped_index) do
    return Err(HybridAuthenticationRejected)
  end
  let public_key = case he_slice(he.skipped_index, index, 32) do
    Err(error) -> return Err(hybrid_ratchet_error(error))
    Ok(value) -> value
  end
  if List.any(seen, fn(value) do Bytes.secure_equals(value, public_key) end) do
    return hybrid_old_header(he, pq, message, header_aad, index + 40, seen)
  end
  let name = case old_id(public_key) do
    Err(error) -> return Err(hybrid_ratchet_error(error))
    Ok(value) -> value
  end
  case hybrid_probe(he, pq, message, header_aad, name)? do
    None -> hybrid_old_header(he,
      pq,
      message,
      header_aad,
      index + 40,
      List.append(seen, public_key))
    Some(header) -> if !Bytes.secure_equals(public_key, header.ec.ratchet_public_key.bytes) do
      Err(HybridInvalidMessage)
    else
      Ok(HybridHeaderMatch { header: header, next: false, old: true })
    end
  end
end

fn hybrid_find_header(he :: borrow RatchetState,
  pq :: borrow SpqrState,
  message :: TripleMessage,
  header_aad :: Bytes) -> HybridHeaderMatch!HybridError do
  case hybrid_probe(he, pq, message, header_aad, Bytes.from_utf8("receiving"))? do
    Some(header) -> if !Bytes.secure_equals(header.ec.ratchet_public_key.bytes,
      he.remote_ratchet_public.bytes) do
      Err(HybridInvalidMessage)
    else
      Ok(HybridHeaderMatch { header: header, next: false, old: false })
    end
    None -> case hybrid_probe(he, pq, message, header_aad, Bytes.from_utf8("next-receiving"))? do
      Some(header) -> if Bytes.secure_equals(header.ec.ratchet_public_key.bytes,
        he.remote_ratchet_public.bytes) do
        Err(HybridInvalidMessage)
      else
        Ok(HybridHeaderMatch { header: header, next: true, old: false })
      end
      None -> hybrid_old_header(he, pq, message, header_aad, 0, List.new())
    end
  end
end

fn hybrid_body_open(he :: borrow RatchetState,
  pq :: borrow SpqrState,
  ec :: consume SecretBytes,
  header :: TripleHeader,
  message :: TripleMessage,
  body_aad :: Bytes) -> (SpqrState, Bytes)!HybridError do
  let shadow = hybrid_fork_pq(pq)?
  let (candidate, quantum) = case spqr_receive_key(shadow,
    hybrid_epoch(header.fragment)?,
    header.pq_message_number) do
    SpqrKeyRefused(_, error) -> return Err(hybrid_spqr_error(error))
    SpqrKeyAccepted(state, key, _) -> (state, key)
  end
  let key = hybrid_body_key(he, pq, ec, quantum)?
  case Crypto.aead_open(key, message.nonce, body_aad, message.ciphertext) do
    Err(AuthenticationFailed) -> Err(HybridAuthenticationRejected)
    Err(_) -> Err(HybridCryptoFailure)
    Ok(clear) -> Ok((candidate, clear))
  end
end

fn hybrid_open_candidate(he :: borrow RatchetState,
  pq :: borrow SpqrState,
  message :: TripleMessage,
  caller :: Bytes) -> HybridReceiveCandidate!HybridError do
  hybrid_pair(he, pq)?
  case encode_triple_message(message) do
    Err(_) -> return Err(HybridInvalidMessage)
    Ok(_) -> nil
  end
  let header_aad = case triple_header_aad(pq.scope.configuration,
    he.session_id,
    Bytes.length(message.encrypted_header),
    caller) do
    Err(_) -> return Err(HybridInvalidMessage)
    Ok(value) -> value
  end
  let body_aad = case triple_body_aad(pq.scope.configuration, he.session_id, message, caller) do
    Err(_) -> return Err(HybridInvalidMessage)
    Ok(value) -> value
  end
  let found = hybrid_find_header(he, pq, message, header_aad)?
  let header = found.header
  let ec_header = header.ec
  let id = case key_id(ec_header.ratchet_public_key.bytes, ec_header.message_number) do
    Err(error) -> return Err(hybrid_ratchet_error(error))
    Ok(value) -> value
  end
  if SecretMap.contains(he.skipped_keys, id) do
    let SkippedReceivePrepared { id, material } = case skipped_receive_prepare(he, ec_header) do
      Err(error) -> return Err(hybrid_ratchet_error(error))
      Ok(value) -> value
    end
    let (candidate, clear) = hybrid_body_open(he, pq, material, header, message, body_aad)?
    let commit = case skipped_receive_finalize(he, ec_header, id, clear) do
      Err(error) -> return Err(hybrid_ratchet_error(error))
      Ok(value) -> value
    end
    return Ok(HybridCachedCandidate(commit, candidate, header))
  end
  if found.old || (!found.next && ec_header.message_number < he.received_count) do
    return Err(HybridReplay)
  end
  if ec_header.message_number >= 4294967295
    || (found.next && he.receive_generation >= 4294967295) do
    return Err(HybridCounterOverflow)
  end
  let old_gap = ec_header.previous_chain_length - he.received_count
  let excessive = if found.next do
    old_gap > 64
      || ec_header.message_number > 64
      || (old_gap > 0 && old_gap + ec_header.message_number > 64)
  else
    ec_header.message_number - he.received_count > 64
  end
  if excessive do
    return Err(HybridExcessiveJump)
  end
  if found.next do
    let NextReceivePrepared {
      receive_root,
      chain,
      material,
      next_receiving,
      candidate,
      has_receiving
    } = case next_receive_prepare(he, ec_header) do
      Err(error) -> return Err(hybrid_ratchet_error(error))
      Ok(value) -> value
    end
    let (quantum_candidate, clear) = hybrid_body_open(he, pq, material, header, message, body_aad)?
    let commit = case next_receive_finalize(he,
      ec_header,
      receive_root,
      chain,
      next_receiving,
      candidate,
      has_receiving,
      clear) do
      Err(error) -> return Err(hybrid_ratchet_error(error))
      Ok(value) -> value
    end
    Ok(HybridNextCandidate(commit, quantum_candidate, header))
  else
    let CurrentReceivePrepared { chain, material, candidate } = case current_receive_prepare(he,
      ec_header) do
      Err(error) -> return Err(hybrid_ratchet_error(error))
      Ok(value) -> value
    end
    let (quantum_candidate, clear) = hybrid_body_open(he, pq, material, header, message, body_aad)?
    let commit = case current_receive_finalize(he, ec_header, chain, candidate, clear) do
      Err(error) -> return Err(hybrid_ratchet_error(error))
      Ok(value) -> value
    end
    Ok(HybridCurrentCandidate(commit, quantum_candidate, header))
  end
end

pub fn he_decrypt_hybrid(he :: consume RatchetState,
  pq :: consume SpqrState,
  message :: TripleMessage,
  caller :: Bytes) -> HybridReceiveOutcome do
  case hybrid_open_candidate(he, pq, message, caller) do
    Err(error) -> HybridOpenRefused(he, pq, error)
    Ok(HybridCachedCandidate(commit, candidate, header)) -> do
      let SkippedCommit { skipped, headers, index, plaintext } = commit
      hybrid_discard_pq(pq)
      HybridOpened(%{he | skipped_keys: skipped, header_keys: headers, skipped_index: index},
        candidate,
        header,
        plaintext)
    end
    Ok(HybridCurrentCandidate(commit, candidate, header)) -> do
      let CurrentCommit { chain, skipped, headers, index, plaintext } = commit
      hybrid_discard_pq(pq)
      HybridOpened(%{he |
          receiving_chain_key: chain,
          received_count: header.ec.message_number + 1,
          skipped_keys: skipped,
          header_keys: headers,
          skipped_index: index
        },
        candidate,
        header,
        plaintext)
    end
    Ok(HybridNextCandidate(commit, candidate, header)) -> do
      let NewCommit {
        root,
        sending,
        receiving,
        private_key,
        public_key,
        skipped,
        headers,
        index,
        generation,
        plaintext
      } = commit
      let previous = he.sent_count
      hybrid_discard_pq(pq)
      HybridOpened(%{he |
          root_key: root,
          sending_chain_key: sending,
          receiving_chain_key: receiving,
          local_ratchet_private: private_key,
          local_ratchet_public: public_key,
          remote_ratchet_public: header.ec.ratchet_public_key,
          previous_chain_length: previous,
          sent_count: 0,
          received_count: header.ec.message_number + 1,
          skipped_keys: skipped,
          header_keys: headers,
          skipped_index: index,
          receive_generation: generation,
          pending_send_ratchet: false
        },
        candidate,
        header,
        plaintext)
    end
  end
end

pub fn he_initial_aad(session :: Bytes) -> Bytes!RatchetError do
  he_join([Bytes.from_utf8("mesh-msg/v2/he-initial"), session])
end

pub fn he_initialize_alice(root :: consume SecretBytes,
  suite :: Int,
  session :: Bytes,
  bootstrap :: X25519PublicKey,
  version :: U64) -> RatchetState!RatchetError do
  let headers = he_empty_headers()?
  he_replace_header(headers,
    Bytes.from_utf8("sending"),
    derive(root, session, Bytes.from_utf8("mesh-msg/v2/he-shared-hka"))?)?
  he_replace_header(headers,
    Bytes.from_utf8("next-receiving"),
    derive(root, session, Bytes.from_utf8("mesh-msg/v2/he-shared-nhkb"))?)?
  let unused_receiving = derive(root,
    session,
    Bytes.from_utf8("mesh-msg/v2/he-unstarted-receiving"))?
  let pair = case Crypto.x25519_generate() do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end?
  let dh = case Crypto.x25519_shared(pair.private_key, bootstrap) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end?
  let (next_root, sending, next_header) = he_root_step(root, dh, session, pair.public_key)?
  Secret.destroy(root)
  he_replace_header(headers, Bytes.from_utf8("next-sending"), next_header)?
  let skipped = case SecretMap.new(64) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end?
  Ok(RatchetState {
    version: 2,
    suite: suite,
    session_id: session,
    root_key: next_root,
    sending_chain_key: sending,
    receiving_chain_key: unused_receiving,
    local_ratchet_public: pair.public_key,
    local_ratchet_private: pair.private_key,
    remote_ratchet_public: bootstrap,
    previous_chain_length: 0,
    sent_count: 0,
    received_count: 0,
    skipped_keys: skipped,
    skipped_index: Bytes.empty(),
    receive_generation: 0,
    pending_send_ratchet: false,
    snapshot_version: version,
    header_keys: headers
  })
end

pub fn he_initialize_bob(root :: consume SecretBytes,
  suite :: Int,
  session :: Bytes,
  private_key :: consume X25519PrivateKey,
  public_key :: X25519PublicKey,
  version :: U64) -> RatchetState!RatchetError do
  let headers = he_empty_headers()?
  he_replace_header(headers,
    Bytes.from_utf8("next-receiving"),
    derive(root, session, Bytes.from_utf8("mesh-msg/v2/he-shared-hka"))?)?
  he_replace_header(headers,
    Bytes.from_utf8("next-sending"),
    derive(root, session, Bytes.from_utf8("mesh-msg/v2/he-shared-nhkb"))?)?
  # Signal's absent body chains are represented by opaque unreachable placeholders.
  # No chain operation is admitted until the corresponding header-key slot exists.
  let sending = derive(root, session, Bytes.from_utf8("mesh-msg/v2/he-unstarted-sending"))?
  let receiving = derive(root, session, Bytes.from_utf8("mesh-msg/v2/he-unstarted-receiving"))?
  let skipped = case SecretMap.new(64) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end?
  Ok(RatchetState {
    version: 2,
    suite: suite,
    session_id: session,
    root_key: root,
    sending_chain_key: sending,
    receiving_chain_key: receiving,
    local_ratchet_private: private_key,
    local_ratchet_public: public_key,
    remote_ratchet_public: X25519PublicKey { bytes: Bytes.empty() },
    previous_chain_length: 0,
    sent_count: 0,
    received_count: 0,
    skipped_keys: skipped,
    skipped_index: Bytes.empty(),
    receive_generation: 0,
    pending_send_ratchet: false,
    snapshot_version: version,
    header_keys: headers
  })
end
