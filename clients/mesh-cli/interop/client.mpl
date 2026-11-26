from Identity.Device import (
  AccountKeys,
  DeviceKeys,
  VerificationPolicy,
  generate_account,
  generate_device,
  issue_hybrid_device_credential
)
from Prekeys.Bundle import (
  OneTimePrekeySecrets,
  PostQuantumPrekeySecrets,
  SignedPrekeySecrets,
  build_hybrid_prekey_bundle,
  generate_one_time_prekey,
  generate_post_quantum_prekey,
  generate_signed_prekey
)
from Protocol.EnvelopeWire import (
  decode_inner_envelope,
  decode_outer_envelope,
  encode_inner_envelope,
  encode_outer_envelope
)
from Protocol.HandshakeWire import decode_initial_message, encode_initial_message
from Protocol.IdentityWire import encode_account_identity
from Protocol.PrekeyWire import encode_prekey_bundle
from Protocol.V1 import (
  AccountIdentity,
  DeviceCredential,
  DirectoryEntry,
  InitialMessage,
  InnerEnvelope,
  OuterEnvelope,
  PrekeyBundle,
  ProtocolExtension
)
from Session.Handshake import RatchetState, initiate
from Session.Header import (
  ratchet_feature_header_encryption,
  ratchet_feature_post_quantum,
  ratchet_session_features_extension
)
from Session.Ratchet import (
  DecryptOutcome,
  RatchetError,
  RatchetMessage,
  decode_ratchet_message,
  decrypt,
  encode_ratchet_message,
  encrypt_sealed,
  ratchet_note_peer_features,
  ratchet_transport_matches
)
from Transport.Packet import (
  TransportPacket,
  decode_client_profile,
  decode_packet,
  direct_conversation_id,
  encode_client_profile,
  encode_initial_plaintext,
  encode_packet,
  session_aad
)
from Transport.Recipient import is_recipient_packet, open_recipient_packet, seal_recipient_packet

pub struct InteropSession do
  local_account_id :: Bytes
  local_device_id :: Bytes
  local_mailbox :: Bytes
  peer_account_id :: Bytes
  peer_device_id :: Bytes
  conversation_id :: Bytes
  session_id :: Bytes
  suite :: Int
end

pub type InteropOpenOutcome do
  ReplyOpened(state :: RatchetState, session :: InteropSession, body :: Bytes)
  ReplyRejected(state :: RatchetState, session :: InteropSession, error :: String)
end

pub fn interop_state_suite(state :: borrow RatchetState) -> Int do
  state.suite
end

pub fn interop_header_encrypted(state :: borrow RatchetState) -> Bool do
  state.header_encrypted
end

pub fn interop_pq_epoch(state :: borrow RatchetState) -> Int do
  state.pq_epoch
end

## What this client reads: ratchet message 4 and the post-quantum ratchet. It
## does not answer session resets, so it does not say it does.

fn session_features() -> List<ProtocolExtension>!String do
  let value = case Bytes.from_list([
    ratchet_feature_header_encryption() + ratchet_feature_post_quantum()
  ]) do
    Err(_) -> Err("interop feature encoding failed")
    Ok(encoded)
  end?
  Ok([
    ProtocolExtension { id: ratchet_session_features_extension(), mandatory: false, value: value }
  ])
end

fn peer_features(extensions :: List<ProtocolExtension>) -> Int do
  case List.find(extensions, fn value -> value.id == ratchet_session_features_extension() end) do
    None -> 0
    Some(extension) -> if Bytes.length(extension.value) != 1 do
      0
    else
      case Bytes.get(extension.value, 0) do
        Err(_) -> 0
        Ok(value) -> value
      end
    end
  end
end

fn discard_state(state :: consume RatchetState) do
  nil
end

pub fn opened_body(outcome :: InteropOpenOutcome) -> Bytes!String do
  case outcome do
    ReplyRejected(state, _, error) -> do
      discard_state(state)
      Err(error)
    end
    ReplyOpened(state, session, body) -> do
      let valid_suite = state.suite == 2 && session.suite == 2
      discard_state(state)
      if valid_suite do
        Ok(body)
      else
        Err("interop reply suite mismatch")
      end
    end
  end
end

fn wide(value :: String) -> U64!String do
  case U64.parse(value) do
    Err(_) -> Err("invalid interop integer")
    Ok(parsed)
  end
end

fn now() -> U64!String do
  wide(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn random(length :: Int) -> Bytes!String do
  case Crypto.random_bytes(length) do
    Err(_) -> Err("interop random generation failed")
    Ok(value)
  end
end

fn account(created_at :: U64) -> Result<(AccountKeys, AccountIdentity), String> do
  case generate_account(created_at, wide("1")?) do
    Err(_) -> Err("interop account generation failed")
    Ok(value)
  end
end

fn device() -> DeviceKeys!String do
  case generate_device() do
    Err(_) -> Err("interop device generation failed")
    Ok(value)
  end
end

fn post_quantum_prekey() -> PostQuantumPrekeySecrets!String do
  case generate_post_quantum_prekey() do
    Err(_) -> Err("interop post-quantum prekey generation failed")
    Ok(value)
  end
end

fn credential(account_keys :: borrow AccountKeys,
  device_keys :: borrow DeviceKeys,
  post_quantum :: borrow PostQuantumPrekeySecrets,
  created_at :: U64,
  expires_at :: U64) -> DeviceCredential!String do
  case issue_hybrid_device_credential(account_keys,
    device_keys,
    post_quantum.public_key,
    wide("1")?,
    created_at,
    expires_at,
    wide("1")?) do
    Err(_) -> Err("interop credential generation failed")
    Ok(value)
  end
end

fn signed_prekey(device_keys :: borrow DeviceKeys,
  value :: DeviceCredential,
  expires_at :: U64) -> SignedPrekeySecrets!String do
  case generate_signed_prekey(device_keys, value, wide("1")?, expires_at) do
    Err(_) -> Err("interop signed prekey generation failed")
    Ok(output)
  end
end

fn one_time_prekey() -> OneTimePrekeySecrets!String do
  case generate_one_time_prekey(wide("2")?) do
    Err(_) -> Err("interop one-time prekey generation failed")
    Ok(value)
  end
end

fn bundle(value :: DeviceCredential,
  signed :: borrow SignedPrekeySecrets,
  one_time :: borrow OneTimePrekeySecrets,
  post_quantum :: borrow PostQuantumPrekeySecrets) -> PrekeyBundle!String do
  case build_hybrid_prekey_bundle(value, signed, one_time, post_quantum) do
    Err(_) -> Err("interop prekey bundle generation failed")
    Ok(output)
  end
end

fn account_wire(value :: AccountIdentity) -> Bytes!String do
  case encode_account_identity(value) do
    Err(_) -> Err("interop account encoding failed")
    Ok(output)
  end
end

fn bundle_wire(value :: PrekeyBundle) -> Bytes!String do
  case encode_prekey_bundle(value) do
    Err(_) -> Err("interop prekey encoding failed")
    Ok(output)
  end
end

fn inner_wire(value :: InnerEnvelope) -> Bytes!String do
  case encode_inner_envelope(value) do
    Err(_) -> Err("interop inner encoding failed")
    Ok(output)
  end
end

fn initial_wire(value :: InitialMessage) -> Bytes!String do
  case encode_initial_message(value) do
    Err(_) -> Err("interop initial encoding failed")
    Ok(output)
  end
end

fn padding_bucket(length :: Int) -> Int!String do
  if length <= 256 do
    Ok(256)
  else if length <= 512 do
    Ok(512)
  else if length <= 1024 do
    Ok(1024)
  else if length <= 2048 do
    Ok(2048)
  else if length <= 4096 do
    Ok(4096)
  else if length <= 8192 do
    Ok(8192)
  else if length <= 16384 do
    Ok(16384)
  else if length <= 32768 do
    Ok(32768)
  else if length <= 65536 do
    Ok(65536)
  else
    Err("interop message too large")
  end
end

fn outer_wire(mailbox :: Bytes, suite :: Int, packet :: Bytes, timestamp :: U64) -> Bytes!String do
  let expiration = U64.add(timestamp, wide("2592000000")?)?
  case encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: random(16)?,
    mailbox_token: mailbox,
    suite: suite,
    expiration: expiration,
    padding_bucket: padding_bucket(Bytes.length(packet))?,
    ciphertext: packet
  }) do
    Err(_) -> Err("interop outer encoding failed")
    Ok(output)
  end
end

fn canonical_outer(input :: Bytes) -> OuterEnvelope!String do
  case decode_outer_envelope(input) do
    Err(_) -> Err("invalid interop outer envelope")
    Ok(value) -> case encode_outer_envelope(value) do
      Err(_) -> Err("invalid interop outer envelope")
      Ok(encoded) -> if Bytes.secure_equals(encoded, input) do
        Ok(value)
      else
        Err("noncanonical interop outer envelope")
      end
    end
  end
end

fn initial_matches(state :: borrow RatchetState,
  outer :: OuterEnvelope,
  peer_mailbox :: Bytes,
  local_account_wire :: Bytes) -> Bool!String do
  # Delivery sees only the sealed transport (outer suite 4), never suite 2.
  Ok(outer.suite == 4
    && state.suite == 2
    && is_recipient_packet(outer.ciphertext)
    && Bytes.secure_equals(outer.mailbox_token, peer_mailbox)
    && !String.contains(Bytes.to_hex(outer.ciphertext), Bytes.to_hex(local_account_wire)))
end

pub fn start_mobile_session(peer_profile :: Bytes,
  body :: Bytes) -> Result<(RatchetState, DeviceKeys, InteropSession, Bytes, Bytes), String> do
  let peer = decode_client_profile(peer_profile)?
  let created_at = now()?
  let expires_at = U64.add(created_at, wide("31536000000")?)?
  let (account_keys, account_identity) = account(created_at)?
  let device_keys = device()?
  let post_quantum = post_quantum_prekey()?
  let local_credential = credential(account_keys,
    device_keys,
    post_quantum,
    created_at,
    expires_at)?
  let signed = signed_prekey(device_keys, local_credential, expires_at)?
  let one_time = one_time_prekey()?
  let local_bundle = bundle(local_credential, signed, one_time, post_quantum)?
  let local_account_wire = account_wire(account_identity)?
  let local_mailbox = random(32)?
  let local_entry = DirectoryEntry {
    version: 1,
    username: "mesh-cli",
    account_identity: local_account_wire,
    prekey_bundle: bundle_wire(local_bundle)?,
    mailbox_token: local_mailbox
  }
  let local_profile = encode_client_profile(local_entry,
    account_identity.account_id,
    local_credential.device_id)?
  decode_client_profile(local_profile)?
  let conversation_id = direct_conversation_id(account_identity.account_id, peer.account_id)?
  let inner = InnerEnvelope {
    version: 1,
    sender_account_id: account_identity.account_id,
    sender_device_id: local_credential.device_id,
    recipient_device_id: peer.device_id,
    conversation_id: conversation_id,
    client_message_id: random(16)?,
    client_timestamp: created_at,
    message_type: 1,
    body: body,
    reply_reference: Bytes.empty(),
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: session_features()?
  }
  let plaintext = encode_initial_plaintext(local_profile, inner_wire(inner)?)?
  let (state, initial) = case initiate(device_keys,
    local_credential,
    peer.account,
    peer.bundle,
    VerificationPolicy {
      current_time: created_at,
      minimum_directory_sequence: peer.account.directory_sequence
    },
    0,
    plaintext) do
    Err(_) -> Err("interop session start failed")
    Ok(value)
  end?
  let packet = seal_recipient_packet(encode_packet(InitialPacket(local_account_wire,
      initial_wire(initial)?))?,
    X25519PublicKey { bytes: peer.credential.dh_public_key })?
  let outer = outer_wire(peer.entry.mailbox_token, 4, packet, created_at)?
  if !initial_matches(state,
    canonical_outer(outer)?,
    peer.entry.mailbox_token,
    local_account_wire)? do
    Err("interop initial invariants failed")
  else
    let session = InteropSession {
      local_account_id: account_identity.account_id,
      local_device_id: local_credential.device_id,
      local_mailbox: local_mailbox,
      peer_account_id: peer.account_id,
      peer_device_id: peer.device_id,
      conversation_id: conversation_id,
      session_id: state.session_id,
      suite: state.suite
    }
    Ok((state, device_keys, session, local_profile, outer))
  end
end

fn reject(state :: consume RatchetState,
  session :: InteropSession,
  error :: String) -> InteropOpenOutcome do
  ReplyRejected(state, session, error)
end

fn validate_reply_inner(value :: InnerEnvelope, session :: InteropSession) -> Bool do
  value.version == 1
    && value.message_type == 1
    && Bytes.secure_equals(value.sender_account_id, session.peer_account_id)
    && Bytes.secure_equals(value.sender_device_id, session.peer_device_id)
    && Bytes.secure_equals(value.recipient_device_id, session.local_device_id)
    && Bytes.secure_equals(value.conversation_id, session.conversation_id)
end

fn opened_reply_message(outer :: OuterEnvelope,
  recipient :: borrow DeviceKeys) -> RatchetMessage!String do
  let packet = case decode_packet(open_recipient_packet(outer.ciphertext,
    recipient.identity_private_key)?) do
    Err(_) -> Err("invalid interop ratchet packet")
    Ok(value)
  end?
  case packet do
    InitialPacket(_, _) -> Err("invalid interop ratchet packet")
    RatchetPacket(message_bytes) -> case decode_ratchet_message(message_bytes) do
      Err(_) -> Err("invalid interop ratchet message")
      Ok(message) -> if ratchet_transport_matches(message, true) do
        Ok(message)
      else
        Err("invalid interop ratchet message")
      end
    end
  end
end

# A version 4 message names no session: its header opens under this
# session's keys or not at all.

fn open_reply_message(state :: consume RatchetState,
  session :: InteropSession,
  message :: RatchetMessage) -> InteropOpenOutcome do
  let wrong_session = message.version != 4
    && (message.suite != 2
      || !Bytes.secure_equals(message.session_id, session.session_id)
      || !Bytes.secure_equals(message.session_id, state.session_id))
  if wrong_session do
    reject(state, session, "interop reply session mismatch")
  else
    case session_aad(state.session_id) do
      Err(error) -> reject(state, session, error)
      Ok(aad) -> case decrypt(state, message, aad) do
        Rejected(next, _) -> ReplyRejected(next, session, "interop reply rejected")
        Opened(next, plaintext) -> reply_outcome(next, session, plaintext)
      end
    end
  end
end

fn reply_outcome(state :: consume RatchetState,
  session :: InteropSession,
  plaintext :: Bytes) -> InteropOpenOutcome do
  case decode_inner_envelope(plaintext) do
    Err(_) -> ReplyRejected(state, session, "invalid interop reply inner envelope")
    Ok(inner) -> if validate_reply_inner(inner, session) do
      ReplyOpened(ratchet_note_peer_features(state, peer_features(inner.extensions)),
        session,
        inner.body)
    else
      ReplyRejected(state, session, "interop reply identity mismatch")
    end
  end
end

pub fn open_mobile_reply(state :: consume RatchetState,
  recipient :: borrow DeviceKeys,
  session :: InteropSession,
  input :: Bytes) -> InteropOpenOutcome do
  case canonical_outer(input) do
    Err(error) -> reject(state, session, error)
    Ok(outer) -> if outer.suite != 4
      || session.suite != 2
      || state.suite != 2
      || !Bytes.secure_equals(outer.mailbox_token, session.local_mailbox) do
      reject(state, session, "interop reply outer mismatch")
    else
      case opened_reply_message(outer, recipient) do
        Err(error) -> reject(state, session, error)
        Ok(message) -> open_reply_message(state, session, message)
      end
    end
  end
end

fn drop_sent(state :: consume RatchetState,
  error :: String) -> Result<(RatchetState, Bytes), String> do
  Err(error)
end

fn reply_outer(message :: RatchetMessage, peer_profile :: Bytes) -> Bytes!String do
  let peer = decode_client_profile(peer_profile)?
  let encoded = case encode_ratchet_message(message) do
    Err(_) -> Err("interop ratchet encoding failed")
    Ok(value)
  end?
  let sealed = seal_recipient_packet(encode_packet(RatchetPacket(encoded))?,
    X25519PublicKey { bytes: peer.credential.dh_public_key })?
  outer_wire(peer.entry.mailbox_token, 4, sealed, now()?)
end

fn sealed_reply(state :: consume RatchetState,
  message :: RatchetMessage,
  peer_profile :: Bytes) -> Result<(RatchetState, Bytes), String> do
  case reply_outer(message, peer_profile) do
    Err(error) -> drop_sent(state, error)
    Ok(outer) -> Ok((state, outer))
  end
end

## A message in the session, sealed to the mobile device. The session moves to
## ratchet message 4 at this client's next sending root step once the mobile
## side has said it reads it.

pub fn send_mobile_message(state :: consume RatchetState,
  session :: InteropSession,
  peer_profile :: Bytes,
  body :: Bytes) -> Result<(RatchetState, Bytes), String> do
  let inner = InnerEnvelope {
    version: 1,
    sender_account_id: session.local_account_id,
    sender_device_id: session.local_device_id,
    recipient_device_id: session.peer_device_id,
    conversation_id: session.conversation_id,
    client_message_id: random(16)?,
    client_timestamp: now()?,
    message_type: 1,
    body: body,
    reply_reference: Bytes.empty(),
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: session_features()?
  }
  let plaintext = inner_wire(inner)?
  let aad = session_aad(session.session_id)?
  case encrypt_sealed(state, plaintext, aad) do
    Err(_) -> Err("interop ratchet encryption failed")
    Ok(value) -> do
      let (next, message) = value
      sealed_reply(next, message, peer_profile)
    end
  end
end

pub fn close_interop_session(state :: consume RatchetState) do
  discard_state(state)
end

## The session after a reply, with the reply, to go on sending in it.

pub fn opened_reply(outcome :: InteropOpenOutcome) -> Result<(RatchetState, Bytes), String> do
  case outcome do
    ReplyRejected(state, _, error) -> do
      discard_state(state)
      Err(error)
    end
    ReplyOpened(state, _, body) -> Ok((state, body))
  end
end
