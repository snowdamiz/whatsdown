from Identity.Device import AccountKeys, DeviceKeys, VerificationPolicy, generate_account, generate_device, issue_device_credential
from Prekeys.Bundle import OneTimePrekeySecrets, PostQuantumPrekeySecrets, SignedPrekeySecrets, build_prekey_bundle, generate_one_time_prekey, generate_post_quantum_prekey, generate_signed_prekey
from Protocol.HandshakeWire import encode_initial_message
from Protocol.IdentityWire import encode_account_identity
from Protocol.V1 import AccountIdentity, DeviceCredential, InitialMessage, PrekeyBundle
from Session.Handshake import RatchetState, SessionError, initiate, receive_initial
from Session.Ratchet import (
  DecryptOutcome,
  RatchetError,
  RatchetMessage,
  decode_ratchet_message,
  decrypt,
  encode_ratchet_message,
  encrypt,
  encrypt_sealed,
  ratchet_transport_matches
)
from Transport.Packet import TransportPacket, encode_packet
from Transport.Recipient import is_recipient_packet, open_recipient_packet, recipient_packet_kind, seal_recipient_packet

fn wide(value :: String) -> U64 ! String do
  case U64.parse(value) do
    Err(_) -> Err("integer failed")
    Ok(parsed) -> Ok(parsed)
  end
end

fn repeated(value :: Int, length :: Int) -> Bytes ! String do
  case Bytes.repeat(value, length) do
    Err(_) -> Err("test byte allocation failed")
    Ok(bytes) -> Ok(bytes)
  end
end

fn account(now :: U64) -> Result <(AccountKeys, AccountIdentity), String > do
  case generate_account(now, wide("1") ?) do
    Err(_) -> Err("account failed")
    Ok(value) -> Ok(value)
  end
end

fn device() -> DeviceKeys ! String do
  case generate_device() do
    Err(_) -> Err("device failed")
    Ok(value) -> Ok(value)
  end
end

fn credential(account_keys :: borrow AccountKeys,
device_keys :: borrow DeviceKeys,
now :: U64,
expires :: U64) -> DeviceCredential ! String do
  case issue_device_credential(account_keys, device_keys, wide("1") ?, now, expires, wide("1") ?) do
    Err(_) -> Err("credential failed")
    Ok(value) -> Ok(value)
  end
end

fn initiated(value :: Result <(RatchetState, InitialMessage), SessionError >) -> Result <(RatchetState, InitialMessage), String > do
  case value do
    Err(_) -> Err("initiation failed")
    Ok(started) -> Ok(started)
  end
end

fn received(value :: Result <(RatchetState, Bytes), SessionError >) -> Result <(RatchetState, Bytes), String > do
  case value do
    Err(_) -> Err("receive failed")
    Ok(opened) -> Ok(opened)
  end
end

fn sealed_message(value :: Result <(RatchetState, RatchetMessage), RatchetError >) -> Result <(RatchetState, RatchetMessage), String > do
  case value do
    Err(_) -> Err("ratchet encryption failed")
    Ok(output) -> Ok(output)
  end
end

fn ratchet_packet(message :: RatchetMessage) -> Bytes ! String do
  let encoded = case encode_ratchet_message(message) do
    Err(_) -> Err("ratchet encoding failed")
    Ok(value) -> Ok(value)
  end ?
  encode_packet(RatchetPacket(encoded))
end

fn opened_plaintext(outcome :: consume DecryptOutcome) -> Bytes ! String do
  case outcome do
    Rejected(state, _) -> do
      discard(state)
      Err("ratchet decryption failed")
    end
    Opened(state, plaintext) -> do
      discard(state)
      Ok(plaintext)
    end
  end
end

fn discard(state :: consume RatchetState) do
  nil
end

fn flipped_last(input :: Bytes) -> Bytes ! String do
  let last = Bytes.get(input, Bytes.length(input) - 1) ?
  let replacement = if last == 0 do
    1
  else
    0
  end
  Bytes.concat(Bytes.slice(input, 0, Bytes.length(input) - 1) ?, repeated(replacement, 1) ?)
end

fn rejected(value :: Bytes ! String) -> Bool do
  case value do
    Err(_) -> true
    Ok(_) -> false
  end
end

fn proof() -> Bool ! String do
  let now = wide("1700000000000") ?
  let expires = wide("1700604800000") ?
  let policy = VerificationPolicy {
    current_time : now,
    minimum_directory_sequence : wide("1") ?
  }
  let (alice_account_keys, alice_account) = account(now) ?
  let alice = device() ?
  let alice_credential = credential(alice_account_keys, alice, now, expires) ?
  let (bob_account_keys, bob_account) = account(now) ?
  let bob = device() ?
  let bob_credential = credential(bob_account_keys, bob, now, expires) ?
  let bob_signed = case generate_signed_prekey(bob, bob_credential, wide("7") ?, expires) do
    Err(_) -> Err("signed prekey failed")
    Ok(value) -> Ok(value)
  end ?
  let bob_one_time = case generate_one_time_prekey(wide("9") ?) do
    Err(_) -> Err("one-time prekey failed")
    Ok(value) -> Ok(value)
  end ?
  let bob_post_quantum = case generate_post_quantum_prekey() do
    Err(_) -> Err("post-quantum prekey failed")
    Ok(value) -> Ok(value)
  end ?
  let bob_bundle = case build_prekey_bundle(bob_credential, bob_signed, bob_one_time) do
    Err(_) -> Err("bundle failed")
    Ok(value) -> Ok(value)
  end ?
  let (alice_state, initial) = initiated(initiate(alice,
  alice_credential,
  bob_account,
  bob_bundle,
  policy,
  0,
  Bytes.from_utf8("hello"))) ?
  let initial_bytes = case encode_initial_message(initial) do
    Err(_) -> Err("initial encoding failed")
    Ok(value) -> Ok(value)
  end ?
  let (bob_state, _greeting) = received(receive_initial(bob,
  bob_account,
  bob_bundle,
  bob_signed,
  bob_one_time,
  bob_post_quantum,
  alice_account,
  policy,
  policy,
  0,
  initial_bytes)) ?
  let aad = Bytes.from_utf8("conversation")
  let body = Bytes.from_utf8("who talks to whom is nobody else's business")
  let (alice_state, message) = sealed_message(encrypt_sealed(alice_state, body, aad)) ?
  assert(message.version == 3)
  let inner = ratchet_packet(message) ?
  let session_hex = Bytes.to_hex(message.session_id)
  let ratchet_key_hex = Bytes.to_hex(message.ratchet_public_key.bytes)
  # The leak being closed: a bare ratchet packet shows delivery a stable
  # session identifier that is identical in both directions of a conversation.
  assert(String.contains(Bytes.to_hex(inner), session_hex))
  let sealed = seal_recipient_packet(inner, bob.identity_public_key) ?
  assert(is_recipient_packet(sealed))
  assert(!is_recipient_packet(inner))
  assert(!String.contains(Bytes.to_hex(sealed), session_hex))
  assert(!String.contains(Bytes.to_hex(sealed), ratchet_key_hex))
  assert(Bytes.length(sealed) == 256)
  # Two encryptions of one packet share nothing delivery could join on.
  let resealed = seal_recipient_packet(inner, bob.identity_public_key) ?
  assert(!Bytes.secure_equals(Bytes.slice(sealed, 4, 32) ?, Bytes.slice(resealed, 4, 32) ?))
  let opened = open_recipient_packet(sealed, bob.identity_private_key) ?
  assert(Bytes.secure_equals(opened, inner))
  assert(rejected(open_recipient_packet(sealed, alice.identity_private_key)))
  assert(rejected(open_recipient_packet(flipped_last(sealed) ?, bob.identity_private_key)))
  assert(rejected(open_recipient_packet(inner, bob.identity_private_key)))
  # Delivery cannot tell an initial packet, a ratchet packet, or a group packet
  # apart; only the recipient learns the kind.
  assert(recipient_packet_kind(opened) == 2)
  let alice_identity = case encode_account_identity(alice_account) do
    Err(_) -> Err("account encoding failed")
    Ok(value) -> Ok(value)
  end ?
  let initial_inner = encode_packet(InitialPacket(alice_identity, initial_bytes)) ?
  assert(recipient_packet_kind(initial_inner) == 1)
  let initial_sealed = seal_recipient_packet(initial_inner, bob.identity_public_key) ?
  assert(Bytes.secure_equals(Bytes.slice(initial_sealed, 0, 4) ?, Bytes.slice(sealed, 0, 4) ?))
  assert(recipient_packet_kind(open_recipient_packet(initial_sealed, bob.identity_private_key) ?) == 1)
  assert(recipient_packet_kind(Bytes.concat(Bytes.from_hex("01475250") ?, repeated(7, 40) ?) ?) == 3)
  assert(recipient_packet_kind(Bytes.from_utf8("neither")) == 0)
  assert(recipient_packet_kind(Bytes.empty()) == 0)
  # Sealed ratchet messages carry no inner padding, and the unpadded form is
  # accepted only inside the sealed transport.
  let received_message = case decode_ratchet_message(message_bytes(opened) ?) do
    Err(_) -> Err("ratchet decoding failed")
    Ok(value) -> Ok(value)
  end ?
  assert(ratchet_transport_matches(received_message, true))
  assert(!ratchet_transport_matches(received_message, false))
  assert(Bytes.secure_equals(opened_plaintext(decrypt(bob_state, received_message, aad)) ?, body))
  let (alice_state, padded) = sealed_message(encrypt(alice_state, body, aad)) ?
  assert(padded.version == 2)
  assert(ratchet_transport_matches(padded, false))
  assert(!ratchet_transport_matches(padded, true))
  assert(ratchet_transport_matches(% {padded | version : 1 }, false))
  assert(!ratchet_transport_matches(% {padded | version : 1 }, true))
  discard(alice_state)
  # Only a size bucket is visible, up to the 65,536-byte envelope ceiling.
  assert(Bytes.length(seal_recipient_packet(repeated(1, 200) ?, bob.identity_public_key) ?) == 256)
  assert(Bytes.length(seal_recipient_packet(repeated(1, 201) ?, bob.identity_public_key) ?) == 512)
  assert(Bytes.length(seal_recipient_packet(repeated(1, 65480) ?, bob.identity_public_key) ?) == 65536)
  assert(rejected(seal_recipient_packet(repeated(1, 65481) ?, bob.identity_public_key)))
  assert(rejected(seal_recipient_packet(Bytes.empty(), bob.identity_public_key)))
  Ok(true)
end

fn message_bytes(packet :: Bytes) -> Bytes ! String do
  # M8P framing: version, magic, kind, empty account vector, then the message vector.
  Bytes.slice(packet, 13, Bytes.length(packet) - 13)
end

test("recipient-sealed packets hide the session, the ratchet header, and the packet kind from delivery") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
