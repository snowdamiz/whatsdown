from Session.State import RatchetState, DecryptOutcome, RatchetError, RatchetMessage
from Identity.Device import (
  AccountKeys,
  DeviceKeys,
  VerificationPolicy,
  generate_account,
  generate_device,
  issue_device_credential
)
from Prekeys.Bundle import (
  OneTimePrekeySecrets,
  PostQuantumPrekeySecrets,
  SignedPrekeySecrets,
  build_prekey_bundle,
  generate_one_time_prekey,
  generate_post_quantum_prekey,
  generate_signed_prekey
)
from Protocol.HandshakeWire import encode_initial_message
from Protocol.IdentityWire import encode_account_identity
from Protocol.V1 import AccountIdentity, DeviceCredential, InitialMessage, PrekeyBundle
from Session.Handshake import SessionError, initiate, receive_initial
from Session.Ratchet import (
  decode_ratchet_message,
  decrypt,
  encode_ratchet_message,
  encrypt,
  encrypt_sealed,
  ratchet_transport_matches
)
from Transport.Packet import TransportPacket, decode_packet, encode_packet
from Transport.Recipient import (
  is_recipient_packet,
  open_recipient_packet,
  recipient_packet_kind,
  seal_recipient_packet
)

fn wide(value :: String) -> U64!String do
  case U64.parse(value) do
    Err(_) -> Err("integer failed")
    Ok(parsed)
  end
end

fn repeated(value :: Int, length :: Int) -> Bytes!String do
  case Bytes.repeat(value, length) do
    Err(_) -> Err("test byte allocation failed")
    Ok(bytes)
  end
end

fn account(now :: U64) -> Result<(AccountKeys, AccountIdentity), String> do
  case generate_account(now, wide("1")?) do
    Err(_) -> Err("account failed")
    Ok(value)
  end
end

fn device() -> DeviceKeys!String do
  case generate_device() do
    Err(_) -> Err("device failed")
    Ok(value)
  end
end

fn credential(account_keys :: borrow AccountKeys,
  device_keys :: borrow DeviceKeys,
  now :: U64,
  expires :: U64) -> DeviceCredential!String do
  case issue_device_credential(account_keys, device_keys, wide("15")?, now, expires, wide("1")?) do
    Err(_) -> Err("credential failed")
    Ok(value)
  end
end

fn initiated(value :: Result<(RatchetState, InitialMessage), SessionError>) -> Result<(RatchetState, InitialMessage), String> do
  case value do
    Err(_) -> Err("initiation failed")
    Ok(started)
  end
end

fn received(value :: Result<(RatchetState, Bytes), SessionError>) -> Result<(RatchetState, Bytes), String> do
  case value do
    Err(_) -> Err("receive failed")
    Ok(opened)
  end
end

fn sealed_message(value :: Result<(RatchetState, RatchetMessage), RatchetError>) -> Result<(RatchetState, RatchetMessage), String> do
  case value do
    Err(_) -> Err("ratchet encryption failed")
    Ok(output)
  end
end

fn ratchet_packet(message :: RatchetMessage) -> Bytes!String do
  let encoded = case encode_ratchet_message(message) do
    Err(_) -> Err("ratchet encoding failed")
    Ok(value)
  end?
  encode_packet(RatchetPacket(encoded))
end

fn opened_plaintext(outcome :: consume DecryptOutcome) -> Bytes!String do
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

fn flipped_last(input :: Bytes) -> Bytes!String do
  let last = Bytes.get(input, Bytes.length(input) - 1)?
  let replacement = if last == 0 do
    1
  else
    0
  end
  Bytes.concat(Bytes.slice(input, 0, Bytes.length(input) - 1)?, repeated(replacement, 1)?)
end

fn rejected(value :: Bytes!String) -> Bool do
  case value do
    Err(_) -> true
    Ok(_) -> false
  end
end

fn proof() -> Bool!String do
  let now = wide("1700000000000")?
  let expires = wide("1700604800000")?
  let policy = VerificationPolicy { current_time: now, minimum_directory_sequence: wide("1")? }
  let (alice_account_keys, alice_account) = account(now)?
  let alice = device()?
  let alice_credential = credential(alice_account_keys, alice, now, expires)?
  let (bob_account_keys, bob_account) = account(now)?
  let bob = device()?
  let bob_credential = credential(bob_account_keys, bob, now, expires)?
  let bob_signed = case generate_signed_prekey(bob, bob_credential, wide("7")?, expires) do
    Err(_) -> Err("signed prekey failed")
    Ok(value)
  end?
  let bob_one_time = case generate_one_time_prekey(wide("9")?) do
    Err(_) -> Err("one-time prekey failed")
    Ok(value)
  end?
  let bob_post_quantum = case generate_post_quantum_prekey() do
    Err(_) -> Err("post-quantum prekey failed")
    Ok(value)
  end?
  let bob_bundle = case build_prekey_bundle(bob_credential, bob_signed, bob_one_time) do
    Err(_) -> Err("bundle failed")
    Ok(value)
  end?
  let (alice_state, initial) = initiated(initiate(alice,
    alice_credential,
    bob_account,
    bob_bundle,
    policy,
    0,
    Bytes.from_utf8("hello")))?
  let initial_bytes = case encode_initial_message(initial) do
    Err(_) -> Err("initial encoding failed")
    Ok(value)
  end?
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
    initial_bytes))?
  assert(initial.version == 2)
  assert(alice_state.version == 2)
  let aad = Bytes.from_utf8("conversation")
  let body = Bytes.from_utf8("who talks to whom is nobody else's business")
  let (alice_state, message) = sealed_message(encrypt_sealed(alice_state, body, aad))?
  assert(message.version == 4)
  let inner = ratchet_packet(message)?
  let session_hex = Bytes.to_hex(initial.transcript_hash)
  let ratchet_key_hex = Bytes.to_hex(alice_state.local_ratchet_public.bytes)
  # The leak being closed: a bare ratchet packet shows delivery a stable
  # session identifier that is identical in both directions of a conversation.
  # Baseline control: the recipient identity-only compromise can open RCP.
  if message.version == 3 do
    assert(String.contains(Bytes.to_hex(inner), session_hex))
  end
  let sealed = seal_recipient_packet(inner, bob.identity_public_key)?
  assert(is_recipient_packet(sealed))
  assert(!is_recipient_packet(inner))
  assert(!String.contains(Bytes.to_hex(sealed), session_hex))
  assert(!String.contains(Bytes.to_hex(sealed), ratchet_key_hex))
  assert(Bytes.length(sealed) == 512)
  # Two encryptions of one packet share nothing delivery could join on.
  let resealed = seal_recipient_packet(inner, bob.identity_public_key)?
  assert(!Bytes.secure_equals(Bytes.slice(sealed, 4, 32)?, Bytes.slice(resealed, 4, 32)?))
  let opened = open_recipient_packet(sealed, bob.identity_private_key)?
  assert(!String.contains(Bytes.to_hex(opened), session_hex))
  assert(!String.contains(Bytes.to_hex(opened), ratchet_key_hex))
  # Identity-only adversary has no root, chain, current/next header key or
  # one-time private prekey. Opening RCP must no longer expose a decodable SID.
  let hidden = case decode_packet(opened) do
    Err(_) -> false
    Ok(InitialPacket(_, _)) -> false
    Ok(RatchetPacket(wire)) -> case decode_ratchet_message(wire) do
      Err(_) -> false
      Ok(decoded) -> !Bytes.secure_equals(decoded.session_id, initial.transcript_hash)
        && Bytes.length(decoded.session_id) == 0
    end
  end
  let wire = case decode_packet(opened) do
    Ok(RatchetPacket(value)) -> value
    _ -> return Err("identity-only packet framing failed")
  end
  assert(Bytes.get(wire, 0)? == 4)
  let decoded = case decode_ratchet_message(wire) do
    Ok(value) -> value
    Err(_) -> return Err("HE wire decoding failed")
  end
  assert(Bytes.length(decoded.session_id) == 0)
  assert(hidden)
  discard(alice_state)
  discard(bob_state)
  Ok(true)
end

test("C4 identity-key-only compromise cannot read evolved HE ratchet headers") do
  assert(Result.unwrap_or(proof(), false))
end
