from Identity.Device import (
  AccountKeys,
  DeviceKeys,
  VerificationPolicy,
  generate_account,
  generate_device,
  issue_device_credential,
  issue_hybrid_device_credential
)
from Prekeys.Bundle import (
  OneTimePrekeySecrets,
  PostQuantumPrekeySecrets,
  SignedPrekeySecrets,
  build_hybrid_prekey_bundle,
  build_prekey_bundle,
  generate_one_time_prekey,
  generate_post_quantum_prekey,
  generate_signed_prekey
)
from Protocol.HandshakeWire import encode_initial_message
from Protocol.V1 import AccountIdentity, DeviceCredential, InitialMessage, PrekeyBundle
from Session.Handshake import RatchetState, SessionError, initiate, receive_initial
from Session.Header import (
  RatchetHeader,
  ratchet_header_decode,
  ratchet_header_encode,
  ratchet_header_open,
  ratchet_header_seal_with_nonce,
  ratchet_root_v2,
  ratchet_upgrade_header_keys,
  ratchet_v4_plaintext_limit
)
from Session.Ratchet import (
  DecryptOutcome,
  RatchetError,
  RatchetMessage,
  decode_ratchet_message,
  decrypt,
  encode_ratchet_message,
  encrypt,
  encrypt_sealed,
  ratchet_header_matches,
  ratchet_jump_authentic,
  ratchet_note_peer_features,
  ratchet_transport_matches
)
from Session.Snapshot import SnapshotOutcome, restore, snapshot
from Tests.SnapshotV2Fixture import fixture_snapshot_v2
from Transport.Packet import TransportPacket, encode_packet
from Transport.Recipient import seal_recipient_packet

# Known answers for the version 4 key schedule. The expected bytes come from an
# independent derivation (OpenSSL's X25519, HKDF-SHA256 and ChaCha20-Poly1305
# through Node, `tests/fixtures/ratchet-v4/kat.mjs`) over the same fixed inputs.
# A secret cannot leave the runtime, so each derived key is compared by what it
# seals: "morse-kat" under a zero nonce and empty associated data.

fn counting(start :: Int, index :: Int, output :: List<Int>) -> List<Int> do
  if index >= 32 do
    output
  else
    counting(start, index + 1, List.append(output, start + index))
  end
end

fn seed(start :: Int) -> Bytes!String do
  case Bytes.from_list(counting(start, 0, List.new())) do
    Err(_) -> Err("seed failed")
    Ok(value)
  end
end

fn shared(first :: Int, second :: Int) -> SecretBytes!String do
  let local = case Crypto.x25519_from_seed(seed(first)?) do
    Err(_) -> Err("x25519 seed failed")
    Ok(value)
  end?
  let peer = case Crypto.x25519_from_seed(seed(second)?) do
    Err(_) -> Err("x25519 seed failed")
    Ok(value)
  end?
  case Crypto.x25519_shared(local.private_key, peer.public_key) do
    Err(_) -> Err("x25519 failed")
    Ok(value)
  end
end

fn public_key(start :: Int) -> X25519PublicKey!String do
  case Crypto.x25519_from_seed(seed(start)?) do
    Err(_) -> Err("x25519 seed failed")
    Ok(value) -> Ok(value.public_key)
  end
end

fn repeated(value :: Int, length :: Int) -> Bytes!String do
  case Bytes.repeat(value, length) do
    Err(_) -> Err("repeat failed")
    Ok(bytes)
  end
end

fn probe(key :: SecretBytes) -> String!String do
  let aead = case Crypto.aead_key(key) do
    Err(_) -> Err("aead key failed")
    Ok(value)
  end?
  case Crypto.aead_seal(aead, repeated(0, 12)?, Bytes.empty(), Bytes.from_utf8("morse-kat")) do
    Err(_) -> Err("probe seal failed")
    Ok(value) -> Ok(Bytes.to_hex(value))
  end
end

fn root_probes(combined :: SecretBytes, mix :: Int) -> List<String>!String do
  let root = shared(0, 32)?
  let (next_root, chain, header_key) = case ratchet_root_v2(root,
    combined,
    repeated(17, 32)?,
    public_key(64)?,
    mix) do
    Err(_) -> Err("root step failed")
    Ok(value)
  end?
  Ok([probe(next_root)?, probe(chain)?, probe(header_key)?])
end

fn hybrid_input() -> SecretBytes!String do
  case Secret.concat(shared(64, 96)?, shared(128, 160)?) do
    Err(_) -> Err("concat failed")
    Ok(value)
  end
end

fn schedule_proof() -> Bool!String do
  let classical = root_probes(shared(64, 96)?, 0)?
  assert(List.get(classical, 0) == "beefb7e6de3222ff3b10e697aa5925f883eca6513a83ef55fe")
  assert(List.get(classical, 1) == "0af9cfecb8ed1bca0f55e13ef8dab9a67ec80fa2f8c0584bf9")
  assert(List.get(classical, 2) == "a2c39b8542a0040cb53d587d565f0664fe189e7b811bcf49e1")
  let hybrid = root_probes(hybrid_input()?, 3)?
  assert(List.get(hybrid, 0) == "e7950c529fddba9f42bef113fe5bb30bf3a7a4497356052b3f")
  assert(List.get(hybrid, 1) == "34726aa064a2cfdb17ee8b8a91736b0d917f3a14f6440bf234")
  assert(List.get(hybrid, 2) == "aae8de054f7d003e9aab8929da1fb3073a3a093100fcc08c4c")
  let root = shared(0, 32)?
  let (first, second) = case ratchet_upgrade_header_keys(root, repeated(17, 32)?) do
    Err(_) -> Err("upgrade keys failed")
    Ok(value)
  end?
  assert(probe(first)? == "1a59ceac7050a254677f974d19d6c3b03f374eb6cd3a6c00a7")
  assert(probe(second)? == "107183f10fcf2bf1e4c3369f7d5d1572d81993305fd02e20c7")
  Ok(true)
end

test("version 4 root chain and upgrade keys match an independent derivation") do
  case schedule_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn kat_header() -> RatchetHeader!String do
  Ok(RatchetHeader {
    suite: 2,
    session_id: repeated(17, 32)?,
    ratchet_public_key: public_key(64)?,
    previous_chain_length: 7,
    message_number: 9,
    pq_mix: 0,
    pq_epoch: 1,
    pq_kind: 1,
    pq_first: 36,
    pq_units: repeated(171, 32)?
  })
end

fn header_proof() -> Bool!String do
  let header = kat_header()?
  let plain = case ratchet_header_encode(header) do
    Err(_) -> Err("header encoding failed")
    Ok(value)
  end?
  assert(Bytes.to_hex(plain) == "0002111111111111111111111111111111111111111111111111111111111111111179a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a00000007000000090000000000000001012401abababababababababababababababababababababababababababababababab")
  let key = shared(64, 96)?
  let nonce = case Bytes.from_hex("000102030405060708090a0b") do
    Err(_) -> Err("nonce failed")
    Ok(value)
  end?
  let blob = case ratchet_header_seal_with_nonce(key, nonce, plain) do
    Err(_) -> Err("header seal failed")
    Ok(value)
  end?
  assert(Bytes.to_hex(blob) == "000102030405060708090a0b0327c12fd780ea09f81d94136914b0775d53bee5818bc8b9f3af01c0eb4a69ba73e9ae4cc78112f7f2a359c4622d0dfc70c9e15141c529405baff17d9d276a5bd41e2d9a4faf29dc6e7c9b95000caaea19f689fe9530160450bc0d849ecb2f12cecb920da2296aa20487bb8328b3926eaa11a4ef1bfef87e71a8b9c571cb16f6578d5eb7b0")
  let opened = case ratchet_header_open(key, blob) do
    Err(_) -> Err("header open failed")
    Ok(value)
  end?
  let decoded = case ratchet_header_decode(opened) do
    Err(_) -> Err("header decoding failed")
    Ok(value)
  end?
  assert(decoded.message_number == 9 && decoded.pq_first == 36 && decoded.pq_kind == 1)
  # Another key, or one flipped bit anywhere, opens nothing.
  let other = shared(0, 32)?
  case ratchet_header_open(other, blob) do
    Ok(_) -> assert(false)
    Err(_) -> assert(true)
  end
  let flipped = case Bytes.from_hex("000102030405060708090a0b0327c12fd780ea09f81d94136914b0775d53bee5818bc8b9f3af01c0eb4a69ba73e9ae4cc78112f7f2a359c4622d0dfc70c9e15141c529405baff17d9d276a5bd41e2d9a4faf29dc6e7c9b95000caaea19f689fe9530160450bc0d849ecb2f12cecb920da2296aa20487bb8328b3926eaa11a4ef1bfef87e71a8b9c571cb16f6578d5eb7b1") do
    Err(_) -> Err("flipped failed")
    Ok(value)
  end?
  case ratchet_header_open(key, flipped) do
    Ok(_) -> assert(false)
    Err(_) -> assert(true)
  end
  # A run longer than its whole set is not a header.
  case ratchet_header_encode(%{header | pq_first: 36, pq_units: repeated(171, 38 * 32)?}) do
    Ok(_) -> assert(false)
    Err(_) -> assert(true)
  end
  Ok(true)
end

test("version 4 header seals to known bytes and rejects other keys and damage") do
  case header_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

# Sessions, as the handshake makes them.

fn wide(value :: String) -> U64!String do
  case U64.parse(value) do
    Err(_) -> Err("integer failed")
    Ok(parsed)
  end
end

fn now() -> U64!String do
  wide("1700000000000")
end

fn expiry() -> U64!String do
  wide("1700604800000")
end

fn account() -> Result<(AccountKeys, AccountIdentity), String> do
  case generate_account(now()?, wide("1")?) do
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

fn post_quantum() -> PostQuantumPrekeySecrets!String do
  case generate_post_quantum_prekey() do
    Err(_) -> Err("post-quantum prekey failed")
    Ok(value)
  end
end

fn credential(account_keys :: borrow AccountKeys,
  device_keys :: borrow DeviceKeys,
  post_quantum_keys :: borrow PostQuantumPrekeySecrets,
  hybrid :: Bool) -> DeviceCredential!String do
  let issued = if hybrid do
    issue_hybrid_device_credential(account_keys,
      device_keys,
      post_quantum_keys.public_key,
      wide("3")?,
      now()?,
      expiry()?,
      wide("1")?)
  else
    issue_device_credential(account_keys, device_keys, wide("1")?, now()?, expiry()?, wide("1")?)
  end
  case issued do
    Err(_) -> Err("credential failed")
    Ok(value)
  end
end

fn policy() -> VerificationPolicy!String do
  Ok(VerificationPolicy { current_time: now()?, minimum_directory_sequence: wide("1")? })
end

fn bundle(value :: DeviceCredential,
  signed :: borrow SignedPrekeySecrets,
  one_time :: borrow OneTimePrekeySecrets,
  post_quantum_keys :: borrow PostQuantumPrekeySecrets,
  hybrid :: Bool) -> PrekeyBundle!String do
  let built = if hybrid do
    build_hybrid_prekey_bundle(value, signed, one_time, post_quantum_keys)
  else
    build_prekey_bundle(value, signed, one_time)
  end
  case built do
    Err(_) -> Err("bundle failed")
    Ok(result)
  end
end

fn initial_wire(value :: InitialMessage) -> Bytes!String do
  case encode_initial_message(value) do
    Err(_) -> Err("initial encoding failed")
    Ok(encoded)
  end
end

fn pair(hybrid :: Bool) -> Result<(RatchetState, RatchetState), String> do
  let (initiator_keys, initiator_account) = account()?
  let initiator_device = device()?
  let initiator_post_quantum = post_quantum()?
  let initiator_credential = credential(initiator_keys,
    initiator_device,
    initiator_post_quantum,
    hybrid)?
  let (responder_keys, responder_account) = account()?
  let responder_device = device()?
  let responder_post_quantum = post_quantum()?
  let responder_credential = credential(responder_keys,
    responder_device,
    responder_post_quantum,
    hybrid)?
  let signed = case generate_signed_prekey(responder_device,
    responder_credential,
    wide("7")?,
    expiry()?) do
    Err(_) -> Err("signed prekey failed")
    Ok(value)
  end?
  let one_time = case generate_one_time_prekey(wide("9")?) do
    Err(_) -> Err("one-time prekey failed")
    Ok(value)
  end?
  let responder_bundle = bundle(responder_credential,
    signed,
    one_time,
    responder_post_quantum,
    hybrid)?
  let (initiator, initial) = case initiate(initiator_device,
    initiator_credential,
    responder_account,
    responder_bundle,
    policy()?,
    0,
    Bytes.from_utf8("hello")) do
    Err(_) -> Err("initiation failed")
    Ok(value)
  end?
  let (responder, _) = case receive_initial(responder_device,
    responder_account,
    responder_bundle,
    signed,
    one_time,
    responder_post_quantum,
    initiator_account,
    policy()?,
    policy()?,
    0,
    initial_wire(initial)?) do
    Err(_) -> Err("receive failed")
    Ok(value)
  end?
  Ok((initiator, responder))
end

fn aad() -> Bytes do
  Bytes.from_utf8("conversation")
end

fn drop_state(state :: consume RatchetState) do
  nil
end

fn drop_states(first :: consume RatchetState, second :: consume RatchetState) do
  nil
end

fn fail_with(state :: consume RatchetState,
  error :: String) -> Result<(RatchetState, RatchetMessage), String> do
  Err(error)
end

## Every message goes through the wire codec, as it would in a packet.

fn post(state :: consume RatchetState,
  text :: Bytes) -> Result<(RatchetState, RatchetMessage), String> do
  case encrypt_sealed(state, text, aad()) do
    Err(_) -> Err("send failed")
    Ok(value) -> do
      let (next, message) = value
      case encode_ratchet_message(message) do
        Err(_) -> fail_with(next, "encoding failed")
        Ok(encoded) -> case decode_ratchet_message(encoded) do
          Err(_) -> fail_with(next, "decoding failed")
          Ok(decoded) -> Ok((next, decoded))
        end
      end
    end
  end
end

fn accept(state :: consume RatchetState,
  message :: RatchetMessage,
  text :: Bytes) -> RatchetState!String do
  case decrypt(state, message, aad()) do
    Rejected(next, _) -> do
      drop_state(next)
      Err("receive failed")
    end
    Opened(next, plaintext) -> if Bytes.secure_equals(plaintext, text) do
      Ok(next)
    else
      drop_state(next)
      Err("wrong plaintext")
    end
  end
end

## A rejected message leaves the session as it was: it is handed back.

fn refused(state :: consume RatchetState,
  message :: RatchetMessage) -> Result<(RatchetState, RatchetError), String> do
  case decrypt(state, message, aad()) do
    Rejected(next, error) -> Ok((next, error))
    Opened(next, _) -> do
      drop_state(next)
      Err("a message that should be refused opened")
    end
  end
end

fn text(value :: Int, length :: Int) -> Bytes!String do
  repeated(65 + value % 26, length)
end

fn classic_proof() -> Bool!String do
  let (initiator, responder) = pair(true)?
  let (responder, reply) = post(responder, text(1, 40)?)?
  assert(reply.version == 3)
  let initiator = accept(initiator, reply, text(1, 40)?)?
  let (initiator, first) = post(initiator, text(2, 40)?)?
  assert(first.version == 3)
  let responder = accept(responder, first, text(2, 40)?)?
  let (responder, second) = post(responder, text(3, 40)?)?
  # Neither side has heard the other read version 4: both stay on version 3.
  assert(second.version == 3 && !responder.header_encrypted)
  let initiator = accept(initiator, second, text(3, 40)?)?
  drop_states(initiator, responder)
  Ok(true)
end

test("a session stays on version 3 until the peer says it reads version 4") do
  case classic_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn upgrade_proof() -> Bool!String do
  let (initiator, responder) = pair(true)?
  let (responder, reply) = post(responder, text(1, 40)?)?
  let initiator = accept(initiator, reply, text(1, 40)?)?
  # Only the initiator has heard: it upgrades at its next sending root step.
  # The responder reads the upgrade without having heard anything itself.
  let initiator = ratchet_note_peer_features(initiator, 7)
  let (initiator, upgraded) = post(initiator, text(2, 40)?)?
  assert(upgraded.version == 4 && initiator.header_encrypted)
  assert(ratchet_header_matches(responder, upgraded))
  let encoded = case encode_ratchet_message(upgraded) do
    Err(_) -> Err("encoding failed")
    Ok(value)
  end?
  # The session ID and the ratchet key are nowhere in the message.
  assert(!String.contains(Bytes.to_hex(encoded), Bytes.to_hex(initiator.session_id)))
  assert(!String.contains(Bytes.to_hex(encoded),
    Bytes.to_hex(initiator.local_ratchet_public.bytes)))
  assert(!ratchet_transport_matches(upgraded, false) && ratchet_transport_matches(upgraded, true))
  let responder = accept(responder, upgraded, text(2, 40)?)?
  assert(responder.header_encrypted)
  let (responder, answer) = post(responder, text(3, 40)?)?
  assert(answer.version == 4)
  let initiator = accept(initiator, answer, text(3, 40)?)?
  # A session that encrypts headers never sends a bare version again.
  case encrypt(initiator, text(4, 40)?, aad()) do
    Ok(value) -> do
      let (unexpected, _) = value
      drop_states(unexpected, responder)
      assert(false)
    end
    Err(_) -> drop_state(responder)
  end
  Ok(true)
end

test("either side upgrades to version 4 at its next sending root step and never goes back") do
  case upgrade_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn upgraded_pair() -> Result<(RatchetState, RatchetState), String> do
  let (initiator, responder) = pair(true)?
  let (responder, reply) = post(responder, text(1, 40)?)?
  let initiator = accept(initiator, reply, text(1, 40)?)?
  Ok((ratchet_note_peer_features(initiator, 7), ratchet_note_peer_features(responder, 7)))
end

## Three messages one way: the second is lost, the third arrives first.

fn volley(sender :: consume RatchetState,
  receiver :: consume RatchetState,
  round :: Int,
  length :: Int) -> Result<(RatchetState, RatchetState), String> do
  let (sender, first) = post(sender, text(round, length)?)?
  let (sender, _) = post(sender, text(round + 1, length)?)?
  let (sender, third) = post(sender, text(round + 2, length)?)?
  let receiver = accept(receiver, third, text(round + 2, length)?)?
  let receiver = accept(receiver, first, text(round, length)?)?
  Ok((sender, receiver))
end

fn conversation(first :: consume RatchetState,
  second :: consume RatchetState,
  round :: Int,
  rounds :: Int,
  length :: Int) -> Result<(RatchetState, RatchetState), String> do
  if round >= rounds do
    Ok((first, second))
  else
    let (first, second) = volley(first, second, round * 6, length)?
    let (second, first) = volley(second, first, round * 6 + 3, length)?
    conversation(first, second, round + 1, rounds, length)
  end
end

fn post_quantum_proof() -> Bool!String do
  let (initiator, responder) = upgraded_pair()?
  # 298-byte messages sit in the 1,024-byte bucket with room for 15 units. An
  # epoch takes about six rounds here: the key and the ciphertext each need
  # three volleys with a message lost in every one, and the secret is mixed at
  # the owner's next sending root step.
  let (initiator, responder) = conversation(initiator, responder, 0, 16, 298)?
  # Each epoch mixed an ML-KEM secret into both roots, or the later messages
  # would not have opened. Losing every second message only slowed it down.
  assert(initiator.pq_epoch >= 3 && responder.pq_epoch >= 3)
  let (initiator, last) = post(initiator, text(9, 298)?)?
  let responder = accept(responder, last, text(9, 298)?)?
  drop_states(initiator, responder)
  Ok(true)
end

test("the post-quantum ratchet completes epochs through loss and reordering") do
  case post_quantum_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn tight_proof() -> Bool!String do
  let (initiator, responder) = upgraded_pair()?
  # A message that fills its bucket carries no units, and the exchange waits.
  let (initiator, responder) = conversation(initiator, responder, 0, 2, 33)?
  assert(initiator.pq_epoch <= 1 && responder.pq_epoch <= 1)
  drop_states(initiator, responder)
  let (initiator, responder) = pair(false)?
  let (responder, reply) = post(responder, text(1, 40)?)?
  let initiator = accept(initiator, reply, text(1, 40)?)?
  let initiator = ratchet_note_peer_features(initiator, 7)
  let responder = ratchet_note_peer_features(responder, 7)
  let (initiator, responder) = conversation(initiator, responder, 0, 3, 298)?
  # A classical session encrypts its headers but never starts the ratchet.
  assert(initiator.header_encrypted && initiator.pq_epoch == 0 && responder.pq_epoch == 0)
  drop_states(initiator, responder)
  Ok(true)
end

test("units only use padding, and classical sessions never start the ratchet") do
  case tight_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn bucket_for(length :: Int, candidate :: Int) -> Int do
  if length <= candidate do
    candidate
  else
    bucket_for(length, candidate * 2)
  end
end

fn sealed_size(message :: RatchetMessage) -> Int!String do
  let encoded = case encode_ratchet_message(message) do
    Err(_) -> Err("encoding failed")
    Ok(value)
  end?
  let recipient = case Crypto.x25519_generate() do
    Err(_) -> Err("recipient failed")
    Ok(value)
  end?
  let sealed = seal_recipient_packet(encode_packet(RatchetPacket(encoded))?, recipient.public_key)?
  Ok(Bytes.length(sealed))
end

fn sizes(state :: consume RatchetState,
  lengths :: List<Int>,
  index :: Int) -> RatchetState!String do
  if index >= List.length(lengths) do
    Ok(state)
  else
    let length = List.get(lengths, index)
    let (state, message) = post(state, text(index, length)?)?
    # Where the message would be without units: 222 bytes of framing around it.
    let expected = bucket_for(222 + length, 256)
    let size = sealed_size(message)?
    if size != expected do
      drop_state(state)
      Err("#{length}-byte message sealed to #{size}, not #{expected}")
    else
      sizes(state, lengths, index + 1)
    end
  end
end

fn padding_proof() -> Bool!String do
  let (initiator, responder) = upgraded_pair()?
  # The initiator owns epoch 1 and sends key units with every message until a
  # ciphertext unit comes back, which it never does here.
  let initiator = sizes(initiator,
    [1, 34, 35, 66, 120, 290, 298, 301, 500, 777, 802, 1800, 4000],
    0)?
  assert(initiator.pq_phase == 1)
  let (initiator, largest) = post(initiator, text(3, ratchet_v4_plaintext_limit())?)?
  assert(sealed_size(largest)? == 65536)
  case encrypt_sealed(initiator, text(3, ratchet_v4_plaintext_limit() + 1)?, aad()) do
    Ok(value) -> do
      let (unexpected, _) = value
      drop_states(unexpected, responder)
      assert(false)
    end
    Err(_) -> drop_state(responder)
  end
  Ok(true)
end

test("units ride in the padding a message has anyway, and the largest message still fits") do
  case padding_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn flipped(value :: Bytes, index :: Int) -> Bytes!String do
  let byte = case Bytes.get(value, index) do
    Err(_) -> Err("byte failed")
    Ok(found)
  end?
  let replacement = case Bytes.from_list([
    if byte == 0 do
      1
    else
      0
    end
  ]) do
    Err(_) -> Err("byte failed")
    Ok(found)
  end?
  let head = case Bytes.slice(value, 0, index) do
    Err(_) -> Err("slice failed")
    Ok(found)
  end?
  let tail = case Bytes.slice(value, index + 1, Bytes.length(value) - index - 1) do
    Err(_) -> Err("slice failed")
    Ok(found)
  end?
  case Bytes.concat(head, replacement) do
    Err(_) -> Err("concat failed")
    Ok(joined) -> case Bytes.concat(joined, tail) do
      Err(_) -> Err("concat failed")
      Ok(found)
    end
  end
end

fn forged_proof() -> Bool!String do
  let (initiator, responder) = upgraded_pair()?
  let (initiator, first) = post(initiator, text(2, 40)?)?
  let (initiator, second) = post(initiator, text(3, 40)?)?
  # A garbled header opens under no key: nothing to try, nothing changed.
  let garbled = %{first | encrypted_header: flipped(first.encrypted_header, 30)?}
  assert(!ratchet_header_matches(responder, garbled))
  let (responder, error) = refused(responder, garbled)?
  assert(error == InvalidMessage)
  # A genuine header moved onto another body fails the body's authentication.
  let moved = %{second | encrypted_header: first.encrypted_header}
  let (responder, error) = refused(responder, moved)?
  assert(error == AuthenticationRejected)
  let responder = accept(responder, second, text(3, 40)?)?
  let responder = accept(responder, first, text(2, 40)?)?
  let (_, error) = refused(responder, first)?
  assert(error == Replay)
  # Another session's message opens under none of this session's keys.
  let (other_initiator, other_responder) = upgraded_pair()?
  let (other_initiator, foreign) = post(other_initiator, text(4, 40)?)?
  assert(!ratchet_header_matches(initiator, foreign))
  let (initiator, error) = refused(initiator, foreign)?
  assert(error == InvalidMessage)
  drop_states(initiator, other_responder)
  drop_state(other_initiator)
  Ok(true)
end

test("garbled, moved and foreign headers are refused and the session goes on") do
  case forged_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn skipped_proof() -> Bool!String do
  let (initiator, responder) = upgraded_pair()?
  let (initiator, first) = post(initiator, text(2, 40)?)?
  let (initiator, second) = post(initiator, text(3, 40)?)?
  let (initiator, third) = post(initiator, text(4, 40)?)?
  let responder = accept(responder, third, text(4, 40)?)?
  let (responder, answer) = post(responder, text(5, 40)?)?
  let initiator = accept(initiator, answer, text(5, 40)?)?
  let (initiator, next_chain) = post(initiator, text(6, 40)?)?
  let responder = accept(responder, next_chain, text(6, 40)?)?
  # The first chain is an earlier chain now: its header key stayed for the two
  # messages still missing from it.
  assert(Bytes.length(responder.header_key_owners) == 32)
  let responder = accept(responder, second, text(3, 40)?)?
  let responder = accept(responder, first, text(2, 40)?)?
  # Its last skipped key used, the chain's header key is gone too.
  assert(Bytes.length(responder.header_key_owners) == 0)
  let (responder, _) = refused(responder, first)?
  drop_states(initiator, responder)
  Ok(true)
end

test("header keys of earlier chains open late messages, then go with the last one") do
  case skipped_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn many(state :: consume RatchetState,
  count :: Int) -> Result<(RatchetState, RatchetMessage), String> do
  let (state, message) = post(state, text(count, 40)?)?
  if count <= 1 do
    Ok((state, message))
  else
    many(state, count - 1)
  end
end

fn jump_proof(upgrade :: Bool) -> Bool!String do
  let (initiator, responder) = if upgrade do
    upgraded_pair()
  else
    pair(true)
  end?
  let (initiator, _) = post(initiator, text(1, 40)?)?
  # 69 more messages are lost; the 70th is too far ahead to keep keys for.
  let (initiator, far) = many(initiator, 69)?
  assert(far.version == if upgrade do
      4
    else
      3
    end)
  let (responder, error) = refused(responder, far)?
  assert(error == ExcessiveJump)
  # It is genuine, which is what lets the receiver ask for a new session.
  assert(ratchet_jump_authentic(responder, far, aad()))
  assert(!ratchet_jump_authentic(responder, far, Bytes.from_utf8("another conversation")))
  let forged = if upgrade do
    %{far | encrypted_header: flipped(far.encrypted_header, 20)?}
  else
    %{far | message_number: 90}
  end
  assert(!ratchet_jump_authentic(responder, forged, aad()))
  drop_states(initiator, responder)
  Ok(true)
end

fn long_jump_proof() -> Bool!String do
  let (initiator, responder) = pair(true)?
  let (initiator, _) = post(initiator, text(1, 40)?)?
  let (initiator, far) = many(initiator, 3000)?
  assert(ratchet_jump_authentic(responder, far, aad()))
  # A cleartext header claiming more than the limit costs nothing to refuse.
  assert(!ratchet_jump_authentic(responder, %{far | message_number: 20000}, aad()))
  drop_states(initiator, responder)
  Ok(true)
end

test("a jump past the skip limit is checked for authenticity before anything else") do
  case jump_proof(false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
  case jump_proof(true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
  case long_jump_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn owner_account() -> Bytes!String do
  repeated(33, 32)
end

fn owner_device() -> Bytes!String do
  repeated(34, 16)
end

fn stored(state :: consume RatchetState,
  key :: borrow StorageKey,
  version :: String) -> Bytes!String do
  case snapshot(state, key, owner_account()?, owner_device()?, wide(version)?) do
    SnapshotRejected(rejected, _) -> do
      drop_state(rejected)
      Err("snapshot failed")
    end
    SnapshotSealed(sealed_state, blob) -> do
      drop_state(sealed_state)
      Ok(blob)
    end
  end
end

fn restored(blob :: Bytes, key :: borrow StorageKey) -> RatchetState!String do
  case restore(blob, key, owner_account()?, owner_device()?, wide("1")?) do
    Err(_) -> Err("restore failed")
    Ok(state)
  end
end

fn format(blob :: Bytes) -> Int!String do
  case Bytes.get(blob, 0) do
    Err(_) -> Err("empty snapshot")
    Ok(value)
  end
end

fn storage_key() -> StorageKey!String do
  case StorageKey.ephemeral() do
    Err(_) -> Err("storage key failed")
    Ok(key)
  end
end

fn snapshot_proof() -> Bool!String do
  let key = storage_key()?
  let (initiator, responder) = upgraded_pair()?
  let (initiator, responder) = conversation(initiator, responder, 0, 3, 298)?
  # Mid-epoch: seeds, collected units and a secret waiting to be mixed.
  assert(initiator.pq_phase != 0 || responder.pq_phase != 0)
  let initiator_blob = stored(initiator, key, "2")?
  let responder_blob = stored(responder, key, "2")?
  assert(format(initiator_blob)? == 3 && format(responder_blob)? == 3)
  # The version 3 fields are in the authenticated header: a changed phase or
  # feature byte unseals nothing.
  let index_length = case Bytes.read_u32_be(initiator_blob, 127) do
    Err(_) -> Err("index length failed")
    Ok(value) -> case U64.to_int(value) do
      Err(_) -> Err("index length failed")
      Ok(number)
    end
  end?
  case restore(flipped(initiator_blob, 131 + index_length)?,
    key,
    owner_account()?,
    owner_device()?,
    wide("1")?) do
    Ok(unexpected) -> do
      drop_state(unexpected)
      assert(false)
    end
    Err(_) -> assert(true)
  end
  let initiator = restored(initiator_blob, key)?
  let responder = restored(responder_blob, key)?
  assert(initiator.header_encrypted && responder.header_encrypted)
  let (initiator, responder) = conversation(initiator, responder, 0, 14, 298)?
  assert(initiator.pq_epoch >= 3 && responder.pq_epoch >= 3)
  drop_states(initiator, responder)
  Ok(true)
end

test("a version 3 snapshot keeps header keys and the post-quantum ratchet mid-epoch") do
  case snapshot_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn migration_proof() -> Bool!String do
  let key = storage_key()?
  let (initiator, responder) = pair(true)?
  let (initiator, early) = post(initiator, text(1, 40)?)?
  let (initiator, late) = post(initiator, text(2, 40)?)?
  let responder = accept(responder, late, text(2, 40)?)?
  # A session as version 2 wrote it, with a key kept for the missing message.
  let old_blob = fixture_snapshot_v2(responder, key, owner_account()?, owner_device()?, wide("5")?)?
  drop_state(responder)
  assert(format(old_blob)? == 2)
  let responder = restored(old_blob, key)?
  assert(!responder.header_encrypted && responder.peer_features == 0)
  let responder = accept(responder, early, text(1, 40)?)?
  # It upgrades like any other session once both sides have spoken.
  let (responder, reply) = post(responder, text(3, 40)?)?
  let initiator = accept(initiator, reply, text(3, 40)?)?
  let initiator = ratchet_note_peer_features(initiator, 7)
  let responder = ratchet_note_peer_features(responder, 7)
  let (initiator, responder) = conversation(initiator, responder, 0, 2, 298)?
  assert(initiator.header_encrypted && responder.header_encrypted)
  # And is written back as version 3.
  let rewritten = stored(responder, key, "6")?
  assert(format(rewritten)? == 3)
  let responder = restored(rewritten, key)?
  let (initiator, next) = post(initiator, text(4, 298)?)?
  let responder = accept(responder, next, text(4, 298)?)?
  drop_states(initiator, responder)
  Ok(true)
end

test("version 2 snapshots are read, keep their skipped keys, and are rewritten as version 3") do
  case migration_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
