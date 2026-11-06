from Session.HeaderWire import he_read_u32
from Session.Snapshot import SnapshotOutcome, snapshot, restore
from Session.State import RatchetState, DecryptOutcome, RatchetError, RatchetMessage
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
  build_prekey_bundle,
  build_hybrid_prekey_bundle,
  generate_one_time_prekey,
  generate_post_quantum_prekey,
  generate_signed_prekey
)
from Protocol.HandshakeWire import encode_initial_message
from Protocol.IdentityWire import encode_account_identity, encode_device_credential
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

fn pair_modes(alice_cap :: String,
  bob_cap :: String) -> Result<(RatchetState, RatchetState), String> do
  let now = wide("1700000000000")?
  let expires = wide("1700604800000")?
  let policy = VerificationPolicy { current_time: now, minimum_directory_sequence: wide("1")? }
  let (alice_account_keys, alice_account) = account(now)?
  let alice = device()?
  let alice_credential = credential_cap(alice_account_keys, alice, now, expires, alice_cap)?
  let (bob_account_keys, bob_account) = account(now)?
  let bob = device()?
  let bob_credential = credential_cap(bob_account_keys, bob, now, expires, bob_cap)?
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
  let (bob_state, greeting) = received(receive_initial(bob,
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
  assert(initial.version == if alice_cap == "15" && bob_cap == "15" do
      2
    else
      1
    end)
  assert(Bytes.secure_equals(greeting, Bytes.from_utf8("hello")))
  Ok((alice_state, bob_state))
end

fn credential_cap(account_keys :: borrow AccountKeys,
  device_keys :: borrow DeviceKeys,
  now :: U64,
  expires :: U64,
  capabilities :: String) -> DeviceCredential!String do
  case issue_device_credential(account_keys,
    device_keys,
    wide(capabilities)?,
    now,
    expires,
    wide("1")?) do
    Err(_) -> Err("credential")
    Ok(value)
  end
end

fn pair() -> Result<(RatchetState, RatchetState), String> do
  pair_modes("15", "15")
end

fn opened(state :: consume RatchetState,
  message :: RatchetMessage,
  aad :: Bytes) -> Result<(RatchetState, Bytes), String> do
  case decrypt(state, message, aad) do
    Rejected(state, _) -> do
      discard(state)
      Err("header ratchet rejected")
    end
    Opened(state, clear) -> Ok((state, clear))
  end
end

fn failed(state :: consume RatchetState,
  message :: RatchetMessage,
  aad :: Bytes) -> RatchetState!String do
  case decrypt(state, message, aad) do
    Opened(state, _) -> do
      discard(state)
      Err("tampered packet accepted")
    end
    Rejected(state, error) -> if case error do
      RatchetError.CryptoFailure -> true
      _ -> false
    end do
      discard(state)
      Err("unrelated resource error")
    else
      Ok(state)
    end
  end
end

fn roundtrip_wire(value :: RatchetMessage) -> RatchetMessage!String do
  case encode_ratchet_message(value) do
    Err(_) -> Err("encode")
    Ok(wire) -> case decode_ratchet_message(wire) do
      Err(_) -> Err("decode")
      Ok(message) -> do
        assert(message.version == 4)
        assert(Bytes.length(message.session_id) == 0)
        assert(Bytes.length(message.ratchet_public_key.bytes) == 0)
        assert(Bytes.length(message.header_nonce) == 24)
        assert(Bytes.length(message.encrypted_header) == 90)
        Ok(message)
      end
    end
  end
end

fn ordered_and_skipped() -> Bool!String do
  let (alice, bob) = pair()?
  let aad = Bytes.from_utf8("conversation")
  let old_public = alice.local_ratchet_public.bytes
  let (alice, first) = sealed_message(encrypt_sealed(alice, Bytes.from_utf8("first"), aad))?
  let (alice, second) = sealed_message(encrypt_sealed(alice, Bytes.from_utf8("second"), aad))?
  let second = roundtrip_wire(second)?
  let bob = failed(bob, %{second | encrypted_header: flipped_last(second.encrypted_header)?}, aad)?
  let bob = failed(bob, %{second | ciphertext: flipped_last(second.ciphertext)?}, aad)?
  let bob = failed(bob, second, Bytes.from_utf8("wrong-session-aad"))?
  let (bob, clear) = opened(bob, second, aad)?
  assert(Bytes.secure_equals(clear, Bytes.from_utf8("second")))
  let (bob, reply) = sealed_message(encrypt_sealed(bob, Bytes.from_utf8("reply"), aad))?
  let (alice, clear) = opened(alice, roundtrip_wire(reply)?, aad)?
  assert(Bytes.secure_equals(clear, Bytes.from_utf8("reply")))
  let (alice, next) = sealed_message(encrypt_sealed(alice, Bytes.from_utf8("next-DH"), aad))?
  let (bob, clear) = opened(bob, roundtrip_wire(next)?, aad)?
  assert(Bytes.secure_equals(clear, Bytes.from_utf8("next-DH")))
  let old_id = Bytes.concat(Bytes.from_utf8("old/"), old_public)?
  assert(SecretMap.contains(bob.header_keys, old_id))
  let (bob, clear) = opened(bob, roundtrip_wire(first)?, aad)?
  assert(Bytes.secure_equals(clear, Bytes.from_utf8("first")))
  assert(!SecretMap.contains(bob.header_keys, old_id))
  let bob = failed(bob, first, aad)?
  discard(alice)
  discard(bob)
  Ok(true)
end

test("HE header/body failures preserve state across both DH rotations and delayed skipped receive") do
  assert(Result.unwrap_or(ordered_and_skipped(), false))
end

fn rotate(alice :: consume RatchetState,
  bob :: consume RatchetState,
  count :: Int) -> Result<(RatchetState, RatchetState), String> do
  if count == 0 do
    return Ok((alice, bob))
  end
  let aad = Bytes.from_utf8("conversation")
  let (bob, message) = sealed_message(encrypt_sealed(bob, Bytes.from_utf8("b"), aad))?
  let (alice, _) = opened(alice, message, aad)?
  let (alice, message) = sealed_message(encrypt_sealed(alice, Bytes.from_utf8("a"), aad))?
  let (bob, _) = opened(bob, message, aad)?
  rotate(alice, bob, count - 1)
end

fn expiry() -> Bool!String do
  let (alice, bob) = pair()?
  let aad = Bytes.from_utf8("conversation")
  let old = alice.local_ratchet_public.bytes
  let (alice, late) = sealed_message(encrypt_sealed(alice, Bytes.from_utf8("late"), aad))?
  let (alice, current) = sealed_message(encrypt_sealed(alice, Bytes.from_utf8("current"), aad))?
  let (bob, _) = opened(bob, current, aad)?
  let (alice, bob) = rotate(alice, bob, 5)?
  assert(Bytes.length(bob.skipped_index) == 0)
  assert(!SecretMap.contains(bob.header_keys, Bytes.concat(Bytes.from_utf8("old/"), old)?))
  let bob = failed(bob, late, aad)?
  discard(alice)
  discard(bob)
  Ok(true)
end

test("HE old header keys expire with the existing five-receiving-generation skipped-key bound") do
  assert(Result.unwrap_or(expiry(), false))
end

fn saved(state :: consume RatchetState,
  key :: borrow StorageKey,
  account :: Bytes,
  device :: Bytes,
  version :: U64) -> Result<(RatchetState, Bytes), String> do
  case snapshot(state, key, account, device, version) do
    SnapshotRejected(state, _) -> do
      discard(state)
      Err("snapshot refused")
    end
    SnapshotSealed(state, blob) -> Ok((state, blob))
  end
end

fn reloaded(blob :: Bytes,
  key :: borrow StorageKey,
  account :: Bytes,
  device :: Bytes,
  version :: U64) -> RatchetState!String do
  case restore(blob, key, account, device, version) do
    Err(_) -> Err("restore refused")
    Ok(state) -> Ok(state)
  end
end

fn restore_refused(blob :: Bytes,
  key :: borrow StorageKey,
  account :: Bytes,
  device :: Bytes,
  version :: U64) -> Bool do
  case restore(blob, key, account, device, version) do
    Err(_) -> true
    Ok(state) -> do
      discard(state)
      false
    end
  end
end

fn snapshot_u32(input :: Bytes, offset :: Int) -> Int!String do
  case he_read_u32(input, offset) do
    Err(_) -> Err("snapshot fixture length")
    Ok(value)
  end
end

fn skip_vectors(input :: Bytes, offset :: Int, count :: Int) -> Int!String do
  if count == 0 do
    return Ok(offset)
  end
  skip_vectors(input, offset + 4 + snapshot_u32(input, offset)?, count - 1)
end

fn swapped_header_slots(blob :: Bytes) -> Bytes!String do
  let names_offset = 131 + snapshot_u32(blob, 127)?
  let keys_offset = names_offset + 4 + snapshot_u32(blob, names_offset)?
  let headers_offset = skip_vectors(blob, keys_offset, 5)? + 4
  assert(snapshot_u32(blob, headers_offset)? == 99)
  assert(snapshot_u32(blob, headers_offset + 103)? == 99)
  Bytes.concat(Bytes.slice(blob, 0, headers_offset)?,
    Bytes.concat(Bytes.slice(blob, headers_offset + 103, 103)?,
      Bytes.concat(Bytes.slice(blob, headers_offset, 103)?,
        Bytes.slice(blob, headers_offset + 206, Bytes.length(blob) - headers_offset - 206)?)?)?)
end

fn snapshots() -> Bool!String do
  let (alice, bob) = pair()?
  let key = case StorageKey.ephemeral() do
    Err(_) -> Err("key generation")
    Ok(value)
  end?
  let wrong = case StorageKey.ephemeral() do
    Err(_) -> Err("key generation")
    Ok(value)
  end?
  let account = repeated(3, 32)?
  let device = repeated(4, 16)?
  let aad = Bytes.from_utf8("conversation")
  let (alice, late) = sealed_message(encrypt_sealed(alice, Bytes.from_utf8("late"), aad))?
  let (alice, current) = sealed_message(encrypt_sealed(alice, Bytes.from_utf8("current"), aad))?
  let (bob, _) = opened(bob, current, aad)?
  let (bob, reply) = sealed_message(encrypt_sealed(bob, Bytes.from_utf8("reply"), aad))?
  let (alice, _) = opened(alice, reply, aad)?
  let (alice, current) = sealed_message(encrypt_sealed(alice, Bytes.from_utf8("new chain"), aad))?
  let (bob, _) = opened(bob, current, aad)?
  let (bob, blob) = saved(bob, key, account, device, wide("1")?)?
  assert(Bytes.get(blob, 0)? == 3)
  assert(Bytes.length(blob) < 70100)
  assert(restore_refused(blob, wrong, account, device, wide("1")?))
  assert(restore_refused(blob, key, repeated(5, 32)?, device, wide("1")?))
  assert(restore_refused(blob, key, account, repeated(6, 16)?, wide("1")?))
  assert(restore_refused(blob, key, account, device, wide("2")?))
  assert(restore_refused(flipped_last(blob)?, key, account, device, wide("1")?))
  assert(restore_refused(swapped_header_slots(blob)?, key, account, device, wide("1")?))
  discard(bob)
  let bob = reloaded(blob, key, account, device, wide("1")?)?
  let (bob, clear) = opened(bob, late, aad)?
  assert(Bytes.secure_equals(clear, Bytes.from_utf8("late")))
  let (bob, blob2) = saved(bob, key, account, device, wide("2")?)?
  discard(bob)
  let bob = reloaded(blob2, key, account, device, wide("2")?)?
  let bob = failed(bob, late, aad)?
  let (bob, message) = sealed_message(encrypt_sealed(bob, Bytes.from_utf8("after restart"), aad))?
  let (alice, clear) = opened(alice, message, aad)?
  assert(Bytes.secure_equals(clear, Bytes.from_utf8("after restart")))
  discard(alice)
  discard(bob)
  Ok(true)
end

test("RST3 restores current/next and retained old headers with role-bound ciphertext; wrong key, identity, mutation and rollback fail") do
  assert(Result.unwrap_or(snapshots(), false))
end

fn nth_send(state :: consume RatchetState,
  count :: Int,
  aad :: Bytes,
  nonces :: List<Bytes>) -> Result<(RatchetState, RatchetMessage), String> do
  let (state, message) = sealed_message(encrypt_sealed(state, Bytes.from_utf8("gap"), aad))?
  assert(!List.any(nonces, fn(value) -> Bytes.secure_equals(value, message.header_nonce) end))
  if count == 0 do
    return Ok((state, message))
  end
  nth_send(state, count - 1, aad, List.append(nonces, message.header_nonce))
end

fn jump_bounds() -> Bool!String do
  let (alice, bob) = pair()?
  let aad = Bytes.from_utf8("conversation")
  let (alice, at_boundary) = nth_send(alice, 64, aad, [])?
  let (alice, too_far) = sealed_message(encrypt_sealed(alice, Bytes.from_utf8("too far"), aad))?
  let bob = failed(bob, too_far, aad)?
  let (bob, clear) = opened(bob, at_boundary, aad)?
  assert(Bytes.secure_equals(clear, Bytes.from_utf8("gap")))
  assert(Bytes.length(bob.skipped_index) == 2560)
  let (bob, clear) = opened(bob, too_far, aad)?
  assert(Bytes.secure_equals(clear, Bytes.from_utf8("too far")))
  discard(alice)
  discard(bob)
  Ok(true)
end

test("HE64 skipped-key admission and fresh192-bit header nonces; excessive jump fails before state commit") do
  assert(Result.unwrap_or(jump_bounds(), false))
end

fn framing_bounds() -> Bool!String do
  let (alice, bob) = pair()?
  let aad = Bytes.from_utf8("conversation")
  let (alice, message) = sealed_message(encrypt_sealed(alice, repeated(7, 65317)?, aad))?
  let wire = case encode_ratchet_message(message) do
    Err(_) -> Err("max encode")
    Ok(value)
  end?
  assert(Bytes.length(wire) == 65467)
  let packet = ratchet_packet(message)?
  assert(Bytes.length(packet) == 65480)
  let decoded = roundtrip_wire(message)?
  let (bob, clear) = opened(bob, decoded, aad)?
  assert(Bytes.length(clear) == 65317)
  assert(case decode_ratchet_message(Bytes.concat(wire, repeated(0, 1)?)?) do
    Err(_) -> true
    Ok(_) -> false
  end)
  assert(case decode_ratchet_message(Bytes.slice(wire, 0, Bytes.length(wire) - 1)?) do
    Err(_) -> true
    Ok(_) -> false
  end)
  let wrong_length = Bytes.concat(Bytes.slice(wire, 0, 130)?,
    Bytes.concat(repeated(0, 4)?, Bytes.slice(wire, 134, Bytes.length(wire) - 134)?)?)?
  assert(case decode_ratchet_message(wrong_length) do
    Err(_) -> true
    Ok(_) -> false
  end)
  assert(!ratchet_transport_matches(message, false))
  assert(case encrypt_sealed(alice, repeated(7, 65318)?, aad) do
    Err(_) -> true
    Ok((state, _)) -> do
      discard(state)
      false
    end
  end)
  discard(bob)
  Ok(true)
end

test("RAT4 exact transport bound and canonical ciphertext length reject trailing/truncated/oversized bodies and bare transport") do
  assert(Result.unwrap_or(framing_bounds(), false))
end

fn explicit_legacy() -> Bool!String do
  let (alice, bob) = pair_modes("15", "7")?
  assert(alice.version == 1 && bob.version == 1)
  let (alice, legacy) = sealed_message(encrypt_sealed(alice,
    Bytes.from_utf8("queued old message"),
    Bytes.empty()))?
  assert(legacy.version == 3)
  let (bob, clear) = opened(bob, legacy, Bytes.empty())?
  assert(Bytes.secure_equals(clear, Bytes.from_utf8("queued old message")))
  let (new_alice, new_bob) = pair()?
  let new_bob = failed(new_bob, legacy, Bytes.empty())?
  let (new_alice, new_message) = sealed_message(encrypt_sealed(new_alice,
    Bytes.from_utf8("new"),
    Bytes.empty()))?
  let bob = failed(bob, new_message, Bytes.empty())?
  discard(alice)
  discard(bob)
  discard(new_alice)
  discard(new_bob)
  Ok(true)
end

test("authenticated mixed capability uses explicit old protocol only; queued legacy reads survive and states never cross-fallback") do
  assert(Result.unwrap_or(explicit_legacy(), false))
end

fn initial_boundary(hybrid :: Bool) -> Bool!String do
  let now = wide("1700000000000")?
  let expires = wide("1700604800000")?
  let policy = VerificationPolicy { current_time: now, minimum_directory_sequence: wide("1")? }
  let (alice_keys, alice_account) = account(now)?
  let (bob_keys, bob_account) = account(now)?
  let alice = device()?
  let bob = device()?
  let alice_pq = case generate_post_quantum_prekey() do
    Err(_) -> Err("initial pq")
    Ok(value)
  end?
  let bob_pq = case generate_post_quantum_prekey() do
    Err(_) -> Err("initial pq")
    Ok(value)
  end?
  let alice_credential = if hybrid do
    case issue_hybrid_device_credential(alice_keys,
      alice,
      alice_pq.public_key,
      wide("15")?,
      now,
      expires,
      wide("1")?) do
      Err(_) -> Err("initial credential")
      Ok(value)
    end?
  else
    credential(alice_keys, alice, now, expires)?
  end
  let bob_credential = if hybrid do
    case issue_hybrid_device_credential(bob_keys,
      bob,
      bob_pq.public_key,
      wide("15")?,
      now,
      expires,
      wide("1")?) do
      Err(_) -> Err("initial credential")
      Ok(value)
    end?
  else
    credential(bob_keys, bob, now, expires)?
  end
  let signed = case generate_signed_prekey(bob, bob_credential, wide("7")?, expires) do
    Err(_) -> Err("initial signed")
    Ok(value)
  end?
  let one_time = case generate_one_time_prekey(wide("9")?) do
    Err(_) -> Err("initial one time")
    Ok(value)
  end?
  let bundle = case if hybrid do
    build_hybrid_prekey_bundle(bob_credential, signed, one_time, bob_pq)
  else
    build_prekey_bundle(bob_credential, signed, one_time)
  end do
    Err(_) -> Err("initial bundle")
    Ok(value)
  end?
  let credential_wire = case encode_device_credential(alice_credential) do
    Err(_) -> Err("credential encoding")
    Ok(value)
  end?
  let maximum = 48512 - Bytes.length(credential_wire) - if hybrid do
      1088
    else
      0
    end
  let (state, initial) = initiated(initiate(alice,
    alice_credential,
    bob_account,
    bundle,
    policy,
    0,
    repeated(7, maximum)?))?
  let wire = case encode_initial_message(initial) do
    Err(_) -> Err("initial boundary encode")
    Ok(value)
  end?
  assert(Bytes.length(wire) == 48800)
  let account_wire = case encode_account_identity(alice_account) do
    Err(_) -> Err("initial account")
    Ok(value)
  end?
  let packet = encode_packet(InitialPacket(account_wire, wire))?
  assert(Bytes.length(packet) <= 65480)
  let sealed = seal_recipient_packet(packet, bob.identity_public_key)?
  assert(Bytes.length(sealed) <= 65536)
  let (bob_state, clear) = received(receive_initial(bob,
    bob_account,
    bundle,
    signed,
    one_time,
    bob_pq,
    alice_account,
    policy,
    policy,
    0,
    wire))?
  assert(Bytes.length(clear) == maximum)
  assert(case encode_initial_message(%{initial | nonce: repeated(1, 12)?}) do
    Err(_) -> true
    Ok(_) -> false
  end)
  let oversized = case initiate(alice,
    alice_credential,
    bob_account,
    bundle,
    policy,
    0,
    repeated(7, maximum + 1)?) do
    Err(SessionError.InvalidHandshake) -> true
    Err(_) -> false
    Ok((state, _)) -> do
      discard(state)
      false
    end
  end
  assert(oversized)
  discard(state)
  discard(bob_state)
  Ok(true)
end

test("first HE INI classical and hybrid exact48800 transport bound admits max and refuses one byte over before encryption") do
  case initial_boundary(false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
  case initial_boundary(true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
