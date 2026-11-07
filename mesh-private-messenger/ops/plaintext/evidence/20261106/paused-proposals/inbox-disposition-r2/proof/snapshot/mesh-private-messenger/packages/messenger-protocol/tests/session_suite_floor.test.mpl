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
from Protocol.V1 import (
  AccountIdentity,
  DeviceCredential,
  InitialMessage,
  PrekeyBundle,
  ProtocolError
)
from Session.State import RatchetState, DecryptOutcome, RatchetMessage
from Session.Handshake import (
  SessionError,
  initiate,
  receive_initial,
  initiate_at_minimum_suite,
  receive_initial_at_minimum_suite
)
from Session.Ratchet import encrypt_sealed, decrypt
from Session.Snapshot import SnapshotOutcome, snapshot, restore
from Transparency.Config import decode_security_config

fn wide(value :: String) -> U64!String do
  case U64.parse(value) do
    Err(_) -> Err("integer failed")
    Ok(parsed)
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

fn post_quantum_prekey() -> PostQuantumPrekeySecrets!String do
  case generate_post_quantum_prekey() do
    Err(_) -> Err("post-quantum prekey failed")
    Ok(value)
  end
end

fn hybrid_credential(account_keys :: borrow AccountKeys,
  device_keys :: borrow DeviceKeys,
  post_quantum :: borrow PostQuantumPrekeySecrets,
  now :: U64,
  expires :: U64) -> DeviceCredential!String do
  case issue_hybrid_device_credential(account_keys,
    device_keys,
    post_quantum.public_key,
    wide("31")?,
    now,
    expires,
    wide("1")?) do
    Err(_) -> Err("hybrid credential failed")
    Ok(value)
  end
end

fn classical_credential(account_keys :: borrow AccountKeys,
  device_keys :: borrow DeviceKeys,
  now :: U64,
  expires :: U64) -> DeviceCredential!String do
  case issue_device_credential(account_keys, device_keys, wide("31")?, now, expires, wide("1")?) do
    Err(_) -> Err("classical credential failed")
    Ok(value)
  end
end

fn signed_prekey(device_keys :: borrow DeviceKeys,
  credential :: DeviceCredential,
  expires :: U64) -> SignedPrekeySecrets!String do
  case generate_signed_prekey(device_keys, credential, wide("7")?, expires) do
    Err(_) -> Err("signed prekey failed")
    Ok(value)
  end
end

fn one_time_prekey() -> OneTimePrekeySecrets!String do
  case generate_one_time_prekey(wide("9")?) do
    Err(_) -> Err("one-time prekey failed")
    Ok(value)
  end
end

fn hybrid_bundle(credential :: DeviceCredential,
  signed :: borrow SignedPrekeySecrets,
  one_time :: borrow OneTimePrekeySecrets,
  post_quantum :: borrow PostQuantumPrekeySecrets) -> PrekeyBundle!String do
  case build_hybrid_prekey_bundle(credential, signed, one_time, post_quantum) do
    Err(_) -> Err("hybrid bundle failed")
    Ok(value)
  end
end

fn classical_bundle(credential :: DeviceCredential,
  signed :: borrow SignedPrekeySecrets,
  one_time :: borrow OneTimePrekeySecrets) -> PrekeyBundle!String do
  case build_prekey_bundle(credential, signed, one_time) do
    Err(_) -> Err("classical bundle failed")
    Ok(value)
  end
end

fn initial_bytes(value :: InitialMessage) -> Bytes!String do
  case encode_initial_message(value) do
    Err(_) -> Err("initial encoding failed")
    Ok(encoded)
  end
end

fn discard(state :: consume RatchetState) do
  nil
end

fn started(value :: Result<(RatchetState, InitialMessage), SessionError>) -> Result<(RatchetState, InitialMessage), String> do
  case value do
    Err(_) -> Err("session_start_failed")
    Ok(output)
  end
end

fn received(value :: Result<(RatchetState, Bytes), SessionError>) -> Result<(RatchetState, Bytes), String> do
  case value do
    Err(_) -> Err("session_receive_failed")
    Ok(output)
  end
end

fn start_refused(value :: Result<(RatchetState, InitialMessage), SessionError>) -> Bool do
  case value do
    Err(MinimumSessionSuiteRequired) -> true
    Err(_) -> false
    Ok((state, _)) -> do
      discard(state)
      false
    end
  end
end

fn receive_refused(value :: Result<(RatchetState, Bytes), SessionError>) -> Bool do
  case value do
    Err(MinimumSessionSuiteRequired) -> true
    Err(_) -> false
    Ok((state, _)) -> do
      discard(state)
      false
    end
  end
end

fn saved(state :: consume RatchetState,
  key :: borrow StorageKey,
  account_id :: Bytes,
  device_id :: Bytes) -> Bytes!String do
  case snapshot(state, key, account_id, device_id, wide("1")?) do
    SnapshotRejected(state, _) -> do
      discard(state)
      Err("snapshot_failed")
    end
    SnapshotSealed(state, blob) -> do
      discard(state)
      Ok(blob)
    end
  end
end

fn restored(blob :: Bytes,
  key :: borrow StorageKey,
  account_id :: Bytes,
  device_id :: Bytes) -> RatchetState!String do
  case restore(blob, key, account_id, device_id, wide("1")?) do
    Err(_) -> Err("restore_failed")
    Ok(state)
  end
end

fn encrypted(state :: consume RatchetState,
  plaintext :: Bytes) -> Result<(RatchetState, RatchetMessage), String> do
  case encrypt_sealed(state, plaintext, Bytes.empty()) do
    Err(_) -> Err("ratchet_encrypt_failed")
    Ok(output)
  end
end

fn decrypted(state :: consume RatchetState,
  message :: RatchetMessage) -> Result<(RatchetState, Bytes), String> do
  case decrypt(state, message, Bytes.empty()) do
    Rejected(state, _) -> do
      discard(state)
      Err("ratchet_decrypt_failed")
    end
    Opened(state, plaintext) -> Ok((state, plaintext))
  end
end

fn classical_proof() -> Bool!String do
  let now = wide("1700000000000")?
  let expires = wide("1700604800000")?
  let policy = VerificationPolicy { current_time: now, minimum_directory_sequence: wide("1")? }
  let (alice_account_key, alice_account) = account(now)?
  let alice = device()?
  let alice_pq = post_quantum_prekey()?
  let alice_credential = hybrid_credential(alice_account_key, alice, alice_pq, now, expires)?
  let (bob_account_key, bob_account) = account(now)?
  let bob = device()?
  let bob_pq = post_quantum_prekey()?
  let bob_credential = classical_credential(bob_account_key, bob, now, expires)?
  assert(U64.compare(alice_credential.capabilities, wide("31")?) == 0)
  assert(U64.compare(bob_credential.capabilities, wide("31")?) == 0)
  let signed = signed_prekey(bob, bob_credential, expires)?
  let otp = one_time_prekey()?
  let bundle = classical_bundle(bob_credential, signed, otp)?
  let plaintext = Bytes.from_utf8("valid classical floor-one hello")
  let (alice_state, initial) = started(initiate(alice,
    alice_credential,
    bob_account,
    bundle,
    policy,
    0,
    plaintext))?
  let (bob_state, opened) = received(receive_initial(bob,
    bob_account,
    bundle,
    signed,
    otp,
    bob_pq,
    alice_account,
    policy,
    policy,
    0,
    initial_bytes(initial)?))?
  assert(alice_state.suite == 1 && bob_state.suite == 1)
  assert(alice_state.version == 2 && bob_state.version == 2)
  assert(Bytes.secure_equals(opened, plaintext))
  println("c3-valid-classical-exchange:passed")
  assert(start_refused(initiate_at_minimum_suite(alice,
    alice_credential,
    bob_account,
    bundle,
    policy,
    0,
    2,
    Bytes.from_utf8("must refuse"))))
  for minimum in [0, 3] do
    let invalid = case initiate_at_minimum_suite(alice,
      alice_credential,
      bob_account,
      bundle,
      policy,
      0,
      minimum,
      Bytes.empty()) do
      Err(InvalidHandshake) -> true
      Err(_) -> false
      Ok((state, _)) -> do
        discard(state)
        false
      end
    end
    assert(invalid)
  end
  let downgrade = case initiate_at_minimum_suite(alice,
    alice_credential,
    bob_account,
    bundle,
    policy,
    2,
    1,
    Bytes.empty()) do
    Err(ProtocolFailure(DowngradeDetected)) -> true
    Err(_) -> false
    Ok((state, _)) -> do
      discard(state)
      false
    end
  end
  assert(downgrade)
  # The floor is not historical suite evidence and does not retire a saved state.
  let floor_wire = "6\n2\n1\n"
    <> String.repeat("11", 32)
    <> "\n"
    <> String.repeat("01", 32)
    <> "\n"
    <> String.repeat("02", 32)
    <> "\n"
    <> String.repeat("22", 32)
    <> "\n16"
  assert(decode_security_config(Bytes.from_utf8(floor_wire))?.minimum_session_suite == 2)
  let key = case StorageKey.ephemeral() do
    Err(_) -> Err("storage_key_failed")
    Ok(value)
  end?
  let alice_blob = saved(alice_state, key, alice_account.account_id, alice_credential.device_id)?
  let bob_blob = saved(bob_state, key, bob_account.account_id, bob_credential.device_id)?
  let alice_state = restored(alice_blob, key, alice_account.account_id, alice_credential.device_id)?
  let bob_state = restored(bob_blob, key, bob_account.account_id, bob_credential.device_id)?
  let (alice_state, message) = encrypted(alice_state, Bytes.from_utf8("after floor-two release"))?
  let (bob_state, clear) = decrypted(bob_state, message)?
  assert(Bytes.secure_equals(clear, Bytes.from_utf8("after floor-two release")))
  let (bob_state, reply) = encrypted(bob_state, Bytes.from_utf8("old session still replies"))?
  let (alice_state, clear) = decrypted(alice_state, reply)?
  assert(Bytes.secure_equals(clear, Bytes.from_utf8("old session still replies")))
  assert(alice_state.suite == 1 && bob_state.suite == 1)
  discard(alice_state)
  discard(bob_state)
  println("c3-outgoing-floor-and-old-snapshot:passed")
  Ok(true)
end

fn incoming_proof(hybrid :: Bool) -> Bool!String do
  let now = wide("1700000000000")?
  let expires = wide("1700604800000")?
  let policy = VerificationPolicy { current_time: now, minimum_directory_sequence: wide("1")? }
  let (alice_account_key, alice_account) = account(now)?
  let alice = device()?
  let alice_pq = post_quantum_prekey()?
  let alice_credential = if hybrid do
    hybrid_credential(alice_account_key, alice, alice_pq, now, expires)
  else
    classical_credential(alice_account_key, alice, now, expires)
  end?
  let (bob_account_key, bob_account) = account(now)?
  let bob = device()?
  let bob_pq = post_quantum_prekey()?
  let bob_credential = hybrid_credential(bob_account_key, bob, bob_pq, now, expires)?
  let signed = signed_prekey(bob, bob_credential, expires)?
  let otp = one_time_prekey()?
  let bundle = hybrid_bundle(bob_credential, signed, otp, bob_pq)?
  let plaintext = Bytes.from_utf8("actual incoming initial")
  let (alice_state, initial) = started(initiate_at_minimum_suite(alice,
    alice_credential,
    bob_account,
    bundle,
    policy,
    0,
    if hybrid do
      2
    else
      1
    end,
    plaintext))?
  assert(initial.suite == if hybrid do
      2
    else
      1
    end)
  if hybrid do
    let (bob_state, opened) = received(receive_initial_at_minimum_suite(bob,
      bob_account,
      bundle,
      signed,
      otp,
      bob_pq,
      alice_account,
      policy,
      policy,
      0,
      2,
      initial_bytes(initial)?))?
    assert(alice_state.suite == 2 && bob_state.suite == 2)
    assert(Bytes.secure_equals(opened, plaintext))
    let (bob_state, reply) = encrypted(bob_state, Bytes.from_utf8("hybrid reply"))?
    let (alice_state, clear) = decrypted(alice_state, reply)?
    assert(Bytes.secure_equals(clear, Bytes.from_utf8("hybrid reply")))
    discard(alice_state)
    discard(bob_state)
    println("c3-hybrid-floor-two:passed")
  else
    assert(receive_refused(receive_initial_at_minimum_suite(bob,
      bob_account,
      bundle,
      signed,
      otp,
      bob_pq,
      alice_account,
      policy,
      policy,
      0,
      2,
      initial_bytes(initial)?)))
    discard(alice_state)
    println("c3-incoming-floor-two:passed")
  end
  Ok(true)
end

test("valid signed classical HE peers obey the release floor and old snapshots survive") do
  case classical_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("a valid classical initiator cannot install a new session at floor two") do
  case incoming_proof(false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("actual hybrid establishment and reply succeed at floor two") do
  case incoming_proof(true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
