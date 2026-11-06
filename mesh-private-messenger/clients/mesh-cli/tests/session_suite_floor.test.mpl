from Client.Security import session_minimum
from Client.Session import initiate_cli, receive_initial_cli
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

fn cli_policy(minimum :: Int) -> Int!String do
  let frame = String.join([
      "1",
      String.repeat("11", 32),
      String.repeat("01", 32),
      String.repeat("02", 32),
      String.repeat("22", 32),
      "16"
    ],
    "\n")
  let config = if minimum == 1 do
    frame
  else
    "6\n#{minimum}\n" <> frame
  end
  session_minimum(Map.put(Map.new(), "MESSENGER_SECURITY_CONFIG", config))
end

fn cli_proof(hybrid :: Bool, incoming :: Bool) -> Bool!String do
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
  let old = cli_policy(1)?
  let strict = cli_policy(2)?
  assert(old == 1 && strict == 2)
  let text = Bytes.from_utf8("actual CLI configured exchange")
  if !hybrid && !incoming do
    # This really opens the same valid classical negotiation through the
    # compatibility API before asserting the configured fixture-role refusal.
    let (alice_state, initial) = started(initiate_cli(old,
      alice,
      alice_credential,
      bob_account,
      bundle,
      policy,
      0,
      text))?
    let (bob_state, opened) = received(receive_initial_cli(old,
      bob,
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
    assert(alice_state.suite == 1 && bob_state.suite == 1 && Bytes.secure_equals(opened, text))
    discard(alice_state)
    discard(bob_state)
    println("c3-cli-classical-opened:passed")
    assert(start_refused(initiate_cli(strict,
      alice,
      alice_credential,
      bob_account,
      bundle,
      policy,
      0,
      text)))
  else
    let (alice_state, initial) = started(initiate_cli(if hybrid do
        strict
      else
        old
      end,
      alice,
      alice_credential,
      bob_account,
      bundle,
      policy,
      0,
      text))?
    if hybrid do
      let (bob_state, opened) = received(receive_initial_cli(strict,
        bob,
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
      assert(alice_state.suite == 2 && bob_state.suite == 2 && Bytes.secure_equals(opened, text))
      discard(bob_state)
    else
      let result = receive_initial_cli(strict,
        bob,
        bob_account,
        bundle,
        signed,
        otp,
        bob_pq,
        alice_account,
        policy,
        policy,
        0,
        initial_bytes(initial)?)
      let refused = case result do
        Err(MinimumSessionSuiteRequired) -> true
        Err(_) -> false
        Ok((state, clear)) -> do
          assert(Bytes.secure_equals(clear, text))
          println("c3-cli-incoming-classical-opened:passed")
          discard(state)
          false
        end
      end
      assert(refused)
    end
    discard(alice_state)
  end
  println("c3-cli-hybrid=#{hybrid}-incoming=#{incoming}:passed")
  Ok(true)
end

test("CLI configured floor hybrid=false incoming=false authentic exchange") do
  case cli_proof(false, false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("CLI configured floor hybrid=false incoming=true authentic exchange") do
  case cli_proof(false, true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("CLI configured floor hybrid=true incoming=true authentic exchange") do
  case cli_proof(true, true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
