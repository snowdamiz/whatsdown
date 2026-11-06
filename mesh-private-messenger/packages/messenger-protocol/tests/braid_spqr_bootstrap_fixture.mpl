##! TEST ONLY actual credential/prekey bootstrap peers. No fixture seed authority.
from Identity.Device import (
  DeviceKeys,
  VerificationPolicy,
  generate_account,
  generate_device,
  issue_hybrid_device_credential
)
from Prekeys.Bundle import (
  SignedPrekeySecrets,
  OneTimePrekeySecrets,
  PostQuantumPrekeySecrets,
  generate_signed_prekey,
  generate_one_time_prekey,
  generate_post_quantum_prekey,
  build_hybrid_prekey_bundle
)
from Protocol.V1 import AccountIdentity, DeviceCredential, PrekeyBundle, InitialMessage
from Protocol.HandshakeWire import encode_initial_message
from Session.Handshake import (
  SessionError,
  C1Initiated,
  C1Received,
  initiate_braid_spqr_at_minimum_suite,
  receive_initial_braid_spqr_at_minimum_suite,
  initiate_at_minimum_suite,
  receive_initial_at_minimum_suite
)
from Session.State import RatchetState
from Session.BraidInitiator import send_header
from Session.BraidResponder import admit_complete_header, BraidHeaderAdmission
from Session.BraidFragmentWords import emit_braid_fragment
from Session.BraidFragment import BraidFragmentKind
from Session.HeaderRatchet import (
  he_encrypt_hybrid,
  he_decrypt_hybrid,
  HybridSendOutcome,
  HybridReceiveOutcome
)
from Session.SpqrStore import SpqrStoreIdentity, seal_spqr, restore_spqr

pub resource struct BootstrapPeers do
  alice :: DeviceKeys
  bob :: DeviceKeys
  alice_account :: AccountIdentity
  bob_account :: AccountIdentity
  alice_credential :: DeviceCredential
  bob_bundle :: PrekeyBundle
  signed :: SignedPrekeySecrets
  otp :: OneTimePrekeySecrets
  pq :: PostQuantumPrekeySecrets
  policy :: VerificationPolicy
end

fn check(ok :: Bool, reason :: String) -> Unit!String do
  if ok do
    Ok(nil)
  else
    Err(reason)
  end
end

fn wide(text :: String) -> U64!String do
  U64.parse(text)
end

pub fn bootstrap_configuration() -> Bytes do
  Crypto.sha256(Bytes.from_utf8("TEST ONLY real C1 bootstrap profile"))
end

pub fn bootstrap_peers() -> BootstrapPeers!String do
  let now = wide("1700000000000")?
  let expiry = wide("1700604800000")?
  let (ak, aa) = case generate_account(now, wide("1")?) do
    Ok(v) -> v
    Err(_) -> return Err("setup_alice_account")
  end
  let (bk, ba) = case generate_account(now, wide("1")?) do
    Ok(v) -> v
    Err(_) -> return Err("setup_bob_account")
  end
  let a = case generate_device() do
    Ok(v) -> v
    Err(_) -> return Err("setup_alice_device")
  end
  let b = case generate_device() do
    Ok(v) -> v
    Err(_) -> return Err("setup_bob_device")
  end
  let apq = case generate_post_quantum_prekey() do
    Ok(v) -> v
    Err(_) -> return Err("setup_alice_pq")
  end
  let pq = case generate_post_quantum_prekey() do
    Ok(v) -> v
    Err(_) -> return Err("setup_bob_pq")
  end
  let ac = case issue_hybrid_device_credential(ak,
    a,
    apq.public_key,
    wide("31")?,
    now,
    expiry,
    wide("1")?) do
    Ok(v) -> v
    Err(_) -> return Err("setup_alice_credential")
  end
  let bc = case issue_hybrid_device_credential(bk,
    b,
    pq.public_key,
    wide("31")?,
    now,
    expiry,
    wide("1")?) do
    Ok(v) -> v
    Err(_) -> return Err("setup_bob_credential")
  end
  let signed = case generate_signed_prekey(b, bc, wide("7")?, expiry) do
    Ok(v) -> v
    Err(_) -> return Err("setup_signed")
  end
  let otp = case generate_one_time_prekey(wide("9")?) do
    Ok(v) -> v
    Err(_) -> return Err("setup_otp")
  end
  let bundle = case build_hybrid_prekey_bundle(bc, signed, otp, pq) do
    Ok(v) -> v
    Err(_) -> return Err("setup_bundle")
  end
  Ok(BootstrapPeers {
    alice: a,
    bob: b,
    alice_account: aa,
    bob_account: ba,
    alice_credential: ac,
    bob_bundle: bundle,
    signed: signed,
    otp: otp,
    pq: pq,
    policy: VerificationPolicy { current_time: now, minimum_directory_sequence: wide("1")? }
  })
end

fn initial_bytes(value :: InitialMessage) -> Bytes!String do
  case encode_initial_message(value) do
    Ok(v)
    Err(_) -> Err("setup_initial_codec")
  end
end

fn started(p :: borrow BootstrapPeers) -> C1Initiated!String do
  case initiate_braid_spqr_at_minimum_suite(p.alice,
    p.alice_credential,
    p.bob_account,
    p.bob_bundle,
    p.policy,
    0,
    2,
    Bytes.empty(),
    bootstrap_configuration()) do
    Ok(v)
    Err(_) -> Err("bootstrap_start_refused")
  end
end

fn roundtrip(p :: consume BootstrapPeers) -> Unit!String do
  let C1Initiated { he: a, spqr: pa, braid: ai, initial } = started(p)?
  let BootstrapPeers {
    alice,
    bob,
    alice_account,
    bob_account,
    alice_credential,
    bob_bundle,
    signed,
    otp,
    pq,
    policy
  } = p
  let C1Received {
    he: b,
    spqr: pb,
    braid: bi,
    plaintext
  } = case receive_initial_braid_spqr_at_minimum_suite(bob,
    bob_account,
    bob_bundle,
    signed,
    otp,
    pq,
    alice_account,
    policy,
    policy,
    0,
    2,
    initial_bytes(initial)?,
    bootstrap_configuration()) do
    Ok(v) -> v
    Err(_) -> return Err("bootstrap_receive_refused")
  end
  check(a.version == 2
      && b.version == 2
      && a.suite == 2
      && b.suite == 2
      && Bytes.secure_equals(a.session_id, b.session_id)
      && Bytes.secure_equals(a.session_id, initial.transcript_hash)
      && pa.direction == 0
      && pb.direction == 1
      && U64.compare(pa.epoch, wide("0")?) == 0
      && U64.compare(pb.knowledge, wide("0")?) == 0,
    "bootstrap_profile_or_direction")?
  let key = case StorageKey.platform() do
    Ok(v) -> v
    Err(_) -> return Err("setup_storage_key")
  end
  let identity = SpqrStoreIdentity {
    revision: wide("1")?,
    transition: Crypto.sha256(Bytes.from_utf8("TEST ONLY bootstrap")),
    descriptor: Crypto.sha256(Bytes.from_utf8("TEST ONLY bootstrap descriptor"))
  }
  let saved_a = seal_spqr(pa, key, identity)?
  let saved_b = seal_spqr(pb, key, identity)?
  let pa = restore_spqr(saved_a, saved_a, key)?
  let pb = restore_spqr(saved_b, saved_b, key)?
  let (sent, header) = case send_header(ai) do
    Ok(v) -> v
    Err(_) -> return Err("bootstrap_header")
  end
  let _ready = case admit_complete_header(bi, sent.epoch, header) do
    BraidHeaderAccepted(v) -> v
    _ -> return Err("bootstrap_braid_peer_agreement")
  end
  let fragment = case emit_braid_fragment(BraidHeaderFragment,
    sent.scope.configuration,
    sent.scope.session_id,
    sent.epoch,
    header,
    0) do
    Ok(v) -> v
    Err(_) -> return Err("bootstrap_fragment")
  end
  let (_a, _pa, message) = case he_encrypt_hybrid(a,
    pa,
    Bytes.from_utf8("actual EC/PQ agreement"),
    fragment,
    Bytes.empty()) do
    HybridSealed(h, q, m) -> (h, q, m)
    _ -> return Err("bootstrap_hybrid_send")
  end
  case he_decrypt_hybrid(b, pb, message, Bytes.empty()) do
    HybridOpened(_h, _q, got, clear) -> do
      check(Bytes.secure_equals(clear, Bytes.from_utf8("actual EC/PQ agreement"))
          && Bytes.secure_equals(got.fragment.word, fragment.word),
        "bootstrap_hybrid_peer_agreement")?
      Ok(nil)
    end
    _ -> Err("bootstrap_hybrid_receive")
  end
end

pub fn b0_protocol_roundtrip() -> Unit!String do
  check(Test.install_in_memory_secure_store(), "setup_secure_store")?
  roundtrip(bootstrap_peers()?)
end

fn refusal(mode :: Int) -> Unit!String do
  let p = bootstrap_peers()?
  let initial = case started(p) do
    Ok(v) -> do
      let C1Initiated { he, spqr, braid, initial } = v
      initial
    end
    Err(error) -> return Err(error)
  end
  let configuration = if mode == 0 do
    Crypto.sha256(Bytes.from_utf8("different C"))
  else
    bootstrap_configuration()
  end
  let initial = if mode == 1 do
    %{initial |
      ciphertext: case Bytes.repeat(0, Bytes.length(initial.ciphertext)) do
        Ok(v) -> v
        Err(_) -> return Err("setup_tamper")
      end
    }
  else
    initial
  end
  let BootstrapPeers {
    alice,
    bob,
    alice_account,
    bob_account,
    alice_credential,
    bob_bundle,
    signed,
    otp,
    pq,
    policy
  } = p
  if mode == 2 do
    check(case receive_initial_at_minimum_suite(bob,
        bob_account,
        bob_bundle,
        signed,
        otp,
        pq,
        alice_account,
        policy,
        policy,
        0,
        2,
        initial_bytes(initial)?) do
        Err(_) -> true
        Ok(_) -> false
      end,
      "bootstrap_legacy_cross_profile_accepted")
  else
    check(case receive_initial_braid_spqr_at_minimum_suite(bob,
        bob_account,
        bob_bundle,
        signed,
        otp,
        pq,
        alice_account,
        policy,
        policy,
        0,
        2,
        initial_bytes(initial)?,
        configuration) do
        Err(_) -> true
        Ok(_) -> false
      end,
      "bootstrap_changed_scope_or_body_accepted")
  end
end

pub fn b0_protocol_refusals() -> Unit!String do
  for mode in 0..3 do
    refusal(mode)?
  end
  let p = bootstrap_peers()?
  let (_a, initial) = case initiate_at_minimum_suite(p.alice,
    p.alice_credential,
    p.bob_account,
    p.bob_bundle,
    p.policy,
    0,
    2,
    Bytes.empty()) do
    Ok(v) -> v
    Err(_) -> return Err("setup_legacy_start")
  end
  let BootstrapPeers {
    alice,
    bob,
    alice_account,
    bob_account,
    alice_credential,
    bob_bundle,
    signed,
    otp,
    pq,
    policy
  } = p
  check(case receive_initial_braid_spqr_at_minimum_suite(bob,
      bob_account,
      bob_bundle,
      signed,
      otp,
      pq,
      alice_account,
      policy,
      policy,
      0,
      2,
      initial_bytes(initial)?,
      bootstrap_configuration()) do
      Err(_) -> true
      Ok(_) -> false
    end,
    "bootstrap_ordinary_initial_accepted")
end

pub fn b0_protocol_actual_api_preflight() -> Unit!String do
  check(Test.install_in_memory_secure_store(), "setup_secure_store")?
  let p = bootstrap_peers()?
  let (_a, initial) = case initiate_at_minimum_suite(p.alice,
    p.alice_credential,
    p.bob_account,
    p.bob_bundle,
    p.policy,
    0,
    2,
    Bytes.empty()) do
    Ok(v) -> v
    Err(_) -> return Err("setup_legacy_start")
  end
  let BootstrapPeers {
    alice,
    bob,
    alice_account,
    bob_account,
    alice_credential,
    bob_bundle,
    signed,
    otp,
    pq,
    policy
  } = p
  let (_b, _clear) = case receive_initial_at_minimum_suite(bob,
    bob_account,
    bob_bundle,
    signed,
    otp,
    pq,
    alice_account,
    policy,
    policy,
    0,
    2,
    initial_bytes(initial)?) do
    Ok(v) -> v
    Err(_) -> return Err("setup_legacy_receive")
  end
  print("B0_ACTUAL_PROTOCOL_API_PREFLIGHT_EXECUTED")
  Ok(nil)
end

pub fn b0_protocol_report(value :: Unit!String) -> Bool do
  case value do
    Ok(_) -> true
    Err(reason) -> do
      print("B0 fixture refusal: " <> reason)
      false
    end
  end
end
