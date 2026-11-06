##! Synthetic complete logical messages. No erasure-code/wire implementation.
from Session.BraidResponder import (
  BraidError,
  BraidScope,
  BraidAwaitHeader,
  BraidHeaderReady,
  BraidCt1Ready,
  BraidHeaderAdmission,
  initialize_responder,
  admit_complete_header,
  prepare_ct1,
  braid_join,
  braid_epoch_bytes
)
from Session.BraidStore import (
  BraidSaved,
  seal_await,
  seal_header,
  seal_ct1,
  seal_ct1_fault,
  restore_await,
  restore_header,
  restore_ct1,
  braid_storage_context
)

pub resource struct BraidPair do
  alice :: BraidAwaitHeader
  bob :: BraidAwaitHeader
  epoch_private :: MlKemPrivateKey
  header :: MlKemHeader64
  vector :: MlKemPublicVector1152
end

fn check(value :: Bool) -> Result<(), BraidError> do
  if value do
    Ok(nil)
  else
    Err(BraidInvalidState)
  end
end

fn bytes(byte :: Int, count :: Int) -> Bytes!BraidError do
  case Bytes.repeat(byte, count) do
    Ok(v)
    Err(_) -> Err(BraidInvalidState)
  end
end

fn number(text :: String) -> U64!BraidError do
  case U64.parse(text) do
    Ok(v)
    Err(_) -> Err(BraidInvalidState)
  end
end

pub fn fixture_scope() -> BraidScope!BraidError do
  Ok(BraidScope {
    protocol_info: Bytes.from_utf8("MorseBraid_MLKEM768_SHA-256"),
    configuration: Crypto.sha256(Bytes.from_utf8("TEST ONLY C1 complete header carrier v1")),
    account_id: bytes(1, 32)?,
    device_id: bytes(2, 16)?,
    peer_account_id: bytes(3, 32)?,
    peer_device_id: bytes(4, 16)?,
    session_id: Crypto.sha256(Bytes.from_utf8("TEST ONLY C1 independent protocol session"))
  })
end

## The initializer key and epoch key are distinct actual KEM generations.
pub fn fixture_pair() -> BraidPair!BraidError do
  let initial = Crypto.mlkem_generate()?
  let (ciphertext, one) = Crypto.mlkem_encapsulate(initial.public_key)?
  let two = Crypto.mlkem_decapsulate(initial.private_key, ciphertext)?
  let scope = fixture_scope()?
  let alice = initialize_responder(scope, one)?
  let bob = initialize_responder(scope, two)?
  Secret.destroy(initial.private_key)
  Secret.destroy(one)
  Secret.destroy(two)
  let epoch_key = Crypto.mlkem_generate()?
  let (header, vector) = Crypto.mlkem_public_parts(epoch_key.private_key)?
  Ok(BraidPair {
    alice: alice,
    bob: bob,
    epoch_private: epoch_key.private_key,
    header: header,
    vector: vector
  })
end

pub fn fixture_header(auth :: borrow BraidAwaitHeader,
  header :: MlKemHeader64) -> Bytes!BraidError do
  let mac = SecretMap.copy(auth.secrets, Bytes.from_utf8("mac"))?
  let tag = Crypto.hmac_sha256_tag(mac,
    braid_join([
      auth.scope.protocol_info,
      Bytes.from_utf8(":ekheader"),
      braid_epoch_bytes(auth.epoch)?,
      header.bytes
    ])?)?
  Secret.destroy(mac)
  braid_join([header.bytes, tag])
end

pub fn accepted(state :: consume BraidAwaitHeader,
  complete :: Bytes) -> BraidHeaderReady!BraidError do
  case admit_complete_header(state, number("1")?, complete) do
    BraidHeaderAccepted(value) -> Ok(value)
    BraidHeaderIgnored(old, _) -> do
      Secret.destroy(old.secrets)
      Err(BraidInvalidState)
    end
    BraidHeaderFatal(error) -> Err(error)
  end
end

fn output_tag(state :: borrow BraidCt1Ready) -> Bytes!BraidError do
  let output = SecretMap.copy(state.secrets, Bytes.from_utf8("output"))?
  let tag = Crypto.hmac_sha256_tag(output, Bytes.from_utf8("TEST ONLY C1 known output challenge"))?
  Secret.destroy(output)
  Ok(tag)
end

fn expected_tag(shared :: borrow SecretBytes,
  scope :: BraidScope,
  epoch :: U64) -> Bytes!BraidError do
  let output = Crypto.hkdf_sha256(shared,
    bytes(0, 32)?,
    braid_join([scope.protocol_info, Bytes.from_utf8(":SCKA Key"), braid_epoch_bytes(epoch)?])?,
    32)?
  let tag = Crypto.hmac_sha256_tag(output, Bytes.from_utf8("TEST ONLY C1 known output challenge"))?
  Secret.destroy(output)
  Ok(tag)
end

fn drop_candidate(value :: consume BraidCt1Ready) do
  nil
end

pub fn receive_then_send_and_agreement() -> Bool!BraidError do
  let BraidPair { alice, bob, epoch_private, header, vector } = fixture_pair()?
  let complete = fixture_header(alice, header)?
  let ready = accepted(bob, complete)?
  check(!SecretMap.contains(ready.secrets, Bytes.from_utf8("output")))?
  let prepared = prepare_ct1(ready)?
  check(Bytes.length(prepared.first.bytes) == 960)?
  # Finish is fixture-only after the explicit complete-vector/ack condition;
  # no production Ct1/Ct2 transition is implied by this agreement control.
  let second = Crypto.mlkem_encapsulate2(prepared.continuation, vector)?
  let repeat = Crypto.mlkem_encapsulate2(prepared.continuation, vector)?
  check(Bytes.secure_equals(second.bytes, repeat.bytes))?
  let shared = Crypto.mlkem_decapsulate_parts(epoch_private, prepared.first, second)?
  check(Bytes.secure_equals(output_tag(prepared)?,
    expected_tag(shared, ready.scope, ready.epoch)?))?
  check(!SecretMap.contains(ready.secrets, Bytes.from_utf8("output")))?
  Secret.destroy(shared)
  Secret.destroy(ready.secrets)
  drop_candidate(prepared)
  Secret.destroy(alice.secrets)
  Secret.destroy(epoch_private)
  Ok(true)
end

fn ignored(state :: consume BraidAwaitHeader,
  epoch :: U64,
  complete :: Bytes,
  expected :: Int) -> BraidAwaitHeader!BraidError do
  case admit_complete_header(state, epoch, complete) do
    BraidHeaderIgnored(old, error) -> do
      check(case error do
        BraidWrongEpoch -> expected == 1
        BraidInvalidHeader -> expected == 2
        _ -> false
      end)?
      Ok(old)
    end
    BraidHeaderAccepted(ready) -> do
      Secret.destroy(ready.secrets)
      Err(BraidInvalidState)
    end
    BraidHeaderFatal(error) -> Err(error)
  end
end

pub fn malformed_and_fatal_are_distinct() -> Bool!BraidError do
  let BraidPair { alice, bob, epoch_private, header, vector } = fixture_pair()?
  let complete = fixture_header(alice, header)?
  let old = ignored(bob, number("2")?, complete, 1)?
  let old = ignored(old, number("1")?, bytes(0, 95)?, 2)?
  let old = ignored(old, number("1")?, braid_join([complete, bytes(0, 1)?])?, 2)?
  let bad = braid_join([header.bytes, bytes(0, 32)?])?
  let fatal = case admit_complete_header(old, number("1")?, bad) do
    BraidHeaderFatal(BraidAuthenticationRejected) -> true
    BraidHeaderIgnored(still_live, _) -> do
      Secret.destroy(still_live.secrets)
      false
    end
    BraidHeaderAccepted(ready) -> do
      Secret.destroy(ready.secrets)
      false
    end
    _ -> false
  end
  check(fatal)?
  Secret.destroy(alice.secrets)
  Secret.destroy(epoch_private)
  Ok(true)
end

pub fn candidate_failure_and_borrowed_retry() -> Bool!BraidError do
  let BraidPair { alice, bob, epoch_private, header, vector } = fixture_pair()?
  let ready = accepted(bob, fixture_header(alice, header)?)?
  let prepared = prepare_ct1(ready)?
  let refused = case Crypto.mlkem_encapsulate2(prepared.continuation,
    MlKemPublicVector1152 { bytes: bytes(0, 1152)? }) do
    Err(InvalidPublicKey) -> true
    _ -> false
  end
  check(refused)?
  let before = Crypto.mlkem_encapsulate2(prepared.continuation, vector)?
  let repeated = Crypto.mlkem_encapsulate2(prepared.continuation, vector)?
  check(Bytes.secure_equals(before.bytes, repeated.bytes))?
  let other = prepare_ct1(ready)?
  check(Bytes.length(other.first.bytes) == 960
    && !SecretMap.contains(ready.secrets, Bytes.from_utf8("output")))?
  drop_candidate(other)
  drop_candidate(prepared)
  Secret.destroy(ready.secrets)
  Secret.destroy(alice.secrets)
  Secret.destroy(epoch_private)
  Ok(true)
end

pub fn typed_storage_phases_and_recovery() -> Bool!BraidError do
  check(Test.install_in_memory_secure_store())?
  let key = StorageKey.platform()?
  let BraidPair { alice, bob, epoch_private, header, vector } = fixture_pair()?
  let transition = Crypto.sha256(Bytes.from_utf8("TEST ONLY C1 exact candidate"))
  let initial = seal_await(bob, key, number("1")?, transition)?
  check(Bytes.length(braid_storage_context(initial, 22)?) == 124
    && Bytes.length(initial.secrets) == 154)?
  let replay = restore_await(initial, key)?
  let ready = accepted(replay, fixture_header(alice, header)?)?
  let saved_header = seal_header(ready, key, number("2")?, transition)?
  check(Bytes.length(saved_header.secrets) == 154)?
  let restored_header = restore_header(saved_header, key)?
  let prepared = prepare_ct1(restored_header)?
  check(case seal_ct1_fault(prepared,
    key,
    number("3")?,
    transition,
    fn() -> Err(BraidInvalidState) end) do
    Err(BraidInvalidState) -> true
    _ -> false
  end)?
  # The partial ciphertext is not returned or stored; the same borrowed
  # opaque candidate remains valid for a complete typed seal afterward.
  let saved = seal_ct1(prepared, key, number("3")?, transition)?
  check(Bytes.length(braid_storage_context(saved, 21)?) == 123
    && Bytes.length(saved.secrets) == 198
    && Bytes.length(saved.continuation) == 167)?
  let recovered = restore_ct1(saved, key)?
  let before = Crypto.mlkem_encapsulate2(prepared.continuation, vector)?
  let restored = Crypto.mlkem_encapsulate2(recovered.continuation, vector)?
  check(Bytes.secure_equals(before.bytes, restored.bytes)
    && Bytes.secure_equals(output_tag(prepared)?, output_tag(recovered)?))?
  for changed in [
    %{saved | transition: Crypto.sha256(Bytes.from_utf8("different candidate"))},
    %{saved | revision: number("4")?},
    %{saved | first: bytes(1, 960)?},
    %{saved | header: bytes(1, 64)?},
    %{saved | scope: %{saved.scope | peer_device_id: bytes(8, 16)?}}
  ] do
    let refused = case restore_ct1(changed, key) do
      Err(_) -> true
      Ok(wrong) -> do
        drop_candidate(wrong)
        false
      end
    end
    check(refused)?
  end
  check(case restore_await(%{initial | phase: 1}, key) do
    Err(_) -> true
    Ok(wrong) -> do
      Secret.destroy(wrong.secrets)
      false
    end
  end)?
  Secret.destroy(bob.secrets)
  Secret.destroy(alice.secrets)
  Secret.destroy(epoch_private)
  Secret.destroy(ready.secrets)
  Secret.destroy(restored_header.secrets)
  drop_candidate(prepared)
  drop_candidate(recovered)
  Secret.destroy(key)
  Ok(true)
end
