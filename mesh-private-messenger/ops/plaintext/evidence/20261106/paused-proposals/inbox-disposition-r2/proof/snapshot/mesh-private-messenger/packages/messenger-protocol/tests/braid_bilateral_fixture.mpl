##! Owned host complete-carrier fixtures. No HE/routing/Ack authority.
from Session.BraidResponder import (
  BraidError,
  BraidScope,
  BraidAwaitHeader,
  BraidHeaderReady,
  BraidHeaderAdmission,
  initialize_responder,
  admit_complete_header,
  braid_join
)
from Session.BraidInitiator import (
  BraidEpochOutput,
  BraidAliceIdle,
  BraidAliceHeaderSent,
  BraidAliceEkSent,
  BraidAliceCt1Received,
  BraidAliceCt1Admission,
  BraidAliceCt2Admission,
  initialize_initiator,
  send_header,
  send_vector,
  receive_ct1,
  receive_ct2,
  bilateral_mac
)
from Session.BraidComplete import (
  BraidBobCt1Sent,
  BraidBobEkReceived,
  BraidBobCt2Sent,
  BraidVectorAdmission,
  BraidCt2Emission,
  BraidNextEpochAdmission,
  send_ct1,
  receive_vector,
  send_ct2,
  recover_ct2,
  receive_next_epoch
)
from Session.BraidBilateralStore import (
  BraidBilateralSaved,
  bilateral_storage_context,
  bilateral_saved_shape,
  bilateral_carrier_epoch,
  save_alice_idle,
  save_alice_header,
  save_alice_ek,
  save_alice_first,
  save_bob_first,
  save_bob_vector,
  save_bob_second,
  restore_alice_idle,
  restore_alice_header,
  restore_alice_ek,
  restore_alice_first,
  restore_bob_first,
  restore_bob_vector,
  restore_bob_second
)
from Tests.BraidResponderFixture import (
  fixture_scope
)

fn check(value :: Bool) -> Result<(), BraidError> do
  if value do
    Ok(nil)
  else
    Err(BraidInvalidState)
  end
end

fn number(text :: String) -> U64!BraidError do
  case U64.parse(text) do
    Ok(v)
    Err(_) -> Err(BraidInvalidState)
  end
end

fn bytes(value :: Int, size :: Int) -> Bytes!BraidError do
  case Bytes.repeat(value, size) do
    Ok(v)
    Err(_) -> Err(BraidInvalidState)
  end
end

fn tag(output :: borrow BraidEpochOutput) -> Bytes!BraidError do
  Ok(Crypto.hmac_sha256_tag(output.key, Bytes.from_utf8("TEST ONLY bilateral output challenge"))?)
end

fn auth_tag(map :: borrow SecretMap) -> Bytes!BraidError do
  let key = SecretMap.copy(map, Bytes.from_utf8("mac"))?
  let value = Crypto.hmac_sha256_tag(key, Bytes.from_utf8("TEST ONLY immutable auth challenge"))?
  Secret.destroy(key)
  Ok(value)
end

# Consume whole affine states so generated resource destruction releases each
# opaque field once; repeated field projections would move the same owner twice.
fn drop_alice_header(state :: consume BraidAliceHeaderSent) do
  nil
end

fn drop_alice_ek(state :: consume BraidAliceEkSent) do
  nil
end

fn drop_alice_first(state :: consume BraidAliceCt1Received) do
  nil
end

fn drop_bob_first(state :: consume BraidBobCt1Sent) do
  nil
end

fn drop_bob_vector(state :: consume BraidBobEkReceived) do
  nil
end

fn pair() -> (BraidAliceIdle, BraidAwaitHeader)!BraidError do
  let initializer = Crypto.mlkem_generate()?
  let (wire, one) = Crypto.mlkem_encapsulate(initializer.public_key)?
  let two = Crypto.mlkem_decapsulate(initializer.private_key, wire)?
  let scope = fixture_scope()?
  let alice = initialize_initiator(scope, one)?
  let peer_scope = %{scope |
    account_id: scope.peer_account_id,
    device_id: scope.peer_device_id,
    peer_account_id: scope.account_id,
    peer_device_id: scope.device_id
  }
  let bob = initialize_responder(peer_scope, two)?
  Secret.destroy(initializer.private_key)
  Secret.destroy(one)
  Secret.destroy(two)
  Ok((alice, bob))
end

fn accept_header(state :: consume BraidAwaitHeader,
  epoch :: U64,
  complete :: Bytes) -> BraidHeaderReady!BraidError do
  case admit_complete_header(state, epoch, complete) do
    BraidHeaderAccepted(value) -> Ok(value)
    _ -> Err(BraidInvalidState)
  end
end

fn accept_first(state :: consume BraidAliceEkSent,
  epoch :: U64,
  first :: MlKemCiphertext1_960) -> BraidAliceCt1Received!BraidError do
  case receive_ct1(state, epoch, first) do
    BraidAliceCt1Accepted(value) -> Ok(value)
    _ -> Err(BraidInvalidState)
  end
end

fn accept_vector(state :: consume BraidBobCt1Sent,
  epoch :: U64,
  vector :: MlKemPublicVector1152) -> BraidBobEkReceived!BraidError do
  case receive_vector(state, epoch, vector) do
    BraidVectorAccepted(value) -> Ok(value)
    _ -> Err(BraidInvalidState)
  end
end

fn emit_second(state :: consume BraidBobEkReceived) -> (BraidBobCt2Sent, Bytes)!BraidError do
  case send_ct2(state) do
    BraidCt2Emitted(value, wire) -> Ok((value, wire))
    _ -> Err(BraidInvalidState)
  end
end

fn accept_second(state :: consume BraidAliceCt1Received,
  epoch :: U64,
  wire :: Bytes) -> (BraidAwaitHeader, BraidEpochOutput)!BraidError do
  case receive_ct2(state, epoch, wire) do
    BraidAliceCt2Accepted(value, output) -> Ok((value, output))
    _ -> Err(BraidInvalidState)
  end
end

fn handoff(state :: consume BraidBobCt2Sent, epoch :: U64) -> BraidAliceIdle!BraidError do
  case receive_next_epoch(state, epoch) do
    BraidNextEpochAccepted(value) -> Ok(value)
    _ -> Err(BraidInvalidState)
  end
end

fn epoch(alice :: consume BraidAliceIdle,
  bob :: consume BraidAwaitHeader) -> (BraidAwaitHeader, BraidAliceIdle, BraidEpochOutput, BraidEpochOutput)!BraidError do
  let e = alice.epoch
  let (header, wire) = send_header(alice)?
  let ready = accept_header(bob, e, wire)?
  let (first, bob_output) = send_ct1(ready)?
  check(!SecretMap.contains(first.secrets, Bytes.from_utf8("output")))?
  let (sent, vector) = send_vector(header)?
  let received = accept_first(sent, e, first.first)?
  let vector_received = accept_vector(first, e, vector)?
  let (sent, wire) = emit_second(vector_received)?
  let (waiting, alice_output) = accept_second(received, e, wire)?
  # This tests only the kernel's successor predicate. The fixture has not
  # authenticated a network next-epoch message and makes no such claim.
  let next = handoff(sent, waiting.epoch)?
  Ok((waiting, next, alice_output, bob_output))
end

pub fn two_epochs_and_unique_outputs() -> Bool!BraidError do
  let (alice, bob) = pair()?
  let (a_wait, b_next, a1, b1) = epoch(alice, bob)?
  check(U64.compare(a1.epoch, number("1")?) == 0 && U64.compare(b1.epoch, a1.epoch) == 0)?
  let first_tag = tag(a1)?
  check(Bytes.secure_equals(first_tag, tag(b1)?))?
  Secret.destroy(a1.key)
  Secret.destroy(b1.key)
  let (b_wait, a_next, b2, a2) = epoch(b_next, a_wait)?
  check(U64.compare(a2.epoch, number("2")?) == 0 && U64.compare(b2.epoch, a2.epoch) == 0)?
  check(Bytes.secure_equals(tag(a2)?, tag(b2)?) && !Bytes.secure_equals(first_tag, tag(a2)?))?
  check(U64.compare(b_wait.epoch, number("3")?) == 0
    && U64.compare(a_next.epoch, b_wait.epoch) == 0)?
  Secret.destroy(a2.key)
  Secret.destroy(b2.key)
  Secret.destroy(b_wait.secrets)
  Secret.destroy(a_next.secrets)
  Ok(true)
end

# Correct SHA3(vector || rho) from the qualified public validator regression;
# every packed coefficient is 4095, above q=3329. This is not a digest mismatch.
fn noncanonical_vector_refused() -> Result<(), BraidError> do
  let (alice, bob) = pair()?
  let header = case Bytes.from_hex("a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6364630f3002f1d94500f3ed876352ea0ec019a697fe4d0a07d8ff71750dbc991") do
    Ok(v) -> v
    Err(_) -> return Err(BraidInvalidState)
  end
  let e = bob.epoch
  let supplied = bilateral_mac(bob.secrets, bob.scope, e, ":ekheader", header)?
  let ready = accept_header(bob, e, braid_join([header, supplied])?)?
  let (first, output) = send_ct1(ready)?
  let before = auth_tag(first.secrets)?
  let first = case receive_vector(first, e, MlKemPublicVector1152 { bytes: bytes(255, 1152)? }) do
    BraidVectorIgnored(old, BraidCryptoFailure(InvalidPublicKey)) -> old
    _ -> return Err(BraidInvalidState)
  end
  check(Bytes.secure_equals(before, auth_tag(first.secrets)?))?
  drop_bob_first(first)
  Secret.destroy(alice.secrets)
  Secret.destroy(output.key)
  Ok(nil)
end

pub fn vector_refusal_and_exact_retry() -> Bool!BraidError do
  noncanonical_vector_refused()?
  let (alice, bob) = pair()?
  let (header, wire) = send_header(alice)?
  let e = header.epoch
  let ready = accept_header(bob, e, wire)?
  let (first, output) = send_ct1(ready)?
  let before = auth_tag(first.secrets)?
  let wrong = Crypto.mlkem_generate()?
  let (_, wrong_vector) = Crypto.mlkem_public_parts(wrong.private_key)?
  let first = case receive_vector(first, e, MlKemPublicVector1152 { bytes: bytes(0, 1151)? }) do
    BraidVectorIgnored(old, BraidCryptoFailure(InvalidLength(1152, 1151))) -> old
    _ -> return Err(BraidInvalidState)
  end
  check(Bytes.secure_equals(before, auth_tag(first.secrets)?))?
  let first = case receive_vector(first, e, wrong_vector) do
    BraidVectorIgnored(old, BraidCryptoFailure(InvalidPublicKey)) -> old
    _ -> return Err(BraidInvalidState)
  end
  check(Bytes.secure_equals(before, auth_tag(first.secrets)?))?
  let (sent, vector) = send_vector(header)?
  let received = accept_first(sent, e, first.first)?
  let accepted = accept_vector(first, e, vector)?
  let (sent, wire) = emit_second(accepted)?
  check(Bytes.secure_equals(wire, recover_ct2(sent)?)
    && Bytes.secure_equals(wire, recover_ct2(sent)?))?
  let (waiting, recovered) = accept_second(received, e, wire)?
  check(Bytes.secure_equals(tag(output)?, tag(recovered)?))?
  Secret.destroy(output.key)
  Secret.destroy(recovered.key)
  Secret.destroy(waiting.secrets)
  Secret.destroy(sent.secrets)
  Secret.destroy(wrong.private_key)
  Ok(true)
end

fn inflight() -> (BraidAliceCt1Received, BraidBobCt2Sent, Bytes, BraidEpochOutput)!BraidError do
  let (alice, bob) = pair()?
  let (header, wire) = send_header(alice)?
  let e = header.epoch
  let ready = accept_header(bob, e, wire)?
  let (first, output) = send_ct1(ready)?
  let (sent, vector) = send_vector(header)?
  let received = accept_first(sent, e, first.first)?
  let accepted = accept_vector(first, e, vector)?
  let (sent, wire) = emit_second(accepted)?
  Ok((received, sent, wire, output))
end

pub fn ciphertext_shape_and_authenticated_terminal() -> Bool!BraidError do
  let (alice, bob, wire, output) = inflight()?
  let e = alice.epoch
  let before = auth_tag(alice.secrets)?
  let alice = case receive_ct2(alice, number("2")?, wire) do
    BraidAliceCt2Ignored(old, BraidWrongEpoch) -> old
    _ -> return Err(BraidInvalidState)
  end
  let alice = case receive_ct2(alice, e, bytes(0, 159)?) do
    BraidAliceCt2Ignored(old, BraidInvalidHeader) -> old
    _ -> return Err(BraidInvalidState)
  end
  check(Bytes.secure_equals(before, auth_tag(alice.secrets)?))?
  let (waiting, actual) = accept_second(alice, e, wire)?
  check(Bytes.secure_equals(tag(output)?, tag(actual)?))?
  Secret.destroy(waiting.secrets)
  Secret.destroy(bob.secrets)
  Secret.destroy(output.key)
  Secret.destroy(actual.key)
  let (alice, bob, wire, output) = inflight()?
  let prefix = case Bytes.slice(wire, 0, 159) do
    Ok(v) -> v
    Err(_) -> return Err(BraidInvalidState)
  end
  let last = List.get(Bytes.to_list(wire), 159)
  let changed = braid_join([
    prefix,
    bytes(if last == 0 do
        1
      else
        0
      end,
      1)?
  ])?
  # A complete admitted frame's internal MAC is deliberately wrong. This pure
  # result does not substitute for the owning HE coordinator's admission/CAS.
  check(case receive_ct2(alice, number("1")?, changed) do
    BraidAliceCt2Fatal(BraidAuthenticationRejected) -> true
    _ -> false
  end)?
  Secret.destroy(bob.secrets)
  Secret.destroy(output.key)
  Ok(true)
end

pub fn typed_key_and_continuation_recovery() -> Bool!BraidError do
  check(Test.install_in_memory_secure_store())?
  let key = StorageKey.platform()?
  let transition = Crypto.sha256(Bytes.from_utf8("TEST ONLY bilateral exact transition"))
  let (alice, bob) = pair()?
  let saved = save_alice_idle(alice, key, number("1")?, transition)?
  check(U64.compare(saved.output_epoch, number("0")?) == 0
    && U64.compare(bilateral_carrier_epoch(saved)?, number("0")?) == 0)?
  let restored = restore_alice_idle(saved, saved, key)?
  Secret.destroy(alice.secrets)
  let (header, wire) = send_header(restored)?
  let e = header.epoch
  let saved = save_alice_header(header, key, number("2")?, transition)?
  check(bilateral_saved_shape(saved)
    && Bytes.length(saved.epoch_key) == 131
    && U64.compare(saved.output_epoch, number("0")?) == 0
    && U64.compare(bilateral_carrier_epoch(saved)?, number("0")?) == 0)?
  let header_key_blob = saved.epoch_key
  let recovered = restore_alice_header(saved, saved, key)?
  drop_alice_header(header)
  let ready = accept_header(bob, e, wire)?
  let (first, output) = send_ct1(ready)?
  let saved = save_bob_first(first, key, number("3")?, transition)?
  check(Bytes.length(saved.continuation) == 167
    && Bytes.length(saved.epoch_key) == 0
    && U64.compare(saved.output_epoch, e) == 0
    && U64.compare(bilateral_carrier_epoch(saved)?, number("0")?) == 0)?
  let first_continuation_blob = saved.continuation
  let first_auth_blob = saved.secrets
  let recovered_first = restore_bob_first(saved, saved, key)?
  drop_bob_first(first)
  let (sent, vector) = send_vector(recovered)?
  let saved = save_alice_ek(sent, key, number("4")?, transition)?
  check(U64.compare(saved.output_epoch, number("0")?) == 0
    && U64.compare(bilateral_carrier_epoch(saved)?, number("0")?) == 0)?
  # Same opaque key, different stage: a valid old ciphertext must not unwrap.
  check(case restore_alice_ek(%{saved | epoch_key: header_key_blob}, saved, key) do
    Err(_) -> true
    _ -> false
  end)?
  let recovered_sent = restore_alice_ek(saved, saved, key)?
  drop_alice_ek(sent)
  let received = accept_first(recovered_sent, e, recovered_first.first)?
  let saved = save_alice_first(received, key, number("5")?, transition)?
  check(U64.compare(saved.output_epoch, number("0")?) == 0
    && U64.compare(bilateral_carrier_epoch(saved)?, number("0")?) == 0)?
  let recovered_received = restore_alice_first(saved, saved, key)?
  drop_alice_first(received)
  let accepted = accept_vector(recovered_first, e, vector)?
  let saved = save_bob_vector(accepted, key, number("6")?, transition)?
  check(U64.compare(saved.output_epoch, e) == 0
    && U64.compare(bilateral_carrier_epoch(saved)?, number("0")?) == 0)?
  # The unchanged private continuation/authenticator cannot be transplanted
  # from the prior stage, even though both encrypted shapes are still valid.
  check(case restore_bob_vector(%{saved | continuation: first_continuation_blob}, saved, key) do
    Err(_) -> true
    _ -> false
  end)?
  check(case restore_bob_vector(%{saved | secrets: first_auth_blob}, saved, key) do
    Err(_) -> true
    _ -> false
  end)?
  let recovered_vector = restore_bob_vector(saved, saved, key)?
  drop_bob_vector(accepted)
  let (sent, wire) = emit_second(recovered_vector)?
  let saved = save_bob_second(sent, key, number("7")?, transition)?
  check(Bytes.length(saved.continuation) == 0
    && Bytes.length(saved.epoch_key) == 0
    && U64.compare(bilateral_carrier_epoch(saved)?, e) == 0)?
  let recovered_second = restore_bob_second(saved, saved, key)?
  Secret.destroy(sent.secrets)
  check(Bytes.secure_equals(recover_ct2(recovered_second)?, wire))?
  let (waiting, actual) = accept_second(recovered_received, e, wire)?
  check(Bytes.secure_equals(tag(output)?, tag(actual)?))?
  Secret.destroy(output.key)
  Secret.destroy(actual.key)
  Secret.destroy(waiting.secrets)
  Secret.destroy(recovered_second.secrets)
  Secret.destroy(key)
  Ok(true)
end

fn refused_header(value :: BraidBilateralSaved,
  expected :: BraidBilateralSaved,
  key :: borrow StorageKey) -> Bool do
  case restore_alice_header(value, expected, key) do
    Err(_) -> true
    _ -> false
  end
end

pub fn stored_identity_and_component_refusals() -> Bool!BraidError do
  check(Test.install_in_memory_secure_store())?
  let key = StorageKey.platform()?
  let (alice, bob) = pair()?
  let (header, wire) = send_header(alice)?
  let saved = save_alice_header(header, key, number("1")?, Crypto.sha256(wire))?
  for changed in [
    %{saved | role: 2},
    %{saved | substate: 2},
    %{saved | epoch: number("2")?},
    %{saved | revision: number("2")?},
    %{saved | transition: bytes(7, 32)?},
    %{saved | output_epoch: number("1")?},
    %{saved | header: bytes(7, 64)?},
    %{saved | vector: bytes(7, 1152)?},
    %{saved | first: bytes(7, 960)?},
    %{saved | scope: %{saved.scope | configuration: bytes(7, 32)?}},
    %{saved | scope: %{saved.scope | account_id: bytes(7, 32)?}},
    %{saved | scope: %{saved.scope | device_id: bytes(7, 16)?}},
    %{saved | scope: %{saved.scope | peer_account_id: bytes(7, 32)?}},
    %{saved | scope: %{saved.scope | peer_device_id: bytes(7, 16)?}},
    %{saved | scope: %{saved.scope | session_id: bytes(7, 32)?}},
    %{saved | scope: %{saved.scope | protocol_info: Bytes.from_utf8("TEST ONLY other profile")}}
  ] do
    # Trusted-basis mismatch and self-described metadata are distinct controls:
    # neither is allowed to unwrap the original private key under changed scope.
    check(refused_header(changed, saved, key) && refused_header(changed, changed, key))?
  end
  for changed in [
    %{saved | secrets: bytes(0, 154)?},
    %{saved | epoch_key: bytes(0, 131)?},
    %{saved | secrets: bytes(0, 153)?},
    %{saved | epoch_key: bytes(0, 132)?},
    %{saved | continuation: bytes(0, 167)?}
  ] do
    check(refused_header(changed, saved, key))?
  end
  let other = StorageKey.ephemeral()?
  check(refused_header(saved, saved, other))?
  let restored = restore_alice_header(saved, saved, key)?
  check(Bytes.length(bilateral_storage_context(saved, 22)?) == 124
    && Bytes.length(bilateral_storage_context(saved, 23)?) == 123)?
  drop_alice_header(restored)
  drop_alice_header(header)
  Secret.destroy(bob.secrets)
  Secret.destroy(other)
  Secret.destroy(key)
  Ok(true)
end

pub fn recovery_no_resampling_and_epoch_limits() -> Bool!BraidError do
  check(Test.install_in_memory_secure_store())?
  let key = StorageKey.platform()?
  let (alice, bob, wire, output) = inflight()?
  let before = auth_tag(bob.secrets)?
  let saved = save_bob_second(bob, key, number("1")?, Crypto.sha256(wire))?
  check(U64.compare(saved.output_epoch, number("1")?) == 0
    && U64.compare(bilateral_carrier_epoch(saved)?, number("1")?) == 0)?
  let restored = restore_bob_second(saved, saved, key)?
  check(Bytes.secure_equals(recover_ct2(restored)?, wire)
    && Bytes.secure_equals(recover_ct2(restored)?, wire)
    && Bytes.secure_equals(before, auth_tag(restored.secrets)?))?
  let restored = case receive_next_epoch(restored, number("1")?) do
    BraidNextEpochIgnored(old, BraidWrongEpoch) -> old
    _ -> return Err(BraidInvalidState)
  end
  let restored = case receive_next_epoch(restored, number("3")?) do
    BraidNextEpochIgnored(old, BraidWrongEpoch) -> old
    _ -> return Err(BraidInvalidState)
  end
  let next = handoff(restored, number("2")?)?
  check(U64.compare(next.epoch, number("2")?) == 0
    && Bytes.secure_equals(before, auth_tag(next.secrets)?))?
  Secret.destroy(next.secrets)
  drop_alice_first(alice)
  Secret.destroy(bob.secrets)
  Secret.destroy(output.key)
  let (alice, bob) = pair()?
  let invalid = BraidAliceIdle {
    scope: alice.scope,
    epoch: number("18446744073709551615")?,
    secrets: alice.secrets
  }
  check(case send_header(invalid) do
    Err(BraidInvalidState) -> true
    _ -> false
  end)?
  Secret.destroy(bob.secrets)
  Secret.destroy(key)
  Ok(true)
end
