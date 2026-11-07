##! Actual Braid carriers through CBF1 public words; no ACK or scheduling authority.
from Session.BraidFragment import BraidFragmentKind, encode_braid_fragment, decode_braid_fragment
from Session.BraidFragmentWords import emit_braid_fragment, recover_braid_carrier
from Session.BraidResponder import (
  BraidError,
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
  receive_ct2
)
from Session.BraidComplete import (
  BraidBobCt1Sent,
  BraidBobEkReceived,
  BraidBobCt2Sent,
  BraidVectorAdmission,
  BraidCt2Emission,
  send_ct1,
  receive_vector,
  send_ct2
)
from Tests.BraidResponderFixture import fixture_scope

fn check(value :: Bool) -> Unit!BraidError do
  if value do
    Ok(nil)
  else
    Err(BraidInvalidState)
  end
end

fn repair_public(message :: Bytes, kind :: BraidFragmentKind, epoch :: U64) -> Bytes!BraidError do
  let scope = fixture_scope()?
  let count = (Bytes.length(message) + 63) / 64
  let fragments = for index in 0..count do
    let fragment = case emit_braid_fragment(kind,
      scope.configuration,
      scope.session_id,
      epoch,
      message,
      65535 - index * 997) do
      Ok(v) -> v
      Err(_) -> return Err(BraidInvalidState)
    end
    let wire = case encode_braid_fragment(fragment) do
      Ok(v) -> v
      Err(_) -> return Err(BraidInvalidState)
    end
    case decode_braid_fragment(wire, scope.configuration, scope.session_id) do
      Ok(v) -> v
      Err(_) -> return Err(BraidInvalidState)
    end
  end
  check(recover_braid_carrier(kind,
    scope.configuration,
    scope.session_id,
    epoch,
    List.take(fragments, count - 1)) == Ok(None))?
  let restored = case recover_braid_carrier(kind,
    scope.configuration,
    scope.session_id,
    epoch,
    List.reverse(fragments)) do
    Ok(Some(v)) -> v
    _ -> return Err(BraidInvalidState)
  end
  check(Bytes.secure_equals(restored, message))?
  Ok(restored)
end

fn pair() -> (BraidAliceIdle, BraidAwaitHeader)!BraidError do
  let initializer = Crypto.mlkem_generate()?
  let (wire, one) = Crypto.mlkem_encapsulate(initializer.public_key)?
  let two = Crypto.mlkem_decapsulate(initializer.private_key, wire)?
  let scope = fixture_scope()?
  let alice = initialize_initiator(scope, one)?
  let bob = initialize_responder(%{scope |
      account_id: scope.peer_account_id,
      device_id: scope.peer_device_id,
      peer_account_id: scope.account_id,
      peer_device_id: scope.device_id
    },
    two)?
  Secret.destroy(initializer.private_key)
  Secret.destroy(one)
  Secret.destroy(two)
  Ok((alice, bob))
end

fn accepted_header(state :: consume BraidAwaitHeader,
  epoch :: U64,
  wire :: Bytes) -> BraidHeaderReady!BraidError do
  case admit_complete_header(state, epoch, wire) do
    BraidHeaderAccepted(value) -> Ok(value)
    _ -> Err(BraidInvalidState)
  end
end

fn accepted_first(state :: consume BraidAliceEkSent,
  epoch :: U64,
  first :: Bytes) -> BraidAliceCt1Received!BraidError do
  case receive_ct1(state, epoch, MlKemCiphertext1_960 { bytes: first }) do
    BraidAliceCt1Accepted(value) -> Ok(value)
    _ -> Err(BraidInvalidState)
  end
end

fn accepted_vector(state :: consume BraidBobCt1Sent,
  epoch :: U64,
  vector :: Bytes) -> BraidBobEkReceived!BraidError do
  case receive_vector(state, epoch, MlKemPublicVector1152 { bytes: vector }) do
    BraidVectorAccepted(value) -> Ok(value)
    _ -> Err(BraidInvalidState)
  end
end

fn emitted_second(state :: consume BraidBobEkReceived) -> (BraidBobCt2Sent, Bytes)!BraidError do
  case send_ct2(state) do
    BraidCt2Emitted(value, wire) -> Ok((value, wire))
    _ -> Err(BraidInvalidState)
  end
end

fn accepted_second(state :: consume BraidAliceCt1Received,
  epoch :: U64,
  wire :: Bytes) -> (BraidAwaitHeader, BraidEpochOutput)!BraidError do
  case receive_ct2(state, epoch, wire) do
    BraidAliceCt2Accepted(value, output) -> Ok((value, output))
    _ -> Err(BraidInvalidState)
  end
end

fn output_tag(output :: borrow BraidEpochOutput) -> Bytes!BraidError do
  Ok(Crypto.hmac_sha256_tag(output.key, Bytes.from_utf8("TEST ONLY erasure carrier output check"))?)
end

fn proof() -> Bool!BraidError do
  let (alice, bob) = pair()?
  let epoch = alice.epoch
  let (header, header_wire) = send_header(alice)?
  check(Bytes.length(header_wire) == 96)?
  let ready = accepted_header(bob, epoch, repair_public(header_wire, BraidHeaderFragment, epoch)?)?
  let (first, bob_output) = send_ct1(ready)?
  let (alice, vector) = send_vector(header)?
  check(Bytes.length(first.first.bytes) == 960 && Bytes.length(vector.bytes) == 1152)?
  let received = accepted_first(alice,
    epoch,
    repair_public(first.first.bytes, BraidFirstFragment, epoch)?)?
  let accepted = accepted_vector(first,
    epoch,
    repair_public(vector.bytes, BraidVectorFragment, epoch)?)?
  let (sent, second_wire) = emitted_second(accepted)?
  check(Bytes.length(second_wire) == 160)?
  let (waiting, alice_output) = accepted_second(received,
    epoch,
    repair_public(second_wire, BraidSecondFragment, epoch)?)?
  check(U64.compare(alice_output.epoch, bob_output.epoch) == 0
    && Bytes.secure_equals(output_tag(alice_output)?, output_tag(bob_output)?))?
  # Each opaque output is consumed once, never serialized or re-emitted.
  Secret.destroy(alice_output.key)
  Secret.destroy(bob_output.key)
  Secret.destroy(waiting.secrets)
  Secret.destroy(sent.secrets)
  println("GF16_REAL_BRAID_COMPLETE_CARRIERS_PASSED")
  Ok(true)
end

fn discard_header(state :: consume BraidAliceHeaderSent) do
  nil
end

fn authenticated_refusal() -> Bool!BraidError do
  let (alice, bob) = pair()?
  let (header, wire) = send_header(alice)?
  let first = case Bytes.get(wire, 0) do
    Err(_) -> return Err(BraidInvalidState)
    Ok(value) -> value
  end
  let changed = case Bytes.repeat(if first == 0 do
      1
    else
      0
    end,
    1) do
    Err(_) -> return Err(BraidInvalidState)
    Ok(value) -> value
  end
  let rest = case Bytes.slice(wire, 1, Bytes.length(wire) - 1) do
    Err(_) -> return Err(BraidInvalidState)
    Ok(value) -> value
  end
  let forged = repair_public(braid_join([changed, rest])?, BraidHeaderFragment, header.epoch)?
  let refused = case admit_complete_header(bob, header.epoch, forged) do
    BraidHeaderFatal(BraidAuthenticationRejected) -> true
    _ -> false
  end
  discard_header(header)
  check(refused)?
  println("GF16_DECODE_IS_NOT_AUTHENTICATION_PASSED")
  Ok(true)
end

test("real bilateral public carriers survive repair-only erasure and existing kernel authentication") do
  case proof() do
    Ok(value) -> assert(value)
    Err(_) -> assert(false)
  end
end

test("a consistently encoded false public carrier still fails the existing kernel MAC") do
  case authenticated_refusal() do
    Ok(value) -> assert(value)
    Err(_) -> assert(false)
  end
end
