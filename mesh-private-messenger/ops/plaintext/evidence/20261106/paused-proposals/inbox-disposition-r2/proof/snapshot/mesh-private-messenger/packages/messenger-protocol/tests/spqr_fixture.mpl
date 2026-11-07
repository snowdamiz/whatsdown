##! P1 inactive fixture. Literal secrets enter through fixed TEST ONLY env seeds.
##! No secret export, storage, fake output token, transport authentication or durability.
from Session.BraidResponder import (
  BraidScope,
  BraidAwaitHeader,
  BraidHeaderAdmission,
  initialize_responder,
  admit_complete_header
)
from Session.BraidInitiator import (
  BraidAliceIdle,
  BraidAliceCt1Admission,
  BraidAliceCt2Admission,
  initialize_initiator,
  send_header,
  send_vector,
  receive_ct1,
  receive_ct2
)
from Session.BraidComplete import (
  BraidVectorAdmission,
  BraidCt2Emission,
  BraidNextEpochAdmission,
  send_ct1,
  receive_vector,
  send_ct2,
  receive_next_epoch
)
from Session.SpqrKdf import SpqrError, spqr_initial_material, spqr_add_material, spqr_step_material
from Session.Spqr import (
  SpqrState,
  SpqrSlot,
  SpqrEpochAdmission,
  SpqrKeyAdmission,
  initialize_spqr,
  incorporate_spqr_epoch,
  spqr_send_key,
  spqr_receive_key
)
from Tests.BraidResponderFixture import fixture_scope

fn check(ok :: Bool) -> Result<(), SpqrError> do
  if ok do
    Ok(nil)
  else
    Err(SpqrInvalidState)
  end
end

fn number(text :: String) -> U64!SpqrError do
  case U64.parse(text) do
    Ok(v)
    Err(_) -> Err(SpqrInvalidState)
  end
end

fn repeated(value :: Int, count :: Int) -> Bytes!SpqrError do
  case Bytes.repeat(value, count) do
    Ok(v)
    Err(_) -> Err(SpqrInvalidState)
  end
end

fn literal_scope() -> BraidScope!SpqrError do
  let scope = case fixture_scope() do
    Ok(v) -> v
    Err(error) -> return Err(SpqrKernelFailure(error))
  end
  Ok(%{scope | configuration: repeated(17, 32)?, session_id: repeated(34, 32)?})
end

fn tag(key :: borrow SecretBytes) -> Bytes!SpqrError do
  Ok(Crypto.hmac_sha256_tag(key, Bytes.from_utf8("TEST ONLY C1 SPQR literal oracle v1"))?)
end

fn expected(key :: borrow SecretBytes, literal :: String) -> Result<(), SpqrError> do
  let bytes = case Bytes.from_hex(literal) do
    Ok(v) -> v
    Err(_) -> return Err(SpqrInvalidState)
  end
  check(Bytes.secure_equals(tag(key)?, bytes))
end

pub fn literal_initial() -> Bool!SpqrError do
  let seed = Env.get_secret_hex("MORSE_C1_SPQR_LITERAL_SEED")?
  let (root, forward, reverse) = spqr_initial_material(literal_scope()?, seed)?
  expected(root, "088b90f2444420cff05aa3f46629dd10b512b59f08e015075cd902b701a4098f")?
  expected(forward, "8c4bb6cc01ee88c21ee927565de56b3b406dd22e22197d5dff937a29fdfa6fa7")?
  expected(reverse, "575d01d9b47ab21e664beee6c0a7ee10808caac873832fbb72bc0a46d8402e6f")?
  Secret.destroy(seed)
  Secret.destroy(root)
  Secret.destroy(forward)
  Secret.destroy(reverse)
  Ok(true)
end

pub fn literal_add() -> Bool!SpqrError do
  let old = Env.get_secret_hex("MORSE_C1_SPQR_LITERAL_ROOT")?
  let update = Env.get_secret_hex("MORSE_C1_SPQR_LITERAL_UPDATE")?
  let (root, forward, reverse) = spqr_add_material(literal_scope()?, old, update, number("1")?)?
  expected(root, "2f933ac7bd3d88ea93ada7f2fedc9387a52743c120e0a62b487101fabb1db5f4")?
  expected(forward, "20686c507ee3e35b8a90c545f2f49fb2384b49039f994a0ca8e02d134b074e21")?
  expected(reverse, "13be25214eea36082214bb29f419274327b1642c86ce7cce1783d37930eed9b3")?
  Secret.destroy(old)
  Secret.destroy(update)
  Secret.destroy(root)
  Secret.destroy(forward)
  Secret.destroy(reverse)
  Ok(true)
end

pub fn literal_steps_and_domains() -> Bool!SpqrError do
  let chain = Env.get_secret_hex("MORSE_C1_SPQR_LITERAL_CHAIN")?
  let scope = literal_scope()?
  let (next0, key0) = spqr_step_material(scope, chain, 0, number("2")?, number("1")?)?
  expected(next0, "134bbb6fe18d871fc3c5e5dcde7336af0325780d0ddf736053ceb6e50de00c42")?
  expected(key0, "072d30db0cc269eeedcc482763c96c2b2be6d956fa86f73743d209ae6cd29a39")?
  Secret.destroy(next0)
  Secret.destroy(key0)
  let (next1, key1) = spqr_step_material(scope, chain, 1, number("2")?, number("1")?)?
  expected(next1, "cc2436eb103c576fe86ca242e36db06ac411207a306455847c1769d48b85cc39")?
  expected(key1, "df265efefd42a92664518feb17158bfd706d8d9b99de1c0c468f487f5e598162")?
  Secret.destroy(next1)
  Secret.destroy(key1)
  let (next2, key2) = spqr_step_material(scope, chain, 0, number("2")?, number("2")?)?
  expected(next2, "1147fc6ce7e4c060fc29e7551000e50dc5fbcfd80f3e066863f56103836b630f")?
  expected(key2, "a47b6658258d2c0d0298fe2a87a9e83ab6fd51d035905a543cff4feb841dea68")?
  Secret.destroy(next2)
  Secret.destroy(key2)
  let (next3, key3) = spqr_step_material(scope,
    chain,
    0,
    number("2")?,
    number("18446744073709551615")?)?
  expected(next3, "1e5a2ada2bca66fbfb9710a3d18c30765784d7f9a04516772d2ad9098f94b3c4")?
  expected(key3, "84387016cf4f62155606d865345ab6d149e02ec6cc435a946a85f0089de23cbe")?
  Secret.destroy(next3)
  Secret.destroy(key3)
  let (next4, key4) = spqr_step_material(%{scope | configuration: repeated(18, 32)?},
    chain,
    0,
    number("2")?,
    number("1")?)?
  expected(next4, "be5a6e7759cac9309b37950fb9d89a4b09b21d5c9e1e3256875a1154f3c1afa7")?
  expected(key4, "3c204801b55a66d44c4f9d30ccc0dbc7acaa643bc41620dba97088ca73bb1125")?
  Secret.destroy(next4)
  Secret.destroy(key4)
  let (next5, key5) = spqr_step_material(%{scope | session_id: repeated(35, 32)?},
    chain,
    0,
    number("2")?,
    number("1")?)?
  expected(next5, "8ad034e7844346088310e31ed9d90a3a17c0f9185196f4fd09f35d95eaa2587d")?
  expected(key5, "1134a937217832a5d971083104bc5d69957973ca3b14bdd1a32c877b2e36c70f")?
  Secret.destroy(next5)
  Secret.destroy(key5)
  let (next6, key6) = spqr_step_material(scope, chain, 0, number("3")?, number("1")?)?
  expected(next6, "9bbbb7266981dd2b1e9a2f25e9937bf88cc3d1d281a0b5a32041af0b870ca0e5")?
  expected(key6, "1bf647f571da11519d75c6b4005545d2edebab0b310c74483ddb5d62d025eb15")?
  Secret.destroy(next6)
  Secret.destroy(key6)
  let zero_refused = case spqr_step_material(scope, chain, 0, number("2")?, number("0")?) do
    Err(SpqrInvalidState) -> true
    _ -> false
  end
  check(zero_refused)?
  let wrong_direction = case spqr_step_material(scope, chain, 2, number("2")?, number("1")?) do
    Err(SpqrInvalidState) -> true
    _ -> false
  end
  let malformed_scope = %{scope | session_id: Bytes.empty()}
  let bad_scope = case spqr_initial_material(malformed_scope, chain) do
    Err(SpqrInvalidState) -> true
    _ -> false
  end
  check(wrong_direction && bad_scope)?
  Secret.destroy(chain)
  Ok(true)
end

fn root_tag(state :: borrow SpqrState) -> Bytes!SpqrError do
  let name = case Bytes.from_list([0]) do
    Ok(v) -> v
    Err(_) -> return Err(SpqrInvalidState)
  end
  let copied = SecretMap.copy(state.chains, name)?
  let result = tag(copied)?
  Secret.destroy(copied)
  Ok(result)
end

fn send_one(one :: consume SpqrState,
  two :: consume SpqrState,
  k :: U64) -> (SpqrState, SpqrState)!SpqrError do
  let (one, key, n) = case spqr_send_key(one, k) do
    SpqrKeyAccepted(s, key, n) -> (s, key, n)
    SpqrKeyRefused(_, error) -> return Err(error)
  end
  let challenge = tag(key)?
  Secret.destroy(key)
  let (two, key, received) = case spqr_receive_key(two, k, n) do
    SpqrKeyAccepted(s, key, n) -> (s, key, n)
    SpqrKeyRefused(_, error) -> return Err(error)
  end
  check(U64.compare(received, n) == 0 && Bytes.secure_equals(challenge, tag(key)?))?
  Secret.destroy(key)
  Ok((one, two))
end

fn both(one :: consume SpqrState,
  two :: consume SpqrState,
  k :: U64) -> (SpqrState, SpqrState)!SpqrError do
  let (one, two) = send_one(one, two, k)?
  let (two, one) = send_one(two, one, k)?
  Ok((one, two))
end

fn epoch(alice :: consume BraidAliceIdle,
  bob :: consume BraidAwaitHeader,
  one :: consume SpqrState,
  two :: consume SpqrState) -> (BraidAwaitHeader, BraidAliceIdle, SpqrState, SpqrState)!SpqrError do
  let e = alice.epoch
  let old = one.epoch
  let d1 = one.direction
  let d2 = two.direction
  let (header, wire) = case send_header(alice) do
    Ok(v) -> v
    Err(error) -> return Err(SpqrKernelFailure(error))
  end
  let ready = case admit_complete_header(bob, e, wire) do
    BraidHeaderAccepted(v) -> v
    _ -> return Err(SpqrInvalidState)
  end
  let (first, output) = case send_ct1(ready) do
    Ok(v) -> v
    Err(error) -> return Err(SpqrKernelFailure(error))
  end
  check(!SecretMap.contains(first.secrets, Bytes.from_utf8("output")))?
  let two = case incorporate_spqr_epoch(two, output) do
    SpqrEpochAccepted(v) -> v
    SpqrEpochRefused(_, error) -> return Err(error)
  end
  check(U64.compare(two.epoch, e) == 0 && U64.compare(two.knowledge, old) == 0)?
  # Output E exists at Bob while both actual message-key directions still use E-1.
  let (one, two) = both(one, two, old)?
  let (sent, vector) = case send_vector(header) do
    Ok(v) -> v
    Err(error) -> return Err(SpqrKernelFailure(error))
  end
  let received = case receive_ct1(sent, e, first.first) do
    BraidAliceCt1Accepted(v) -> v
    _ -> return Err(SpqrInvalidState)
  end
  let got_vector = case receive_vector(first, e, vector) do
    BraidVectorAccepted(v) -> v
    _ -> return Err(SpqrInvalidState)
  end
  let (sent, wire) = case send_ct2(got_vector) do
    BraidCt2Emitted(v, wire) -> (v, wire)
    _ -> return Err(SpqrInvalidState)
  end
  let (waiting, output) = case receive_ct2(received, e, wire) do
    BraidAliceCt2Accepted(v, output) -> (v, output)
    _ -> return Err(SpqrInvalidState)
  end
  let one = case incorporate_spqr_epoch(one, output) do
    SpqrEpochAccepted(v) -> v
    SpqrEpochRefused(_, error) -> return Err(error)
  end
  check(U64.compare(one.epoch, e) == 0
    && Bytes.secure_equals(root_tag(one)?, root_tag(two)?)
    && one.direction == d1
    && two.direction == d2)?
  let next = case receive_next_epoch(sent, waiting.epoch) do
    BraidNextEpochAccepted(v) -> v
    _ -> return Err(SpqrInvalidState)
  end
  Ok((waiting, next, one, two))
end

fn pair() -> (BraidAliceIdle, BraidAwaitHeader, SpqrState, SpqrState)!SpqrError do
  let initial = Crypto.mlkem_generate()?
  let (ciphertext, seed) = Crypto.mlkem_encapsulate(initial.public_key)?
  let peer_seed = Crypto.mlkem_decapsulate(initial.private_key, ciphertext)?
  let scope = case fixture_scope() do
    Ok(v) -> v
    Err(error) -> return Err(SpqrKernelFailure(error))
  end
  let peer = %{scope |
    account_id: scope.peer_account_id,
    device_id: scope.peer_device_id,
    peer_account_id: scope.account_id,
    peer_device_id: scope.device_id
  }
  let alice = case initialize_initiator(scope, seed) do
    Ok(v) -> v
    Err(error) -> return Err(SpqrKernelFailure(error))
  end
  let bob = case initialize_responder(peer, peer_seed) do
    Ok(v) -> v
    Err(error) -> return Err(SpqrKernelFailure(error))
  end
  let one = initialize_spqr(scope, 0, seed)?
  let two = initialize_spqr(peer, 1, peer_seed)?
  Secret.destroy(initial.private_key)
  Secret.destroy(seed)
  Secret.destroy(peer_seed)
  Ok((alice, bob, one, two))
end

pub fn actual_outputs_two_epochs_and_window() -> Bool!SpqrError do
  let (alice, bob, one, two) = pair()?
  check(one.direction == 0 && two.direction == 1)?
  let initial_tag = root_tag(one)?
  let (a_wait, b_next, one, two) = epoch(alice, bob, one, two)?
  let e1_tag = root_tag(one)?
  check(!Bytes.secure_equals(initial_tag, e1_tag))?
  let original_slots = one.slots
  let future_slots = for slot in one.slots do
    if U64.compare(slot.epoch, number("1")?) == 0 do
      %{slot | receive_count: number("1")?}
    else
      slot
    end
  end
  let one = %{one | slots: future_slots}
  let one = case spqr_send_key(one, number("0")?) do
    SpqrKeyRefused(v, SpqrInvalidState) -> v
    _ -> return Err(SpqrInvalidState)
  end
  check(Bytes.secure_equals(e1_tag, root_tag(one)?))?
  let one = %{one | slots: original_slots}
  let (one, two) = both(one, two, number("1")?)?
  let original_slots = one.slots
  let receive_name = case Bytes.from_hex("01000000000000000001") do
    Ok(v) -> v
    Err(_) -> return Err(SpqrInvalidState)
  end
  let old_send_name = case Bytes.from_hex("01000000000000000000") do
    Ok(v) -> v
    Err(_) -> return Err(SpqrInvalidState)
  end
  let old_fixture_key = SecretMap.copy(one.chains, receive_name)?
  SecretMap.insert(one.chains, old_send_name, old_fixture_key)?
  let two_active = for slot in one.slots do
    if U64.compare(slot.epoch, number("0")?) == 0 do
      %{slot | send_present: true, send_count: number("1")?}
    else
      slot
    end
  end
  let one = %{one | slots: two_active}
  let one = case spqr_send_key(one, number("1")?) do
    SpqrKeyRefused(v, SpqrInvalidState) -> v
    _ -> return Err(SpqrInvalidState)
  end
  check(Bytes.secure_equals(e1_tag, root_tag(one)?))?
  SecretMap.delete(one.chains, old_send_name)?
  let one = %{one | slots: original_slots}
  let (b_wait, a_next, two, one) = epoch(b_next, a_wait, two, one)?
  check(one.direction == 0
    && two.direction == 1
    && U64.compare(one.epoch, number("2")?) == 0
    && U64.compare(one.knowledge, number("1")?) == 0
    && List.length(one.slots) == 3
    && List.length(two.slots) == 3
    && !Bytes.secure_equals(e1_tag, root_tag(one)?))?
  let (one, two) = both(one, two, number("2")?)?
  let zero = number("0")?
  check(List.length(one.slots) == 2
    && List.length(two.slots) == 2
    && List.all(one.slots, fn(slot) -> U64.compare(slot.epoch, zero) > 0 end))?
  let before = root_tag(one)?
  let one = case spqr_receive_key(one, number("0")?, number("1")?) do
    SpqrKeyRefused(v, SpqrRetired) -> v
    _ -> return Err(SpqrInvalidState)
  end
  check(Bytes.secure_equals(before, root_tag(one)?) && one.direction == 0)?
  let one = case spqr_receive_key(one, number("1")?, number("1")?) do
    SpqrKeyRefused(v, SpqrReplay) -> v
    _ -> return Err(SpqrInvalidState)
  end
  Secret.destroy(b_wait.secrets)
  Secret.destroy(a_next.secrets)
  Ok(true)
end

pub fn skip64_selected_key_and_capacity() -> Bool!SpqrError do
  let seed = Env.get_secret_hex("MORSE_C1_SPQR_LITERAL_SEED")?
  let state = initialize_spqr(literal_scope()?, 0, seed)?
  let state = case spqr_receive_key(state, number("0")?, number("65")?) do
    SpqrKeyAccepted(v, key, _) -> do
      Secret.destroy(key)
      v
    end
    _ -> return Err(SpqrInvalidState)
  end
  check(Bytes.length(state.skipped_index) == 1024)?
  let saved_index = state.skipped_index
  let dropped_index = case Bytes.slice(saved_index, 16, 1008) do
    Ok(v) -> v
    Err(_) -> return Err(SpqrInvalidState)
  end
  let wanted = case Bytes.from_hex("0200000000000000000000000000000001") do
    Ok(v) -> v
    Err(_) -> return Err(SpqrInvalidState)
  end
  let before = root_tag(state)?
  let state = %{state | skipped_index: dropped_index}
  let state = case spqr_receive_key(state, number("0")?, number("1")?) do
    SpqrKeyRefused(v, SpqrReplay) -> v
    _ -> return Err(SpqrInvalidState)
  end
  check(Bytes.secure_equals(before, root_tag(state)?)
    && Bytes.secure_equals(dropped_index, state.skipped_index)
    && SecretMap.contains(state.skipped, wanted))?
  let state = %{state | skipped_index: saved_index}
  let state = case spqr_receive_key(state, number("0")?, number("67")?) do
    SpqrKeyRefused(v, SpqrSkipLimit) -> v
    _ -> return Err(SpqrInvalidState)
  end
  check(Bytes.length(state.skipped_index) == 1024)?
  let state = case spqr_receive_key(state, number("0")?, number("1")?) do
    SpqrKeyAccepted(v, key, _) -> do
      Secret.destroy(key)
      v
    end
    _ -> return Err(SpqrInvalidState)
  end
  check(Bytes.length(state.skipped_index) == 1008)?
  let legitimate = state.skipped_index
  let selected_name = case Bytes.from_hex("0200000000000000000000000000000041") do
    Ok(v) -> v
    Err(_) -> return Err(SpqrInvalidState)
  end
  let selected_index = case Bytes.from_hex("00000000000000000000000000000041") do
    Ok(v) -> v
    Err(_) -> return Err(SpqrInvalidState)
  end
  let malformed_key = Env.get_secret_hex("MORSE_C1_SPQR_LITERAL_CHAIN")?
  SecretMap.insert(state.skipped, selected_name, malformed_key)?
  let malformed_index = case Bytes.concat(legitimate, selected_index) do
    Ok(v) -> v
    Err(_) -> return Err(SpqrInvalidState)
  end
  let state = %{state | skipped_index: malformed_index}
  let state = case spqr_receive_key(state, number("0")?, number("67")?) do
    SpqrKeyRefused(v, SpqrInvalidState) -> v
    _ -> return Err(SpqrInvalidState)
  end
  check(Bytes.secure_equals(before, root_tag(state)?)
    && Bytes.secure_equals(malformed_index, state.skipped_index)
    && SecretMap.contains(state.skipped, selected_name))?
  SecretMap.delete(state.skipped, selected_name)?
  let state = %{state | skipped_index: legitimate}
  let state = case spqr_receive_key(state, number("0")?, number("67")?) do
    SpqrKeyAccepted(v, key, _) -> do
      Secret.destroy(key)
      v
    end
    _ -> return Err(SpqrInvalidState)
  end
  check(Bytes.length(state.skipped_index) == 1024)?
  let fresh = initialize_spqr(literal_scope()?, 0, seed)?
  let fresh = case spqr_receive_key(fresh, number("0")?, number("66")?) do
    SpqrKeyRefused(v, SpqrSkipLimit) -> v
    _ -> return Err(SpqrInvalidState)
  end
  check(Bytes.length(fresh.skipped_index) == 0)?
  let wrong_direction = case initialize_spqr(literal_scope()?, -1, seed) do
    Err(SpqrInvalidState) -> true
    _ -> false
  end
  check(wrong_direction)?
  let before = root_tag(fresh)?
  let duplicate_slots = List.append(fresh.slots, List.head(fresh.slots))
  let fresh = %{fresh | slots: duplicate_slots}
  let fresh = case spqr_receive_key(fresh, number("0")?, number("1")?) do
    SpqrKeyRefused(v, SpqrInvalidState) -> v
    _ -> return Err(SpqrInvalidState)
  end
  check(List.length(fresh.slots) == 2
    && Bytes.length(fresh.skipped_index) == 0
    && Bytes.secure_equals(before, root_tag(fresh)?))?
  Secret.destroy(seed)
  Ok(true)
end

pub fn actual_duplicate_gap_and_counter_limit() -> Bool!SpqrError do
  let (alice, bob, one, two) = pair()?
  let initial = root_tag(one)?
  let e = alice.epoch
  let (header, wire) = case send_header(alice) do
    Ok(v) -> v
    Err(error) -> return Err(SpqrKernelFailure(error))
  end
  let ready = case admit_complete_header(bob, e, wire) do
    BraidHeaderAccepted(v) -> v
    _ -> return Err(SpqrInvalidState)
  end
  let (first, output) = case send_ct1(ready) do
    Ok(v) -> v
    Err(error) -> return Err(SpqrKernelFailure(error))
  end
  let two = case incorporate_spqr_epoch(two, output) do
    SpqrEpochAccepted(v) -> v
    SpqrEpochRefused(_, error) -> return Err(error)
  end
  let e1 = root_tag(two)?
  let (sent, vector) = case send_vector(header) do
    Ok(v) -> v
    Err(error) -> return Err(SpqrKernelFailure(error))
  end
  let received = case receive_ct1(sent, e, first.first) do
    BraidAliceCt1Accepted(v) -> v
    _ -> return Err(SpqrInvalidState)
  end
  let received_vector = case receive_vector(first, e, vector) do
    BraidVectorAccepted(v) -> v
    _ -> return Err(SpqrInvalidState)
  end
  let (sent, wire) = case send_ct2(received_vector) do
    BraidCt2Emitted(v, wire) -> (v, wire)
    _ -> return Err(SpqrInvalidState)
  end
  let (waiting, actual_second_owner_e1) = case receive_ct2(received, e, wire) do
    BraidAliceCt2Accepted(v, output) -> (v, output)
    _ -> return Err(SpqrInvalidState)
  end
  # An actual independently emitted same-epoch owner must not update L1 again.
  let two = case incorporate_spqr_epoch(two, actual_second_owner_e1) do
    SpqrEpochRefused(v, SpqrEpochOrder) -> v
    _ -> return Err(SpqrInvalidState)
  end
  check(U64.compare(two.epoch, number("1")?) == 0 && Bytes.secure_equals(e1, root_tag(two)?))?
  let next = case receive_next_epoch(sent, waiting.epoch) do
    BraidNextEpochAccepted(v) -> v
    _ -> return Err(SpqrInvalidState)
  end
  let (header, wire) = case send_header(next) do
    Ok(v) -> v
    Err(error) -> return Err(SpqrKernelFailure(error))
  end
  let ready = case admit_complete_header(waiting, header.epoch, wire) do
    BraidHeaderAccepted(v) -> v
    _ -> return Err(SpqrInvalidState)
  end
  let (sent_e2, actual_e2) = case send_ct1(ready) do
    Ok(v) -> v
    Err(error) -> return Err(SpqrKernelFailure(error))
  end
  # Feed the real E2 owner into an untouched epoch0 consumer: this is a gap.
  let one = case incorporate_spqr_epoch(one, actual_e2) do
    SpqrEpochRefused(v, SpqrEpochOrder) -> v
    _ -> return Err(SpqrInvalidState)
  end
  check(U64.compare(one.epoch, number("0")?) == 0 && Bytes.secure_equals(initial, root_tag(one)?))?
  # A bounded owned fixture seeds the final counter, without iterating2^64 times.
  let maximum = number("18446744073709551615")?
  let slots = for slot in one.slots do
    %{slot | send_count: maximum}
  end
  let one = %{one | slots: slots}
  let one = case spqr_send_key(one, number("0")?) do
    SpqrKeyRefused(v, SpqrCounterOverflow) -> v
    _ -> return Err(SpqrInvalidState)
  end
  check(Bytes.secure_equals(initial, root_tag(one)?) && Bytes.length(one.skipped_index) == 0)?
  Ok(true)
end
