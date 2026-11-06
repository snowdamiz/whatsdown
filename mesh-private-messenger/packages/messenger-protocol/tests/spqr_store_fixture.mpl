##! Prepared real-kernel state and independent literal context tests. No Mesh run yet.
from Session.BraidResponder import BraidScope, initialize_responder, admit_complete_header
from Session.BraidInitiator import (
  initialize_initiator,
  send_header,
  send_vector,
  receive_ct1,
  receive_ct2,
  BraidAliceEkSent
)
from Session.BraidComplete import send_ct1, receive_vector, send_ct2, BraidBobCt1Sent
from Session.Spqr import (
  SpqrState,
  SpqrSlot,
  initialize_spqr,
  incorporate_spqr_epoch,
  spqr_send_key,
  spqr_receive_key
)
from Session.SpqrKdf import SpqrError
from Session.SpqrStore import (
  SpqrSaved,
  SpqrStoreIdentity,
  spqr_storage_context,
  seal_spqr,
  restore_spqr
)

pub resource struct SpqrStoreFixture do
  state :: SpqrState
  bob :: BraidBobCt1Sent
  alice :: BraidAliceEkSent
  vector :: MlKemPublicVector1152
end

fn fixture_checked_bytes(value :: Result<Bytes, BytesError>) -> Bytes!String do
  case value do
    Ok(value)
    Err(_) -> Err("fixture_checked_bytes_api")
  end
end

fn fixture_crypto_bytes(value :: Result<Bytes, CryptoError>) -> Bytes!String do
  case value do
    Ok(value)
    Err(_) -> Err("fixture_public_crypto_api")
  end
end

fn fixture_crypto_map(value :: consume Result<SecretMap, CryptoError>) -> SecretMap!String do
  case value do
    Ok(value)
    Err(_) -> Err("fixture_public_crypto_api")
  end
end

fn fixture_crypto_secret(value :: consume Result<SecretBytes, CryptoError>) -> SecretBytes!String do
  case value do
    Ok(value)
    Err(_) -> Err("fixture_public_crypto_api")
  end
end

fn fixture_storage_key(value :: consume Result<StorageKey, CryptoError>) -> StorageKey!String do
  case value do
    Ok(value)
    Err(_) -> Err("fixture_public_crypto_api")
  end
end

fn check(value :: Bool) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err("fixture_spqr_store_assertion")
  end
end

fn bytes(value :: Int, count :: Int) -> Bytes!String do
  fixture_checked_bytes(Bytes.repeat(value, count))
end

fn number(value :: String) -> U64!String do
  U64.parse(value)
end

pub fn store_fixture_scope() -> BraidScope!String do
  Ok(BraidScope {
    protocol_info: Bytes.from_utf8("Morse"),
    configuration: bytes(17, 32)?,
    account_id: bytes(49, 32)?,
    device_id: bytes(65, 16)?,
    peer_account_id: bytes(50, 32)?,
    peer_device_id: bytes(66, 16)?,
    session_id: bytes(34, 32)?
  })
end

fn identity() -> SpqrStoreIdentity!String do
  Ok(SpqrStoreIdentity {
    revision: number("7")?,
    transition: bytes(85, 32)?,
    descriptor: bytes(136, 32)?
  })
end

fn slot(epoch :: String, received :: String) -> SpqrSlot!String do
  Ok(SpqrSlot {
    epoch: number(epoch)?,
    send_present: true,
    send_count: number("0")?,
    receive_present: true,
    receive_count: number(received)?
  })
end

fn literal_saved(local :: String,
  knowledge :: String,
  slots :: List<SpqrSlot>,
  index :: Bytes) -> SpqrSaved!String do
  let id = identity()?
  Ok(SpqrSaved {
    scope: store_fixture_scope()?,
    direction: 1,
    epoch: number(local)?,
    knowledge: number(knowledge)?,
    slots: slots,
    skipped_index: index,
    revision: id.revision,
    transition: id.transition,
    descriptor: id.descriptor,
    chains: Bytes.empty(),
    skipped: Bytes.empty()
  })
end

pub fn actual_store_fixture() -> SpqrStoreFixture!String do
  let scope = store_fixture_scope()?
  let shared = fixture_crypto_secret(Env.get_secret_hex("MORSE_C1_SPQR_JOURNAL_BRAID"))?
  let seed = fixture_crypto_secret(Env.get_secret_hex("MORSE_C1_SPQR_JOURNAL_SEED"))?
  let alice = case initialize_initiator(scope, shared) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_real_braid_init")
  end
  let bob = case initialize_responder(scope, shared) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_real_braid_init")
  end
  let (sent, header) = case send_header(alice) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_real_braid_header")
  end
  let ready = case admit_complete_header(bob, number("1")?, header) do
    BraidHeaderAccepted(value) -> value
    _ -> return Err("fixture_real_braid_admission")
  end
  let (bob_first, output) = case send_ct1(ready) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_real_braid_output")
  end
  let state = case initialize_spqr(scope, 1, seed) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_real_spqr_init")
  end
  let state = case incorporate_spqr_epoch(state, output) do
    SpqrEpochAccepted(value) -> value
    _ -> return Err("fixture_real_output_consume")
  end
  let (alice_vector, vector) = case send_vector(sent) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_real_vector")
  end
  Secret.destroy(shared)
  Secret.destroy(seed)
  Ok(SpqrStoreFixture { state: state, bob: bob_first, alice: alice_vector, vector: vector })
end

fn map_tag(map :: borrow SecretMap, name :: Bytes) -> Bytes!String do
  let key = fixture_crypto_secret(SecretMap.copy(map, name))?
  let value = fixture_crypto_bytes(Crypto.hmac_sha256_tag(key,
    Bytes.from_utf8("TEST ONLY SPQR journal saved-state agreement")))?
  Secret.destroy(key)
  Ok(value)
end

fn same_maps(left :: borrow SecretMap, right :: borrow SecretMap) -> Result<(), String> do
  check(Bytes.secure_equals(map_tag(left, bytes(0, 1)?)?, map_tag(right, bytes(0, 1)?)?))?
  for epoch in ["0", "1"] do
    for direction in [0, 1] do
      let name = fixture_checked_bytes(Bytes.concat_many([
          bytes(1, 1)?,
          fixture_checked_bytes(Bytes.write_u64_be(number(epoch)?))?,
          bytes(direction, 1)?
        ],
        10))?
      check(Bytes.secure_equals(map_tag(left, name)?, map_tag(right, name)?))?
    end
  end
  Ok(nil)
end

fn real_store_roundtrip_inner() -> Result<(), String> do
  check(Test.install_in_memory_secure_store())?
  let key = fixture_storage_key(StorageKey.platform())?
  let SpqrStoreFixture { state, bob, alice, vector } = actual_store_fixture()?
  let before = map_tag(state.chains, bytes(0, 1)?)?
  let saved = seal_spqr(state, key, identity()?)?
  let restored = restore_spqr(saved, saved, key)?
  same_maps(state.chains, restored.chains)?
  check(Bytes.secure_equals(before, map_tag(state.chains, bytes(0, 1)?)?))?
  check(U64.compare(restored.epoch, number("1")?) == 0
    && U64.compare(restored.knowledge, number("0")?) == 0)?
  let first = bob.first
  let ready = case receive_vector(bob, number("1")?, vector) do
    BraidVectorAccepted(value) -> value
    _ -> return Err("fixture_real_peer_vector")
  end
  let wire = case send_ct2(ready) do
    BraidCt2Emitted(_, value) -> value
    _ -> return Err("fixture_real_peer_second")
  end
  let received = case receive_ct1(alice, number("1")?, first) do
    BraidAliceCt1Accepted(value) -> value
    _ -> return Err("fixture_real_peer_first")
  end
  let output = case receive_ct2(received, number("1")?, wire) do
    BraidAliceCt2Accepted(_, value) -> value
    _ -> return Err("fixture_real_peer_output")
  end
  let seed = fixture_crypto_secret(Env.get_secret_hex("MORSE_C1_SPQR_JOURNAL_SEED"))?
  let peer = case initialize_spqr(store_fixture_scope()?, 0, seed) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_real_peer_spqr")
  end
  let peer = case incorporate_spqr_epoch(peer, output) do
    SpqrEpochAccepted(value) -> value
    _ -> return Err("fixture_real_peer_consume")
  end
  same_maps(restored.chains, peer.chains)?
  # A real small receive gap creates one cached key; no journal K advancement.
  let zero = number("0")?
  let (peer, peer_first_key, first_number) = case spqr_send_key(peer, zero) do
    SpqrKeyAccepted(next, material, n) -> (next, material, n)
    _ -> return Err("fixture_real_peer_first_message_key")
  end
  let (peer, peer_second_key, second_number) = case spqr_send_key(peer, zero) do
    SpqrKeyAccepted(next, material, n) -> (next, material, n)
    _ -> return Err("fixture_real_peer_second_message_key")
  end
  check(U64.compare(first_number, number("1")?) == 0
    && U64.compare(second_number, number("2")?) == 0
    && U64.compare(peer.knowledge, zero) == 0)?
  let first_tag = fixture_crypto_bytes(Crypto.hmac_sha256_tag(peer_first_key,
    Bytes.from_utf8("TEST ONLY restored skipped-key peer agreement")))?
  let second_tag = fixture_crypto_bytes(Crypto.hmac_sha256_tag(peer_second_key,
    Bytes.from_utf8("TEST ONLY restored skipped-key peer agreement")))?
  let (gap, selected_key, selected_number) = case spqr_receive_key(restored, zero, second_number) do
    SpqrKeyAccepted(next, material, n) -> (next, material, n)
    _ -> return Err("fixture_real_out_of_order_receive")
  end
  check(U64.compare(selected_number, second_number) == 0 && Bytes.length(gap.skipped_index) == 16)?
  check(Bytes.secure_equals(second_tag,
    fixture_crypto_bytes(Crypto.hmac_sha256_tag(selected_key,
      Bytes.from_utf8("TEST ONLY restored skipped-key peer agreement")))?))?
  let gap_saved = seal_spqr(gap,
    key,
    SpqrStoreIdentity {
      revision: number("8")?,
      transition: bytes(86, 32)?,
      descriptor: bytes(137, 32)?
    })?
  let gap_restored = restore_spqr(gap_saved, gap_saved, key)?
  let skip_name = fixture_checked_bytes(Bytes.concat_many([
      bytes(2, 1)?,
      fixture_checked_bytes(Bytes.write_u64_be(zero))?,
      fixture_checked_bytes(Bytes.write_u64_be(first_number))?
    ],
    17))?
  check(Bytes.length(gap_restored.skipped_index) == 16
    && SecretMap.contains(gap_restored.skipped, skip_name))?
  let (used, cached_key, cached_number) = case spqr_receive_key(gap_restored, zero, first_number) do
    SpqrKeyAccepted(next, material, n) -> (next, material, n)
    _ -> return Err("fixture_restored_cached_key_admission")
  end
  check(U64.compare(cached_number, first_number) == 0
    && Bytes.length(used.skipped_index) == 0
    && !SecretMap.contains(used.skipped, skip_name))?
  check(Bytes.secure_equals(first_tag,
    fixture_crypto_bytes(Crypto.hmac_sha256_tag(cached_key,
      Bytes.from_utf8("TEST ONLY restored skipped-key peer agreement")))?))?
  let root_after_use = map_tag(used.chains, bytes(0, 1)?)?
  check(case spqr_receive_key(used, zero, first_number) do
    SpqrKeyRefused(original, SpqrReplay) -> Bytes.length(original.skipped_index) == 0
      && !SecretMap.contains(original.skipped, skip_name)
      && Bytes.secure_equals(map_tag(original.chains, bytes(0, 1)?)?, root_after_use)
    _ -> false
  end)?
  Secret.destroy(peer_first_key)
  Secret.destroy(peer_second_key)
  Secret.destroy(selected_key)
  Secret.destroy(cached_key)
  Secret.destroy(seed)
  Ok(nil)
end

fn refused(saved :: SpqrSaved, expected :: SpqrSaved, key :: borrow StorageKey) -> Bool do
  case restore_spqr(saved, expected, key) do
    Ok(_) -> false
    Err(_) -> true
  end
end

fn store_binding_refusals_inner() -> Result<(), String> do
  check(Test.install_in_memory_secure_store())?
  let key = fixture_storage_key(StorageKey.platform())?
  let f = actual_store_fixture()?
  let saved = seal_spqr(f.state, key, identity()?)?
  for changed in [
    %{saved | chains: saved.skipped},
    %{saved | skipped: saved.chains},
    %{saved | transition: bytes(86, 32)?},
    %{saved | descriptor: bytes(137, 32)?},
    %{saved | revision: number("8")?},
    %{saved | direction: 0},
    %{saved | scope: %{saved.scope | session_id: bytes(35, 32)?}},
    %{saved | scope: %{saved.scope | configuration: bytes(18, 32)?}},
    %{saved | scope: %{saved.scope | peer_account_id: bytes(51, 32)?}},
    %{saved | scope: %{saved.scope | peer_device_id: bytes(67, 16)?}},
    %{saved | scope: %{saved.scope | protocol_info: Bytes.from_utf8("Other")}},
    %{saved | skipped: bytes(1, 71)?}
  ] do
    check(refused(changed, saved, key))?
    check(refused(changed, changed, key))?
  end
  let restored = restore_spqr(saved, saved, key)?
  same_maps(f.state.chains, restored.chains)?
  # New public identity requires fresh seals of BOTH maps, even unchanged keys.
  let newer = seal_spqr(f.state,
    key,
    SpqrStoreIdentity {
      revision: number("8")?,
      transition: bytes(86, 32)?,
      descriptor: bytes(137, 32)?
    })?
  check(!Bytes.secure_equals(saved.chains, newer.chains)
    && !Bytes.secure_equals(saved.skipped, newer.skipped))?
  check(refused(%{newer | chains: saved.chains}, newer, key))?
  check(refused(%{newer | skipped: saved.skipped}, newer, key))?
  let valid = restore_spqr(newer, newer, key)?
  same_maps(restored.chains, valid.chains)
end

fn literal_store_contexts_inner() -> Result<(), String> do
  let value0 = literal_saved("0", "0", [slot("0", "0")?], Bytes.from_hex("")?)?
  check(Bytes.secure_equals(spqr_storage_context(value0, 24)?,
    Bytes.from_hex("013131313131313131313131313131313131313131313131313131313131313131414141414141414141414141414141412222222222222222222222222222222222222222222222222222222222222222ebb16dbfd48254a75eb0546ba2e1cf173f8ce9465c5dcef94c1c273453bb10a5001800000000000000070101000000000000000000000000000000005555555555555555555555555555555555555555555555555555555555555555888888888888888888888888888888888888888888888888888888888888888801000000000000000001000000000000000001000000000000000000")?))?
  let value1 = literal_saved("0", "0", [slot("0", "0")?], Bytes.from_hex("")?)?
  check(Bytes.secure_equals(spqr_storage_context(value1, 25)?,
    Bytes.from_hex("01313131313131313131313131313131313131313131313131313131313131313141414141414141414141414141414141222222222222222222222222222222222222222222222222222222222222222235cc85bcbe780ee3819cfc1e85ecc6d6ab35e55a8a47373e6936da1f5431153b001900000000000000070101000000000000000000000000000000005555555555555555555555555555555555555555555555555555555555555555888888888888888888888888888888888888888888888888888888888888888801000000000000000001000000000000000001000000000000000000")?))?
  let value2 = literal_saved("1", "0", [slot("0", "0")?, slot("1", "0")?], Bytes.from_hex("")?)?
  check(Bytes.secure_equals(spqr_storage_context(value2, 24)?,
    Bytes.from_hex("013131313131313131313131313131313131313131313131313131313131313131414141414141414141414141414141412222222222222222222222222222222222222222222222222222222222222222ebb16dbfd48254a75eb0546ba2e1cf173f8ce9465c5dcef94c1c273453bb10a50018000000000000000701010000000000000001000000000000000055555555555555555555555555555555555555555555555555555555555555558888888888888888888888888888888888888888888888888888888888888888020000000000000000010000000000000000010000000000000000000000000000000101000000000000000001000000000000000000")?))?
  let value3 = literal_saved("1", "0", [slot("0", "0")?, slot("1", "0")?], Bytes.from_hex("")?)?
  check(Bytes.secure_equals(spqr_storage_context(value3, 25)?,
    Bytes.from_hex("01313131313131313131313131313131313131313131313131313131313131313141414141414141414141414141414141222222222222222222222222222222222222222222222222222222222222222235cc85bcbe780ee3819cfc1e85ecc6d6ab35e55a8a47373e6936da1f5431153b0019000000000000000701010000000000000001000000000000000055555555555555555555555555555555555555555555555555555555555555558888888888888888888888888888888888888888888888888888888888888888020000000000000000010000000000000000010000000000000000000000000000000101000000000000000001000000000000000000")?))?
  let value4 = literal_saved("2",
    "1",
    [slot("0", "65")?, slot("1", "0")?, slot("2", "0")?],
    Bytes.from_hex("0000000000000000000000000000000100000000000000000000000000000002000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005000000000000000000000000000000060000000000000000000000000000000700000000000000000000000000000008000000000000000000000000000000090000000000000000000000000000000a0000000000000000000000000000000b0000000000000000000000000000000c0000000000000000000000000000000d0000000000000000000000000000000e0000000000000000000000000000000f000000000000000000000000000000100000000000000000000000000000001100000000000000000000000000000012000000000000000000000000000000130000000000000000000000000000001400000000000000000000000000000015000000000000000000000000000000160000000000000000000000000000001700000000000000000000000000000018000000000000000000000000000000190000000000000000000000000000001a0000000000000000000000000000001b0000000000000000000000000000001c0000000000000000000000000000001d0000000000000000000000000000001e0000000000000000000000000000001f000000000000000000000000000000200000000000000000000000000000002100000000000000000000000000000022000000000000000000000000000000230000000000000000000000000000002400000000000000000000000000000025000000000000000000000000000000260000000000000000000000000000002700000000000000000000000000000028000000000000000000000000000000290000000000000000000000000000002a0000000000000000000000000000002b0000000000000000000000000000002c0000000000000000000000000000002d0000000000000000000000000000002e0000000000000000000000000000002f000000000000000000000000000000300000000000000000000000000000003100000000000000000000000000000032000000000000000000000000000000330000000000000000000000000000003400000000000000000000000000000035000000000000000000000000000000360000000000000000000000000000003700000000000000000000000000000038000000000000000000000000000000390000000000000000000000000000003a0000000000000000000000000000003b0000000000000000000000000000003c0000000000000000000000000000003d0000000000000000000000000000003e0000000000000000000000000000003f00000000000000000000000000000040")?)?
  check(Bytes.secure_equals(spqr_storage_context(value4, 24)?,
    Bytes.from_hex("013131313131313131313131313131313131313131313131313131313131313131414141414141414141414141414141412222222222222222222222222222222222222222222222222222222222222222ebb16dbfd48254a75eb0546ba2e1cf173f8ce9465c5dcef94c1c273453bb10a5001800000000000000070101000000000000000200000000000000015555555555555555555555555555555555555555555555555555555555555555888888888888888888888888888888888888888888888888888888888888888803000000000000000001000000000000000001000000000000004100000000000000010100000000000000000100000000000000000000000000000002010000000000000000010000000000000000400000000000000000000000000000000100000000000000000000000000000002000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005000000000000000000000000000000060000000000000000000000000000000700000000000000000000000000000008000000000000000000000000000000090000000000000000000000000000000a0000000000000000000000000000000b0000000000000000000000000000000c0000000000000000000000000000000d0000000000000000000000000000000e0000000000000000000000000000000f000000000000000000000000000000100000000000000000000000000000001100000000000000000000000000000012000000000000000000000000000000130000000000000000000000000000001400000000000000000000000000000015000000000000000000000000000000160000000000000000000000000000001700000000000000000000000000000018000000000000000000000000000000190000000000000000000000000000001a0000000000000000000000000000001b0000000000000000000000000000001c0000000000000000000000000000001d0000000000000000000000000000001e0000000000000000000000000000001f000000000000000000000000000000200000000000000000000000000000002100000000000000000000000000000022000000000000000000000000000000230000000000000000000000000000002400000000000000000000000000000025000000000000000000000000000000260000000000000000000000000000002700000000000000000000000000000028000000000000000000000000000000290000000000000000000000000000002a0000000000000000000000000000002b0000000000000000000000000000002c0000000000000000000000000000002d0000000000000000000000000000002e0000000000000000000000000000002f000000000000000000000000000000300000000000000000000000000000003100000000000000000000000000000032000000000000000000000000000000330000000000000000000000000000003400000000000000000000000000000035000000000000000000000000000000360000000000000000000000000000003700000000000000000000000000000038000000000000000000000000000000390000000000000000000000000000003a0000000000000000000000000000003b0000000000000000000000000000003c0000000000000000000000000000003d0000000000000000000000000000003e0000000000000000000000000000003f00000000000000000000000000000040")?))?
  let value5 = literal_saved("2",
    "1",
    [slot("0", "65")?, slot("1", "0")?, slot("2", "0")?],
    Bytes.from_hex("0000000000000000000000000000000100000000000000000000000000000002000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005000000000000000000000000000000060000000000000000000000000000000700000000000000000000000000000008000000000000000000000000000000090000000000000000000000000000000a0000000000000000000000000000000b0000000000000000000000000000000c0000000000000000000000000000000d0000000000000000000000000000000e0000000000000000000000000000000f000000000000000000000000000000100000000000000000000000000000001100000000000000000000000000000012000000000000000000000000000000130000000000000000000000000000001400000000000000000000000000000015000000000000000000000000000000160000000000000000000000000000001700000000000000000000000000000018000000000000000000000000000000190000000000000000000000000000001a0000000000000000000000000000001b0000000000000000000000000000001c0000000000000000000000000000001d0000000000000000000000000000001e0000000000000000000000000000001f000000000000000000000000000000200000000000000000000000000000002100000000000000000000000000000022000000000000000000000000000000230000000000000000000000000000002400000000000000000000000000000025000000000000000000000000000000260000000000000000000000000000002700000000000000000000000000000028000000000000000000000000000000290000000000000000000000000000002a0000000000000000000000000000002b0000000000000000000000000000002c0000000000000000000000000000002d0000000000000000000000000000002e0000000000000000000000000000002f000000000000000000000000000000300000000000000000000000000000003100000000000000000000000000000032000000000000000000000000000000330000000000000000000000000000003400000000000000000000000000000035000000000000000000000000000000360000000000000000000000000000003700000000000000000000000000000038000000000000000000000000000000390000000000000000000000000000003a0000000000000000000000000000003b0000000000000000000000000000003c0000000000000000000000000000003d0000000000000000000000000000003e0000000000000000000000000000003f00000000000000000000000000000040")?)?
  check(Bytes.secure_equals(spqr_storage_context(value5, 25)?,
    Bytes.from_hex("01313131313131313131313131313131313131313131313131313131313131313141414141414141414141414141414141222222222222222222222222222222222222222222222222222222222222222235cc85bcbe780ee3819cfc1e85ecc6d6ab35e55a8a47373e6936da1f5431153b001900000000000000070101000000000000000200000000000000015555555555555555555555555555555555555555555555555555555555555555888888888888888888888888888888888888888888888888888888888888888803000000000000000001000000000000000001000000000000004100000000000000010100000000000000000100000000000000000000000000000002010000000000000000010000000000000000400000000000000000000000000000000100000000000000000000000000000002000000000000000000000000000000030000000000000000000000000000000400000000000000000000000000000005000000000000000000000000000000060000000000000000000000000000000700000000000000000000000000000008000000000000000000000000000000090000000000000000000000000000000a0000000000000000000000000000000b0000000000000000000000000000000c0000000000000000000000000000000d0000000000000000000000000000000e0000000000000000000000000000000f000000000000000000000000000000100000000000000000000000000000001100000000000000000000000000000012000000000000000000000000000000130000000000000000000000000000001400000000000000000000000000000015000000000000000000000000000000160000000000000000000000000000001700000000000000000000000000000018000000000000000000000000000000190000000000000000000000000000001a0000000000000000000000000000001b0000000000000000000000000000001c0000000000000000000000000000001d0000000000000000000000000000001e0000000000000000000000000000001f000000000000000000000000000000200000000000000000000000000000002100000000000000000000000000000022000000000000000000000000000000230000000000000000000000000000002400000000000000000000000000000025000000000000000000000000000000260000000000000000000000000000002700000000000000000000000000000028000000000000000000000000000000290000000000000000000000000000002a0000000000000000000000000000002b0000000000000000000000000000002c0000000000000000000000000000002d0000000000000000000000000000002e0000000000000000000000000000002f000000000000000000000000000000300000000000000000000000000000003100000000000000000000000000000032000000000000000000000000000000330000000000000000000000000000003400000000000000000000000000000035000000000000000000000000000000360000000000000000000000000000003700000000000000000000000000000038000000000000000000000000000000390000000000000000000000000000003a0000000000000000000000000000003b0000000000000000000000000000003c0000000000000000000000000000003d0000000000000000000000000000003e0000000000000000000000000000003f00000000000000000000000000000040")?))?
  let value = literal_saved("0", "0", [slot("0", "0")?], Bytes.empty())?
  check(case spqr_storage_context(value, 22) do
    Err(_) -> true
    Ok(_) -> false
  end)?
  Ok(nil)
end

pub fn direct_public_api_preflight() -> Result<(), String> do
  check(Test.install_in_memory_secure_store())?
  let key = fixture_storage_key(StorageKey.platform())?
  let f = actual_store_fixture()?
  let context24 = Bytes.from_hex("013131313131313131313131313131313131313131313131313131313131313131414141414141414141414141414141412222222222222222222222222222222222222222222222222222222222222222ebb16dbfd48254a75eb0546ba2e1cf173f8ce9465c5dcef94c1c273453bb10a50018000000000000000701010000000000000001000000000000000055555555555555555555555555555555555555555555555555555555555555558888888888888888888888888888888888888888888888888888888888888888020000000000000000010000000000000000010000000000000000000000000000000101000000000000000001000000000000000000")?
  let blob24 = fixture_crypto_bytes(SecretMap.seal_for_storage(f.state.chains, key, context24))?
  let map24 = fixture_crypto_map(SecretMap.unseal_from_storage(blob24, key, context24))?
  let context25 = Bytes.from_hex("01313131313131313131313131313131313131313131313131313131313131313141414141414141414141414141414141222222222222222222222222222222222222222222222222222222222222222235cc85bcbe780ee3819cfc1e85ecc6d6ab35e55a8a47373e6936da1f5431153b0019000000000000000701010000000000000001000000000000000055555555555555555555555555555555555555555555555555555555555555558888888888888888888888888888888888888888888888888888888888888888020000000000000000010000000000000000010000000000000000000000000000000101000000000000000001000000000000000000")?
  let blob25 = fixture_crypto_bytes(SecretMap.seal_for_storage(f.state.skipped, key, context25))?
  let map25 = fixture_crypto_map(SecretMap.unseal_from_storage(blob25, key, context25))?
  same_maps(f.state.chains, map24)?
  check(!SecretMap.contains(map25, bytes(0, 1)?))?
  Ok(nil)
end

## Finite test-only diagnostics: unknown errors are never printed as arbitrary payload.
fn report_prepared_store(result :: Result<(), String>) -> Result<(), String> do
  case result do
    Ok(_) -> Ok(nil)
    Err(reason) -> do
      let stubs = ["c1_spqr_store_stub", "c1_spqr_state_stub", "c1_spqr_journal_stub"]
      let fixture_tags = [
        "fixture_real_braid_admission",
        "fixture_real_braid_header",
        "fixture_real_braid_init",
        "fixture_real_braid_output",
        "fixture_real_out_of_order_receive",
        "fixture_real_output_consume",
        "fixture_real_peer_consume",
        "fixture_real_peer_first",
        "fixture_real_peer_first_message_key",
        "fixture_real_peer_output",
        "fixture_real_peer_second",
        "fixture_real_peer_second_message_key",
        "fixture_real_peer_spqr",
        "fixture_real_peer_vector",
        "fixture_real_spqr_init",
        "fixture_real_vector",
        "fixture_restored_cached_key_admission",
        "fixture_spqr_store_assertion"
      ]
      if List.contains(stubs, reason) do
        println("C1_SPQR_PREPARED_STUB_REFUSAL:#{reason}")
      else if List.contains(fixture_tags, reason) do
        println("C1_SPQR_PREPARED_FIXTURE_REFUSAL:#{reason}")
      else
        println("C1_SPQR_PREPARED_SETUP_UNCLASSIFIED")
      end
      Err(reason)
    end
  end
end

pub fn literal_store_contexts() -> Result<(), String> do
  report_prepared_store(literal_store_contexts_inner())
end

pub fn real_store_roundtrip() -> Result<(), String> do
  report_prepared_store(real_store_roundtrip_inner())
end

pub fn store_binding_refusals() -> Result<(), String> do
  report_prepared_store(store_binding_refusals_inner())
end
