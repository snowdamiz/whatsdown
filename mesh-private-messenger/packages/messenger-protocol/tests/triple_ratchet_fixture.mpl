##! TEST ONLY inactive whole-message HE/PQ fixture; never scheduler/CAS authority.
from Protocol.V1 import ProtocolError
from Session.State import RatchetState, RatchetError
from Session.HeaderWire import OpenedHeader, he_read_u32
from Session.HeaderRatchet import (
  HybridError,
  HybridSendOutcome,
  HybridReceiveOutcome,
  he_encrypt_hybrid,
  he_decrypt_hybrid,
  he_initialize_alice,
  he_initialize_bob,
  he_empty_headers,
  he_replace_header
)
from Session.TripleWire import (
  TripleHeader,
  TripleMessage,
  encode_triple_header,
  encode_triple_message,
  decode_triple_message,
  triple_header_aad
)
from Session.BraidFragment import BraidFragment, BraidFragmentKind
from Session.BraidFragmentWords import emit_braid_fragment
from Session.Spqr import (
  SpqrState,
  SpqrSlot,
  SpqrEpochAdmission,
  initialize_spqr,
  incorporate_spqr_epoch
)
from Session.SpqrKdf import SpqrError
from Session.BraidResponder import (
  BraidError,
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
from Tests.BraidResponderFixture import fixture_scope

pub type TripleFixtureError do
  TripleFixtureCheck
  TripleFixtureCrypto(error :: CryptoError)
  TripleFixtureHe(error :: RatchetError)
  TripleFixturePq(error :: SpqrError)
  TripleFixtureBraid(error :: BraidError)
  TripleFixtureWire(error :: ProtocolError)
  TripleFixtureHybrid(error :: HybridError)
end

impl From<CryptoError> for TripleFixtureError do
  fn from(error :: CryptoError) -> TripleFixtureError do
    TripleFixtureCrypto(error)
  end
end

impl From<RatchetError> for TripleFixtureError do
  fn from(error :: RatchetError) -> TripleFixtureError do
    TripleFixtureHe(error)
  end
end

impl From<SpqrError> for TripleFixtureError do
  fn from(error :: SpqrError) -> TripleFixtureError do
    TripleFixturePq(error)
  end
end

impl From<BraidError> for TripleFixtureError do
  fn from(error :: BraidError) -> TripleFixtureError do
    TripleFixtureBraid(error)
  end
end

impl From<ProtocolError> for TripleFixtureError do
  fn from(error :: ProtocolError) -> TripleFixtureError do
    TripleFixtureWire(error)
  end
end

fn triple_check(ok :: Bool) -> Unit!TripleFixtureError do
  if ok do
    Ok(nil)
  else
    Err(TripleFixtureCheck)
  end
end

fn triple_wide(text :: String) -> U64!TripleFixtureError do
  case U64.parse(text) do
    Ok(v)
    Err(_) -> Err(TripleFixtureCheck)
  end
end

fn triple_bytes(byte :: Int, count :: Int) -> Bytes!TripleFixtureError do
  case Bytes.repeat(byte, count) do
    Ok(v)
    Err(_) -> Err(TripleFixtureCheck)
  end
end

fn triple_hex(text :: String) -> Bytes!TripleFixtureError do
  case Bytes.from_hex(text) do
    Ok(v)
    Err(_) -> Err(TripleFixtureCheck)
  end
end

fn triple_slice(value :: Bytes, offset :: Int, count :: Int) -> Bytes!TripleFixtureError do
  case Bytes.slice(value, offset, count) do
    Ok(v)
    Err(_) -> Err(TripleFixtureCheck)
  end
end

fn triple_join(parts :: List<Bytes>) -> Bytes!TripleFixtureError do
  case Bytes.concat_many(parts, 131072) do
    Ok(v)
    Err(_) -> Err(TripleFixtureCheck)
  end
end

fn triple_u32(value :: Int) -> Bytes!TripleFixtureError do
  let wide = triple_wide(Int.to_string(value))?
  case Bytes.write_u32_be(wide) do
    Ok(v)
    Err(_) -> Err(TripleFixtureCheck)
  end
end

fn triple_u64(value :: U64) -> Bytes!TripleFixtureError do
  case Bytes.write_u64_be(value) do
    Ok(v)
    Err(_) -> Err(TripleFixtureCheck)
  end
end

fn triple_flip(value :: Bytes) -> Bytes!TripleFixtureError do
  let n = Bytes.length(value)
  let byte = case Bytes.get(value, n - 1) do
    Ok(v) -> v
    Err(_) -> return Err(TripleFixtureCheck)
  end
  triple_join([
    triple_slice(value, 0, n - 1)?,
    triple_bytes(if byte == 0 do
        1
      else
        0
      end,
      1)?
  ])
end

fn triple_tag(key :: borrow SecretBytes) -> Bytes!TripleFixtureError do
  Ok(Crypto.hmac_sha256_tag(key, Bytes.from_utf8("TEST ONLY hybrid state fingerprint v1"))?)
end

fn triple_map_tag(map :: borrow SecretMap, name :: Bytes) -> Bytes!TripleFixtureError do
  if !SecretMap.contains(map, name) do
    return Ok(Bytes.empty())
  end
  let key = SecretMap.copy(map, name)?
  let result = triple_tag(key)?
  Secret.destroy(key)
  Ok(result)
end

fn triple_he_cached(he :: borrow RatchetState, offset :: Int) -> Bytes!TripleFixtureError do
  if offset >= Bytes.length(he.skipped_index) do
    return Ok(Bytes.empty())
  end
  triple_check(offset < 2560)?
  let public = triple_slice(he.skipped_index, offset, 32)?
  let n = he_read_u32(he.skipped_index, offset + 32)?
  let name = Crypto.sha256(triple_join([
    Bytes.from_utf8("mesh-msg/v2/he-skipped"),
    public,
    triple_u32(n)?
  ])?)
  triple_join([
    triple_map_tag(he.skipped_keys, name)?,
    triple_map_tag(he.header_keys, triple_join([Bytes.from_utf8("old/"), public])?)?,
    triple_he_cached(he, offset + 40)?
  ])
end

fn triple_pq_cached(pq :: borrow SpqrState, offset :: Int) -> Bytes!TripleFixtureError do
  if offset >= Bytes.length(pq.skipped_index) do
    return Ok(Bytes.empty())
  end
  triple_check(offset < 1024)?
  let name = triple_join([triple_hex("02")?, triple_slice(pq.skipped_index, offset, 16)?])?
  triple_join([triple_map_tag(pq.skipped, name)?, triple_pq_cached(pq, offset + 16)?])
end

# TEST ONLY: bind actual private custody without extracting private key bytes.
fn triple_private_custody_tag(he :: borrow RatchetState) -> Bytes!TripleFixtureError do
  let basepoint = X25519PublicKey {
    bytes: triple_hex("0900000000000000000000000000000000000000000000000000000000000000")?
  }
  let shared = Crypto.x25519_shared(he.local_ratchet_private, basepoint)?
  let tagged = Crypto.hmac_sha256_tag(shared,
    Bytes.from_utf8("TEST ONLY hybrid private DH custody v1"))
  # Destroy before propagating a possible tagging error as well as on success.
  Secret.destroy(shared)
  Ok(tagged?)
end

fn triple_fingerprint(he :: borrow RatchetState,
  pq :: borrow SpqrState) -> Bytes!TripleFixtureError do
  let slots = for slot in pq.slots do
    triple_join([
      triple_u64(slot.epoch)?,
      Bytes.from_utf8(if slot.send_present do
        "1"
      else
        "0"
      end),
      triple_u64(slot.send_count)?,
      Bytes.from_utf8(if slot.receive_present do
        "1"
      else
        "0"
      end),
      triple_u64(slot.receive_count)?
    ])?
  end
  let chains = for slot in pq.slots do
    triple_join([
      triple_map_tag(pq.chains,
        triple_join([triple_hex("01")?, triple_u64(slot.epoch)?, triple_hex("00")?])?)?,
      triple_map_tag(pq.chains,
        triple_join([triple_hex("01")?, triple_u64(slot.epoch)?, triple_hex("01")?])?)?
    ])?
  end
  Ok(Crypto.sha256(triple_join([
    he.session_id,
    he.local_ratchet_public.bytes,
    he.remote_ratchet_public.bytes,
    triple_private_custody_tag(he)?,
    Bytes.from_utf8(Int.to_string(he.version)
      <> ":"
      <> Int.to_string(he.suite)
      <> ":"
      <> Int.to_string(he.previous_chain_length)
      <> ":"
      <> Int.to_string(he.sent_count)
      <> ":"
      <> Int.to_string(he.received_count)
      <> ":"
      <> Int.to_string(he.receive_generation)),
    Bytes.from_utf8(if he.pending_send_ratchet do
      "1"
    else
      "0"
    end),
    triple_u64(he.snapshot_version)?,
    he.skipped_index,
    triple_tag(he.root_key)?,
    triple_tag(he.sending_chain_key)?,
    triple_tag(he.receiving_chain_key)?,
    triple_map_tag(he.header_keys, Bytes.from_utf8("sending"))?,
    triple_map_tag(he.header_keys, Bytes.from_utf8("receiving"))?,
    triple_map_tag(he.header_keys, Bytes.from_utf8("next-sending"))?,
    triple_map_tag(he.header_keys, Bytes.from_utf8("next-receiving"))?,
    triple_he_cached(he, 0)?,
    pq.scope.protocol_info,
    pq.scope.configuration,
    pq.scope.account_id,
    pq.scope.device_id,
    pq.scope.peer_account_id,
    pq.scope.peer_device_id,
    pq.scope.session_id,
    Bytes.from_utf8(Int.to_string(pq.direction)),
    triple_u64(pq.epoch)?,
    triple_u64(pq.knowledge)?,
    triple_join(slots)?,
    pq.skipped_index,
    triple_map_tag(pq.chains, triple_hex("00")?)?,
    triple_join(chains)?,
    triple_pq_cached(pq, 0)?
  ])?))
end

fn triple_error_code(error :: HybridError) -> Int do
  case error do
    HybridInvalidState -> 1
    HybridInvalidMessage -> 2
    HybridAuthenticationRejected -> 3
    HybridReplay -> 4
    HybridExcessiveJump -> 5
    HybridRetired -> 6
    HybridSkipLimit -> 7
    HybridCounterOverflow -> 8
    HybridCryptoFailure -> 9
  end
end

fn triple_send(he :: consume RatchetState,
  pq :: consume SpqrState,
  plain :: Bytes,
  fragment :: BraidFragment,
  caller :: Bytes) -> (RatchetState, SpqrState, TripleMessage)!TripleFixtureError do
  let old_sent = he.sent_count
  case he_encrypt_hybrid(he, pq, plain, fragment, caller) do
    HybridSealRefused(_, _, error) -> do
      if triple_error_code(error) == 9 do
        println("C1_HYBRID_STUB_SEND_REFUSAL")
      end
      Err(TripleFixtureHybrid(error))
    end
    HybridSealed(he, pq, message) -> do
      triple_check(he.sent_count == old_sent + 1)?
      let encoded = encode_triple_message(message)?
      let decoded = decode_triple_message(encoded)?
      triple_check(Bytes.secure_equals(decoded.ciphertext, message.ciphertext))?
      Ok((he, pq, decoded))
    end
  end
end

fn triple_open(he :: consume RatchetState,
  pq :: consume SpqrState,
  message :: TripleMessage,
  caller :: Bytes) -> (RatchetState, SpqrState, TripleHeader, Bytes)!TripleFixtureError do
  case he_decrypt_hybrid(he, pq, message, caller) do
    HybridOpenRefused(_, _, error) -> do
      if triple_error_code(error) == 9 do
        println("C1_HYBRID_STUB_OPEN_REFUSAL")
      end
      Err(TripleFixtureHybrid(error))
    end
    HybridOpened(he, pq, header, clear) -> Ok((he, pq, header, clear))
  end
end

fn triple_refuse(he :: consume RatchetState,
  pq :: consume SpqrState,
  message :: TripleMessage,
  caller :: Bytes,
  expected :: HybridError) -> (RatchetState, SpqrState)!TripleFixtureError do
  let before = triple_fingerprint(he, pq)?
  case he_decrypt_hybrid(he, pq, message, caller) do
    HybridOpened(_, _, _, _) -> Err(TripleFixtureCheck)
    HybridOpenRefused(he, pq, error) -> do
      if triple_error_code(error) == 9 do
        println("C1_HYBRID_STUB_OPEN_REFUSAL")
      end
      triple_check(triple_error_code(error) == triple_error_code(expected)
        && Bytes.secure_equals(before, triple_fingerprint(he, pq)?))?
      Ok((he, pq))
    end
  end
end

fn triple_send_refuse(he :: consume RatchetState,
  pq :: consume SpqrState,
  plain :: Bytes,
  fragment :: BraidFragment,
  caller :: Bytes,
  expected :: HybridError) -> (RatchetState, SpqrState)!TripleFixtureError do
  let before = triple_fingerprint(he, pq)?
  case he_encrypt_hybrid(he, pq, plain, fragment, caller) do
    HybridSealed(_, _, _) -> Err(TripleFixtureCheck)
    HybridSealRefused(he, pq, error) -> do
      if triple_error_code(error) == 9 do
        println("C1_HYBRID_STUB_SEND_REFUSAL")
      end
      triple_check(triple_error_code(error) == triple_error_code(expected)
        && Bytes.secure_equals(before, triple_fingerprint(he, pq)?))?
      Ok((he, pq))
    end
  end
end

fn triple_fragment(pq :: borrow SpqrState,
  epoch :: U64,
  data :: Bool,
  carrier :: Bytes) -> BraidFragment!TripleFixtureError do
  Ok(emit_braid_fragment(if data do
      BraidHeaderFragment
    else
      NoBraidFragment
    end,
    pq.scope.configuration,
    pq.scope.session_id,
    epoch,
    carrier,
    0)?)
end

pub fn triple_fixture_pair() -> (RatchetState, RatchetState, SpqrState, SpqrState, BraidAliceIdle, BraidAwaitHeader)!TripleFixtureError do
  let scope = fixture_scope()?
  let peer = %{scope |
    account_id: scope.peer_account_id,
    device_id: scope.peer_device_id,
    peer_account_id: scope.account_id,
    peer_device_id: scope.device_id
  }
  let kem = Crypto.mlkem_generate()?
  let (cipher, seed) = Crypto.mlkem_encapsulate(kem.public_key)?
  let peer_seed = Crypto.mlkem_decapsulate(kem.private_key, cipher)?
  let a = initialize_initiator(scope, seed)?
  let b = initialize_responder(peer, peer_seed)?
  let p = initialize_spqr(scope, 0, seed)?
  let q = initialize_spqr(peer, 1, peer_seed)?
  Secret.destroy(kem.private_key)
  Secret.destroy(seed)
  Secret.destroy(peer_seed)
  let bootstrap = Crypto.x25519_generate()?
  let bootstrap_public = bootstrap.public_key
  let ha = he_initialize_alice(Env.get_secret_hex("MORSE_C1_TRIPLE_ROOT")?,
    2,
    scope.session_id,
    bootstrap_public,
    triple_wide("1")?)?
  let hb = he_initialize_bob(Env.get_secret_hex("MORSE_C1_TRIPLE_ROOT")?,
    2,
    scope.session_id,
    bootstrap.private_key,
    bootstrap_public,
    triple_wide("1")?)?
  Ok((ha, hb, p, q, a, b))
end

fn triple_actual_epoch(a :: consume BraidAliceIdle,
  b :: consume BraidAwaitHeader,
  p :: consume SpqrState,
  q :: consume SpqrState) -> (BraidAwaitHeader, BraidAliceIdle, SpqrState, SpqrState, Bytes)!TripleFixtureError do
  let e = a.epoch
  let old_p = p.knowledge
  let old_q = q.knowledge
  let (sent, header) = send_header(a)?
  let ready = case admit_complete_header(b, e, header) do
    BraidHeaderAccepted(v) -> v
    _ -> return Err(TripleFixtureCheck)
  end
  let (first, output) = send_ct1(ready)?
  let q = case incorporate_spqr_epoch(q, output) do
    SpqrEpochAccepted(v) -> v
    SpqrEpochRefused(_, error) -> return Err(TripleFixturePq(error))
  end
  let (sent, vector) = send_vector(sent)?
  let got_first = case receive_ct1(sent, e, first.first) do
    BraidAliceCt1Accepted(v) -> v
    _ -> return Err(TripleFixtureCheck)
  end
  let got_vector = case receive_vector(first, e, vector) do
    BraidVectorAccepted(v) -> v
    _ -> return Err(TripleFixtureCheck)
  end
  let (sent, second) = case send_ct2(got_vector) do
    BraidCt2Emitted(v, wire) -> (v, wire)
    _ -> return Err(TripleFixtureCheck)
  end
  let (waiting, output) = case receive_ct2(got_first, e, second) do
    BraidAliceCt2Accepted(v, output) -> (v, output)
    _ -> return Err(TripleFixtureCheck)
  end
  let p = case incorporate_spqr_epoch(p, output) do
    SpqrEpochAccepted(v) -> v
    SpqrEpochRefused(_, error) -> return Err(TripleFixturePq(error))
  end
  let next = case receive_next_epoch(sent, waiting.epoch) do
    BraidNextEpochAccepted(v) -> v
    _ -> return Err(TripleFixtureCheck)
  end
  triple_check(U64.compare(p.epoch, e) == 0
    && U64.compare(q.epoch, e) == 0
    && U64.compare(p.knowledge, old_p) == 0
    && U64.compare(q.knowledge, old_q) == 0)?
  Ok((waiting, next, p, q, header))
end

fn triple_swap_receiving(state :: consume RatchetState,
  replacement :: consume SecretBytes) -> (RatchetState, SecretBytes) do
  let RatchetState {
    version,
    suite,
    session_id,
    root_key,
    sending_chain_key,
    receiving_chain_key,
    local_ratchet_private,
    local_ratchet_public,
    remote_ratchet_public,
    previous_chain_length,
    sent_count,
    received_count,
    skipped_keys,
    skipped_index,
    receive_generation,
    pending_send_ratchet,
    snapshot_version,
    header_keys
  } = state
  (RatchetState {
      version: version,
      suite: suite,
      session_id: session_id,
      root_key: root_key,
      sending_chain_key: sending_chain_key,
      receiving_chain_key: replacement,
      local_ratchet_private: local_ratchet_private,
      local_ratchet_public: local_ratchet_public,
      remote_ratchet_public: remote_ratchet_public,
      previous_chain_length: previous_chain_length,
      sent_count: sent_count,
      received_count: received_count,
      skipped_keys: skipped_keys,
      skipped_index: skipped_index,
      receive_generation: receive_generation,
      pending_send_ratchet: pending_send_ratchet,
      snapshot_version: snapshot_version,
      header_keys: header_keys
    },
    receiving_chain_key)
end

fn triple_oracle_pair() -> (RatchetState, SpqrState)!TripleFixtureError do
  let base = fixture_scope()?
  let scope = %{base | configuration: triple_bytes(17, 32)?, session_id: triple_bytes(34, 32)?}
  let seed = Env.get_secret_hex("MORSE_C1_TRIPLE_PQ_SEED")?
  let pq = initialize_spqr(scope, 1, seed)?
  Secret.destroy(seed)
  let headers = he_empty_headers()?
  he_replace_header(headers,
    Bytes.from_utf8("receiving"),
    Env.get_secret_hex("MORSE_C1_TRIPLE_HEADER_KEY")?)?
  let local = Crypto.x25519_generate()?
  let local_public = local.public_key
  let he = RatchetState {
    version: 2,
    suite: 2,
    session_id: scope.session_id,
    root_key: Env.get_secret_hex("MORSE_C1_TRIPLE_ROOT")?,
    sending_chain_key: Env.get_secret_hex("MORSE_C1_TRIPLE_WRONG_KEY")?,
    receiving_chain_key: Env.get_secret_hex("MORSE_C1_TRIPLE_EC_CHAIN")?,
    local_ratchet_private: local.private_key,
    local_ratchet_public: local_public,
    remote_ratchet_public: X25519PublicKey {
      bytes: triple_hex("0900000000000000000000000000000000000000000000000000000000000000")?
    },
    previous_chain_length: 0,
    sent_count: 0,
    received_count: 0,
    skipped_keys: SecretMap.new(64)?,
    skipped_index: Bytes.empty(),
    receive_generation: 0,
    pending_send_ratchet: false,
    snapshot_version: triple_wide("1")?,
    header_keys: headers
  }
  Ok((he, pq))
end

fn triple_oracle() -> Unit!TripleFixtureError do
  let (he, pq) = triple_oracle_pair()?
  let message = decode_triple_message(triple_hex("43484631000102030405060708090a0b0c0d0e0f101112131415161700b7c2da77e02fdbaa16858831ecc93ea90a715e45b694a4389301c3ec3b9eec47d95df1b8c6a3620c330285894ff13a5cefc2f5418bd71cc055eadbd33f67d6d89f7bb79dd77a29eb6e45cfc379c31e6c8f35b1aee982f18e1cbdc65337c5b55ee838bc6904a7a95a76f2040eb6f423a6402b2f0af498c97e69da1aeb91978eca173a7cc4b6dbfe5fde7126c02a1599106320dede88215b21df548e789d1fdae59edd77f98e5ce35d8bc592f46850d466e75b1201598fb563707172737475767778797a7b00000031df422e4cab050b9557cb63896a142838c68ba05cc9c1786be428c7ac2fdcdf148f536863883438ffe9212bb375a89c4c8d")?)?
  let (he, pq, header, clear) = triple_open(he,
    pq,
    message,
    triple_hex("54455354204f4e4c59206879627269642077686f6c652d626f647920414144207631")?)?
  triple_check(Bytes.secure_equals(clear,
    triple_hex("54455354204f4e4c5920636f6d62696e656420626f6479206f7261636c65207631")?)
    && Bytes.secure_equals(triple_tag(he.receiving_chain_key)?,
      triple_hex("8f200662e44d1e3fc23feb4f58889e9539186af9bed60662f249ee0277652c05")?)
    && he.received_count == 1
    && U64.compare(header.pq_message_number, triple_wide("1")?) == 0)?
  let (he, pq) = triple_oracle_pair()?
  let message = decode_triple_message(triple_hex("43484631000102030405060708090a0b0c0d0e0f101112131415161700fdc2da77e02fdbaa16858831ecc93ea90a715e45b694a4389301c3ec3b9eec47d95df1b8c6a3620c330285894ff13a5cefc2f5418bd71cc055eadbd33f67d6d89f7bb79dd77a29eb6e45cfc379c31e6c8f35b1aee982f18e1c67c65337c5b55fe838bc6904a7a95a76f2040eb6f423a6402b2f0af498c97e69da1aeb91978eca173a7cc4b6dbfe5fde7126c02a1599106320dede88215b21df548e789d1fdae59edd77f98e5ce35ddafe272f6370c7e8520cf600fb1bf5b96317c595ec23d71cfb0b8c912dec3535e1de29c22f7c71d810b62173abf846292d486752fc7ae4a6d88de4ef7fb3b8ccc2c8af0da40551951893cf305c740a45a577398b5e51707172737475767778797a7b00000031df422e4cab050b9557cb63896a142838c68ba05cc9c1786be428c7ac2fdcdf148f67edc875ca0c2c9d28f5f321cb23708f")?)?
  let (he, pq, header, clear) = triple_open(he,
    pq,
    message,
    triple_hex("54455354204f4e4c59206879627269642077686f6c652d626f647920414144207631")?)?
  triple_check(Bytes.secure_equals(clear,
    triple_hex("54455354204f4e4c5920636f6d62696e656420626f6479206f7261636c65207631")?)
    && Bytes.secure_equals(triple_tag(he.receiving_chain_key)?,
      triple_hex("8f200662e44d1e3fc23feb4f58889e9539186af9bed60662f249ee0277652c05")?)
    && he.received_count == 1
    && U64.compare(header.pq_message_number, triple_wide("1")?) == 0)?
  Ok(nil)
end

pub fn triple_fixture_agreement() -> Bool!TripleFixtureError do
  triple_oracle()?
  let (a, b, p, q, ka, kb) = triple_fixture_pair()?
  let caller = Bytes.from_utf8("TEST ONLY hybrid agreement")
  let control = triple_fragment(p, triple_wide("1")?, false, Bytes.empty())?
  let (a, p, first) = triple_send(a, p, Bytes.from_utf8("control"), control, caller)?
  let (b, q, h, clear) = triple_open(b, q, first, caller)?
  triple_check(Bytes.length(first.encrypted_header) == 183
    && Bytes.secure_equals(clear, Bytes.from_utf8("control"))
    && h.fragment.kind == NoBraidFragment)?
  let data = triple_fragment(p, triple_wide("1")?, true, triple_bytes(7, 96)?)?
  let (a, p, second) = triple_send(a, p, Bytes.from_utf8("data"), data, caller)?
  let (b, q, h, clear) = triple_open(b, q, second, caller)?
  triple_check(Bytes.length(second.encrypted_header) == 253
    && Bytes.secure_equals(clear, Bytes.from_utf8("data"))
    && h.fragment.kind == BraidHeaderFragment
    && a.sent_count == 2
    && b.received_count == 2
    && p.direction == 0
    && q.direction == 1)?
  Ok(true)
end

pub fn triple_fixture_current_rollback() -> Bool!TripleFixtureError do
  let (a, b, p, q, ka, kb) = triple_fixture_pair()?
  let caller = Bytes.from_utf8("TEST ONLY current rollback")
  let f = triple_fragment(p, triple_wide("1")?, false, Bytes.empty())?
  let (a, p, first) = triple_send(a, p, Bytes.from_utf8("first"), f, caller)?
  let (b, q, _, _) = triple_open(b, q, first, caller)?
  let (a, p, second) = triple_send(a, p, Bytes.from_utf8("second"), f, caller)?
  let (b, q) = triple_refuse(b,
    q,
    %{second | ciphertext: triple_flip(second.ciphertext)?},
    caller,
    HybridAuthenticationRejected)?
  let expected = triple_fingerprint(b, q)?
  # Valid EC material and authenticated header, but a wrong actual PQ chain.
  let receive_name = triple_hex("01000000000000000000")?
  let saved = SecretMap.copy(q.chains, receive_name)?
  SecretMap.delete(q.chains, receive_name)?
  SecretMap.insert(q.chains, receive_name, Env.get_secret_hex("MORSE_C1_TRIPLE_WRONG_KEY")?)?
  let (b, q) = triple_refuse(b, q, second, caller, HybridAuthenticationRejected)?
  SecretMap.delete(q.chains, receive_name)?
  SecretMap.insert(q.chains, receive_name, saved)?
  triple_check(Bytes.secure_equals(expected, triple_fingerprint(b, q)?))?
  # Valid PQ material and header, but a wrong actual EC receiving chain.
  let (b, saved) = triple_swap_receiving(b, Env.get_secret_hex("MORSE_C1_TRIPLE_WRONG_KEY")?)
  let (b, q) = triple_refuse(b, q, second, caller, HybridAuthenticationRejected)?
  let (b, wrong) = triple_swap_receiving(b, saved)
  Secret.destroy(wrong)
  triple_check(Bytes.secure_equals(expected, triple_fingerprint(b, q)?))?
  let (b, q, _, clear) = triple_open(b, q, second, caller)?
  triple_check(Bytes.secure_equals(clear, Bytes.from_utf8("second")) && b.received_count == 2)?
  let (b, q) = triple_refuse(b, q, second, caller, HybridReplay)?
  Ok(true)
end

pub fn triple_fixture_cached_rollback() -> Bool!TripleFixtureError do
  let (a, b, p, q, ka, kb) = triple_fixture_pair()?
  let caller = Bytes.from_utf8("TEST ONLY cached rollback")
  let f = triple_fragment(p, triple_wide("1")?, false, Bytes.empty())?
  let old_public = a.local_ratchet_public.bytes
  let (a, p, late) = triple_send(a, p, Bytes.from_utf8("late"), f, caller)?
  let (a, p, current) = triple_send(a, p, Bytes.from_utf8("current"), f, caller)?
  let (b, q, _, _) = triple_open(b, q, current, caller)?
  triple_check(Bytes.length(b.skipped_index) == 40 && Bytes.length(q.skipped_index) == 16)?
  let (b, q, reply) = triple_send(b, q, Bytes.from_utf8("reply"), f, caller)?
  let (a, p, _, _) = triple_open(a, p, reply, caller)?
  let (a, p, next) = triple_send(a, p, Bytes.from_utf8("next DH"), f, caller)?
  let (b, q, _, _) = triple_open(b, q, next, caller)?
  let old_name = triple_join([Bytes.from_utf8("old/"), old_public])?
  triple_check(SecretMap.contains(b.header_keys, old_name)
    && Bytes.length(b.skipped_index) == 40
    && Bytes.length(q.skipped_index) == 16)?
  let (b, q) = triple_refuse(b,
    q,
    %{late | ciphertext: triple_flip(late.ciphertext)?},
    caller,
    HybridAuthenticationRejected)?
  let (b, q, _, clear) = triple_open(b, q, late, caller)?
  triple_check(Bytes.secure_equals(clear, Bytes.from_utf8("late"))
    && Bytes.length(b.skipped_index) == 0
    && Bytes.length(q.skipped_index) == 0
    && !SecretMap.contains(b.header_keys, old_name))?
  let before = triple_fingerprint(b, q)?
  case he_decrypt_hybrid(b, q, late, caller) do
    HybridOpened(_, _, _, _) -> return Err(TripleFixtureCheck)
    HybridOpenRefused(b, q, error) -> triple_check((triple_error_code(error) == 3
      || triple_error_code(error) == 4)
      && Bytes.secure_equals(before, triple_fingerprint(b, q)?))?
  end
  Ok(true)
end

pub fn triple_fixture_next_lifecycle() -> Bool!TripleFixtureError do
  let (a, b, p, q, ka, kb) = triple_fixture_pair()?
  let caller = Bytes.from_utf8("TEST ONLY next lifecycle")
  let f = triple_fragment(p, triple_wide("1")?, false, Bytes.empty())?
  let (a, p, first) = triple_send(a, p, Bytes.from_utf8("first next"), f, caller)?
  let original_public = b.local_ratchet_public.bytes
  triple_check(b.receive_generation == 0
    && !SecretMap.contains(b.header_keys, Bytes.from_utf8("receiving")))?
  println("C1_HYBRID_NEXT_BAD_BEGIN")
  let (b, q) = triple_refuse(b,
    q,
    %{first | ciphertext: triple_flip(first.ciphertext)?},
    caller,
    HybridAuthenticationRejected)?
  println("C1_HYBRID_NEXT_BAD_END")
  triple_check(b.receive_generation == 0
    && Bytes.secure_equals(original_public, b.local_ratchet_public.bytes))?
  println("C1_HYBRID_NEXT_GOOD_BEGIN")
  let (b, q, _, clear) = triple_open(b, q, first, caller)?
  println("C1_HYBRID_NEXT_GOOD_END")
  triple_check(b.receive_generation == 1
    && !Bytes.secure_equals(original_public, b.local_ratchet_public.bytes)
    && Bytes.secure_equals(clear, Bytes.from_utf8("first next")))?
  Ok(true)
end

# Authenticated header-only admission controls; body bytes are never treated as proof.
fn triple_admission_message(he :: borrow RatchetState,
  pq :: borrow SpqrState,
  ec_number :: Int,
  pq_number :: U64) -> TripleMessage!TripleFixtureError do
  let fragment = triple_fragment(pq, triple_wide("1")?, false, Bytes.empty())?
  let header = TripleHeader {
    ec: OpenedHeader {
      suite: 2,
      session_id: he.session_id,
      ratchet_public_key: he.remote_ratchet_public,
      previous_chain_length: 0,
      message_number: ec_number
    },
    pq_message_number: pq_number,
    fragment: fragment
  }
  let nonce = Crypto.random_bytes(24)?
  let key = Crypto.aead_key(SecretMap.copy(he.header_keys, Bytes.from_utf8("receiving"))?)?
  let encrypted = Crypto.xchacha20poly1305_seal(key,
    nonce,
    triple_header_aad(pq.scope.configuration,
      pq.scope.session_id,
      183,
      Bytes.from_utf8("TEST ONLY scope bounds"))?,
    encode_triple_header(header)?)?
  Ok(TripleMessage {
    header_nonce: nonce,
    encrypted_header: encrypted,
    nonce: triple_bytes(0, 12)?,
    ciphertext: triple_bytes(0, 16)?
  })
end

pub fn triple_fixture_scope_bounds() -> Bool!TripleFixtureError do
  let (a, b, p, q, ka, kb) = triple_fixture_pair()?
  let caller = Bytes.from_utf8("TEST ONLY scope bounds")
  let f = triple_fragment(p, triple_wide("1")?, true, triple_bytes(8, 96)?)?
  let (a, p) = triple_send_refuse(a, p, triple_bytes(0, 65153)?, f, caller, HybridInvalidMessage)?
  let (a, p) = triple_send_refuse(a,
    p,
    Bytes.empty(),
    %{f | configuration: triple_bytes(9, 32)?},
    caller,
    HybridInvalidMessage)?
  let (a, p) = triple_send_refuse(a,
    p,
    Bytes.empty(),
    f,
    triple_bytes(0, 130669)?,
    HybridInvalidMessage)?
  let a = %{a | suite: 1}
  let (a, p) = triple_send_refuse(a, p, Bytes.empty(), f, caller, HybridInvalidState)?
  let a = %{a | suite: 2}
  let (a, p, message) = triple_send(a, p, triple_bytes(4, 65152)?, f, caller)?
  triple_check(Bytes.length(encode_triple_message(message)?) == 65467)?
  for changed in [
    %{message | header_nonce: triple_bytes(0, 23)?},
    %{message | encrypted_header: triple_bytes(0, 254)?},
    %{message | nonce: triple_bytes(0, 13)?},
    %{message | ciphertext: triple_bytes(0, 15)?}
  ] do
    # Independent disposable pair per direct-struct framing control.
    let (ta, tb, tp, tq, tka, tkb) = triple_fixture_pair()?
    let (tb, tq) = triple_refuse(tb, tq, changed, caller, HybridInvalidMessage)?
  end
  let (b, q) = triple_refuse(b,
    q,
    message,
    Bytes.from_utf8("wrong caller"),
    HybridAuthenticationRejected)?
  let config = q.scope.configuration
  let scope = q.scope
  let q = %{q | scope: %{scope | configuration: triple_bytes(9, 32)?}}
  let (b, q) = triple_refuse(b, q, message, caller, HybridAuthenticationRejected)?
  let scope = q.scope
  let q = %{q | scope: %{scope | configuration: config}}
  let session = q.scope.session_id
  let scope = q.scope
  let q = %{q | scope: %{scope | session_id: triple_bytes(9, 32)?}}
  let (b, q) = triple_refuse(b, q, message, caller, HybridInvalidState)?
  let scope = q.scope
  let q = %{q | scope: %{scope | session_id: session}}
  let (b, q) = triple_refuse(b,
    q,
    %{message | header_nonce: triple_flip(message.header_nonce)?},
    caller,
    HybridAuthenticationRejected)?
  let (b, q) = triple_refuse(b,
    q,
    %{message | encrypted_header: triple_flip(message.encrypted_header)?},
    caller,
    HybridAuthenticationRejected)?
  let (b, q) = triple_refuse(b,
    q,
    %{message | nonce: triple_flip(message.nonce)?},
    caller,
    HybridAuthenticationRejected)?
  let (b, q, _, clear) = triple_open(b, q, message, caller)?
  triple_check(Bytes.length(clear) == 65152)?
  let excessive = triple_admission_message(b, q, b.received_count + 65, triple_wide("2")?)?
  let (b, q) = triple_refuse(b, q, excessive, caller, HybridExcessiveJump)?
  let pq_jump = triple_admission_message(b, q, b.received_count, triple_wide("67")?)?
  let (b, q) = triple_refuse(b, q, pq_jump, caller, HybridSkipLimit)?
  let slots = p.slots
  let terminal = for slot in slots do
    %{slot | send_count: triple_wide("18446744073709551615")?}
  end
  let p = %{p | slots: terminal}
  let (a, p) = triple_send_refuse(a, p, Bytes.empty(), f, caller, HybridCounterOverflow)?
  let p = %{p | slots: slots}
  let max_data_caller = triple_bytes(0, 130668)?
  let (a, p, bounded) = triple_send(a, p, Bytes.empty(), f, max_data_caller)?
  let (b, q, _, clear) = triple_open(b, q, bounded, max_data_caller)?
  triple_check(Bytes.length(clear) == 0)?
  let control = triple_fragment(p, triple_wide("1")?, false, Bytes.empty())?
  let max_control_caller = triple_bytes(0, 130738)?
  let (a, p, bounded) = triple_send(a, p, Bytes.empty(), control, max_control_caller)?
  let (b, q, _, clear) = triple_open(b, q, bounded, max_control_caller)?
  triple_check(Bytes.length(clear) == 0)?
  # Both chains are fixture-owned and still equal; place their public counters
  # at the penultimate wire value without deriving billions of messages.
  let a = %{a | sent_count: 4294967294}
  let b = %{b | received_count: 4294967294}
  let (a, p, last) = triple_send(a,
    p,
    Bytes.from_utf8("last representable result"),
    control,
    caller)?
  let (b, q, _, clear) = triple_open(b, q, last, caller)?
  triple_check(a.sent_count == 4294967295
    && b.received_count == 4294967295
    && Bytes.secure_equals(clear, Bytes.from_utf8("last representable result")))?
  let (a, p) = triple_send_refuse(a, p, Bytes.empty(), control, caller, HybridCounterOverflow)?
  let overflow = triple_admission_message(b, q, 4294967295, triple_wide("5")?)?
  let (b, q) = triple_refuse(b, q, overflow, caller, HybridCounterOverflow)?
  # A real next-DH message may reset a full sending counter; PN=max remains valid.
  let (b, q, reply) = triple_send(b, q, Bytes.from_utf8("reset boundary"), control, caller)?
  let (a, p, _, _) = triple_open(a, p, reply, caller)?
  triple_check(a.sent_count == 0 && a.previous_chain_length == 4294967295)?
  let (a, p, reset) = triple_send(a, p, Bytes.from_utf8("after reset"), control, caller)?
  let (b, q, _, clear) = triple_open(b, q, reset, caller)?
  triple_check(a.sent_count == 1 && Bytes.secure_equals(clear, Bytes.from_utf8("after reset")))?
  # The next-DH receive generation is persisted u32 independently of EC n.
  let (ga, gb, gp, gq, gka, gkb) = triple_fixture_pair()?
  let control = triple_fragment(gp, triple_wide("1")?, false, Bytes.empty())?
  let (ga, gp, first) = triple_send(ga,
    gp,
    Bytes.from_utf8("generation boundary"),
    control,
    caller)?
  let gb = %{gb | receive_generation: 4294967295}
  let (gb, gq) = triple_refuse(gb, gq, first, caller, HybridCounterOverflow)?
  let gb = %{gb | receive_generation: 4294967294}
  let (gb, gq, _, clear) = triple_open(gb, gq, first, caller)?
  triple_check(gb.receive_generation == 4294967295
    && Bytes.secure_equals(clear, Bytes.from_utf8("generation boundary")))?
  let (ga, gp, current) = triple_send(ga,
    gp,
    Bytes.from_utf8("current at terminal generation"),
    control,
    caller)?
  let (gb, gq, _, _) = triple_open(gb, gq, current, caller)?
  triple_check(gb.receive_generation == 4294967295)?
  let (gb, gq, reply) = triple_send(gb, gq, Bytes.from_utf8("generation reverse"), control, caller)?
  let (ga, gp, _, _) = triple_open(ga, gp, reply, caller)?
  let (ga, gp, next) = triple_send(ga,
    gp,
    Bytes.from_utf8("generation exhausted next"),
    control,
    caller)?
  let (gb, gq) = triple_refuse(gb, gq, next, caller, HybridCounterOverflow)?
  let (gb, gq, still_usable) = triple_send(gb,
    gq,
    Bytes.from_utf8("original generation owner usable"),
    control,
    caller)?
  let (ga, gp, _, clear) = triple_open(ga, gp, still_usable, caller)?
  triple_check(Bytes.secure_equals(clear, Bytes.from_utf8("original generation owner usable")))?
  Ok(true)
end

pub fn triple_fixture_progression() -> Bool!TripleFixtureError do
  let (a, b, p, q, ka, kb) = triple_fixture_pair()?
  let caller = Bytes.from_utf8("TEST ONLY actual epoch progression")
  let (ka, kb, p, q, carrier1) = triple_actual_epoch(ka, kb, p, q)?
  triple_check(U64.compare(p.epoch, triple_wide("1")?) == 0
    && U64.compare(p.knowledge, triple_wide("0")?) == 0)?
  let e1 = triple_fragment(p, triple_wide("1")?, true, carrier1)?
  let (a, p, late0) = triple_send(a, p, Bytes.from_utf8("late epoch0 first"), e1, caller)?
  let (a, p, late1) = triple_send(a, p, Bytes.from_utf8("late epoch0 retired"), e1, caller)?
  let e2 = triple_fragment(p, triple_wide("2")?, false, Bytes.empty())?
  let (a, p, current) = triple_send(a, p, Bytes.from_utf8("epoch1 current"), e2, caller)?
  let (b, q, _, _) = triple_open(b, q, current, caller)?
  triple_check(U64.compare(q.knowledge, triple_wide("1")?) == 0
    && Bytes.length(b.skipped_index) == 80
    && Bytes.length(q.skipped_index) == 0)?
  # EC selects cached old material while PQ derives a fresh retained epoch0 key.
  let (b, q) = triple_refuse(b,
    q,
    %{late0 | ciphertext: triple_flip(late0.ciphertext)?},
    caller,
    HybridAuthenticationRejected)?
  let (b, q, _, clear) = triple_open(b, q, late0, caller)?
  triple_check(Bytes.secure_equals(clear, Bytes.from_utf8("late epoch0 first"))
    && U64.compare(q.knowledge, triple_wide("1")?) == 0
    && Bytes.length(b.skipped_index) == 40)?
  let (kb, ka, q, p, carrier2) = triple_actual_epoch(kb, ka, q, p)?
  triple_check(U64.compare(p.epoch, triple_wide("2")?) == 0
    && U64.compare(p.knowledge, triple_wide("1")?) == 0
    && List.length(p.slots) == 3)?
  let f2 = triple_fragment(q, triple_wide("2")?, true, carrier2)?
  let (b, q, reply) = triple_send(b, q, Bytes.from_utf8("epoch1 reverse"), f2, caller)?
  let (a, p, _, _) = triple_open(a, p, reply, caller)?
  let f3 = triple_fragment(p, triple_wide("3")?, false, Bytes.empty())?
  let (a, p, next) = triple_send(a, p, Bytes.from_utf8("epoch2 forward"), f3, caller)?
  let (b, q, _, clear) = triple_open(b, q, next, caller)?
  triple_check(Bytes.secure_equals(clear, Bytes.from_utf8("epoch2 forward"))
    && p.direction == 0
    && q.direction == 1
    && U64.compare(q.knowledge, triple_wide("2")?) == 0
    && List.length(q.slots) == 2
    && Bytes.length(b.skipped_index) == 40)?
  let (b, q) = triple_refuse(b, q, late1, caller, HybridRetired)?
  let (b, q, final) = triple_send(b, q, Bytes.from_utf8("after retired refusal"), f3, caller)?
  let (a, p, _, clear) = triple_open(a, p, final, caller)?
  triple_check(Bytes.secure_equals(clear, Bytes.from_utf8("after retired refusal"))
    && a.receive_generation > 0
    && b.receive_generation > 0)?
  Ok(true)
end
