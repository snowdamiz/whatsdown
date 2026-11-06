##! TEST ONLY real opaque HE owners and authenticated u32 counter boundaries.
from Session.State import RatchetState, RatchetMessage, RatchetError, DecryptOutcome
from Session.HeaderRatchet import he_initialize_alice, he_initialize_bob, he_encrypt, he_decrypt
from Session.HeaderWire import (
  OpenedHeader,
  encode_header,
  decode_header,
  he_header_aad,
  he_body_aad,
  he_encode_message,
  he_join,
  he_u32,
  he_read_u32,
  he_slice
)
from Session.Snapshot import SnapshotError, SnapshotOutcome, snapshot, restore

pub type C4CounterFixtureError do
  C4CounterCheck
  C4CounterCrypto(error :: CryptoError)
  C4CounterRatchet(error :: RatchetError)
  C4CounterSnapshot(error :: SnapshotError)
end

impl From<CryptoError> for C4CounterFixtureError do
  fn from(error :: CryptoError) -> C4CounterFixtureError do
    C4CounterCrypto(error)
  end
end

impl From<RatchetError> for C4CounterFixtureError do
  fn from(error :: RatchetError) -> C4CounterFixtureError do
    C4CounterRatchet(error)
  end
end

impl From<SnapshotError> for C4CounterFixtureError do
  fn from(error :: SnapshotError) -> C4CounterFixtureError do
    C4CounterSnapshot(error)
  end
end

fn counter_check(ok :: Bool) -> Unit!C4CounterFixtureError do
  if ok do
    Ok(nil)
  else
    Err(C4CounterCheck)
  end
end

fn counter_wide(text :: String) -> U64!C4CounterFixtureError do
  case U64.parse(text) do
    Ok(value)
    Err(_) -> Err(C4CounterCheck)
  end
end

fn counter_bytes(value :: Int, count :: Int) -> Bytes!C4CounterFixtureError do
  case Bytes.repeat(value, count) do
    Ok(bytes)
    Err(_) -> Err(C4CounterCheck)
  end
end

fn counter_aad() -> Bytes do
  Bytes.from_utf8("TEST ONLY C4 u32 boundary")
end

fn counter_discard(state :: consume RatchetState) do
  nil
end

fn counter_pair() -> (RatchetState, RatchetState)!C4CounterFixtureError do
  let session = counter_bytes(36, 32)?
  let seed = Secret.random(32)?
  let root_a = Crypto.hkdf_sha256(seed,
    session,
    Bytes.from_utf8("TEST ONLY C4 paired HE roots"),
    32)?
  let root_b = Crypto.hkdf_sha256(seed,
    session,
    Bytes.from_utf8("TEST ONLY C4 paired HE roots"),
    32)?
  Secret.destroy(seed)
  let bootstrap = Crypto.x25519_generate()?
  let public = bootstrap.public_key
  let a = he_initialize_alice(root_a, 2, session, public, counter_wide("0")?)?
  let b = he_initialize_bob(root_b, 2, session, bootstrap.private_key, public, counter_wide("0")?)?
  Ok((a, b))
end

fn counter_send(state :: consume RatchetState,
  text :: String) -> (RatchetState, RatchetMessage)!C4CounterFixtureError do
  Ok(he_encrypt(state, Bytes.from_utf8(text), counter_aad())?)
end

fn counter_receive(state :: consume RatchetState,
  message :: RatchetMessage,
  expected :: String) -> RatchetState!C4CounterFixtureError do
  case he_decrypt(state, message, counter_aad()) do
    Rejected(_, error) -> Err(C4CounterRatchet(error))
    Opened(state, clear) -> do
      counter_check(Bytes.secure_equals(clear, Bytes.from_utf8(expected)))?
      Ok(state)
    end
  end
end

fn counter_established() -> (RatchetState, RatchetState)!C4CounterFixtureError do
  let (a, b) = counter_pair()?
  let (a, message) = counter_send(a, "initial current chain")?
  let b = counter_receive(b, message, "initial current chain")?
  Ok((a, b))
end

fn counter_tag(secret :: borrow SecretBytes) -> Bytes!C4CounterFixtureError do
  Ok(Crypto.hmac_sha256_tag(secret, Bytes.from_utf8("TEST ONLY C4 complete owner fingerprint"))?)
end

fn counter_map_tag(map :: borrow SecretMap, name :: Bytes) -> Bytes!C4CounterFixtureError do
  if !SecretMap.contains(map, name) do
    return Ok(Bytes.empty())
  end
  let value = SecretMap.copy(map, name)?
  let tag = counter_tag(value)
  Secret.destroy(value)
  tag
end

fn counter_cached_tag(state :: borrow RatchetState, offset :: Int) -> Bytes!C4CounterFixtureError do
  if offset >= Bytes.length(state.skipped_index) do
    return Ok(Bytes.empty())
  end
  counter_check(offset < 2560)?
  let public = he_slice(state.skipped_index, offset, 32)?
  let n = he_read_u32(state.skipped_index, offset + 32)?
  let name = Crypto.sha256(he_join([
    Bytes.from_utf8("mesh-msg/v2/he-skipped"),
    public,
    he_u32(n)?
  ])?)
  Ok(he_join([
    counter_map_tag(state.skipped_keys, name)?,
    counter_map_tag(state.header_keys, he_join([Bytes.from_utf8("old/"), public])?)?,
    counter_cached_tag(state, offset + 40)?
  ])?)
end

fn counter_fingerprint(state :: borrow RatchetState) -> Bytes!C4CounterFixtureError do
  let base = case Bytes.from_hex("0900000000000000000000000000000000000000000000000000000000000000") do
    Ok(value) -> value
    Err(_) -> return Err(C4CounterCheck)
  end
  let shared = Crypto.x25519_shared(state.local_ratchet_private, X25519PublicKey { bytes: base })?
  let private_tag = counter_tag(shared)
  Secret.destroy(shared)
  Ok(Crypto.sha256(he_join([
    state.session_id,
    state.local_ratchet_public.bytes,
    state.remote_ratchet_public.bytes,
    private_tag?,
    Bytes.from_utf8(Int.to_string(state.version)
      <> ":"
      <> Int.to_string(state.suite)
      <> ":"
      <> Int.to_string(state.previous_chain_length)
      <> ":"
      <> Int.to_string(state.sent_count)
      <> ":"
      <> Int.to_string(state.received_count)
      <> ":"
      <> Int.to_string(state.receive_generation)),
    Bytes.from_utf8(if state.pending_send_ratchet do
      "1"
    else
      "0"
    end),
    case Bytes.write_u64_be(state.snapshot_version) do
      Ok(value) -> value
      Err(_) -> return Err(C4CounterCheck)
    end,
    state.skipped_index,
    counter_tag(state.root_key)?,
    counter_tag(state.sending_chain_key)?,
    counter_tag(state.receiving_chain_key)?,
    counter_map_tag(state.header_keys, Bytes.from_utf8("sending"))?,
    counter_map_tag(state.header_keys, Bytes.from_utf8("receiving"))?,
    counter_map_tag(state.header_keys, Bytes.from_utf8("next-sending"))?,
    counter_map_tag(state.header_keys, Bytes.from_utf8("next-receiving"))?,
    counter_cached_tag(state, 0)?
  ])?))
end

fn counter_roundtrip(state :: consume RatchetState,
  key :: borrow StorageKey) -> RatchetState!C4CounterFixtureError do
  let version = case U64.add(state.snapshot_version, counter_wide("1")?) do
    Ok(value) -> value
    Err(_) -> return Err(C4CounterCheck)
  end
  let account = counter_bytes(3, 32)?
  let device = counter_bytes(4, 16)?
  let (state, blob) = case snapshot(state, key, account, device, version) do
    SnapshotRejected(_, error) -> return Err(C4CounterSnapshot(error))
    SnapshotSealed(state, blob) -> (state, blob)
  end
  let expected = counter_fingerprint(state)?
  let restored = restore(blob, key, account, device, version)?
  counter_check(Bytes.secure_equals(expected, counter_fingerprint(restored)?))?
  counter_discard(state)
  Ok(restored)
end

fn counter_refuse(state :: consume RatchetState,
  message :: RatchetMessage) -> RatchetState!C4CounterFixtureError do
  let before = counter_fingerprint(state)?
  case he_decrypt(state, message, counter_aad()) do
    Opened(state, _) -> do
      println("C4_COUNTER_RECEIVE_ACCEPTED_OVERFLOW")
      println(Int.to_string(state.received_count) <> ":" <> Int.to_string(state.receive_generation))
      Err(C4CounterCheck)
    end
    Rejected(state, error) -> do
      counter_check(case error do
        InvalidMessage -> true
        _ -> false
      end)?
      counter_check(Bytes.secure_equals(before, counter_fingerprint(state)?))?
      Ok(state)
    end
  end
end

fn counter_header(state :: borrow RatchetState,
  message :: RatchetMessage,
  name :: String) -> OpenedHeader!C4CounterFixtureError do
  let key = Crypto.aead_key(SecretMap.copy(state.header_keys, Bytes.from_utf8(name))?)?
  let clear = Crypto.xchacha20poly1305_open(key,
    message.header_nonce,
    he_header_aad(counter_aad())?,
    message.encrypted_header)?
  Ok(decode_header(clear)?)
end

# Independent current-chain packet construction: no he_encrypt or chain_step.
# Only fixture-owned opaque chains are borrowed; expected n and body are literals.
fn counter_authenticated_max(a :: borrow RatchetState,
  b :: borrow RatchetState) -> RatchetMessage!C4CounterFixtureError do
  let n = 4294967295
  let header = OpenedHeader {
    suite: a.suite,
    session_id: a.session_id,
    ratchet_public_key: a.local_ratchet_public,
    previous_chain_length: a.previous_chain_length,
    message_number: n
  }
  let header_nonce = Crypto.random_bytes(24)?
  let header_key = Crypto.aead_key(SecretMap.copy(a.header_keys, Bytes.from_utf8("sending"))?)?
  let encrypted_header = Crypto.xchacha20poly1305_seal(header_key,
    header_nonce,
    he_header_aad(counter_aad())?,
    encode_header(header)?)?
  let info = he_join([
    Bytes.from_utf8("mesh-msg/v2/he-message-key"),
    a.local_ratchet_public.bytes,
    he_u32(n)?
  ])?
  let key = Crypto.aead_key(Crypto.hkdf_sha256(a.sending_chain_key, a.session_id, info, 32)?)?
  let nonce = Crypto.random_bytes(12)?
  let framed = RatchetMessage {
    version: 4,
    suite: 0,
    session_id: Bytes.empty(),
    ratchet_public_key: X25519PublicKey { bytes: Bytes.empty() },
    previous_chain_length: 0,
    message_number: 0,
    header_nonce: header_nonce,
    encrypted_header: encrypted_header,
    nonce: nonce,
    ciphertext: Bytes.empty()
  }
  let ciphertext = Crypto.aead_seal(key,
    nonce,
    he_body_aad(framed, counter_aad())?,
    Bytes.from_utf8("independently authenticated max packet"))?
  let output = %{framed | ciphertext: ciphertext}
  he_encode_message(output)?
  let opened_header = counter_header(b, output, "receiving")?
  counter_check(opened_header.message_number == n
    && Bytes.secure_equals(opened_header.ratchet_public_key.bytes, b.remote_ratchet_public.bytes))?
  let receiver_info = he_join([
    Bytes.from_utf8("mesh-msg/v2/he-message-key"),
    b.remote_ratchet_public.bytes,
    he_u32(n)?
  ])?
  let receiver_key = Crypto.aead_key(Crypto.hkdf_sha256(b.receiving_chain_key,
    b.session_id,
    receiver_info,
    32)?)?
  let clear = Crypto.aead_open(receiver_key,
    output.nonce,
    he_body_aad(output, counter_aad())?,
    output.ciphertext)?
  counter_check(Bytes.secure_equals(clear,
    Bytes.from_utf8("independently authenticated max packet")))?
  println("C4_COUNTER_MAX_HEADER_AND_BODY_INDEPENDENTLY_AUTHENTICATED")
  Ok(output)
end

pub fn counter_sender_boundary() -> Bool!C4CounterFixtureError do
  let key = StorageKey.ephemeral()?
  let (a, b) = counter_established()?
  let a = %{a | sent_count: 4294967294}
  let b = %{b | received_count: 4294967294}
  let (a, message) = counter_send(a, "last representable sender and receiver")?
  let b = counter_receive(b, message, "last representable sender and receiver")?
  counter_check(a.sent_count == 4294967295 && b.received_count == 4294967295)?
  let a = counter_roundtrip(a, key)?
  let b = counter_roundtrip(b, key)?
  case he_encrypt(a, Bytes.from_utf8("must refuse before encryption"), counter_aad()) do
    Err(InvalidMessage) -> Ok(true)
    Ok((a, _)) -> do
      println("C4_COUNTER_SEND_ACCEPTED_OVERFLOW")
      println(Int.to_string(a.sent_count))
      Err(C4CounterCheck)
    end
    Err(error) -> Err(C4CounterRatchet(error))
  end
end

pub fn counter_receive_boundary() -> Bool!C4CounterFixtureError do
  let key = StorageKey.ephemeral()?
  let (a, b) = counter_established()?
  let a = %{a | sent_count: 4294967295}
  let b = %{b | received_count: 4294967295}
  let message = counter_authenticated_max(a, b)?
  let b = counter_refuse(b, message)?
  let b = counter_roundtrip(b, key)?
  let (b, reply) = counter_send(b, "reverse resets full sending chain")?
  let a = counter_receive(a, reply, "reverse resets full sending chain")?
  counter_check(a.sent_count == 0 && a.previous_chain_length == 4294967295)?
  let (a, reset) = counter_send(a, "new chain retry after max refusal")?
  let opened_header = counter_header(b, reset, "next-receiving")?
  counter_check(opened_header.previous_chain_length == 4294967295
    && opened_header.message_number == 0)?
  let b = counter_receive(b, reset, "new chain retry after max refusal")?
  let b = counter_roundtrip(b, key)?
  let (a, current) = counter_send(a, "current after reset")?
  let b = counter_receive(b, current, "current after reset")?
  Ok(b.received_count == 2)
end

pub fn counter_generation_boundary() -> Bool!C4CounterFixtureError do
  let key = StorageKey.ephemeral()?
  let (a, b) = counter_pair()?
  let b = %{b | receive_generation: 4294967294}
  let (a, first) = counter_send(a, "last representable generation")?
  let b = counter_receive(b, first, "last representable generation")?
  counter_check(b.receive_generation == 4294967295)?
  let b = counter_roundtrip(b, key)?
  let (a, current) = counter_send(a, "current at terminal generation")?
  let b = counter_receive(b, current, "current at terminal generation")?
  let b = counter_roundtrip(b, key)?
  let (a, delayed) = counter_send(a, "current retry survives next refusal")?
  let (a, later) = counter_send(a, "cache at terminal generation")?
  let b = counter_receive(b, later, "cache at terminal generation")?
  counter_check(b.receive_generation == 4294967295
    && b.received_count == 4
    && Bytes.length(b.skipped_index) == 40)?
  let b = counter_roundtrip(b, key)?
  let (b, reply) = counter_send(b, "trigger actual opposite DH")?
  let a = counter_receive(a, reply, "trigger actual opposite DH")?
  let (a, next) = counter_send(a, "generation must not overflow")?
  let header = counter_header(b, next, "next-receiving")?
  counter_check(header.message_number == 0
    && !Bytes.secure_equals(header.ratchet_public_key.bytes, b.remote_ratchet_public.bytes))?
  let b = counter_refuse(b, next)?
  let b = counter_receive(b, delayed, "current retry survives next refusal")?
  let b = counter_roundtrip(b, key)?
  Ok(b.receive_generation == 4294967295
    && b.received_count == 4
    && Bytes.length(b.skipped_index) == 0)
end

pub fn counter_cached_and_reset_controls() -> Bool!C4CounterFixtureError do
  let key = StorageKey.ephemeral()?
  let (a, b) = counter_established()?
  let a = %{a | sent_count: 4294967292}
  let b = %{b | received_count: 4294967292}
  let (a, late_current) = counter_send(a, "cached current terminal counter")?
  let (a, late_old) = counter_send(a, "cached retained old header")?
  let (a, latest) = counter_send(a, "reach terminal receive count")?
  let b = counter_receive(b, latest, "reach terminal receive count")?
  counter_check(b.received_count == 4294967295 && Bytes.length(b.skipped_index) == 80)?
  let b = counter_roundtrip(b, key)?
  let generation = b.receive_generation
  let b = counter_receive(b, late_current, "cached current terminal counter")?
  counter_check(b.received_count == 4294967295
    && b.receive_generation == generation
    && Bytes.length(b.skipped_index) == 40)?
  let b = counter_roundtrip(b, key)?
  let old = a.local_ratchet_public.bytes
  let (b, reply) = counter_send(b, "reset terminal counters")?
  let a = counter_receive(a, reply, "reset terminal counters")?
  let (a, new_chain) = counter_send(a, "new chain retains delayed old header")?
  let b = counter_receive(b, new_chain, "new chain retains delayed old header")?
  counter_check(b.received_count == 1
    && b.receive_generation == generation + 1
    && SecretMap.contains(b.header_keys, he_join([Bytes.from_utf8("old/"), old])?))?
  let b = counter_roundtrip(b, key)?
  let b = counter_receive(b, late_old, "cached retained old header")?
  counter_check(b.received_count == 1
    && b.receive_generation == generation + 1
    && Bytes.length(b.skipped_index) == 0
    && !SecretMap.contains(b.header_keys, he_join([Bytes.from_utf8("old/"), old])?))?
  let b = counter_roundtrip(b, key)?
  Ok(b.received_count == 1)
end
