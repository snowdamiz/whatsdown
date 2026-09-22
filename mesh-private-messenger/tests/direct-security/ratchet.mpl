from Identity.Device import AccountKeys, DeviceKeys, IdentityError, VerificationPolicy, generate_account, generate_device, issue_device_credential
from Prekeys.Bundle import OneTimePrekeySecrets, PostQuantumPrekeySecrets, PrekeyError, SignedPrekeySecrets, build_prekey_bundle, generate_one_time_prekey, generate_post_quantum_prekey, generate_signed_prekey
from Protocol.V1 import AccountIdentity, DeviceCredential, InitialMessage, PrekeyBundle
from Protocol.HandshakeWire import encode_initial_message
from Session.Handshake import RatchetState, SessionError, initiate, receive_initial
from Session.Ratchet import DecryptOutcome, RatchetError, RatchetMessage, decode_ratchet_message, decrypt, encode_ratchet_message, encrypt, is_retryable_ratchet_error
from Session.Snapshot import ReplacementOutcome, SnapshotError, SnapshotOutcome, replace_session, restore, snapshot
from Session.SnapshotV1 import SnapshotOutcomeV1, snapshot_v1

type ProofError do
  CryptoProblem(error :: CryptoError)

  IdentityProblem(error :: IdentityError)

  PrekeyProblem(error :: PrekeyError)

  SessionProblem(error :: SessionError)

  RatchetProblem(error :: RatchetError)

  SnapshotProblem(error :: SnapshotError)

  InvalidFixture
end

fn wide(value :: String) -> U64 ! ProofError do
  case U64.parse(value) do
    Err(_) -> Err(InvalidFixture)
    Ok(parsed) -> Ok(parsed)
  end
end

fn account(created_at :: U64) -> Result <(AccountKeys, AccountIdentity), ProofError > do
  case generate_account(created_at, wide("1") ?) do
    Err(error) -> Err(IdentityProblem(error))
    Ok(value) -> Ok(value)
  end
end

fn device() -> DeviceKeys ! ProofError do
  case generate_device() do
    Err(error) -> Err(IdentityProblem(error))
    Ok(value) -> Ok(value)
  end
end

fn credential(account_keys :: borrow AccountKeys,
device_keys :: borrow DeviceKeys,
created_at :: U64,
expires_at :: U64) -> DeviceCredential ! ProofError do
  case issue_device_credential(account_keys,
  device_keys,
  wide("1") ?,
  created_at,
  expires_at,
  wide("1") ?) do
    Err(error) -> Err(IdentityProblem(error))
    Ok(value) -> Ok(value)
  end
end

fn signed_prekey(device_keys :: borrow DeviceKeys, value :: DeviceCredential, expires_at :: U64) -> SignedPrekeySecrets ! ProofError do
  case generate_signed_prekey(device_keys, value, wide("1") ?, expires_at) do
    Err(error) -> Err(PrekeyProblem(error))
    Ok(value) -> Ok(value)
  end
end

fn one_time_prekey() -> OneTimePrekeySecrets ! ProofError do
  case generate_one_time_prekey(wide("2") ?) do
    Err(error) -> Err(PrekeyProblem(error))
    Ok(value) -> Ok(value)
  end
end

fn post_quantum_prekey() -> PostQuantumPrekeySecrets ! ProofError do
  case generate_post_quantum_prekey() do
    Err(error) -> Err(PrekeyProblem(error))
    Ok(value) -> Ok(value)
  end
end

fn bundle(value :: DeviceCredential,
signed :: borrow SignedPrekeySecrets,
one_time :: borrow OneTimePrekeySecrets) -> PrekeyBundle ! ProofError do
  case build_prekey_bundle(value, signed, one_time) do
    Err(error) -> Err(PrekeyProblem(error))
    Ok(value) -> Ok(value)
  end
end

fn encoded_initial(value :: InitialMessage) -> Bytes ! ProofError do
  case encode_initial_message(value) do
    Err(_) -> Err(InvalidFixture)
    Ok(encoded) -> Ok(encoded)
  end
end

fn wire_message(value :: RatchetMessage) -> RatchetMessage ! ProofError do
  let encoded = case encode_ratchet_message(value) do
    Err(error) -> Err(RatchetProblem(error))
    Ok(bytes) -> Ok(bytes)
  end ?
  let trailing = case Bytes.concat(encoded, Bytes.from_utf8("x")) do
    Err(_) -> Err(InvalidFixture)
    Ok(bytes) -> Ok(bytes)
  end ?
  let truncated = case Bytes.slice(encoded, 0, Bytes.length(encoded) - 1) do
    Err(_) -> Err(InvalidFixture)
    Ok(bytes) -> Ok(bytes)
  end ?
  let _ = case decode_ratchet_message(trailing) do
    Err(InvalidMessage) -> Ok(nil)
    Err(error) -> Err(RatchetProblem(error))
    Ok(_) -> Err(InvalidFixture)
  end ?
  let _ = case decode_ratchet_message(truncated) do
    Err(InvalidMessage) -> Ok(nil)
    Err(error) -> Err(RatchetProblem(error))
    Ok(_) -> Err(InvalidFixture)
  end ?
  case decode_ratchet_message(encoded) do
    Err(error) -> Err(RatchetProblem(error))
    Ok(decoded) -> Ok(decoded)
  end
end

fn opened(state :: consume RatchetState, value :: Bytes, expected :: Bytes) -> RatchetState do
  if Bytes.secure_equals(value, expected) do
    println("ratchet:ok")
  else
    println("ratchet:wrong-plaintext")
  end
  state
end

fn rejected(state :: consume RatchetState, error :: RatchetError) -> RatchetState do
  println("ratchet:rejected")
  state
end

fn accept_message(state :: consume RatchetState,
message :: RatchetMessage,
associated_data :: Bytes,
expected :: Bytes) -> RatchetState do
  case decrypt(state, message, associated_data) do
    Opened(next, value) -> opened(next, value, expected)
    Rejected(next, error) -> rejected(next, error)
  end
end

fn expect_replay(state :: consume RatchetState, message :: RatchetMessage, associated_data :: Bytes) -> RatchetState do
  case decrypt(state, message, associated_data) do
    Opened(next, _) -> do
      println("replay:opened")
      next
    end
    Rejected(next, Replay) -> do
      println("replay:ok")
      next
    end
    Rejected(next, _) -> do
      println("replay:wrong-error")
      next
    end
  end
end

fn expect_jump_rejection(state :: consume RatchetState,
message :: RatchetMessage,
associated_data :: Bytes) -> RatchetState do
  case decrypt(state, message, associated_data) do
    Opened(next, _) -> do
      println("jump:opened")
      next
    end
    Rejected(next, ExcessiveJump) -> do
      println("jump:ok")
      next
    end
    Rejected(next, _) -> do
      println("jump:wrong-error")
      next
    end
  end
end

fn expect_authentication_rejection(state :: consume RatchetState,
message :: RatchetMessage,
associated_data :: Bytes) -> RatchetState do
  case decrypt(state, message, associated_data) do
    Opened(next, _) -> do
      println("authentication:opened")
      next
    end
    Rejected(next, AuthenticationRejected) -> do
      println("authentication:ok")
      next
    end
    Rejected(next, _) -> do
      println("authentication:wrong-error")
      next
    end
  end
end

# A key kept for a message that never came must not be kept for ever: whoever
# held the message back could open it after taking the device much later. The
# refusal has to be final, or the envelope would wait in the mailbox instead.

fn expect_aged(state :: consume RatchetState, message :: RatchetMessage, associated_data :: Bytes) -> RatchetState do
  case decrypt(state, message, associated_data) do
    Opened(next, _) -> do
      println("aged:opened")
      next
    end
    Rejected(next, error) -> do
      if is_retryable_ratchet_error(error) do
        println("aged:retryable")
      else
        println("aged:ok")
      end
      next
    end
  end
end

fn quiet_accept(state :: consume RatchetState, message :: RatchetMessage, associated_data :: Bytes) -> RatchetState do
  case decrypt(state, message, associated_data) do
    Opened(next, _) -> next
    Rejected(next, _) -> do
      println("round-trip:rejected")
      next
    end
  end
end

fn sent(state :: consume RatchetState, text :: String, associated_data :: Bytes) -> Result <(RatchetState, RatchetMessage), ProofError > do
  case encrypt(state, Bytes.from_utf8(text), associated_data) do
    Err(error) -> Err(RatchetProblem(error))
    Ok(value) -> Ok(value)
  end
end

# Sends `count` messages and hands back only the last: the rest are lost.

fn burn(state :: consume RatchetState, count :: Int, associated_data :: Bytes) -> Result <(RatchetState, RatchetMessage), ProofError > do
  let (next, message) = sent(state, "lost", associated_data) ?
  if count <= 1 do
    Ok((next, message))
  else
    burn(next, count - 1, associated_data)
  end
end

# Each turn gives both sides a new receiving chain, except that the first gives
# the replier's peer one only if the replier had a chain to answer.

fn round_trips(alice :: consume RatchetState,
bob :: consume RatchetState,
count :: Int,
associated_data :: Bytes) -> Result <(RatchetState, RatchetState), ProofError > do
  if count <= 0 do
    Ok((alice, bob))
  else
    let (bob, reply) = sent(bob, "reply", associated_data) ?
    let alice = quiet_accept(alice, reply, associated_data)
    let (alice, next) = sent(alice, "next", associated_data) ?
    let bob = quiet_accept(bob, next, associated_data)
    round_trips(alice, bob, count - 1, associated_data)
  end
end

fn storage_key() -> StorageKey ! ProofError do
  case StorageKey.ephemeral() do
    Err(error) -> Err(CryptoProblem(error))
    Ok(value) -> Ok(value)
  end
end

fn sealed(state :: consume RatchetState,
wrapping_key :: borrow StorageKey,
account_id :: Bytes,
device_id :: Bytes,
version :: U64) -> Result <(RatchetState, Bytes), ProofError > do
  case snapshot(state, wrapping_key, account_id, device_id, version) do
    SnapshotSealed(next, blob) -> Ok((next, blob))
    SnapshotRejected(rejected, _) -> do
      println("snapshot:seal-rejected")
      Ok((rejected, Bytes.empty()))
    end
  end
end

fn restored(blob :: Bytes,
wrapping_key :: borrow StorageKey,
account_id :: Bytes,
device_id :: Bytes,
minimum_version :: U64) -> RatchetState ! ProofError do
  case restore(blob, wrapping_key, account_id, device_id, minimum_version) do
    Err(error) -> Err(SnapshotProblem(error))
    Ok(state) -> do
      println("snapshot:restored")
      Ok(state)
    end
  end
end

fn replaced(current :: consume RatchetState,
blob :: Bytes,
wrapping_key :: borrow StorageKey,
account_id :: Bytes,
device_id :: Bytes) -> RatchetState ! ProofError do
  case replace_session(current, blob, wrapping_key, account_id, device_id) do
    ReplacementRejected(rejected, _) -> do
      println("snapshot:replace-rejected")
      Ok(rejected)
    end
    SessionReplaced(state) -> do
      println("snapshot:replaced")
      Ok(state)
    end
  end
end

fn rejects_rollback(current :: consume RatchetState,
blob :: Bytes,
wrapping_key :: borrow StorageKey,
account_id :: Bytes,
device_id :: Bytes) -> RatchetState do
  case replace_session(current, blob, wrapping_key, account_id, device_id) do
    SessionReplaced(state) -> do
      println("snapshot:rollback-replaced")
      state
    end
    ReplacementRejected(state, RollbackRejected) -> do
      println("snapshot:rollback-ok")
      state
    end
    ReplacementRejected(state, _) -> do
      println("snapshot:rollback-wrong-error")
      state
    end
  end
end

# Skipped keys age out. Bob misses one message, and the record of it has to
# survive being stored. Five receiving chains later its key is gone, while a
# key skipped one chain after it still opens its message.

fn skipped_keys_age_out(alice_session :: consume RatchetState,
bob_session :: consume RatchetState,
wrapping_key :: borrow StorageKey,
account_id :: Bytes,
device_id :: Bytes,
associated_data :: Bytes) -> Result <(RatchetState, RatchetState), ProofError > do
  let (alice_session, lost_early) = sent(alice_session, "early", associated_data) ?
  let (alice_session, kept) = sent(alice_session, "kept", associated_data) ?
  let bob_session = accept_message(bob_session, kept, associated_data, Bytes.from_utf8("kept"))
  let (_stored_session, blob) = sealed(bob_session,
  wrapping_key,
  account_id,
  device_id,
  wide("3") ?) ?
  let bob_session = restored(blob, wrapping_key, account_id, device_id, wide("3") ?) ?
  let (bob_session, reply) = sent(bob_session, "reply", associated_data) ?
  let alice_session = quiet_accept(alice_session, reply, associated_data)
  let (alice_session, late) = sent(alice_session, "late", associated_data) ?
  let (alice_session, next) = sent(alice_session, "next", associated_data) ?
  let bob_session = quiet_accept(bob_session, next, associated_data)
  let (alice_session, bob_session) = round_trips(alice_session, bob_session, 4, associated_data) ?
  let bob_session = expect_aged(bob_session, lost_early, associated_data)
  let bob_session = accept_message(bob_session, late, associated_data, Bytes.from_utf8("late"))
  Ok((alice_session, bob_session))
end

# More skipped keys than a session keeps push out the oldest instead of
# stopping the session, and what is left still ages out afterwards.

fn oldest_keys_are_pushed_out(alice_session :: consume RatchetState,
bob_session :: consume RatchetState,
associated_data :: Bytes) -> Result <(RatchetState, RatchetState), ProofError > do
  let lost = Bytes.from_utf8("lost")
  let (bob_session, pushed_out) = sent(bob_session, "lost", associated_data) ?
  let (bob_session, _) = burn(bob_session, 52, associated_data) ?
  let (bob_session, oldest_kept) = sent(bob_session, "lost", associated_data) ?
  let (bob_session, _) = burn(bob_session, 4, associated_data) ?
  let (bob_session, used) = sent(bob_session, "lost", associated_data) ?
  let (bob_session, sixtieth) = sent(bob_session, "lost", associated_data) ?
  let alice_session = accept_message(alice_session, sixtieth, associated_data, lost)
  # A key that is used leaves the list too, or the list would run ahead of the
  # map and lose track of the oldest key still kept.
  let alice_session = accept_message(alice_session, used, associated_data, lost)
  let (bob_session, survivor) = burn(bob_session, 58, associated_data) ?
  let (bob_session, newest) = sent(bob_session, "lost", associated_data) ?
  let (bob_session, last) = sent(bob_session, "lost", associated_data) ?
  let alice_session = accept_message(alice_session, last, associated_data, lost)
  let alice_session = expect_replay(alice_session, pushed_out, associated_data)
  let alice_session = accept_message(alice_session, newest, associated_data, lost)
  let (alice_session, bob_session) = round_trips(alice_session, bob_session, 6, associated_data) ?
  let alice_session = expect_aged(alice_session, oldest_kept, associated_data)
  let alice_session = expect_aged(alice_session, survivor, associated_data)
  Ok((alice_session, bob_session))
end

# Forty messages lost at the end of one chain and forty at the start of the
# next are each within the limit, but more than a session keeps together. That
# is a jump, which is final, not a fault to try again.

fn combined_jump_is_final(alice_session :: consume RatchetState,
bob_session :: consume RatchetState,
associated_data :: Bytes) -> Result <(RatchetState, RatchetState), ProofError > do
  let (alice_session, _) = burn(alice_session, 40, associated_data) ?
  let (bob_session, reply) = sent(bob_session, "reply", associated_data) ?
  let alice_session = quiet_accept(alice_session, reply, associated_data)
  let (alice_session, beyond) = burn(alice_session, 41, associated_data) ?
  let bob_session = expect_jump_rejection(bob_session, beyond, associated_data)
  Ok((alice_session, bob_session))
end

# A snapshot written before version 2 is still read. It cannot say which
# skipped keys it holds, so those are left behind, and the session carries on.

fn sealed_v1(state :: consume RatchetState,
wrapping_key :: borrow StorageKey,
account_id :: Bytes,
device_id :: Bytes,
version :: U64) -> Result <(RatchetState, Bytes), ProofError > do
  case snapshot_v1(state, wrapping_key, account_id, device_id, version) do
    SnapshotSealedV1(next, blob) -> Ok((next, blob))
    SnapshotRejectedV1(rejected, _) -> do
      println("snapshot:seal-rejected")
      Ok((rejected, Bytes.empty()))
    end
  end
end

fn sealed_format(blob :: Bytes) -> Int do
  case Bytes.get(blob, 0) do
    Err(_) -> 0
    Ok(value) -> value
  end
end

fn version_one_snapshot_is_read(alice_session :: consume RatchetState,
bob_session :: consume RatchetState,
wrapping_key :: borrow StorageKey,
account_id :: Bytes,
device_id :: Bytes,
associated_data :: Bytes) -> Int ! ProofError do
  let (bob_session, skipped) = sent(bob_session, "skipped", associated_data) ?
  let (bob_session, earlier) = sent(bob_session, "earlier", associated_data) ?
  let alice_session = accept_message(alice_session,
  earlier,
  associated_data,
  Bytes.from_utf8("earlier"))
  let (_stored_session, blob) = sealed_v1(alice_session,
  wrapping_key,
  account_id,
  device_id,
  wide("1") ?) ?
  println("migration:format-" <> Int.to_string(sealed_format(blob)))
  let alice_session = restored(blob, wrapping_key, account_id, device_id, wide("1") ?) ?
  let alice_session = expect_replay(alice_session, skipped, associated_data)
  let (_bob_session, later) = sent(bob_session, "later", associated_data) ?
  let _alice_session = accept_message(alice_session,
  later,
  associated_data,
  Bytes.from_utf8("later"))
  Ok(0)
end

fn proof() -> Int ! ProofError do
  let created_at = wide("1700000000000") ?
  let expires_at = wide("1700604800000") ?
  let policy = VerificationPolicy {
    current_time : created_at,
    minimum_directory_sequence : wide("1") ?
  }
  let (alice_account_keys, alice_account) = account(created_at) ?
  let (bob_account_keys, bob_account) = account(created_at) ?
  let alice = device() ?
  let bob = device() ?
  let post_quantum = post_quantum_prekey() ?
  let alice_credential = credential(alice_account_keys, alice, created_at, expires_at) ?
  let bob_credential = credential(bob_account_keys, bob, created_at, expires_at) ?
  let signed = signed_prekey(bob, bob_credential, expires_at) ?
  let one_time = one_time_prekey() ?
  let published = bundle(bob_credential, signed, one_time) ?
  let (alice_session, initial) = case initiate(alice,
  alice_credential,
  bob_account,
  published,
  policy,
  1,
  Bytes.from_utf8("offline hello")) do
    Err(error) -> Err(SessionProblem(error))
    Ok(value) -> Ok(value)
  end ?
  let (bob_session, _) = case receive_initial(bob,
  bob_account,
  published,
  signed,
  one_time,
  post_quantum,
  alice_account,
  policy,
  policy,
  1,
  encoded_initial(initial) ?) do
    Err(error) -> Err(SessionProblem(error))
    Ok(value) -> Ok(value)
  end ?
  let first = Bytes.from_utf8("ratcheted one")
  let second = Bytes.from_utf8("ratcheted two")
  let third = Bytes.from_utf8("ratcheted three")
  let fourth = Bytes.from_utf8("ratcheted four")
  let associated_data = Bytes.from_utf8("conversation-1")
  let (alice_session, first_message) = case encrypt(alice_session, first, associated_data) do
    Err(error) -> Err(RatchetProblem(error))
    Ok(value) -> Ok(value)
  end ?
  let (alice_session, second_message) = case encrypt(alice_session, second, associated_data) do
    Err(error) -> Err(RatchetProblem(error))
    Ok(value) -> Ok(value)
  end ?
  let (alice_session, third_message) = case encrypt(alice_session, third, associated_data) do
    Err(error) -> Err(RatchetProblem(error))
    Ok(value) -> Ok(value)
  end ?
  let (alice_session, fourth_message) = case encrypt(alice_session, fourth, associated_data) do
    Err(error) -> Err(RatchetProblem(error))
    Ok(value) -> Ok(value)
  end ?
  let first_message = wire_message(first_message) ?
  let second_message = wire_message(second_message) ?
  let third_message = wire_message(third_message) ?
  let fourth_message = wire_message(fourth_message) ?
  let bob_session = accept_message(bob_session, third_message, associated_data, third)
  let wrapping_key = storage_key() ?
  let (persisted_session, blob_v1) = sealed(bob_session,
  wrapping_key,
  bob_account.account_id,
  bob_credential.device_id,
  wide("1") ?) ?
  let bob_session = restored(blob_v1,
  wrapping_key,
  bob_account.account_id,
  bob_credential.device_id,
  wide("1") ?) ?
  let bob_session = accept_message(bob_session, first_message, associated_data, first)
  let bob_session = accept_message(bob_session, second_message, associated_data, second)
  let (replacement_source, blob_v2) = sealed(bob_session,
  wrapping_key,
  bob_account.account_id,
  bob_credential.device_id,
  wide("2") ?) ?
  let bob_session = replaced(persisted_session,
  blob_v2,
  wrapping_key,
  bob_account.account_id,
  bob_credential.device_id) ?
  let bob_session = rejects_rollback(bob_session,
  blob_v1,
  wrapping_key,
  bob_account.account_id,
  bob_credential.device_id)
  let bob_session = expect_replay(bob_session, first_message, associated_data)
  let excessive = % {fourth_message | message_number : 100 }
  let bob_session = expect_jump_rejection(bob_session, excessive, associated_data)
  let bob_session = expect_authentication_rejection(bob_session,
  fourth_message,
  Bytes.from_utf8("wrong-conversation"))
  let bob_session = accept_message(bob_session, fourth_message, associated_data, fourth)
  let response = Bytes.from_utf8("ratcheted response")
  let (bob_session, response_message) = case encrypt(bob_session, response, associated_data) do
    Err(error) -> Err(RatchetProblem(error))
    Ok(value) -> Ok(value)
  end ?
  let alice_session = accept_message(alice_session, response_message, associated_data, response)
  let (alice_session, bob_session) = skipped_keys_age_out(alice_session,
  bob_session,
  wrapping_key,
  bob_account.account_id,
  bob_credential.device_id,
  associated_data) ?
  let (alice_session, bob_session) = oldest_keys_are_pushed_out(alice_session,
  bob_session,
  associated_data) ?
  let (alice_session, bob_session) = combined_jump_is_final(alice_session,
  bob_session,
  associated_data) ?
  version_one_snapshot_is_read(alice_session,
  bob_session,
  wrapping_key,
  alice_account.account_id,
  alice_credential.device_id,
  associated_data)
end

fn main() do
  case proof() do
    Err(_) -> println("proof:error")
    Ok(_) -> nil
  end
end
