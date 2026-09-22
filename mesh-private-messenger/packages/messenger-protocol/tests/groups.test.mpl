from Groups.GroupSnapshot import group_snapshot, restore_group
from Groups.Mls import GroupSnapshotOutcome
from Groups.GroupCodec import delivery_targets, negotiate_group_extensions
from Groups.GroupMessages import decrypt_group_message, encrypt_group_message
from Groups.Membership import apply_commit, commit_add, commit_remove, commit_update, create_group, join_from_welcome
from Groups.KeySchedule import group_open_update_path, group_derive_verified_patch, group_prepare_patch
from Groups.CommitWire import group_update_path_context, encode_group_commit
from Groups.SenderKeys import sender_message_key
from Groups.Mls import (
  CommitApplyOutcome,
  GroupAddOutcome,
  GroupDecryptOutcome,
  GroupEncryptOutcome,
  GroupError,
  GroupRemoveOutcome,
  GroupState,
  GroupTransparencyPolicy
)
from Groups.Tree import GroupMember, member_count
from Groups.GroupCodec import group_byte, group_join, group_write_u16, group_write_u32, group_write_u64

# Independent attacker derivation of the original retained-root schedule.

fn retained_root_opens(state :: borrow GroupState, message :: GroupMessage, aad :: Bytes) -> Bool ! GroupError do
  let info = group_join([Bytes.from_utf8("mesh-mls/v1/message-key"), group_write_u16(message.sender_leaf) ?, group_write_u32(message.generation) ?],
  0,
  Bytes.empty()) ?
  let material = case Crypto.hkdf_sha256(state.key_material.epoch_secret,
  message.group_id,
  info,
  32) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value) -> Ok(value)
  end ?
  captured_message_opens(material, message, aad)
end

fn current_chain_opens(state :: borrow GroupState, message :: GroupMessage, aad :: Bytes) -> Bool ! GroupError do
  let key = sender_message_key(state.key_material.sender_chains,
  message.group_id,
  message.sender_leaf,
  message.generation) ?
  captured_message_opens(key, message, aad)
end

fn captured_message_opens(material :: SecretBytes, message :: GroupMessage, aad :: Bytes) -> Bool ! GroupError do
  let key = case Crypto.aead_key(material) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value) -> Ok(value)
  end ?
  let context = group_join([Bytes.from_utf8("mesh-mls/v1/group-message"), group_byte(message.version) ?, group_write_u16(message.suite) ?, message.group_id, group_write_u64(message.epoch) ?, message.tree_hash, group_write_u16(message.sender_leaf) ?, group_write_u32(message.generation) ?, message.nonce, aad],
  0,
  Bytes.empty()) ?
  case Crypto.aead_open(key, message.nonce, context, message.ciphertext) do
    Err(_) -> Ok(false)
    Ok(_) -> Ok(true)
  end
end

fn repeated(value :: Int, length :: Int) -> Bytes do
  case Bytes.repeat(value, length) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

fn wide(value :: Int) -> U64 ! GroupError do
  case U64.parse(Int.to_string(value)) do
    Err(_) -> Err(InvalidGroup)
    Ok(output) -> Ok(output)
  end
end

fn signing_pair() -> SigningKeyPair ! GroupError do
  case Crypto.signing_generate() do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value) -> Ok(value)
  end
end

fn init_pair() -> X25519KeyPair ! GroupError do
  case Crypto.x25519_generate() do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value) -> Ok(value)
  end
end

fn member(account :: Int,
device :: Int,
signing :: SigningPublicKey,
init :: X25519PublicKey,
leaf :: X25519PublicKey,
checkpoint :: Bytes) -> GroupMember ! GroupError do
  Ok(GroupMember {
    version : 1,
    account_id : repeated(account, 32),
    device_id : repeated(device, 16),
    signing_public_key : signing,
    init_public_key : init,
    leaf_public_key : leaf,
    mailbox_token : repeated(device + 40, 32),
    directory_sequence : wide(5) ?,
    transparency_checkpoint_hash : checkpoint,
    witness_count : 2,
    extensions : [1]
  })
end

fn consume_state(value :: consume GroupState) do
  nil
end

fn group_error_name(value :: GroupError) -> String do
  case value do
    AuthenticationRejected -> "AuthenticationRejected"
    CryptoFailure(_) -> "CryptoFailure"
    FutureEpoch -> "FutureEpoch"
    InvalidGroup -> "InvalidGroup"
    InvalidMember -> "InvalidMember"
    InvalidPolicy -> "InvalidPolicy"
    Replay -> "Replay"
    RemovedMember -> "RemovedMember"
    RollbackRejected -> "RollbackRejected"
    StaleEpoch -> "StaleEpoch"
    TreeFailure(_) -> "TreeFailure"
  end
end

fn added(outcome :: GroupAddOutcome) -> Result <(GroupState, GroupCommit, GroupWelcome), GroupError > do
  case outcome do
    GroupMemberAdded(state, commit, welcome) -> Ok((state, commit, welcome))
    GroupAddRejected(state, error) -> do
      consume_state(state)
      Err(error)
    end
  end
end

fn rejected_add(outcome :: GroupAddOutcome) -> GroupState ! GroupError do
  case outcome do
    GroupMemberAdded(state, _, _) -> do
      consume_state(state)
      Err(AuthenticationRejected)
    end
    GroupAddRejected(state, _) -> Ok(state)
  end
end

fn removed(outcome :: GroupRemoveOutcome) -> Result <(GroupState, GroupCommit), GroupError > do
  case outcome do
    GroupMemberRemoved(state, commit) -> Ok((state, commit))
    GroupRemoveRejected(state, error) -> do
      consume_state(state)
      Err(error)
    end
  end
end

fn rejected_remove(outcome :: GroupRemoveOutcome) -> GroupState ! GroupError do
  case outcome do
    GroupMemberRemoved(state, _) -> do
      consume_state(state)
      Err(AuthenticationRejected)
    end
    GroupRemoveRejected(state, _) -> Ok(state)
  end
end

fn encrypted(outcome :: GroupEncryptOutcome) -> Result <(GroupState, GroupMessage), GroupError > do
  case outcome do
    GroupMessageEncrypted(state, message) -> Ok((state, message))
    GroupEncryptRejected(state, error) -> do
      consume_state(state)
      Err(error)
    end
  end
end

fn rejected_encryption(outcome :: GroupEncryptOutcome) -> GroupState ! GroupError do
  case outcome do
    GroupMessageEncrypted(state, _) -> do
      consume_state(state)
      Err(AuthenticationRejected)
    end
    GroupEncryptRejected(state, _) -> Ok(state)
  end
end

fn opened(outcome :: GroupDecryptOutcome, expected :: Bytes) -> GroupState ! GroupError do
  case outcome do
    MessageOpened(state, plaintext) -> if Bytes.secure_equals(plaintext, expected) do
      Ok(state)
    else
      consume_state(state)
      Err(AuthenticationRejected)
    end
    MessageRejected(state, error) -> do
      consume_state(state)
      Err(error)
    end
  end
end

fn applied(outcome :: CommitApplyOutcome) -> GroupState ! GroupError do
  case outcome do
    CommitApplied(state) -> Ok(state)
    CommitRejected(state, error) -> do
      consume_state(state)
      Err(error)
    end
  end
end

fn rejected_commit(outcome :: CommitApplyOutcome, expected :: GroupError) -> GroupState ! GroupError do
  case outcome do
    CommitApplied(state) -> do
      consume_state(state)
      Err(AuthenticationRejected)
    end
    CommitRejected(state, error) -> case (error, expected) do
      (FutureEpoch, FutureEpoch) -> Ok(state)
      (AuthenticationRejected, AuthenticationRejected) -> Ok(state)
      (RemovedMember, RemovedMember) -> Ok(state)
      (StaleEpoch, StaleEpoch) -> Ok(state)
      _ -> do
        consume_state(state)
        Err(AuthenticationRejected)
      end
    end
  end
end

fn rejected_message(outcome :: GroupDecryptOutcome) -> GroupState ! GroupError do
  case outcome do
    MessageOpened(state, _) -> do
      consume_state(state)
      Err(AuthenticationRejected)
    end
    MessageRejected(state, _) -> Ok(state)
  end
end

fn proof() -> Bool ! GroupError do
  let checkpoint = repeated(90, 32)
  let policy = GroupTransparencyPolicy {
    minimum_directory_sequence : wide(4) ?,
    checkpoint_hash : checkpoint,
    witness_threshold : 2
  }
  let alice_signing = signing_pair() ?
  let alice_init = init_pair() ?
  let alice_leaf = init_pair() ?
  let bob_signing = signing_pair() ?
  let bob_init = init_pair() ?
  let bob_leaf = init_pair() ?
  let alice_second_signing = signing_pair() ?
  let alice_second_init = init_pair() ?
  let alice_second_leaf = init_pair() ?
  let alice = member(1,
  1,
  alice_signing.public_key,
  alice_init.public_key,
  alice_leaf.public_key,
  checkpoint) ?
  let bob = member(2,
  2,
  bob_signing.public_key,
  bob_init.public_key,
  bob_leaf.public_key,
  checkpoint) ?
  let alice_second = member(1,
  3,
  alice_second_signing.public_key,
  alice_second_init.public_key,
  alice_second_leaf.public_key,
  checkpoint) ?
  let alice_state = create_group(alice, alice_leaf.private_key, [1], policy) ?
  let invalid_bob = % {bob | witness_count : 0 }
  let alice_state = rejected_add(commit_add(alice_state, alice_signing.private_key, invalid_bob)) ?
  let (alice_state, bob_commit, bob_welcome) = added(commit_add(alice_state,
  alice_signing.private_key,
  bob)) ?
  assert(List.length(bob_commit.update_path.nodes) == 6)
  assert(List.length(List.get(bob_commit.update_path.nodes, 0).parent.unmerged_leaves) == 0)
  let bob_state = join_from_welcome(bob_welcome, bob_init.private_key, bob_leaf.private_key) ?
  assert(member_count(alice_state.tree) == 2)
  assert(member_count(bob_state.tree) == 2)
  let (alice_state, second_commit, second_welcome) = added(commit_add(alice_state,
  alice_signing.private_key,
  alice_second)) ?
  let bob_state = applied(apply_commit(bob_state, second_commit)) ?
  # The retained receiving leaf still opens captured TreeKEM traffic. Current
  # init material must not reconstruct the epoch seed that fed erased chains.
  let captured_context = group_update_path_context(second_commit.version,
  second_commit.suite,
  second_commit.group_id,
  second_commit.prior_epoch,
  second_commit.epoch,
  second_commit.committer_leaf,
  second_commit.prior_transcript_hash,
  second_commit.tree_hash,
  second_commit.proposal,
  second_commit.update_path) ?
  let captured_path = group_open_update_path(second_commit.update_path.nodes,
  0,
  bob_state.key_material,
  bob_state.local_leaf,
  captured_context) ?
  let captured_level = captured_path.level
  let captured_patch = group_derive_verified_patch(captured_path.secret,
  captured_level,
  second_commit.update_path.nodes,
  captured_context) ?
  case group_prepare_patch(captured_patch,
  bob_state.key_material.epoch_secret,
  bob_state.group_id,
  bob_state.tree,
  captured_context,
  second_commit.confirmation) do
    Err(AuthenticationRejected) -> assert(true)
    Err(_) -> assert(false)
    Ok(value) -> do
      discard_attack(value)
      assert(false)
    end
  end
  let alice_second_state = join_from_welcome(second_welcome,
  alice_second_init.private_key,
  alice_second_leaf.private_key) ?
  assert(member_count(alice_state.tree) == 3)
  assert(member_count(bob_state.tree) == 3)
  assert(member_count(alice_second_state.tree) == 3)
  let targets = delivery_targets(alice_state.tree, alice_state.local_leaf) ?
  assert(List.length(targets) == 2)
  let negotiated = negotiate_group_extensions(alice_state.tree, [1, 2]) ?
  assert(List.length(negotiated) == 1)
  assert(List.head(negotiated) == 1)
  assert(U64.compare(bob_commit.epoch, wide(1) ?) == 0)
  let plaintext = Bytes.from_utf8("hello devices")
  let caller_data = Bytes.from_utf8("conversation")
  let alice_state = rejected_encryption(encrypt_group_message(alice_state,
  alice_signing.private_key,
  repeated(7, 65521),
  caller_data)) ?
  let (alice_state, message) = encrypted(encrypt_group_message(alice_state,
  alice_signing.private_key,
  plaintext,
  caller_data)) ?
  let bob_state = opened(decrypt_group_message(bob_state, message, caller_data), plaintext) ?
  assert(!retained_root_opens(bob_state, message, caller_data) ?)
  assert(!current_chain_opens(bob_state, message, caller_data) ?)
  let (alice_state, earlier) = encrypted(encrypt_group_message(alice_state,
  alice_signing.private_key,
  plaintext,
  caller_data)) ?
  let (alice_state, later) = encrypted(encrypt_group_message(alice_state,
  alice_signing.private_key,
  plaintext,
  caller_data)) ?
  let bob_state = opened(decrypt_group_message(bob_state, later, caller_data), plaintext) ?
  let bob_state = opened(decrypt_group_message(bob_state, earlier, caller_data), plaintext) ?
  let bob_state = rejected_message(decrypt_group_message(bob_state, earlier, caller_data)) ?
  let (bob_state, reply) = encrypted(encrypt_group_message(bob_state,
  bob_signing.private_key,
  plaintext,
  caller_data)) ?
  let alice_state = opened(decrypt_group_message(alice_state, reply, caller_data), plaintext) ?
  let alice_second_state = opened(decrypt_group_message(alice_second_state, message, caller_data),
  plaintext) ?
  # Recovery of Alice's temporary encryption-state compromise requires Alice's
  # own fresh leaf update; an attacker retaining another member needs its update too.
  let (alice_state, refresh) = removed(commit_update(alice_state, alice_signing.private_key)) ?
  case encode_group_commit(% {refresh | version : 1, confirmation : Bytes.empty() }) do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
  let bob_state = applied(apply_commit(bob_state, refresh)) ?
  let (alice_state, recovered) = encrypted(encrypt_group_message(alice_state,
  alice_signing.private_key,
  plaintext,
  caller_data)) ?
  let bob_state = opened(decrypt_group_message(bob_state, recovered, caller_data), plaintext) ?
  let alice_second_state = rejected_message(decrypt_group_message(alice_second_state,
  recovered,
  caller_data)) ?
  consume_state(alice_state)
  consume_state(bob_state)
  consume_state(alice_second_state)
  Ok(true)
end

fn discard_attack(value :: consume(TreeKemPathPatch, GroupEpochKeys)) do
  nil
end

test("MLS group add, welcome, message, and multi-device membership") do
  case proof() do
    Err(error) -> do
      println(group_error_name(error))
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn removal_proof() -> Bool ! GroupError do
  let checkpoint = repeated(91, 32)
  let policy = GroupTransparencyPolicy {
    minimum_directory_sequence : wide(4) ?,
    checkpoint_hash : checkpoint,
    witness_threshold : 2
  }
  let alice_signing = signing_pair() ?
  let alice_init = init_pair() ?
  let alice_leaf = init_pair() ?
  let bob_signing = signing_pair() ?
  let bob_init = init_pair() ?
  let bob_leaf = init_pair() ?
  let carol_signing = signing_pair() ?
  let carol_init = init_pair() ?
  let carol_leaf = init_pair() ?
  let alice = member(11,
  11,
  alice_signing.public_key,
  alice_init.public_key,
  alice_leaf.public_key,
  checkpoint) ?
  let bob = member(12,
  12,
  bob_signing.public_key,
  bob_init.public_key,
  bob_leaf.public_key,
  checkpoint) ?
  let carol = member(13,
  13,
  carol_signing.public_key,
  carol_init.public_key,
  carol_leaf.public_key,
  checkpoint) ?
  let alice_state = create_group(alice, alice_leaf.private_key, [1], policy) ?
  let (alice_state, _, bob_welcome) = added(commit_add(alice_state, alice_signing.private_key, bob)) ?
  let bob_state = join_from_welcome(bob_welcome, bob_init.private_key, bob_leaf.private_key) ?
  let (alice_state, carol_commit, carol_welcome) = added(commit_add(alice_state,
  alice_signing.private_key,
  carol)) ?
  let carol_state = join_from_welcome(carol_welcome, carol_init.private_key, carol_leaf.private_key) ?
  let alice_state = rejected_remove(commit_remove(alice_state, bob_signing.private_key, 1)) ?
  let (alice_state, removal_commit) = removed(commit_remove(alice_state,
  alice_signing.private_key,
  1)) ?
  let bob_state = rejected_commit(apply_commit(bob_state, removal_commit), FutureEpoch) ?
  let tampered_carol_commit = % {carol_commit | signature : Signature { bytes : repeated(0, 64) } }
  let bob_state = rejected_commit(apply_commit(bob_state, tampered_carol_commit),
  AuthenticationRejected) ?
  let bob_state = applied(apply_commit(bob_state, carol_commit)) ?
  let bob_state = rejected_commit(apply_commit(bob_state, removal_commit), RemovedMember) ?
  let carol_state = applied(apply_commit(carol_state, removal_commit)) ?
  let carol_state = rejected_commit(apply_commit(carol_state, carol_commit), StaleEpoch) ?
  let plaintext = Bytes.from_utf8("after removal")
  let caller_data = Bytes.from_utf8("group removal")
  let (alice_state, message) = encrypted(encrypt_group_message(alice_state,
  alice_signing.private_key,
  plaintext,
  caller_data)) ?
  let carol_state = opened(decrypt_group_message(carol_state, message, caller_data), plaintext) ?
  let bob_state = rejected_message(decrypt_group_message(bob_state, message, caller_data)) ?
  assert(member_count(alice_state.tree) == 2)
  assert(member_count(carol_state.tree) == 2)
  consume_state(alice_state)
  consume_state(bob_state)
  consume_state(carol_state)
  Ok(true)
end

test("MLS removal rejects reordered epochs and excludes the removed device") do
  case removal_proof() do
    Err(error) -> do
      println(group_error_name(error))
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

struct PendingGroupMessage do
  message :: GroupMessage
  body :: Bytes
  from_alice :: Bool
end

fn restart_group(state :: consume GroupState,
key :: borrow StorageKey,
account :: Int,
device :: Int) -> GroupState ! GroupError do
  let version = case U64.add(state.snapshot_version, wide(1) ?) do
    Err(_) -> Err(InvalidGroup)
    Ok(value) -> Ok(value)
  end ?
  case group_snapshot(state, key, repeated(account, 32), repeated(device, 16), version) do
    GroupSnapshotRejected(rejected, error) -> do
      consume_state(rejected)
      Err(error)
    end
    GroupSnapshotSealed(saved, blob) -> do
      consume_state(saved)
      restore_group(blob, key, repeated(account, 32), repeated(device, 16), version)
    end
  end
end

fn seeded_group_step(alice :: consume GroupState,
bob :: consume GroupState,
alice_key :: borrow SigningPrivateKey,
bob_key :: borrow SigningPrivateKey,
storage :: borrow StorageKey,
pending :: List < PendingGroupMessage >,
step :: Int,
random :: Int) -> Result <(GroupState, GroupState, List < PendingGroupMessage >), GroupError > do
  let aad = Bytes.from_utf8("seeded-group-campaign/v1")
  if step % 16 < 8 do
    let from_alice = step % 2 == 0
    let body = Bytes.from_utf8("campaign step #{step}")
    if from_alice do
      let (next, message) = encrypted(encrypt_group_message(alice, alice_key, body, aad)) ?
      if current_chain_opens(next, message, aad) ? do
        return Err(AuthenticationRejected)
      end
      Ok((next,
      bob,
      List.append(pending,
      PendingGroupMessage {
        message : message,
        body : body,
        from_alice : true
      })))
    else
      let (next, message) = encrypted(encrypt_group_message(bob, bob_key, body, aad)) ?
      if current_chain_opens(next, message, aad) ? do
        return Err(AuthenticationRejected)
      end
      Ok((alice,
      next,
      List.append(pending,
      PendingGroupMessage {
        message : message,
        body : body,
        from_alice : false
      })))
    end
  else
    let index = random % List.length(pending)
    let delivery = List.get(pending, index)
    let rest = List.concat(List.take(pending, index), List.drop(pending, index + 1))
    let forged = % {delivery.message | signature : Signature { bytes : repeated(0, 64) } }
    let (alice, bob) = if delivery.from_alice do
      let receiver = rejected_message(decrypt_group_message(bob, forged, aad)) ?
      let receiver = opened(decrypt_group_message(receiver, delivery.message, aad), delivery.body) ?
      let receiver = rejected_message(decrypt_group_message(receiver, delivery.message, aad)) ?
      (alice, receiver)
    else
      let receiver = rejected_message(decrypt_group_message(alice, forged, aad)) ?
      let receiver = opened(decrypt_group_message(receiver, delivery.message, aad), delivery.body) ?
      let receiver = rejected_message(decrypt_group_message(receiver, delivery.message, aad)) ?
      (receiver, bob)
    end
    if step % 32 == 31 do
      let alice = restart_group(alice, storage, 1, 1) ?
      let bob = restart_group(bob, storage, 2, 2) ?
      let (alice, commit) = removed(commit_update(alice, alice_key)) ?
      let bob = applied(apply_commit(bob, commit)) ?
      Ok((alice, bob, rest))
    else
      Ok((alice, bob, rest))
    end
  end
end

fn seeded_group_steps(alice :: consume GroupState,
bob :: consume GroupState,
alice_key :: borrow SigningPrivateKey,
bob_key :: borrow SigningPrivateKey,
storage :: borrow StorageKey,
pending :: List < PendingGroupMessage >,
step :: Int,
random :: Int,
trace :: String) -> Bool ! GroupError do
  # Twelve sixteen-operation batches: 192 sends/receives plus six restart/update boundaries.
  if step >= 192 do
    assert(List.length(pending) == 0)
    consume_state(alice)
    consume_state(bob)
    Ok(true)
  else
    let random = (random * 48271) % 2147483647
    let action = if step % 16 < 8 do
      "send"
    else
      "receive"
    end
    let trace = trace <> " #{step}:#{action}:#{random}"
    case seeded_group_step(alice, bob, alice_key, bob_key, storage, pending, step, random) do
      Err(error) -> do
        # The prefix ends at the first failing operation; the seed reproduces it exactly.
        println("failing action prefix:" <> trace)
        Err(error)
      end
      Ok(values) -> do
        let (alice, bob, pending) = values
        seeded_group_steps(alice,
        bob,
        alice_key,
        bob_key,
        storage,
        pending,
        step + 1,
        random,
        trace)
      end
    end
  end
end

fn seeded_group(seed :: Int) -> Bool ! GroupError do
  let checkpoint = repeated(90, 32)
  let policy = GroupTransparencyPolicy {
    minimum_directory_sequence : wide(4) ?,
    checkpoint_hash : checkpoint,
    witness_threshold : 2
  }
  let alice_signing = signing_pair() ?
  let alice_init = init_pair() ?
  let alice_leaf = init_pair() ?
  let bob_signing = signing_pair() ?
  let bob_init = init_pair() ?
  let bob_leaf = init_pair() ?
  let alice = member(1,
  1,
  alice_signing.public_key,
  alice_init.public_key,
  alice_leaf.public_key,
  checkpoint) ?
  let bob = member(2,
  2,
  bob_signing.public_key,
  bob_init.public_key,
  bob_leaf.public_key,
  checkpoint) ?
  let alice_state = create_group(alice, alice_leaf.private_key, [1], policy) ?
  let (alice_state, _, welcome) = added(commit_add(alice_state, alice_signing.private_key, bob)) ?
  let bob_state = join_from_welcome(welcome, bob_init.private_key, bob_leaf.private_key) ?
  let storage = case StorageKey.ephemeral() do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value) -> Ok(value)
  end ?
  seeded_group_steps(alice_state,
  bob_state,
  alice_signing.private_key,
  bob_signing.private_key,
  storage,
  [],
  0,
  seed,
  "")
end

test("C2 C3 C4 seeded groups preserve reordering, erasure, replay and restore across updates") do
  let count = Env.get_int("MESSENGER_CAMPAIGN_SEEDS", 4)
  assert(count > 0 && count <= 10000)
  for seed in 1..(count + 1) do
    case seeded_group(seed) do
      Ok(value) -> assert(value)
      Err(error) -> do
        println("group campaign seed #{seed}: " <> group_error_name(error))
        assert(false)
      end
    end
  end
  println("group campaign seeds=#{count} operations_per_seed=198")
end
