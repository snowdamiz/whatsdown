from Groups.Mls import CommitApplyOutcome, GroupAddOutcome, GroupDecryptOutcome, GroupEncryptOutcome, GroupError, GroupRemoveOutcome, GroupState, GroupTransparencyPolicy, apply_commit, commit_add, commit_remove, create_group, decrypt_group_message, delivery_targets, encrypt_group_message, join_from_welcome, negotiate_group_extensions
from Groups.Tree import GroupMember, member_count

fn repeated(value :: Int, length :: Int) -> Bytes do
  case Bytes.repeat(value, length) do
    Err( _) -> Bytes.empty()
    Ok( output) -> output
  end
end

fn wide(value :: Int) -> U64 ! GroupError do
  case U64.parse(Int.to_string(value)) do
    Err( _) -> Err(InvalidGroup)
    Ok( output) -> Ok(output)
  end
end

fn signing_pair() -> SigningKeyPair ! GroupError do
  case Crypto.signing_generate() do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end
end

fn init_pair() -> X25519KeyPair ! GroupError do
  case Crypto.x25519_generate() do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
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
    CryptoFailure( _) -> "CryptoFailure"
    FutureEpoch -> "FutureEpoch"
    InvalidGroup -> "InvalidGroup"
    InvalidMember -> "InvalidMember"
    InvalidPolicy -> "InvalidPolicy"
    Replay -> "Replay"
    RemovedMember -> "RemovedMember"
    RollbackRejected -> "RollbackRejected"
    StaleEpoch -> "StaleEpoch"
    TreeFailure( _) -> "TreeFailure"
  end
end

fn added(outcome :: GroupAddOutcome) -> Result <( GroupState, GroupCommit, GroupWelcome), GroupError > do
  case outcome do
    GroupMemberAdded( state, commit, welcome) -> Ok((state, commit, welcome))
    GroupAddRejected( state, error) -> do
      consume_state(state)
      Err(error)
    end
  end
end

fn rejected_add(outcome :: GroupAddOutcome) -> GroupState ! GroupError do
  case outcome do
    GroupMemberAdded( state, _, _) -> do
      consume_state(state)
      Err(AuthenticationRejected)
    end
    GroupAddRejected( state, _) -> Ok(state)
  end
end

fn removed(outcome :: GroupRemoveOutcome) -> Result <( GroupState, GroupCommit), GroupError > do
  case outcome do
    GroupMemberRemoved( state, commit) -> Ok((state, commit))
    GroupRemoveRejected( state, error) -> do
      consume_state(state)
      Err(error)
    end
  end
end

fn rejected_remove(outcome :: GroupRemoveOutcome) -> GroupState ! GroupError do
  case outcome do
    GroupMemberRemoved( state, _) -> do
      consume_state(state)
      Err(AuthenticationRejected)
    end
    GroupRemoveRejected( state, _) -> Ok(state)
  end
end

fn encrypted(outcome :: GroupEncryptOutcome) -> Result <( GroupState, GroupMessage), GroupError > do
  case outcome do
    GroupMessageEncrypted( state, message) -> Ok((state, message))
    GroupEncryptRejected( state, error) -> do
      consume_state(state)
      Err(error)
    end
  end
end

fn rejected_encryption(outcome :: GroupEncryptOutcome) -> GroupState ! GroupError do
  case outcome do
    GroupMessageEncrypted( state, _) -> do
      consume_state(state)
      Err(AuthenticationRejected)
    end
    GroupEncryptRejected( state, _) -> Ok(state)
  end
end

fn opened(outcome :: GroupDecryptOutcome, expected :: Bytes) -> GroupState ! GroupError do
  case outcome do
    MessageOpened( state, plaintext) -> if Bytes.secure_equals(plaintext, expected) do
      Ok(state)
    else
      consume_state(state)
      Err(AuthenticationRejected)
    end
    MessageRejected( state, error) -> do
      consume_state(state)
      Err(error)
    end
  end
end

fn applied(outcome :: CommitApplyOutcome) -> GroupState ! GroupError do
  case outcome do
    CommitApplied( state) -> Ok(state)
    CommitRejected( state, error) -> do
      consume_state(state)
      Err(error)
    end
  end
end

fn rejected_commit(outcome :: CommitApplyOutcome, expected :: GroupError) -> GroupState ! GroupError do
  case outcome do
    CommitApplied( state) -> do
      consume_state(state)
      Err(AuthenticationRejected)
    end
    CommitRejected( state, error) -> case (error, expected) do
      ( FutureEpoch, FutureEpoch) -> Ok(state)
      ( AuthenticationRejected, AuthenticationRejected) -> Ok(state)
      ( RemovedMember, RemovedMember) -> Ok(state)
      ( StaleEpoch, StaleEpoch) -> Ok(state)
      _ -> do
        consume_state(state)
        Err(AuthenticationRejected)
      end
    end
  end
end

fn rejected_message(outcome :: GroupDecryptOutcome) -> GroupState ! GroupError do
  case outcome do
    MessageOpened( state, _) -> do
      consume_state(state)
      Err(AuthenticationRejected)
    end
    MessageRejected( state, _) -> Ok(state)
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
  let invalid_bob = % { bob | witness_count : 0 }
  let alice_state = rejected_add(commit_add(alice_state, alice_signing.private_key, invalid_bob)) ?
  let ( alice_state, bob_commit, bob_welcome) = added(commit_add(alice_state,
  alice_signing.private_key,
  bob)) ?
  assert(List.length(bob_commit.update_path.nodes) == 6)
  assert(List.length(List.get(bob_commit.update_path.nodes, 0).parent.unmerged_leaves) == 0)
  let bob_state = join_from_welcome(bob_welcome, bob_init.private_key, bob_leaf.private_key) ?
  assert(member_count(alice_state.tree) == 2)
  assert(member_count(bob_state.tree) == 2)
  let ( alice_state, second_commit, second_welcome) = added(commit_add(alice_state,
  alice_signing.private_key,
  alice_second)) ?
  let bob_state = applied(apply_commit(bob_state, second_commit)) ?
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
  let ( alice_state, message) = encrypted(encrypt_group_message(alice_state,
  alice_signing.private_key,
  plaintext,
  caller_data)) ?
  let bob_state = opened(decrypt_group_message(bob_state, message, caller_data), plaintext) ?
  let alice_second_state = opened(decrypt_group_message(alice_second_state, message, caller_data),
  plaintext) ?
  consume_state(alice_state)
  consume_state(bob_state)
  consume_state(alice_second_state)
  Ok(true)
end

test("MLS group add, welcome, message, and multi-device membership") do
  case proof() do
    Err( error) -> do
      println(group_error_name(error))
      assert(false)
    end
    Ok( value) -> assert(value)
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
  let ( alice_state, _, bob_welcome) = added(commit_add(alice_state, alice_signing.private_key, bob)) ?
  let bob_state = join_from_welcome(bob_welcome, bob_init.private_key, bob_leaf.private_key) ?
  let ( alice_state, carol_commit, carol_welcome) = added(commit_add(alice_state,
  alice_signing.private_key,
  carol)) ?
  let carol_state = join_from_welcome(carol_welcome, carol_init.private_key, carol_leaf.private_key) ?
  let alice_state = rejected_remove(commit_remove(alice_state, bob_signing.private_key, 1)) ?
  let ( alice_state, removal_commit) = removed(commit_remove(alice_state,
  alice_signing.private_key,
  1)) ?
  let bob_state = rejected_commit(apply_commit(bob_state, removal_commit), FutureEpoch) ?
  let tampered_carol_commit = % { carol_commit | signature : Signature { bytes : repeated(0, 64) } }
  let bob_state = rejected_commit(apply_commit(bob_state, tampered_carol_commit),
  AuthenticationRejected) ?
  let bob_state = applied(apply_commit(bob_state, carol_commit)) ?
  let bob_state = rejected_commit(apply_commit(bob_state, removal_commit), RemovedMember) ?
  let carol_state = applied(apply_commit(carol_state, removal_commit)) ?
  let carol_state = rejected_commit(apply_commit(carol_state, carol_commit), StaleEpoch) ?
  let plaintext = Bytes.from_utf8("after removal")
  let caller_data = Bytes.from_utf8("group removal")
  let ( alice_state, message) = encrypted(encrypt_group_message(alice_state,
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
    Err( error) -> do
      println(group_error_name(error))
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
