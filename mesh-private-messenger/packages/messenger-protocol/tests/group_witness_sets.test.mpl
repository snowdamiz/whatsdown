from Groups.CommitWire import decode_group_commit, encode_group_commit
from Groups.GroupMessages import decrypt_group_message, encrypt_group_message
from Groups.GroupSnapshot import group_snapshot, restore_group
from Groups.Membership import (
  apply_commit,
  commit_add,
  commit_add_with_set,
  commit_update_with_set,
  create_group,
  join_from_welcome
)
from Groups.Mls import (
  CommitApplyOutcome,
  GroupAddOutcome,
  GroupDecryptOutcome,
  GroupEncryptOutcome,
  GroupError,
  GroupRemoveOutcome,
  GroupSnapshotOutcome,
  GroupState,
  GroupTransparencyPolicy
)
from Groups.WelcomeWire import decode_group_welcome, encode_group_welcome
from Groups.Tree import GroupMember

fn repeated(value :: Int, length :: Int) -> Bytes do
  case Bytes.repeat(value, length) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

fn wide(value :: Int) -> U64!GroupError do
  case U64.parse(Int.to_string(value)) do
    Err(_) -> Err(InvalidGroup)
    Ok(output)
  end
end

fn append(left :: Bytes, right :: Bytes) -> Bytes!GroupError do
  case Bytes.concat(left, right) do
    Err(_) -> Err(InvalidGroup)
    Ok(value)
  end
end

fn witness_set(set_id :: Bytes, threshold :: Int) -> Bytes!GroupError do
  case Bytes.from_list([threshold]) do
    Err(_) -> Err(InvalidGroup)
    Ok(value) -> append(set_id, value)
  end
end

fn first_byte(input :: Bytes) -> Int do
  case Bytes.get(input, 0) do
    Err(_) -> -1
    Ok(value) -> value
  end
end

fn signing_pair() -> SigningKeyPair!GroupError do
  case Crypto.signing_generate() do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end

fn x25519_pair() -> X25519KeyPair!GroupError do
  case Crypto.x25519_generate() do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end

fn member(account :: Int,
  signing :: SigningPublicKey,
  init :: X25519PublicKey,
  leaf :: X25519PublicKey,
  checkpoint :: Bytes,
  witnesses :: Int) -> GroupMember!GroupError do
  Ok(GroupMember {
    version: 1,
    account_id: repeated(account, 32),
    device_id: repeated(account, 16),
    signing_public_key: signing,
    init_public_key: init,
    leaf_public_key: leaf,
    mailbox_token: repeated(account + 40, 32),
    directory_sequence: wide(5)?,
    transparency_checkpoint_hash: checkpoint,
    witness_count: witnesses,
    extensions: [1]
  })
end

fn consume_state(value :: consume GroupState) do
  nil
end

fn added(outcome :: GroupAddOutcome) -> Result<(GroupState, GroupCommit, GroupWelcome), GroupError> do
  case outcome do
    GroupMemberAdded(state, commit, welcome) -> Ok((state, commit, welcome))
    GroupAddRejected(state, error) -> do
      consume_state(state)
      Err(error)
    end
  end
end

fn updated(outcome :: GroupRemoveOutcome) -> Result<(GroupState, GroupCommit), GroupError> do
  case outcome do
    GroupMemberRemoved(state, commit) -> Ok((state, commit))
    GroupRemoveRejected(state, error) -> do
      consume_state(state)
      Err(error)
    end
  end
end

fn applied(outcome :: CommitApplyOutcome) -> GroupState!GroupError do
  case outcome do
    CommitApplied(state) -> Ok(state)
    CommitRejected(state, error) -> do
      consume_state(state)
      Err(error)
    end
  end
end

fn refused(outcome :: CommitApplyOutcome) -> GroupState!GroupError do
  case outcome do
    CommitApplied(state) -> do
      consume_state(state)
      Err(AuthenticationRejected)
    end
    CommitRejected(state, _) -> Ok(state)
  end
end

fn exchanged(sender :: consume GroupState,
  key :: borrow SigningPrivateKey,
  receiver :: consume GroupState) -> Result<(GroupState, GroupState), GroupError> do
  let plaintext = Bytes.from_utf8("after the set moved")
  let caller = Bytes.from_utf8("group-witness-sets-test")
  case encrypt_group_message(sender, key, plaintext, caller) do
    GroupEncryptRejected(state, error) -> do
      consume_state(state)
      consume_state(receiver)
      Err(error)
    end
    GroupMessageEncrypted(next_sender, message) -> case decrypt_group_message(receiver,
      message,
      caller) do
      MessageRejected(state, error) -> do
        consume_state(state)
        consume_state(next_sender)
        Err(error)
      end
      MessageOpened(next_receiver, opened) -> if Bytes.secure_equals(opened, plaintext) do
        Ok((next_sender, next_receiver))
      else
        consume_state(next_sender)
        consume_state(next_receiver)
        Err(AuthenticationRejected)
      end
    end
  end
end

fn same_policy(state :: borrow GroupState, set_id :: Bytes, threshold :: Int) -> Bool do
  Bytes.secure_equals(state.policy.set_id, set_id) && state.policy.witness_threshold == threshold
end

fn rejects_group(value :: Result<GroupState, GroupError>) -> Bool do
  case value do
    Err(_) -> true
    Ok(state) -> do
      consume_state(state)
      false
    end
  end
end

fn moving_proof() -> Bool!GroupError do
  let checkpoint = repeated(74, 32)
  let first_set = repeated(11, 32)
  let second_set = repeated(22, 32)
  let policy = GroupTransparencyPolicy {
    minimum_directory_sequence: wide(4)?,
    checkpoint_hash: checkpoint,
    witness_threshold: 2,
    set_id: first_set
  }
  let alice_signing = signing_pair()?
  let alice_init = x25519_pair()?
  let alice_leaf = x25519_pair()?
  let bob_signing = signing_pair()?
  let bob_init = x25519_pair()?
  let bob_leaf = x25519_pair()?
  let alice_state = create_group(member(1,
      alice_signing.public_key,
      alice_init.public_key,
      alice_leaf.public_key,
      checkpoint,
      2)?,
    alice_leaf.private_key,
    [1],
    policy)?
  let (alice_state, _, welcome) = added(commit_add(alice_state,
    alice_signing.private_key,
    member(2, bob_signing.public_key, bob_init.public_key, bob_leaf.public_key, checkpoint, 2)?))?
  let welcome_wire = encode_group_welcome(welcome)?
  assert(first_byte(welcome_wire) == 2)
  let decoded = decode_group_welcome(welcome_wire)?
  assert(Bytes.secure_equals(decoded.policy.set_id, first_set))
  let bob_state = join_from_welcome(decoded, bob_init.private_key, bob_leaf.private_key)?
  # Bob's build pins another set, 3 of 5: his next commit moves the group there.
  let (bob_state, commit) = updated(commit_update_with_set(bob_state,
    bob_signing.private_key,
    witness_set(second_set, 3)?))?
  let commit_wire = encode_group_commit(commit)?
  assert(first_byte(commit_wire) == 2)
  let decoded_commit = decode_group_commit(commit_wire)?
  assert(Bytes.secure_equals(decoded_commit.witness_set, witness_set(second_set, 3)?))
  # The moved set is signed and bound into the epoch: altering it is refused.
  let tampered = %{decoded_commit | witness_set: witness_set(second_set, 2)?}
  let alice_state = refused(apply_commit(alice_state, tampered))?
  assert(same_policy(alice_state, first_set, 2))
  let alice_state = applied(apply_commit(alice_state, decoded_commit))?
  assert(same_policy(alice_state, second_set, 3))
  assert(same_policy(bob_state, second_set, 3))
  let (alice_state, bob_state) = exchanged(alice_state, alice_signing.private_key, bob_state)?
  # The moved policy survives a restart.
  let storage = case StorageKey.ephemeral() do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end?
  let (alice_state, blob) = case group_snapshot(alice_state,
    storage,
    repeated(1, 32),
    repeated(1, 16),
    wide(1)?) do
    GroupSnapshotSealed(state, value) -> Ok((state, value))
    GroupSnapshotRejected(state, error) -> do
      consume_state(state)
      Err(error)
    end
  end?
  let restored = restore_group(blob, storage, repeated(1, 32), repeated(1, 16), wide(1)?)?
  assert(same_policy(restored, second_set, 3))
  let (restored, bob_state) = exchanged(restored, alice_signing.private_key, bob_state)?
  consume_state(alice_state)
  consume_state(restored)
  consume_state(bob_state)
  Ok(true)
end

fn legacy_proof() -> Bool!GroupError do
  let checkpoint = repeated(75, 32)
  let legacy = GroupTransparencyPolicy {
    minimum_directory_sequence: wide(4)?,
    checkpoint_hash: checkpoint,
    witness_threshold: 2,
    set_id: Bytes.empty()
  }
  let alice_signing = signing_pair()?
  let alice_init = x25519_pair()?
  let alice_leaf = x25519_pair()?
  let bob_signing = signing_pair()?
  let bob_init = x25519_pair()?
  let bob_leaf = x25519_pair()?
  let carol_signing = signing_pair()?
  let carol_init = x25519_pair()?
  let carol_leaf = x25519_pair()?
  let alice_state = create_group(member(1,
      alice_signing.public_key,
      alice_init.public_key,
      alice_leaf.public_key,
      checkpoint,
      2)?,
    alice_leaf.private_key,
    [1],
    legacy)?
  let (alice_state, _, welcome) = added(commit_add(alice_state,
    alice_signing.private_key,
    member(2, bob_signing.public_key, bob_init.public_key, bob_leaf.public_key, checkpoint, 2)?))?
  # A version 1 policy keeps the version 1 welcome, byte for byte.
  let welcome_wire = encode_group_welcome(welcome)?
  assert(first_byte(welcome_wire) == 1)
  let decoded = decode_group_welcome(welcome_wire)?
  assert(Bytes.length(decoded.policy.set_id) == 0 && decoded.policy.witness_threshold == 2)
  let bob_state = join_from_welcome(decoded, bob_init.private_key, bob_leaf.private_key)?
  # Alice moves the group to a pinned set while adding Carol, who pinned 2 of 3.
  let set_id = repeated(33, 32)
  let (alice_state, commit, carol_welcome) = added(commit_add_with_set(alice_state,
    alice_signing.private_key,
    member(3,
      carol_signing.public_key,
      carol_init.public_key,
      carol_leaf.public_key,
      checkpoint,
      2)?,
    witness_set(set_id, 2)?))?
  let carol_wire = encode_group_welcome(carol_welcome)?
  assert(first_byte(carol_wire) == 2)
  let carol_state = join_from_welcome(decode_group_welcome(carol_wire)?,
    carol_init.private_key,
    carol_leaf.private_key)?
  let bob_state = applied(apply_commit(bob_state,
    decode_group_commit(encode_group_commit(commit)?)?))?
  assert(same_policy(alice_state, set_id, 2))
  assert(same_policy(bob_state, set_id, 2))
  assert(same_policy(carol_state, set_id, 2))
  # A welcome whose policy disagrees with the set its commit moved to is refused.
  let mismatched = %{carol_welcome | policy: %{carol_welcome.policy | witness_threshold: 3}}
  case encode_group_welcome(mismatched) do
    Ok(_) -> assert(false)
    Err(_) -> assert(true)
  end
  # Sets carry a strict majority of 1 to 16 and a 32-byte set_id.
  let dave_signing = signing_pair()?
  let dave_init = x25519_pair()?
  let dave_leaf = x25519_pair()?
  assert(rejects_group(create_group(member(4,
      dave_signing.public_key,
      dave_init.public_key,
      dave_leaf.public_key,
      checkpoint,
      2)?,
    dave_leaf.private_key,
    [1],
    %{legacy | set_id: set_id, witness_threshold: 17})))
  let erin_signing = signing_pair()?
  let erin_init = x25519_pair()?
  let erin_leaf = x25519_pair()?
  assert(rejects_group(create_group(member(5,
      erin_signing.public_key,
      erin_init.public_key,
      erin_leaf.public_key,
      checkpoint,
      2)?,
    erin_leaf.private_key,
    [1],
    %{legacy | set_id: repeated(33, 31)})))
  # Members keep the k their build pinned: the legacy policy still wants 2, a
  # pinned set accepts a member whose build pinned fewer.
  let fay_signing = signing_pair()?
  let fay_init = x25519_pair()?
  let fay_leaf = x25519_pair()?
  assert(rejects_group(create_group(member(6,
      fay_signing.public_key,
      fay_init.public_key,
      fay_leaf.public_key,
      checkpoint,
      1)?,
    fay_leaf.private_key,
    [1],
    legacy)))
  let gus_signing = signing_pair()?
  let gus_init = x25519_pair()?
  let gus_leaf = x25519_pair()?
  let gus_state = create_group(member(7,
      gus_signing.public_key,
      gus_init.public_key,
      gus_leaf.public_key,
      checkpoint,
      1)?,
    gus_leaf.private_key,
    [1],
    %{legacy | set_id: set_id, witness_threshold: 3})?
  consume_state(gus_state)
  consume_state(alice_state)
  consume_state(bob_state)
  consume_state(carol_state)
  Ok(true)
end

test("a commit moves the group to the committer's witness set in step for every member") do
  case moving_proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end

test("version 1 policies keep version 1 welcomes and move at the next commit") do
  case legacy_proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end
