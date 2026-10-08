from Groups.GroupMessages import (
  decode_group_message,
  decrypt_deniable_group_message,
  decrypt_group_message,
  encode_group_message,
  encrypt_group_message_deniable,
  encrypt_group_message_for_transport,
  group_message_signed_input
)
from Groups.Membership import (
  apply_commit,
  commit_add,
  commit_remove,
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
  GroupState,
  GroupTransparencyPolicy
)
from Groups.SenderAnnouncement import (
  GroupSenderAnnouncement,
  decode_group_sender_announcement,
  encode_group_sender_announcement
)
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

fn signing_pair() -> SigningKeyPair!GroupError do
  case Crypto.signing_generate() do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end

fn init_pair() -> X25519KeyPair!GroupError do
  case Crypto.x25519_generate() do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end

fn member(account :: Int,
  signing :: SigningPublicKey,
  init :: X25519PublicKey,
  leaf :: X25519PublicKey,
  checkpoint :: Bytes) -> GroupMember!GroupError do
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
    witness_count: 2,
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

fn removed(outcome :: GroupRemoveOutcome) -> Result<(GroupState, GroupCommit), GroupError> do
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

fn encrypted(outcome :: GroupEncryptOutcome) -> Result<(GroupState, GroupMessage), GroupError> do
  case outcome do
    GroupMessageEncrypted(state, message) -> Ok((state, message))
    GroupEncryptRejected(state, error) -> do
      consume_state(state)
      Err(error)
    end
  end
end

fn opened(outcome :: GroupDecryptOutcome, expected :: Bytes) -> GroupState!GroupError do
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

fn refused(outcome :: GroupDecryptOutcome) -> GroupState!GroupError do
  case outcome do
    MessageOpened(state, _) -> do
      consume_state(state)
      Err(InvalidGroup)
    end
    MessageRejected(state, _) -> Ok(state)
  end
end

fn verifies(key :: SigningPublicKey, input :: Bytes, signature :: Signature) -> Bool do
  case Crypto.verify(key, input, signature) do
    Ok(value) -> value
    Err(_) -> false
  end
end

fn signed_with(key :: borrow SigningPrivateKey, input :: Bytes) -> Signature!GroupError do
  case Crypto.sign(key, input) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end

fn holds(haystack :: Bytes, needle :: Bytes) -> Bool do
  List.any(for start in 0..(Bytes.length(haystack) - Bytes.length(needle) + 1) do
      case Bytes.slice(haystack, start, Bytes.length(needle)) do
        Ok(part) -> Bytes.secure_equals(part, needle)
        Err(_) -> false
      end
    end,
    fn(found) do found end)
end

fn rejects_announcement(input :: Bytes) -> Bool do
  case decode_group_sender_announcement(input) do
    Err(_) -> true
    Ok(_) -> false
  end
end

fn slice(input :: Bytes, start :: Int, length :: Int) -> Bytes do
  case Bytes.slice(input, start, length) do
    Err(_) -> Bytes.empty()
    Ok(value) -> value
  end
end

fn append(left :: Bytes, right :: Bytes) -> Bytes do
  case Bytes.concat(left, right) do
    Err(_) -> Bytes.empty()
    Ok(value) -> value
  end
end

# The announcement: 76 bytes, no signature, nothing long-term in it.

fn announcement_proof(group_id :: Bytes,
  epoch :: U64,
  ephemeral :: SigningPublicKey,
  long_term :: SigningPublicKey) -> Bytes!GroupError do
  let wire = encode_group_sender_announcement(GroupSenderAnnouncement {
    group_id: group_id,
    epoch: epoch,
    signing_public_key: ephemeral
  })?
  assert(Bytes.length(wire) == 76)
  assert(!holds(wire, long_term.bytes))
  let decoded = decode_group_sender_announcement(wire)?
  assert(Bytes.secure_equals(decoded.group_id, group_id))
  assert(U64.compare(decoded.epoch, epoch) == 0)
  assert(Bytes.secure_equals(decoded.signing_public_key.bytes, ephemeral.bytes))
  assert(rejects_announcement(append(wire, Bytes.from_utf8("x"))))
  assert(rejects_announcement(slice(wire, 0, 75)))
  assert(rejects_announcement(append(repeated(2, 1), slice(wire, 1, 75))))
  Ok(wire)
end

fn proof() -> Bool!GroupError do
  let checkpoint = repeated(73, 32)
  let policy = GroupTransparencyPolicy {
    minimum_directory_sequence: wide(4)?,
    checkpoint_hash: checkpoint,
    witness_threshold: 2,
    set_id: Bytes.empty()
  }
  let alice_signing = signing_pair()?
  let alice_init = init_pair()?
  let alice_leaf = init_pair()?
  let bob_signing = signing_pair()?
  let bob_init = init_pair()?
  let bob_leaf = init_pair()?
  let carol_signing = signing_pair()?
  let carol_init = init_pair()?
  let carol_leaf = init_pair()?
  let alice = member(1,
    alice_signing.public_key,
    alice_init.public_key,
    alice_leaf.public_key,
    checkpoint)?
  let bob = member(2, bob_signing.public_key, bob_init.public_key, bob_leaf.public_key, checkpoint)?
  let carol = member(3,
    carol_signing.public_key,
    carol_init.public_key,
    carol_leaf.public_key,
    checkpoint)?
  let alice_state = create_group(alice, alice_leaf.private_key, [1], policy)?
  let (alice_state, _, bob_welcome) = added(commit_add(alice_state,
    alice_signing.private_key,
    bob))?
  let bob_state = join_from_welcome(bob_welcome, bob_init.private_key, bob_leaf.private_key)?
  let (alice_state, carol_commit, carol_welcome) = added(commit_add(alice_state,
    alice_signing.private_key,
    carol))?
  let bob_state = applied(apply_commit(bob_state, carol_commit))?
  let carol_state = join_from_welcome(carol_welcome,
    carol_init.private_key,
    carol_leaf.private_key)?
  # Each sender's key for this epoch, as its pairwise sessions would carry it.
  let alice_ephemeral = signing_pair()?
  let carol_ephemeral = signing_pair()?
  let wire = announcement_proof(alice_state.group_id,
    alice_state.epoch,
    alice_ephemeral.public_key,
    alice_signing.public_key)?
  let plaintext = Bytes.from_utf8("deniable hello")
  let caller_data = Bytes.from_utf8("group-deniable-test")
  let (alice_state, message) = encrypted(encrypt_group_message_deniable(alice_state,
    alice_ephemeral.private_key,
    alice_ephemeral.public_key,
    plaintext,
    caller_data))?
  assert(message.version == 6)
  let message = decode_group_message(encode_group_message(message)?)?
  # A transcript of the message and its announcement verifies under the
  # ephemeral key and under no member's long-term key.
  let signed = group_message_signed_input(message, caller_data)?
  assert(verifies(alice_ephemeral.public_key, signed, message.signature))
  assert(!verifies(alice_signing.public_key, signed, message.signature))
  assert(!verifies(bob_signing.public_key, signed, message.signature))
  assert(!verifies(carol_signing.public_key, signed, message.signature))
  assert(!holds(wire, alice_signing.public_key.bytes))
  # The long-term path cannot open it, and it is not version 5 in disguise.
  let bob_state = refused(decrypt_group_message(bob_state, message, caller_data))?
  let bob_state = refused(decrypt_group_message(bob_state, %{message | version: 5}, caller_data))?
  # Carol re-signs Alice's message with her own announced key: refused under Alice's.
  let forged = %{message | signature: signed_with(carol_ephemeral.private_key, signed)?}
  let bob_state = refused(decrypt_deniable_group_message(bob_state,
    forged,
    caller_data,
    alice_ephemeral.public_key))?
  let bob_state = refused(decrypt_deniable_group_message(bob_state,
    message,
    caller_data,
    carol_ephemeral.public_key))?
  let bob_state = opened(decrypt_deniable_group_message(bob_state,
      message,
      caller_data,
      alice_ephemeral.public_key),
    plaintext)?
  let bob_state = refused(decrypt_deniable_group_message(bob_state,
    message,
    caller_data,
    alice_ephemeral.public_key))?
  let carol_state = opened(decrypt_deniable_group_message(carol_state,
      message,
      caller_data,
      alice_ephemeral.public_key),
    plaintext)?
  # Carol's own deniable message opens under her key only.
  let (carol_state, from_carol) = encrypted(encrypt_group_message_deniable(carol_state,
    carol_ephemeral.private_key,
    carol_ephemeral.public_key,
    plaintext,
    caller_data))?
  let bob_state = refused(decrypt_deniable_group_message(bob_state,
    from_carol,
    caller_data,
    alice_ephemeral.public_key))?
  let bob_state = opened(decrypt_deniable_group_message(bob_state,
      from_carol,
      caller_data,
      carol_ephemeral.public_key),
    plaintext)?
  # A deniable key never signs for a long-term message, and version 4 still reads.
  let (alice_state, signed_message) = encrypted(encrypt_group_message_for_transport(alice_state,
    alice_signing.private_key,
    plaintext,
    caller_data))?
  let bob_state = refused(decrypt_deniable_group_message(bob_state,
    signed_message,
    caller_data,
    alice_signing.public_key))?
  let bob_state = opened(decrypt_group_message(bob_state, signed_message, caller_data), plaintext)?
  # Removing Carol ends her key: her next message, from the old epoch, is refused.
  let (alice_state, removal) = removed(commit_remove(alice_state, alice_signing.private_key, 2))?
  let bob_state = applied(apply_commit(bob_state, removal))?
  let (carol_state, after_removal) = encrypted(encrypt_group_message_deniable(carol_state,
    carol_ephemeral.private_key,
    carol_ephemeral.public_key,
    plaintext,
    caller_data))?
  let bob_state = refused(decrypt_deniable_group_message(bob_state,
    after_removal,
    caller_data,
    carol_ephemeral.public_key))?
  consume_state(alice_state)
  consume_state(bob_state)
  consume_state(carol_state)
  Ok(true)
end

test("deniable group messages verify only under the sender's announced key") do
  case proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end
