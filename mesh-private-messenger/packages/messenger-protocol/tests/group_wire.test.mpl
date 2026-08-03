from Groups.Mls import GroupAddOutcome, GroupDecryptOutcome, GroupEncryptOutcome, GroupError, GroupProposal, GroupState, GroupTransparencyPolicy, create_group, commit_add, decode_group_commit, decode_group_message, decode_group_welcome, decrypt_group_message, encode_group_commit, encode_group_message, encode_group_welcome, encrypt_group_message, join_from_welcome
from Groups.Tree import GroupMember

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
checkpoint :: Bytes) -> GroupMember ! GroupError do
  Ok(GroupMember {
    version : 1,
    account_id : repeated(account, 32),
    device_id : repeated(device, 16),
    signing_public_key : signing,
    init_public_key : init,
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

fn added(outcome :: GroupAddOutcome) -> Result <( GroupState, GroupCommit, GroupWelcome), GroupError > do
  case outcome do
    GroupMemberAdded( state, commit, welcome) -> Ok((state, commit, welcome))
    GroupAddRejected( state, error) -> do
      consume_state(state)
      Err(error)
    end
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

fn append(left :: Bytes, right :: Bytes) -> Bytes ! GroupError do
  case Bytes.concat(left, right) do
    Err( _) -> Err(InvalidGroup)
    Ok( value) -> Ok(value)
  end
end

fn rejects_commit(input :: Bytes) -> Bool do
  case decode_group_commit(input) do
    Err( InvalidGroup) -> true
    _ -> false
  end
end

fn rejects_welcome(value :: GroupWelcome) -> Bool do
  case encode_group_welcome(value) do
    Err( _) -> true
    _ -> false
  end
end

fn proof() -> Bool ! GroupError do
  let checkpoint = repeated(72, 32)
  let policy = GroupTransparencyPolicy {
    minimum_directory_sequence : wide(4) ?,
    checkpoint_hash : checkpoint,
    witness_threshold : 2
  }
  let alice_signing = signing_pair() ?
  let alice_init = init_pair() ?
  let bob_signing = signing_pair() ?
  let bob_init = init_pair() ?
  let alice = member(1, 1, alice_signing.public_key, alice_init.public_key, checkpoint) ?
  let bob = member(2, 2, bob_signing.public_key, bob_init.public_key, checkpoint) ?
  let alice_state = create_group(alice, [1], policy) ?
  let ( alice_state, commit, welcome) = added(commit_add(alice_state,
  alice_signing.private_key,
  bob)) ?
  let commit_wire = encode_group_commit(commit) ?
  let decoded_commit = decode_group_commit(commit_wire) ?
  assert(decoded_commit.committer_leaf == commit.committer_leaf)
  assert(Bytes.secure_equals(decoded_commit.tree_hash, commit.tree_hash))
  assert(rejects_commit(append(commit_wire, Bytes.from_utf8("x")) ?))
  let welcome_wire = encode_group_welcome(welcome) ?
  let inconsistent = % { welcome | commit : % { welcome.commit | proposal : AddMember(welcome.recipient_leaf,
  alice) } }
  assert(rejects_welcome(inconsistent))
  let bob_state = join_from_welcome(decode_group_welcome(welcome_wire) ?, bob_init.private_key) ?
  let plaintext = Bytes.from_utf8("canonical group wire")
  let caller_data = Bytes.from_utf8("group-wire-test")
  let ( alice_state, message) = encrypted(encrypt_group_message(alice_state,
  alice_signing.private_key,
  plaintext,
  caller_data)) ?
  let message_wire = encode_group_message(message) ?
  let bob_state = opened(decrypt_group_message(bob_state,
  decode_group_message(message_wire) ?,
  caller_data),
  plaintext) ?
  assert(Bytes.length(encode_group_welcome(decode_group_welcome(welcome_wire) ?) ?) == Bytes.length(welcome_wire))
  assert(Bytes.length(encode_group_message(decode_group_message(message_wire) ?) ?) == Bytes.length(message_wire))
  assert(rejects_commit(repeated(0, 70000)))
  consume_state(alice_state)
  consume_state(bob_state)
  Ok(true)
end

test("group commit, welcome, and message codecs are canonical and bounded") do
  case proof() do
    Err( _) -> assert(false)
    Ok( value) -> assert(value)
  end
end
