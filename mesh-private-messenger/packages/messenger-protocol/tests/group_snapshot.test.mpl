from Groups.Mls import GroupAddOutcome, GroupDecryptOutcome, GroupEncryptOutcome, GroupError, GroupSnapshotOutcome, GroupState, GroupTransparencyPolicy, create_group, commit_add, decrypt_group_message, encrypt_group_message, group_snapshot, join_from_welcome, restore_group
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

fn storage_key() -> StorageKey ! GroupError do
  case StorageKey.ephemeral() do
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
    leaf_public_key : X25519PublicKey { bytes : repeated(device + 70, 32) },
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

fn sealed(outcome :: GroupSnapshotOutcome) -> Result <( GroupState, Bytes), GroupError > do
  case outcome do
    GroupSnapshotSealed( state, blob) -> Ok((state, blob))
    GroupSnapshotRejected( state, error) -> do
      consume_state(state)
      Err(error)
    end
  end
end

fn rollback_rejected(outcome :: GroupSnapshotOutcome) -> GroupState ! GroupError do
  case outcome do
    GroupSnapshotSealed( state, _) -> do
      consume_state(state)
      Err(AuthenticationRejected)
    end
    GroupSnapshotRejected( state, RollbackRejected) -> Ok(state)
    GroupSnapshotRejected( state, error) -> do
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

fn tamper_last_byte(input :: Bytes) -> Bytes ! GroupError do
  let length = Bytes.length(input)
  let last = case Bytes.get(input, length - 1) do
    Err( _) -> Err(InvalidGroup)
    Ok( value) -> Ok(value)
  end ?
  let prefix = case Bytes.slice(input, 0, length - 1) do
    Err( _) -> Err(InvalidGroup)
    Ok( value) -> Ok(value)
  end ?
  let replacement = if last == 120 do
    Bytes.from_utf8("y")
  else
    Bytes.from_utf8("x")
  end
  case Bytes.concat(prefix, replacement) do
    Err( _) -> Err(InvalidGroup)
    Ok( value) -> Ok(value)
  end
end

fn rejects_restore(blob :: Bytes,
key :: borrow StorageKey,
account_id :: Bytes,
device_id :: Bytes,
minimum :: U64) -> Bool do
  case restore_group(blob, key, account_id, device_id, minimum) do
    Err( _) -> true
    Ok( state) -> do
      consume_state(state)
      false
    end
  end
end

fn proof() -> Bool ! GroupError do
  let checkpoint = repeated(73, 32)
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
  let bob_account = bob.account_id
  let bob_device = bob.device_id
  let alice_state = create_group(alice, [1], policy) ?
  let ( alice_state, _, welcome) = added(commit_add(alice_state, alice_signing.private_key, bob)) ?
  let bob_state = join_from_welcome(welcome, bob_init.private_key) ?
  let key = storage_key() ?
  let ( bob_state, blob) = sealed(group_snapshot(bob_state, key, bob_account, bob_device, wide(1) ?)) ?
  let bob_state = rollback_rejected(group_snapshot(bob_state,
  key,
  bob_account,
  bob_device,
  wide(1) ?)) ?
  assert(rejects_restore(tamper_last_byte(blob) ?, key, bob_account, bob_device, wide(1) ?))
  assert(rejects_restore(blob, key, bob_account, bob_device, wide(2) ?))
  let restored = restore_group(blob, key, bob_account, bob_device, wide(1) ?) ?
  let plaintext = Bytes.from_utf8("message after restart")
  let caller_data = Bytes.from_utf8("group-snapshot-test")
  let ( alice_state, message) = encrypted(encrypt_group_message(alice_state,
  alice_signing.private_key,
  plaintext,
  caller_data)) ?
  let restored = opened(decrypt_group_message(restored, message, caller_data), plaintext) ?
  consume_state(alice_state)
  consume_state(bob_state)
  consume_state(restored)
  Ok(true)
end

test("group state recovery seals epoch secrets and rejects rollback or tampering") do
  case proof() do
    Err( _) -> assert(false)
    Ok( value) -> assert(value)
  end
end
