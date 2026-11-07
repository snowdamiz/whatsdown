from Groups.GroupSnapshot import group_snapshot, require_group_snapshot_custody
from Groups.Membership import create_group
from Groups.Mls import GroupError, GroupState, GroupSnapshotOutcome, GroupTransparencyPolicy
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

fn consume_state(state :: consume GroupState) do
  nil
end

# Assertion-free fixture constructor: real public member, actual MLS group,
# and actual sealed snapshot under the caller's retained storage-key owner.
fn custody_snapshot(key :: borrow StorageKey,
  account :: Bytes,
  device :: Bytes,
  set_id :: Bytes) -> Result<(Bytes, Bytes), GroupError> do
  let signing = case Crypto.signing_generate() do
    Err(error) -> return Err(CryptoFailure(error))
    Ok(value) -> value
  end
  let initial = case Crypto.x25519_generate() do
    Err(error) -> return Err(CryptoFailure(error))
    Ok(value) -> value
  end
  let leaf = case Crypto.x25519_generate() do
    Err(error) -> return Err(CryptoFailure(error))
    Ok(value) -> value
  end
  let checkpoint = repeated(73, 32)
  let member = GroupMember {
    version: 1,
    account_id: account,
    device_id: device,
    signing_public_key: signing.public_key,
    init_public_key: initial.public_key,
    leaf_public_key: leaf.public_key,
    mailbox_token: repeated(41, 32),
    directory_sequence: wide(5)?,
    transparency_checkpoint_hash: checkpoint,
    witness_count: 2,
    extensions: [1]
  }
  Secret.destroy(signing.private_key)
  Secret.destroy(initial.private_key)
  let policy = GroupTransparencyPolicy {
    minimum_directory_sequence: wide(4)?,
    checkpoint_hash: checkpoint,
    witness_threshold: 2,
    set_id: set_id
  }
  let state = create_group(member, leaf.private_key, [1], policy)?
  let group_id = state.group_id
  case group_snapshot(state, key, account, device, wide(1)?) do
    GroupSnapshotRejected(rejected, error) -> do
      consume_state(rejected)
      Err(error)
    end
    GroupSnapshotSealed(saved, blob) -> do
      consume_state(saved)
      Ok((group_id, blob))
    end
  end
end

fn key() -> StorageKey!GroupError do
  case StorageKey.ephemeral() do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end

fn change_byte(input :: Bytes, offset :: Int) -> Bytes!GroupError do
  let value = case Bytes.get(input, offset) do
    Err(_) -> return Err(InvalidGroup)
    Ok(value) -> value
  end
  let prefix = case Bytes.slice(input, 0, offset) do
    Err(_) -> return Err(InvalidGroup)
    Ok(value) -> value
  end
  let suffix = case Bytes.slice(input, offset + 1, Bytes.length(input) - offset - 1) do
    Err(_) -> return Err(InvalidGroup)
    Ok(value) -> value
  end
  let replacement = if value == 120 do
    Bytes.from_utf8("y")
  else
    Bytes.from_utf8("x")
  end
  case Bytes.concat(prefix, replacement) do
    Err(_) -> Err(InvalidGroup)
    Ok(changed) -> case Bytes.concat(changed, suffix) do
      Err(_) -> Err(InvalidGroup)
      Ok(output)
    end
  end
end

fn owner_checks_on(wrapping :: borrow StorageKey, set_id :: Bytes) -> Result<(), GroupError> do
  let account = repeated(1, 32)
  let device = repeated(2, 16)
  let (group, blob) = custody_snapshot(wrapping, account, device, set_id)?
  require_group_snapshot_custody(blob, wrapping, account, device, group, wide(1)?)?
  println("GROUP_CUSTODY_VALID_OWNER_READY")
  assert(Result.is_err(require_group_snapshot_custody(blob,
    wrapping,
    repeated(9, 32),
    device,
    group,
    wide(1)?)))
  assert(Result.is_err(require_group_snapshot_custody(blob,
    wrapping,
    account,
    repeated(9, 16),
    group,
    wide(1)?)))
  assert(Result.is_err(require_group_snapshot_custody(blob,
    wrapping,
    account,
    device,
    repeated(9, 32),
    wide(1)?)))
  assert(case require_group_snapshot_custody(blob, wrapping, account, device, group, wide(2)?) do
    Err(RollbackRejected) -> true
    _ -> false
  end)
  Ok(nil)
end

fn owner_checks() -> Result<(), GroupError> do
  let wrapping = key()?
  let result = case owner_checks_on(wrapping, Bytes.empty()) do
    Err(error)
    Ok(_) -> owner_checks_on(wrapping, repeated(91, 32))
  end
  Secret.destroy(wrapping)
  result
end

test("snapshot custody accepts real owners and rejects foreign account device group and rollback") do
  assert(Result.is_ok(owner_checks()))
end

fn malformed_checks() -> Result<(), GroupError> do
  let wrapping = key()?
  let account = repeated(1, 32)
  let device = repeated(2, 16)
  let group = repeated(3, 32)
  for blob in [Bytes.empty(), Bytes.from_utf8("sealed opaque marker"), repeated(7, 65536)] do
    assert(Result.is_err(require_group_snapshot_custody(blob,
      wrapping,
      account,
      device,
      group,
      wide(1)?)))
  end
  Secret.destroy(wrapping)
  Ok(nil)
end

test("snapshot custody refuses malformed opaque and over-budget snapshot bytes") do
  assert(Result.is_ok(malformed_checks()))
end

fn epoch_secret_tag_offset(blob :: Bytes, index :: Int) -> Int!GroupError do
  if index + 8 * 103 > Bytes.length(blob) do
    return Err(InvalidGroup)
  end
  let expected_length = wide(99)?
  let matches = for slot in 0..8 do
    case Bytes.read_u32_be(blob, index + slot * 103) do
      Err(_) -> false
      Ok(length) -> U64.compare(length, expected_length) == 0
    end
  end
  if List.all(matches, fn(value) -> value end) do
    Ok(index + 4 + 98)
  else
    epoch_secret_tag_offset(blob, index + 1)
  end
end

fn authentication_checks_on(wrapping :: borrow StorageKey,
  wrong :: borrow StorageKey) -> Result<(), GroupError> do
  let account = repeated(1, 32)
  let device = repeated(2, 16)
  let (group, blob) = custody_snapshot(wrapping, account, device, repeated(91, 32))?
  require_group_snapshot_custody(blob, wrapping, account, device, group, wide(1)?)?
  println("GROUP_CUSTODY_AUTHENTIC_HEADER_READY")
  # Offset39 is the first epoch byte after wire/GST/version/suite and group ID.
  # Changing it leaves a structurally valid owner/tree/group header; AEAD must
  # authenticate that full header rather than accepting its public claims.
  let forged = change_byte(blob, 39)?
  assert(case require_group_snapshot_custody(forged, wrapping, account, device, group, wide(1)?) do
    Err(CryptoFailure(_)) -> true
    _ -> false
  end)
  let damaged_epoch = change_byte(blob, epoch_secret_tag_offset(blob, 0)?)?
  assert(case require_group_snapshot_custody(damaged_epoch,
    wrapping,
    account,
    device,
    group,
    wide(1)?) do
    Err(CryptoFailure(_)) -> true
    _ -> false
  end)
  assert(case require_group_snapshot_custody(blob, wrong, account, device, group, wide(1)?) do
    Err(CryptoFailure(_)) -> true
    _ -> false
  end)
  require_group_snapshot_custody(blob, wrapping, account, device, group, wide(1)?)?
  Ok(nil)
end

fn authentication_checks() -> Result<(), GroupError> do
  let wrapping = key()?
  let wrong = key()?
  let result = authentication_checks_on(wrapping, wrong)
  Secret.destroy(wrong)
  Secret.destroy(wrapping)
  result
end

test("snapshot custody authenticates epoch secret against exact header and storage key") do
  assert(Result.is_ok(authentication_checks()))
end
