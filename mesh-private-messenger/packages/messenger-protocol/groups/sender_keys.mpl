from Groups.GroupCodec import group_append, group_write_u32
from Groups.KeySchedule import group_chain_id, group_derive_secret
from Groups.Mls import GroupError, TreeKemKeyMaterial

pub fn fork_keys(keys :: borrow SecretMap) -> SecretMap ! GroupError do
  case SecretMap.fork(keys) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value) -> Ok(value)
  end
end

fn copy_key(keys :: borrow SecretMap, id :: Bytes) -> SecretBytes ! GroupError do
  case SecretMap.copy(keys, id) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value) -> Ok(value)
  end
end

fn delete_key(keys :: borrow SecretMap, id :: Bytes) -> Result <(), GroupError > do
  case SecretMap.delete(keys, id) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(_) -> Ok(nil)
  end
end

fn insert_key(keys :: borrow SecretMap, id :: Bytes, key :: SecretBytes) -> Result <(), GroupError > do
  case SecretMap.insert(keys, id, key) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(_) -> Ok(nil)
  end
end

pub fn skipped_id(leaf :: Int, generation :: Int) -> Bytes ! GroupError do
  group_append(group_chain_id(leaf) ?, group_write_u32(generation) ?)
end

pub fn sender_message_key(chains :: borrow SecretMap,
group_id :: Bytes,
leaf :: Int,
generation :: Int) -> SecretBytes ! GroupError do
  let chain = copy_key(chains, group_chain_id(leaf) ?) ?
  group_derive_secret(chain,
  group_id,
  group_append(Bytes.from_utf8("mesh-mls/v2/message-key"), skipped_id(leaf, generation) ?) ?)
end

fn step_chain(chains :: borrow SecretMap, group_id :: Bytes, leaf :: Int, generation :: Int) -> Result <(), GroupError > do
  let id = group_chain_id(leaf) ?
  let chain = copy_key(chains, id) ?
  let next = group_derive_secret(chain,
  group_id,
  group_append(Bytes.from_utf8("mesh-mls/v2/chain-next"), skipped_id(leaf, generation) ?) ?) ?
  delete_key(chains, id) ?
  insert_key(chains, id, next)
end

pub fn advance_sender(chains :: borrow SecretMap, group_id :: Bytes, leaf :: Int, generation :: Int) -> SecretMap ! GroupError do
  let candidate = fork_keys(chains) ?
  step_chain(candidate, group_id, leaf, generation) ?
  Ok(candidate)
end

# The reordering window is 32 generations per sender, at most 64 keys per group.
# Capacity errors preserve committed state; an authenticated epoch refresh clears the window.

fn prune_skipped(skipped :: borrow SecretMap, leaf :: Int, generation :: Int, stop :: Int) -> Result <(), GroupError > do
  if generation >= stop do
    Ok(nil)
  else
    if generation >= 0 do
      delete_key(skipped, skipped_id(leaf, generation) ?) ?
    else
      nil
    end
    prune_skipped(skipped, leaf, generation + 1, stop)
  end
end

fn skip_until(chains :: borrow SecretMap,
skipped :: borrow SecretMap,
group_id :: Bytes,
leaf :: Int,
current :: Int,
target :: Int) -> SecretBytes ! GroupError do
  let key = sender_message_key(chains, group_id, leaf, current) ?
  step_chain(chains, group_id, leaf, current) ?
  if current == target do
    Ok(key)
  else
    insert_key(skipped, skipped_id(leaf, current) ?, key) ?
    skip_until(chains, skipped, group_id, leaf, current + 1, target)
  end
end

pub fn receive_key(material :: borrow TreeKemKeyMaterial,
group_id :: Bytes,
leaf :: Int,
generation :: Int,
last :: Int) -> Result <(SecretMap, SecretMap, SecretBytes), GroupError > do
  if generation > last + 33 || generation >= 4294967295 do
    return Err(InvalidGroup)
  end
  let chains = fork_keys(material.sender_chains) ?
  let skipped = fork_keys(material.skipped_keys) ?
  if generation <= last do
    let id = skipped_id(leaf, generation) ?
    if generation < last - 32 || !SecretMap.contains(skipped, id) do
      Err(Replay)
    else
      let key = copy_key(skipped, id) ?
      delete_key(skipped, id) ?
      Ok((chains, skipped, key))
    end
  else
    prune_skipped(skipped, leaf, last - 32, generation - 32) ?
    let key = skip_until(chains, skipped, group_id, leaf, last + 1, generation) ?
    Ok((chains, skipped, key))
  end
end
