from Groups.Mls import GroupTransparencyPolicy
from Mobile.Codec import mobile_byte, mobile_join
from Mobile.Transparency import transparency_witness_sets
from Mobile.Types import MobileSecurityConfig
from Security.Config import SecurityConfig, SecurityWitness
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local, seal_local
from Storage.Records import store_updated_blobs

##! Mobile.GroupSets: which pinned witness set a group's policy names.
##!
##! A group policy carries a set_id and its k. A version 1 policy (no set_id)
##! is the set version 1 configs pin: witness-a and witness-b, 2 of 2. This
##! device knows its own set, the version 1 set, and every set it verified
##! under before an update. Its commits move a group to its own set; a
##! welcome or commit naming a set it does not know is newer than this build
##! (`group_witness_set_unknown`: update Morse) and waits in the mailbox.

fn same_bytes(left :: Bytes, right :: Bytes) -> Bool do
  Bytes.secure_equals(left, right)
end

# The config pins exactly the version 1 set, so its groups keep version 1
# policies and welcomes that older builds read.

fn version_one_set(config :: MobileSecurityConfig) -> Bool do
  let witnesses = config.config.witnesses
  config.config.threshold == 2
    && List.length(witnesses) == 2
    && List.get(witnesses, 0).witness_id == "witness-a"
    && List.get(witnesses, 1).witness_id == "witness-b"
    && List.all(witnesses, fn witness -> witness.label == "Morse" end)
end

fn set_entry(set_id :: Bytes, threshold :: Int) -> Bytes!String do
  mobile_join([set_id, mobile_byte(threshold)?], 0, Bytes.empty())
end

pub fn group_policy_for_config(config :: MobileSecurityConfig,
  minimum_directory_sequence :: U64,
  checkpoint_hash :: Bytes) -> GroupTransparencyPolicy do
  let pinned = !version_one_set(config)
  GroupTransparencyPolicy {
    minimum_directory_sequence: minimum_directory_sequence,
    checkpoint_hash: checkpoint_hash,
    witness_threshold: config.config.threshold,
    set_id: if pinned do
      config.config.set_id
    else
      Bytes.empty()
    end
  }
end

fn policy_is_config(config :: MobileSecurityConfig, policy :: GroupTransparencyPolicy) -> Bool do
  if Bytes.length(policy.set_id) == 0 do
    version_one_set(config) && policy.witness_threshold == 2
  else
    same_bytes(policy.set_id, config.config.set_id)
      && policy.witness_threshold == config.config.threshold
  end
end

# What this device's next commit carries: nothing while the group is on its
# set, otherwise its set_id and k.

pub fn group_set_move(config :: MobileSecurityConfig,
  policy :: GroupTransparencyPolicy) -> Bytes!String do
  if policy_is_config(config, policy) do
    Ok(Bytes.empty())
  else
    set_entry(config.config.set_id, config.config.threshold)
  end
end

fn unknown_sets_label() -> String do
  "group-unknown-sets/v1"
end

fn load_unknown_sets(database_path :: String,
  wrapping_key :: borrow StorageKey) -> List<Bytes>!String do
  case load_blob(database_path, unknown_sets_label()) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(List.new())
    else
      Err(error)
    end
    Ok(blob) -> do
      let encoded = open_local(blob, wrapping_key, local_context(unknown_sets_label())?)?
      Ok(for index in 0..Bytes.length(encoded) / 33 do
        Bytes.slice(encoded, index * 33, 33)?
      end)
    end
  end
end

fn remember_unknown_set(database_path :: String,
  wrapping_key :: borrow StorageKey,
  entry :: Bytes) -> Result<(), String> do
  let values = List.filter(load_unknown_sets(database_path, wrapping_key)?,
    fn value -> !same_bytes(value, entry) end)
    ++ [entry]
  let kept = List.drop(values, List.length(values) - 16)
  let blob = seal_local(mobile_join(kept, 0, Bytes.empty())?,
    wrapping_key,
    local_context(unknown_sets_label())?)?
  store_updated_blobs(database_path, [unknown_sets_label()], [blob])
end

fn entry_known(database_path :: String,
  wrapping_key :: borrow StorageKey,
  config :: MobileSecurityConfig,
  entry :: Bytes) -> Bool!String do
  Ok(same_bytes(entry, set_entry(config.config.set_id, config.config.threshold)?)
    || List.any(transparency_witness_sets(database_path, wrapping_key)?,
      fn value -> same_bytes(value, entry) end))
end

# A policy from a welcome: the version 1 set, or a set this device knows.

pub fn group_policy_known(database_path :: String,
  wrapping_key :: borrow StorageKey,
  config :: MobileSecurityConfig,
  policy :: GroupTransparencyPolicy) -> Result<(), String> do
  if Bytes.length(policy.set_id) == 0 do
    if policy.witness_threshold == 2 do
      Ok(nil)
    else
      Err("group_welcome_rejected")
    end
  else
    let entry = set_entry(policy.set_id, policy.witness_threshold)?
    if entry_known(database_path, wrapping_key, config, entry)? do
      Ok(nil)
    else
      remember_unknown_set(database_path, wrapping_key, entry)?
      Err("group_witness_set_unknown")
    end
  end
end

# The set a commit moves to: none, the group's own, or one this device knows.

pub fn group_commit_set_known(database_path :: String,
  wrapping_key :: borrow StorageKey,
  config :: MobileSecurityConfig,
  policy :: GroupTransparencyPolicy,
  witness_set :: Bytes) -> Result<(), String> do
  let unchanged = Bytes.length(witness_set) == 0
    || (Bytes.length(policy.set_id) == 32
      && same_bytes(witness_set, set_entry(policy.set_id, policy.witness_threshold)?))
  if unchanged do
    Ok(nil)
  else if entry_known(database_path, wrapping_key, config, witness_set)? do
    Ok(nil)
  else
    remember_unknown_set(database_path, wrapping_key, witness_set)?
    Err("group_witness_set_unknown")
  end
end

# A group named a set this build does not know and it still does not: the
# person should update Morse.

pub fn group_update_required(database_path :: String,
  wrapping_key :: borrow StorageKey,
  config :: MobileSecurityConfig) -> Bool!String do
  let unknown = load_unknown_sets(database_path, wrapping_key)?
  let known = for entry in unknown do
    entry_known(database_path, wrapping_key, config, entry)?
  end
  Ok(List.any(known, fn value -> !value end))
end
