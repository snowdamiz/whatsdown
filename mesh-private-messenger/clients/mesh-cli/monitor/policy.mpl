from Transparency.AnchorRing import AnchorEntry
from Transparency.AnchorWitnessSet import AnchorWitnessSet, AnchorCosigner, anchor_cosigners
from Transparency.Config import WitnessPin, witness_set_id

pub struct MonitorPolicy do
  witnesses :: List<WitnessPin>
  threshold :: Int
end

# Chain registration alone never grants monitor trust. During a release
# rotation, one complete supported policy must pass; their votes cannot pool.
pub fn monitor_threshold(entry :: AnchorEntry,
  set :: Option<AnchorWitnessSet>,
  policies :: List<MonitorPolicy>) -> Bool!String do
  if List.length(policies) < 1 || List.length(policies) > 16 do
    return Err("invalid_monitor_policies")
  end
  for policy in policies do
    witness_set_id(policy.witnesses, policy.threshold)?
  end
  if entry.witness_generation == 0 do
    if entry.cosign_bitmap != 0 || entry.native_bitmap != 0 do
      return Err("anchor_witness_set_mismatch")
    end
    return Ok(false)
  end
  let generation = case set do
    None -> return Err("anchor_witness_set_unavailable")
    Some(value) -> value
  end
  let cosigners = anchor_cosigners(entry, generation)?
  for policy in policies do
    let signed = List.filter(policy.witnesses,
      fn(pin) do List.any(cosigners,
        fn(signer) do signer.witness_id == pin.witness_id
          && Bytes.secure_equals(signer.public_key, pin.public_key) end) end)
    if List.length(signed) >= policy.threshold do
      return Ok(true)
    end
  end
  Ok(false)
end

fn same_entry(left :: AnchorEntry, right :: AnchorEntry) -> Bool do
  U64.compare(left.slot, right.slot) == 0
    && Bytes.secure_equals(left.checkpoint_hash, right.checkpoint_hash)
    && U64.compare(left.sequence, right.sequence) == 0
    && U64.compare(left.tree_size, right.tree_size) == 0
    && U64.compare(left.timestamp, right.timestamp) == 0
    && Bytes.secure_equals(left.tree_root, right.tree_root)
    && left.log_version == right.log_version
    && left.witness_generation == right.witness_generation
    && left.rollback == right.rollback
end

# Input is an authenticated stable ring snapshot, oldest to newest. Preserve
# posting order: a signed sequence/size rollback is evidence to inspect.
pub fn monitor_successors(entries :: List<AnchorEntry>,
  previous :: Option<AnchorEntry>) -> List<Int>!String do
  if List.length(entries) > 4096 do
    return Err("invalid_monitor_snapshot")
  end
  let start = case previous do
    None -> 0
    Some(saved) -> do
      let found = List.find(List.enumerate(entries),
        fn(pair) do
          let (_, value) = pair
          same_entry(value, saved)
        end)
      case found do
        None -> return Err("monitor_history_gap")
        Some((index, _)) -> index + 1
      end
    end
  end
  Ok(for index in start..List.length(entries) do
    index
  end)
end
