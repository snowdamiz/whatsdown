from Monitor.Policy import MonitorPolicy, monitor_threshold, monitor_successors
from Transparency.AnchorRing import AnchorEntry
from Transparency.AnchorWitnessSet import AnchorWitnessSet, AnchorWitness
from Transparency.Config import WitnessPin

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn bytes(value :: String) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, 32))
end

fn member(id :: String, key :: String) -> AnchorWitness!String do
  Ok(AnchorWitness {
    address: bytes(key)?,
    witness_id: id,
    public_key: bytes(key)?,
    payout: bytes("ff")?
  })
end

fn policy(values :: List<AnchorWitness>) -> MonitorPolicy do
  MonitorPolicy {
    threshold: List.length(values) / 2 + 1,
    witnesses: for value in values do
      WitnessPin {
        witness_id: value.witness_id,
        public_key: value.public_key,
        operator_label: "operator"
      }
    end
  }
end

fn entry(sequence :: Int, slot :: Int, hash :: String) -> AnchorEntry!String do
  Ok(AnchorEntry {
    sequence: wide(sequence)?,
    tree_size: wide(sequence)?,
    tree_root: bytes(hash)?,
    checkpoint_hash: bytes(hash)?,
    timestamp: wide(slot)?,
    slot: wide(slot)?,
    cosign_bitmap: 0,
    log_version: 2,
    rollback: false,
    native_bitmap: 0,
    witness_generation: 7
  })
end

fn check() -> Bool!String do
  let a = member("a", "11")?
  let b = member("b", "22")?
  let c = member("c", "33")?
  let rotated = member("c", "44")?
  let d = member("d", "55")?
  let set = AnchorWitnessSet {
    log_id: bytes("aa")?,
    generation: 7,
    ready_at: wide(0)?,
    witnesses: [a, b, rotated, d]
  }
  let old = policy([a, b, c])
  let next = policy([b, rotated, d])
  let first = entry(1, 100, "01")?
  assert(!monitor_threshold(%{first | cosign_bitmap: 9}, Some(set), [old, next])?)
  assert(monitor_threshold(%{first | cosign_bitmap: 12}, Some(set), [old, next])?)
  assert(!monitor_threshold(%{first | cosign_bitmap: 5}, Some(set), [old])?)
  assert(monitor_threshold(%{first | cosign_bitmap: 3, native_bitmap: 0}, Some(set), [old])?)
  assert(!monitor_threshold(%{first | witness_generation: 0}, None, [old])?)
  case monitor_threshold(first, Some(%{set | generation: 8}), [old]) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  case monitor_threshold(first, Some(set), [%{old | threshold: 1}]) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  let second = entry(2, 200, "02")?
  let third = entry(3, 300, "03")?
  assert(monitor_successors([first, second, third], None)? == [0, 1, 2])
  assert(monitor_successors([first, second, third], Some(first))? == [1, 2])
  assert(monitor_successors([first, second, third], Some(%{second | cosign_bitmap: 3}))? == [2])
  assert(List.length(monitor_successors([first, second, third], Some(third))?) == 0)
  # A ring wrap cannot silently skip unseen anchors, nor may a replay of an
  # older checkpoint at a new slot impersonate the saved cursor.
  case monitor_successors([second, third], Some(first)) do
    Err(error) -> assert(error == "monitor_history_gap")
    Ok(_) -> assert(false)
  end
  case monitor_successors([%{first | slot: wide(101)?}, second], Some(first)) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  # Rollbacks must reach the fork verifier, not disappear in sequence sorting.
  let rollback = %{first | slot: wide(301)?, rollback: true}
  assert(monitor_successors([first, second, third, rollback], Some(third))? == [3])
  Ok(true)
end

test("monitor follows posting order and requires one complete supported witness policy") do
  case check() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
