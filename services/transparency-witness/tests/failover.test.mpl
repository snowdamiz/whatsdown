from Tests.Support import (
  fixture_checkpoint,
  fixture_leaves,
  fixture_now,
  fixture_signer,
  stub_consistency_v2,
  stub_file,
  stub_posted,
  stub_publish,
  stub_reset,
  stub_serve,
  stub_set,
  stub_start,
  stub_url
)
from Transparency.Merkle import TransparencyCheckpoint, checkpoint_hash
from Witness.Config import WitnessSetup, witness_relay_list
from Witness.Round import WitnessOutcome, witness_pull, witness_round
from Witness.State import witness_halt, witness_state_write

fn port() -> Int do
  18963
end

# Primary and standby: separate processes on separate hosts in production,
# sharing the witness key and one state volume. Here, two instances with
# separate in-memory views over one state file.

fn instance(scenario :: String, log_key :: Bytes, witness_key :: Bytes) -> WitnessSetup do
  WitnessSetup {
    witness_id: "witness-c",
    base_url: stub_url(port(), scenario),
    state_path: stub_file(scenario, "state"),
    log_key: log_key,
    witness_key: witness_key,
    evidence_dir: "/tmp",
    relay_urls: List.new(),
    require_bootstrap: true,
    bootstrap: "new-identity",
    guard_path: ""
  }
end

fn signed(outcome :: WitnessOutcome!String) -> Bool do
  case outcome do
    Ok(WitnessSigned(_)) -> true
    _ -> false
  end
end

fn halted(outcome :: WitnessOutcome!String) -> Bool do
  case outcome do
    Ok(WitnessHalted(_)) -> true
    _ -> false
  end
end

fn signed_hashes(scenario :: String) -> List<String>!String do
  Ok(List.map(stub_posted(scenario)?, fn value -> Bytes.to_hex(value.checkpoint_hash) end))
end

fn hex_hash(value :: TransparencyCheckpoint) -> String!String do
  Ok(Bytes.to_hex(checkpoint_hash(value)?))
end

fn failover_proof() -> Bool!String do
  stub_start(port())
  stub_reset("failover")
  let log = fixture_signer(81)?
  let witness = fixture_signer(82)?
  let key = log.public_key.bytes
  let primary = instance("failover", key, witness.public_key.bytes)
  let standby = instance("failover", key, witness.public_key.bytes)
  let leaves = fixture_leaves("failover", 3)?
  let t = fixture_now()
  let first = fixture_checkpoint(log.private_key, key, 1, List.take(leaves, 2), None, t)?
  stub_serve("failover", first)?
  assert(signed(witness_round(primary, witness.private_key, t + 500, Bytes.empty())))
  stub_publish("failover", first)?
  # The primary stops; the standby takes over from the shared state.
  let second = fixture_checkpoint(log.private_key,
    key,
    2,
    List.take(leaves, 2),
    Some(first),
    t + 1000)?
  stub_serve("failover", second)?
  assert(signed(witness_round(standby, witness.private_key, t + 1500, Bytes.empty())))
  stub_publish("failover", second)?
  # The primary comes back remembering only the first checkpoint: it reads the
  # state again and finds nothing to sign.
  case witness_round(primary, witness.private_key, t + 1600, checkpoint_hash(first)?)? do
    WitnessCurrent(hash) -> assert(Bytes.secure_equals(hash, checkpoint_hash(second)?))
    _ -> assert(false)
  end
  # An instance that read the first checkpoint before the standby committed
  # the second loses the compare-and-swap and cannot sign a sibling of it.
  let sibling = fixture_checkpoint(log.private_key, key, 2, leaves, Some(first), t + 1700)?
  assert(witness_state_write(primary.state_path,
    Some(first),
    sibling) == Err("witness state changed underneath this instance"))
  # A fork that extends the first checkpoint but not the second is refused by
  # either instance, and the halt is shared through the volume.
  let forked_leaves = fixture_leaves("failover-fork", 3)?
  stub_serve("failover",
    fixture_checkpoint(log.private_key, key, 3, forked_leaves, Some(second), t + 2000)?)?
  stub_consistency_v2("failover", forked_leaves, 2, 3)?
  assert(halted(witness_round(standby, witness.private_key, t + 2500, Bytes.empty())))
  assert(halted(witness_round(primary, witness.private_key, t + 2600, Bytes.empty())))
  Ok(signed_hashes("failover")? == [hex_hash(first)?, hex_hash(second)?])
end

test("primary and standby share one state and never sign a fork of each other") do
  case failover_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn pull_proof() -> Bool!String do
  stub_start(port())
  stub_reset("pull")
  let log = fixture_signer(81)?
  let witness = fixture_signer(82)?
  let key = log.public_key.bytes
  let setup = instance("pull", key, witness.public_key.bytes)
  let leaves = fixture_leaves("pull", 2)?
  let t = fixture_now()
  let first = fixture_checkpoint(log.private_key, key, 1, leaves, None, t)?
  stub_serve("pull", first)?
  # Three polls of a quiet log sign once.
  assert(witness_pull(setup, witness.private_key, 20, 3, Bytes.empty()) == Ok(nil))
  assert(List.length(stub_posted("pull")?) == 1)
  stub_publish("pull", first)?
  stub_serve("pull",
    fixture_checkpoint(log.private_key, key, 2, leaves, Some(first), fixture_now())?)?
  assert(witness_pull(setup, witness.private_key, 20, 2, Bytes.empty()) == Ok(nil))
  assert(List.length(stub_posted("pull")?) == 2)
  # A directory outage is logged and polled through.
  stub_set("pull", "checkpoint-status", "503")?
  assert(witness_pull(setup, witness.private_key, 20, 2, Bytes.empty()) == Ok(nil))
  # A halt ends the loop with its reason.
  witness_halt(setup.state_path, "operator stop")?
  Ok(witness_pull(setup, witness.private_key, 20, 0, Bytes.empty()) == Err("operator stop"))
end

test("the pull loop signs each new checkpoint once, polls through outages and stops at a halt") do
  case pull_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("relay URLs are a comma-separated list of origins") do
  assert(witness_relay_list("") == Ok(List.new()))
  assert(witness_relay_list(" https://relay-1.example/, https://relay-2.example ") == Ok([
      "https://relay-1.example",
      "https://relay-2.example"
    ]))
  assert(witness_relay_list("https://relay.example/?token=1") == Err("invalid MESSENGER_WITNESS_RELAY_URLS"))
  assert(witness_relay_list("ftp://relay.example") == Err("invalid MESSENGER_WITNESS_RELAY_URLS"))
end
