from Tests.Support import (
  fixture_checkpoint,
  fixture_leaves,
  fixture_linked,
  fixture_now,
  fixture_signer,
  fixture_zero_hash,
  stub_consistency_v1,
  stub_consistency_v2,
  stub_file,
  stub_posted,
  stub_publish,
  stub_queries,
  stub_relayed,
  stub_reset,
  stub_serve,
  stub_set,
  stub_start,
  stub_url
)
from Transparency.Fork import ForkEvidence, fork_decode
from Transparency.Merkle import TransparencyCheckpoint, checkpoint_hash
from Transparency.Wire import encode_checkpoint
from Witness.Config import WitnessSetup
from Witness.Round import WitnessOutcome, witness_restore, witness_round
from Witness.State import witness_halted

fn port() -> Int do
  18962
end

fn setup_for(scenario :: String,
  log_key :: Bytes,
  witness_key :: Bytes,
  require_bootstrap :: Bool,
  bootstrap :: String) -> WitnessSetup do
  WitnessSetup {
    witness_id: "witness-c",
    base_url: stub_url(port(), scenario),
    state_path: stub_file(scenario, "state"),
    log_key: log_key,
    witness_key: witness_key,
    evidence_dir: "/tmp",
    relay_urls: [stub_url(port(), scenario <> "-relay")],
    require_bootstrap: require_bootstrap,
    bootstrap: bootstrap,
    guard_path: ""
  }
end

# A host that also keeps the guard copy of its last signed checkpoint on its
# own disk, off the shared state volume.

fn guarded_setup(scenario :: String, log_key :: Bytes, witness_key :: Bytes) -> WitnessSetup do
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
    guard_path: stub_file(scenario, "guard")
  }
end

fn start(scenario :: String) do
  stub_start(port())
  stub_reset(scenario)
  stub_reset(scenario <> "-relay")
end

fn signed(outcome :: WitnessOutcome!String) -> Bool do
  case outcome do
    Ok(WitnessSigned(_)) -> true
    _ -> false
  end
end

fn refused_because(outcome :: WitnessOutcome!String, text :: String) -> Bool do
  case outcome do
    Ok(WitnessRefused(reason)) -> String.contains(reason, text)
    _ -> false
  end
end

fn halted_because(outcome :: WitnessOutcome!String, text :: String) -> Bool do
  case outcome do
    Ok(WitnessHalted(reason)) -> String.contains(reason, text)
    _ -> false
  end
end

fn posted_count(scenario :: String) -> Int!String do
  Ok(List.length(stub_posted(scenario)?))
end

fn state_holds(setup :: WitnessSetup, expected :: TransparencyCheckpoint) -> Bool!String do
  case File.read(setup.state_path) do
    Err(_) -> Ok(false)
    Ok(text) -> Ok(String.trim(text) == Bytes.to_base64(encode_checkpoint(expected)?))
  end
end

# The line of the halt marker that starts with label, without the label.

fn marker_line(setup :: WitnessSetup, label :: String) -> String!String do
  let text = case witness_halted(setup.state_path)? do
    None -> Err("no halt marker")
    Some(value) -> Ok(value)
  end?
  let lines = List.filter(String.split(text, "\n"),
    fn line -> String.starts_with(line, label <> " ") end)
  if List.length(lines) != 1 do
    Err("halt marker lacks #{label}")
  else
    let line = List.head(lines)
    Ok(String.slice(line, String.length(label) + 1, String.length(line)))
  end
end

fn evidence_field(setup :: WitnessSetup, name :: String) -> String!String do
  let path = marker_line(setup, "evidence")?
  let text = case File.read(path) do
    Err(_) -> Err("evidence file missing")
    Ok(value)
  end?
  let root = Json.parse(text)?
  Json.as_string(Json.object_get(root, name)?)
end

fn w1_proof() -> Bool!String do
  start("w1")
  let log = fixture_signer(91)?
  let witness = fixture_signer(92)?
  let setup = setup_for("w1", log.public_key.bytes, witness.public_key.bytes, false, "")
  let leaves = fixture_leaves("w1", 2)?
  let t = fixture_now()
  let first = fixture_checkpoint(log.private_key, log.public_key.bytes, 1, leaves, None, t)?
  stub_serve("w1", first)?
  assert(signed(witness_round(setup, witness.private_key, t + 500, Bytes.empty())))
  stub_publish("w1", first)?
  # A checkpoint stamped two minutes ahead is refused.
  stub_serve("w1",
    fixture_checkpoint(log.private_key, log.public_key.bytes, 2, leaves, Some(first), t + 120000)?)?
  assert(refused_because(witness_round(setup, witness.private_key, t + 1000, Bytes.empty()),
    "more than 60 s from the witness clock"))
  # So is one that is more than 60 s old when the witness sees it.
  stub_serve("w1",
    fixture_checkpoint(log.private_key, log.public_key.bytes, 2, leaves, Some(first), t + 1000)?)?
  assert(refused_because(witness_round(setup, witness.private_key, t + 70000, Bytes.empty()),
    "more than 60 s from the witness clock"))
  # And one no later than the last signed checkpoint.
  stub_serve("w1",
    fixture_checkpoint(log.private_key, log.public_key.bytes, 2, leaves, Some(first), t)?)?
  assert(refused_because(witness_round(setup, witness.private_key, t + 1000, Bytes.empty()),
    "not later than the last signed checkpoint"))
  assert(posted_count("w1")? == 1)
  assert(state_holds(setup, first)?)
  # The honest refresh: the same tree under the next sequence, linked to the
  # last signed checkpoint, needs no proof and is signed.
  let refresh = fixture_checkpoint(log.private_key,
    log.public_key.bytes,
    2,
    leaves,
    Some(first),
    t + 1000)?
  stub_serve("w1", refresh)?
  assert(signed(witness_round(setup, witness.private_key, t + 2000, Bytes.empty())))
  assert(posted_count("w1")? == 2)
  assert(List.length(stub_queries("w1")) == 0)
  Ok(state_holds(setup, refresh)?)
end

test("W1: a future or stale timestamp is refused and the honest refresh is signed") do
  case w1_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn broken_link_proof() -> Bool!String do
  start("w1-link")
  let log = fixture_signer(91)?
  let witness = fixture_signer(92)?
  let setup = setup_for("w1-link", log.public_key.bytes, witness.public_key.bytes, false, "")
  let leaves = fixture_leaves("link", 2)?
  let t = fixture_now()
  let first = fixture_checkpoint(log.private_key, log.public_key.bytes, 1, leaves, None, t)?
  stub_serve("w1-link", first)?
  assert(signed(witness_round(setup, witness.private_key, t + 500, Bytes.empty())))
  # The next sequence names a previous checkpoint other than the one signed:
  # the directory signed two checkpoints at sequence 1.
  stub_serve("w1-link",
    fixture_linked(log.private_key,
      log.public_key.bytes,
      2,
      leaves,
      fixture_zero_hash()?,
      t + 1000)?)?
  assert(halted_because(witness_round(setup, witness.private_key, t + 2000, Bytes.empty()),
    "broken-link"))
  assert(evidence_field(setup, "reason")? == "broken-link")
  Ok(posted_count("w1-link")? == 1)
end

test("W1: a checkpoint whose previous-checkpoint hash breaks the chain is refused") do
  case broken_link_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn first_byte(value :: Bytes) -> Int do
  case Bytes.get(value, 0) do
    Err(_) -> -1
    Ok(byte) -> byte
  end
end

fn growth_proof(scenario :: String, v1_only :: Bool) -> Bool!String do
  start(scenario)
  let log = fixture_signer(91)?
  let witness = fixture_signer(92)?
  let setup = setup_for(scenario, log.public_key.bytes, witness.public_key.bytes, false, "")
  let leaves = fixture_leaves(scenario, 5)?
  let t = fixture_now()
  let first = fixture_checkpoint(log.private_key,
    log.public_key.bytes,
    1,
    List.take(leaves, 2),
    None,
    t)?
  stub_serve(scenario, first)?
  assert(signed(witness_round(setup, witness.private_key, t + 500, Bytes.empty())))
  stub_publish(scenario, first)?
  let grown = fixture_checkpoint(log.private_key,
    log.public_key.bytes,
    2,
    leaves,
    Some(first),
    t + 1000)?
  stub_serve(scenario, grown)?
  stub_consistency_v2(scenario, leaves, 2, 5)?
  stub_consistency_v1(scenario, List.take(leaves, 2), leaves)?
  if v1_only do
    stub_set(scenario, "v1-only", "1")?
  end
  assert(signed(witness_round(setup, witness.private_key, t + 2000, Bytes.empty())))
  Ok(List.map(stub_queries(scenario), first_byte) == if v1_only do
      [2, 1]
    else
      [2]
    end)
end

test("growth is proved with a KTC v2 proof, and through v1 only when the directory answers v1") do
  case growth_proof("grow-v2", false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
  case growth_proof("grow-v1", true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn fork_kind(bytes :: Bytes) -> Int!String do
  let evidence = fork_decode(bytes)?
  Ok(evidence.kind)
end

# Signs first, then is served bad; returns the halted outcome's reason check,
# the evidence's FRK hex and the relayed FRKs.

fn rollback_proof() -> Bool!String do
  start("ev-rollback")
  let log = fixture_signer(91)?
  let witness = fixture_signer(92)?
  let setup = setup_for("ev-rollback", log.public_key.bytes, witness.public_key.bytes, false, "")
  let leaves = fixture_leaves("rollback", 3)?
  let t = fixture_now()
  let first = fixture_checkpoint(log.private_key, log.public_key.bytes, 1, leaves, None, t)?
  stub_serve("ev-rollback", first)?
  assert(signed(witness_round(setup, witness.private_key, t + 500, Bytes.empty())))
  # A later sequence over a smaller tree.
  let shrunk = fixture_checkpoint(log.private_key,
    log.public_key.bytes,
    2,
    List.take(leaves, 2),
    Some(first),
    t + 1000)?
  stub_serve("ev-rollback", shrunk)?
  assert(halted_because(witness_round(setup, witness.private_key, t + 2000, Bytes.empty()),
    "rollback"))
  assert(evidence_field(setup, "reason")? == "rollback")
  assert(evidence_field(setup, "previous_checkpoint")? == Bytes.to_hex(encode_checkpoint(first)?))
  assert(evidence_field(setup, "current_checkpoint")? == Bytes.to_hex(encode_checkpoint(shrunk)?))
  let frk = Bytes.from_hex(evidence_field(setup, "fork_evidence")?)?
  assert(fork_kind(frk)? == 3)
  let relayed = stub_relayed("ev-rollback-relay")
  assert(List.length(relayed) == 1)
  assert(Bytes.secure_equals(List.head(relayed), frk))
  # Never signs after a failure, even when the directory turns honest again.
  stub_serve("ev-rollback",
    fixture_checkpoint(log.private_key, log.public_key.bytes, 2, leaves, Some(first), t + 3000)?)?
  assert(halted_because(witness_round(setup, witness.private_key, t + 4000, Bytes.empty()),
    "rollback"))
  Ok(posted_count("ev-rollback")? == 1)
end

fn conflict_proof() -> Bool!String do
  start("ev-conflict")
  let log = fixture_signer(91)?
  let witness = fixture_signer(92)?
  let setup = setup_for("ev-conflict", log.public_key.bytes, witness.public_key.bytes, false, "")
  let t = fixture_now()
  let first = fixture_checkpoint(log.private_key,
    log.public_key.bytes,
    1,
    fixture_leaves("conflict-a", 2)?,
    None,
    t)?
  stub_serve("ev-conflict", first)?
  assert(signed(witness_round(setup, witness.private_key, t + 500, Bytes.empty())))
  # A second checkpoint at the same sequence and size with another root.
  let other = fixture_checkpoint(log.private_key,
    log.public_key.bytes,
    1,
    fixture_leaves("conflict-b", 2)?,
    None,
    t + 1000)?
  stub_serve("ev-conflict", other)?
  assert(halted_because(witness_round(setup, witness.private_key, t + 2000, Bytes.empty()),
    "conflict"))
  let frk = Bytes.from_hex(evidence_field(setup, "fork_evidence")?)?
  assert(fork_kind(frk)? == 1)
  assert(List.length(stub_relayed("ev-conflict-relay")) == 1)
  Ok(posted_count("ev-conflict")? == 1)
end

fn inconsistency_proof() -> Bool!String do
  start("ev-proof")
  let log = fixture_signer(91)?
  let witness = fixture_signer(92)?
  let setup = setup_for("ev-proof", log.public_key.bytes, witness.public_key.bytes, false, "")
  let t = fixture_now()
  let first = fixture_checkpoint(log.private_key,
    log.public_key.bytes,
    1,
    fixture_leaves("honest", 2)?,
    None,
    t)?
  stub_serve("ev-proof", first)?
  assert(signed(witness_round(setup, witness.private_key, t + 500, Bytes.empty())))
  # A larger tree whose history differs: no proof can join them.
  let forked_leaves = fixture_leaves("forked", 4)?
  stub_serve("ev-proof",
    fixture_checkpoint(log.private_key,
      log.public_key.bytes,
      2,
      forked_leaves,
      Some(first),
      t + 1000)?)?
  stub_consistency_v2("ev-proof", forked_leaves, 2, 4)?
  assert(halted_because(witness_round(setup, witness.private_key, t + 2000, Bytes.empty()),
    "inconsistency"))
  let proof = Bytes.from_hex(evidence_field(setup, "consistency_proof")?)?
  assert(first_byte(proof) == 2)
  # Two sizes and no leaf comparison: no FRK, so nothing is relayed.
  assert(evidence_field(setup, "fork_evidence")? == "")
  assert(List.length(stub_relayed("ev-proof-relay")) == 0)
  Ok(posted_count("ev-proof")? == 1)
end

test("a rollback, a conflict and a failed proof are kept as evidence, forks are relayed, and nothing is signed after") do
  for proof in [rollback_proof, conflict_proof, inconsistency_proof] do
    case proof() do
      Err(error) -> do
        println(error)
        assert(false)
      end
      Ok(value) -> assert(value)
    end
  end
end

fn stale_backup_proof() -> Bool!String do
  start("stale")
  let log = fixture_signer(91)?
  let witness = fixture_signer(92)?
  let setup = setup_for("stale",
    log.public_key.bytes,
    witness.public_key.bytes,
    true,
    "new-identity")
  let leaves = fixture_leaves("stale", 3)?
  let t = fixture_now()
  let first = fixture_checkpoint(log.private_key,
    log.public_key.bytes,
    1,
    List.take(leaves, 2),
    None,
    t)?
  stub_serve("stale", first)?
  assert(signed(witness_round(setup, witness.private_key, t + 500, Bytes.empty())))
  stub_publish("stale", first)?
  let backup = case File.read(setup.state_path) do
    Err(_) -> Err("state missing")
    Ok(value)
  end?
  let second = fixture_checkpoint(log.private_key,
    log.public_key.bytes,
    2,
    List.take(leaves, 2),
    Some(first),
    t + 1000)?
  stub_serve("stale", second)?
  assert(signed(witness_round(setup, witness.private_key, t + 1500, Bytes.empty())))
  stub_publish("stale", second)?
  # The operator restores the older backup and restarts the witness.
  File.write(setup.state_path, backup)?
  assert(halted_because(witness_round(setup, witness.private_key, t + 2000, Bytes.empty()),
    "stale state"))
  # The directory moves on; the witness still refuses.
  let third = fixture_checkpoint(log.private_key,
    log.public_key.bytes,
    3,
    leaves,
    Some(second),
    t + 3000)?
  stub_serve("stale", third)?
  stub_consistency_v2("stale", leaves, 2, 3)?
  assert(halted_because(witness_round(setup, witness.private_key, t + 3500, Bytes.empty()),
    "stale state"))
  assert(posted_count("stale")? == 2)
  # Continuity back from an older checkpoint is refused; from the one the
  # marker names, the witness signs again.
  let named = Bytes.from_hex(marker_line(setup, "checkpoint")?)?
  assert(Bytes.secure_equals(named, encode_checkpoint(second)?))
  File.write(setup.state_path, Bytes.to_base64(encode_checkpoint(second)?))?
  assert(witness_restore(setup,
    encode_checkpoint(first)?) == Err("restore checkpoint is older than the witness state"))
  File.write(setup.state_path, backup)?
  witness_restore(setup, named)?
  assert(signed(witness_round(setup, witness.private_key, t + 4000, Bytes.empty())))
  Ok(posted_count("stale")? == 3)
end

test("a restart from a stale backup refuses to sign until continuity is restored") do
  case stale_backup_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn guard_proof() -> Bool!String do
  start("guard")
  let log = fixture_signer(91)?
  let witness = fixture_signer(92)?
  let key = log.public_key.bytes
  let setup = guarded_setup("guard", key, witness.public_key.bytes)
  let leaves = fixture_leaves("guard", 3)?
  let t = fixture_now()
  let first = fixture_checkpoint(log.private_key, key, 1, List.take(leaves, 2), None, t)?
  stub_serve("guard", first)?
  assert(signed(witness_round(setup, witness.private_key, t + 500, Bytes.empty())))
  let backup = case File.read(setup.state_path) do
    Err(_) -> Err("state missing")
    Ok(value)
  end?
  let second = fixture_checkpoint(log.private_key,
    key,
    2,
    List.take(leaves, 2),
    Some(first),
    t + 1000)?
  stub_serve("guard", second)?
  assert(signed(witness_round(setup, witness.private_key, t + 1500, Bytes.empty())))
  # The state volume is restored from a snapshot while the directory moves
  # on: the directory shows no signature of this witness on its checkpoint,
  # but the host's guard still remembers the second one.
  File.write(setup.state_path, backup)?
  let third = fixture_checkpoint(log.private_key, key, 3, leaves, Some(second), t + 3000)?
  stub_serve("guard", third)?
  stub_consistency_v2("guard", leaves, 2, 3)?
  assert(halted_because(witness_round(setup, witness.private_key, t + 3500, Bytes.empty()),
    "stale state"))
  assert(posted_count("guard")? == 2)
  let named = Bytes.from_hex(marker_line(setup, "checkpoint")?)?
  assert(Bytes.secure_equals(named, encode_checkpoint(second)?))
  assert(witness_restore(setup,
    encode_checkpoint(first)?) == Err("restore checkpoint is older than this host's last signed checkpoint"))
  witness_restore(setup, named)?
  assert(signed(witness_round(setup, witness.private_key, t + 4000, Bytes.empty())))
  Ok(posted_count("guard")? == 3)
end

test("a state volume restored while the directory moved on is caught by the host's guard") do
  case guard_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn bootstrap_proof() -> Bool!String do
  start("boot")
  let log = fixture_signer(91)?
  let witness = fixture_signer(92)?
  let key = log.public_key.bytes
  let leaves = fixture_leaves("boot", 2)?
  let t = fixture_now()
  let first = fixture_checkpoint(log.private_key, key, 1, leaves, None, t)?
  stub_serve("boot", first)?
  # No state and no instruction: refuse, and write nothing.
  let unset = setup_for("boot", key, witness.public_key.bytes, true, "")
  assert(halted_because(witness_round(unset, witness.private_key, t + 500, Bytes.empty()),
    "explicit checkpoint transfer"))
  assert(!File.exists(unset.state_path))
  # A transferred checkpoint becomes the state; the refresh after it is signed.
  let transfer = setup_for("boot",
    key,
    witness.public_key.bytes,
    true,
    Bytes.to_hex(encode_checkpoint(first)?))
  let refresh = fixture_checkpoint(log.private_key, key, 2, leaves, Some(first), t + 1000)?
  stub_serve("boot", refresh)?
  assert(signed(witness_round(transfer, witness.private_key, t + 1500, Bytes.empty())))
  stub_publish("boot", refresh)?
  # A wiped state restarted as a new identity is caught by its own signature.
  File.delete(transfer.state_path)?
  let fresh = setup_for("boot", key, witness.public_key.bytes, true, "new-identity")
  Ok(halted_because(witness_round(fresh, witness.private_key, t + 2000, Bytes.empty()),
    "stale state"))
end

test("a pull-mode witness without state starts only as a new identity or from a transferred checkpoint") do
  case bootstrap_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
