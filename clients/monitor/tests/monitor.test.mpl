from Monitor.Cycle import monitor_cycle
from Monitor.Flags import MonitorConfig, monitor_config_parse
from Monitor.Store import monitor_kv_get, monitor_store_open
from Security.Config import SecurityConfig, security_config_parse
from Tests.Support import (
  MtestWitness,
  mtest_address,
  mtest_anchor,
  mtest_ed25519,
  mtest_file,
  mtest_leaves,
  mtest_lines,
  mtest_log_account,
  mtest_put,
  mtest_remove,
  mtest_reset,
  mtest_ring_entry,
  mtest_ring_header,
  mtest_root,
  mtest_serve_leaves,
  mtest_set,
  mtest_signer,
  mtest_start,
  mtest_transaction,
  mtest_url
)
from Transparency.Fork import ForkEvidence, ForkLog, ForkRingEntry, fork_decode, fork_verify
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  WitnessKey,
  checkpoint_hash,
  sign_checkpoint,
  sign_witness
)
from Transparency.Wire import encode_checkpoint, encode_witnesses

fn port() -> Int do
  18971
end

fn judge() -> String do
  mtest_address(17)
end

fn log_account() -> String do
  mtest_address(34)
end

fn ring_address() -> String do
  mtest_address(51)
end

fn now() -> Int do
  DateTime.to_unix_ms(DateTime.utc_now())
end

fn epoch() -> Int do
  now() / 1000 / 604800
end

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn zero_hash() -> Bytes!String do
  case Bytes.repeat(0, 32) do
    Err(_) -> Err("zero hash failed")
    Ok(value)
  end
end

fn bytes(values :: List<Int>) -> Bytes!String do
  case Bytes.from_list(values) do
    Err(_) -> Err("bytes failed")
    Ok(value)
  end
end

fn concat(left :: Bytes, right :: Bytes) -> Bytes!String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("concat failed")
    Ok(value)
  end
end

fn checkpoint(log :: borrow SigningPrivateKey,
  log_public :: Bytes,
  sequence :: Int,
  leaves :: List<Bytes>) -> TransparencyCheckpoint!String do
  sign_checkpoint(log, log_public, wide(sequence)?, leaves, zero_hash()?, wide(now())?)
end

# The RFC 7748 test vector's X25519 public key stands in for the delivery key.

fn frame(log_public :: Bytes, a :: Bytes, b :: Bytes) -> String do
  "2\n#{Bytes.to_hex(log_public)}\n8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a\n16\n2\n2\nwitness-a #{Bytes.to_hex(a)} Morse\nwitness-b #{Bytes.to_hex(b)} Morse\n-\n0\n0\n-\n-\n1"
end

fn set(log_public :: Bytes, a :: Bytes, b :: Bytes) -> SecurityConfig!String do
  security_config_parse(Bytes.from_utf8(frame(log_public, a, b)))
end

fn config(scenario :: String, sets :: List<SecurityConfig>) -> MonitorConfig!String do
  Ok(MonitorConfig {
    log_name: "morse-main",
    directory: mtest_url(port(), scenario, "dir"),
    judge: judge(),
    log_account: log_account(),
    rpc_urls: [
      mtest_url(port(), scenario, "rpc/rpc1"),
      mtest_url(port(), scenario, "rpc/rpc2"),
      mtest_url(port(), scenario, "rpc/rpc3")
    ],
    sets: sets,
    relays: [mtest_url(port(), scenario, "relay")],
    state_path: mtest_file(scenario, "state.sqlite"),
    listen: 0,
    interval_ms: 1000,
    finder: zero_hash()?,
    once: true
  })
end

# A fresh chain: the Log account (witness-a and witness-b listed from slot
# 0), an empty ring, and both providers at finalized slot 100,000.

fn chain(scenario :: String, log_public :: Bytes, a :: Bytes, b :: Bytes) -> Result<(), String> do
  mtest_start(port())
  mtest_reset(scenario)
  mtest_set(scenario, "owner", judge())?
  mtest_set(scenario, "ring-address", ring_address())?
  mtest_set(scenario, "slot", "100000")?
  mtest_put(scenario,
    "account-#{log_account()}",
    mtest_log_account("morse-main",
      log_public,
      ring_address(),
      [
        MtestWitness { witness_id: "witness-a", public_key: a, since_slot: 0 },
        MtestWitness { witness_id: "witness-b", public_key: b, since_slot: 0 }
      ]))?
  header(scenario, 0, 0, 0, 0, 0)
end

fn header(scenario :: String,
  head :: Int,
  count :: Int,
  sequence :: Int,
  size :: Int,
  slot :: Int) -> Result<(), String> do
  mtest_put(scenario,
    "ring-header",
    mtest_ring_header("morse-main", head, count, sequence, size, slot))
end

fn anchor(scenario :: String,
  index :: Int,
  value :: TransparencyCheckpoint,
  slot :: Int,
  bitmap :: Int,
  evidence :: Int) -> Result<(), String> do
  mtest_put(scenario, "ring-#{index}", mtest_anchor(value, slot, bitmap, evidence, epoch())?)
end

fn registry(scenario :: String, entries :: List<(String, Bytes)>) -> Result<(), String> do
  let items = for (id, key) in entries do
    registry_item(id, key)
  end
  mtest_set(scenario, "dir-registry", "{\"witnesses\":[#{String.join(items, ",")}]}")
end

fn registry_item(id :: String, key :: Bytes) -> String do
  "{\"witness_id\":\"#{id}\",\"public_key\":\"#{Bytes.to_hex(key)}\",\"operator\":\"Morse\",\"status\":\"pinned\",\"software\":\"mesh\",\"morse_run\":true,\"c2sp_name\":null}"
end

fn status(scenario :: String) -> Json!String do
  let db = monitor_store_open(mtest_file(scenario, "state.sqlite"))?
  let text = monitor_kv_get(db, "status")
  Sqlite.close(db)
  Json.parse(text?)
end

fn at(value :: Json, key :: String) -> Json!String do
  Json.object_get(value, key)
end

fn number(value :: Json, key :: String) -> Int!String do
  Json.as_int(at(value, key)?)
end

fn kinds(value :: Json) -> List<String>!String do
  let findings = at(value, "findings")?
  let count = Json.array_length(findings)?
  Ok(for index in 0..count do
    Json.as_string(at(Json.array_get(findings, index)?, "kind")?)?
  end)
end

fn count_of(values :: List<String>, wanted :: String) -> Int do
  List.length(List.filter(values, fn value -> value == wanted end))
end

fn notes(value :: Json) -> String!String do
  Ok(Json.encode(at(value, "notes")?))
end

fn relayed(scenario :: String) -> List<Bytes>!String do
  Ok(for line in mtest_lines(scenario, "relayed") do
    Bytes.from_hex(line)?
  end)
end

fn fork_log(log_public :: Bytes, a :: Bytes, b :: Bytes) -> ForkLog do
  ForkLog {
    service_public_key: log_public,
    witnesses: [
      WitnessKey { witness_id: "witness-a", public_key: a },
      WitnessKey { witness_id: "witness-b", public_key: b }
    ]
  }
end

fn ring_entry(value :: TransparencyCheckpoint, bitmap :: Int) -> ForkRingEntry!String do
  Ok(ForkRingEntry {
    sequence: value.sequence,
    tree_size: value.tree_size,
    root: value.tree_root,
    checkpoint_hash: checkpoint_hash(value)?,
    cosign_bitmap: bitmap
  })
end

fn run(scenario :: String, sets :: List<SecurityConfig>) -> Json!String do
  monitor_cycle(config(scenario, sets)?, now())?
  status(scenario)
end

fn report(result :: Bool!String) do
  case result do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

# --- An honest log: three anchors, each extending the last.

fn honest_proof() -> Bool!String do
  let scenario = "honest"
  let log = mtest_signer(91)?
  let a = mtest_signer(92)?
  let b = mtest_signer(93)?
  chain(scenario, log.public_key.bytes, a.public_key.bytes, b.public_key.bytes)?
  let leaves = mtest_leaves(scenario, 8)?
  let first = checkpoint(log.private_key, log.public_key.bytes, 1, List.take(leaves, 2))?
  let second = checkpoint(log.private_key, log.public_key.bytes, 2, List.take(leaves, 5))?
  let third = checkpoint(log.private_key, log.public_key.bytes, 3, leaves)?
  anchor(scenario, 0, first, 100, 3, 0)?
  anchor(scenario, 1, second, 200, 3, 0)?
  anchor(scenario, 2, third, 300, 3, 0)?
  header(scenario, 3, 3, 3, 8, 300)?
  mtest_serve_leaves(scenario, leaves)?
  mtest_put(scenario, "dir-checkpoint", encode_checkpoint(third)?)?
  mtest_set(scenario,
    "dir-anchor-2",
    "{\"sequence\":2,\"tree_size\":5,\"checkpoint_hash\":\"#{Bytes.to_hex(checkpoint_hash(second)?)}\",\"ring_index\":1,\"tx_signature\":\"sig\",\"slot\":200}")?
  registry(scenario, [("witness-a", a.public_key.bytes), ("witness-b", b.public_key.bytes)])?
  let sets = [set(log.public_key.bytes, a.public_key.bytes, b.public_key.bytes)?]
  let result = run(scenario, sets)?
  let pair = at(result, "last_verified_pair")?
  let witnesses = at(Json.array_get(at(result, "epochs")?, 0)?, "witnesses")?
  assert(Json.as_bool(at(result, "ok")?)?)
  assert(List.length(kinds(result)?) == 0)
  assert(number(pair, "old_sequence")? == 2 && number(pair, "new_sequence")? == 3)
  assert(number(at(result, "position")?, "sequence")? == 3)
  assert(number(at(result, "mirror")?, "verified_size")? == 8)
  assert(number(Json.array_get(witnesses, 0)?, "cosigned")? == 3)
  Ok(List.length(relayed(scenario)?) == 0)
end

test("an honest progression of anchors passes every check") do
  report(honest_proof())
end

# --- The directory rewrites a leaf the monitor already holds: F2.

fn rewrite_proof() -> Bool!String do
  let scenario = "rewrite"
  let log = mtest_signer(91)?
  let a = mtest_signer(92)?
  let b = mtest_signer(93)?
  chain(scenario, log.public_key.bytes, a.public_key.bytes, b.public_key.bytes)?
  let sets = [set(log.public_key.bytes, a.public_key.bytes, b.public_key.bytes)?]
  let leaves = mtest_leaves(scenario, 6)?
  let older = checkpoint(log.private_key, log.public_key.bytes, 1, List.take(leaves, 4))?
  anchor(scenario, 0, older, 100, 3, 0)?
  header(scenario, 1, 1, 1, 4, 100)?
  mtest_serve_leaves(scenario, leaves)?
  mtest_put(scenario, "dir-checkpoint", encode_checkpoint(older)?)?
  mtest_put(scenario,
    "dir-witnesses",
    encode_witnesses([sign_witness("witness-a", a.private_key, older)?])?)?
  let first = run(scenario, sets)?
  assert(List.length(kinds(first)?) == 0)
  assert(number(at(first, "mirror")?, "verified_size")? == 4)
  # History rewritten at leaf 1, then a larger tree anchored on top of it.
  let other = mtest_leaves("rewritten", 2)?
  let rewritten = [List.get(leaves, 0), List.get(other, 1)] ++ List.drop(leaves, 2)
  let newer = checkpoint(log.private_key, log.public_key.bytes, 2, rewritten)?
  anchor(scenario, 1, newer, 200, 1, 0)?
  header(scenario, 2, 2, 2, 6, 200)?
  mtest_serve_leaves(scenario, rewritten)?
  mtest_put(scenario, "dir-checkpoint", encode_checkpoint(newer)?)?
  let second = run(scenario, sets)?
  let filed = relayed(scenario)?
  assert(count_of(kinds(second)?, "fork_kind_2") == 1)
  assert(List.length(filed) == 1)
  let evidence = fork_decode(List.get(filed, 0))?
  assert(evidence.kind == 2 && evidence.ring_index == 1 && evidence.leaf_index == 1)
  assert(Bytes.secure_equals(checkpoint_hash(evidence.first)?, checkpoint_hash(older)?))
  let implicated = fork_verify(evidence,
    fork_log(log.public_key.bytes, a.public_key.bytes, b.public_key.bytes),
    Some(ring_entry(newer, 1)?))?
  let finding = Json.array_get(at(second, "findings")?, 0)?
  let filing = Json.array_get(at(finding, "filed")?, 0)?
  assert(number(filing, "status")? == 202)
  Ok(implicated == ["witness-a"])
end

test("a rewritten history between two anchors yields a verified contradiction proof, filed with the relay") do
  report(rewrite_proof())
end

# --- Two anchors of the same size with different roots, proven from the
# chain alone: the KTK from post_anchor, witness-a's statement from cosign.

fn same_size_proof() -> Bool!String do
  let scenario = "samesize"
  let log = mtest_signer(91)?
  let a = mtest_signer(92)?
  let b = mtest_signer(93)?
  chain(scenario, log.public_key.bytes, a.public_key.bytes, b.public_key.bytes)?
  let sets = [set(log.public_key.bytes, a.public_key.bytes, b.public_key.bytes)?]
  let shown = checkpoint(log.private_key, log.public_key.bytes, 1, mtest_leaves("public", 4)?)?
  let forked = checkpoint(log.private_key, log.public_key.bytes, 2, mtest_leaves("hidden", 4)?)?
  anchor(scenario, 0, shown, 100, 1, 0)?
  anchor(scenario, 1, forked, 300, 1, 1)?
  header(scenario, 2, 2, 1, 4, 100)?
  let post = concat(bytes([6, 0])?, encode_checkpoint(shown)?)?
  let attestation = sign_witness("witness-a", a.private_key, shown)?
  let witness_statement = concat(Bytes.from_utf8("mesh-msg/v1/transparency-witnesswitness-a"),
    checkpoint_hash(shown)?)?
  let ed25519 = mtest_ed25519(a.public_key.bytes, attestation.signature, witness_statement)
  mtest_set(scenario,
    "signatures",
    "[{\"signature\":\"cosA\",\"slot\":150,\"err\":null},{\"signature\":\"postA\",\"slot\":100,\"err\":null}]")?
  mtest_set(scenario,
    "tx-postA",
    mtest_transaction(100,
      [("Ed25519SigVerify111111111111111111111111111", Bytes.empty()), (judge(), post)]))?
  mtest_set(scenario,
    "tx-cosA",
    mtest_transaction(150,
      [("Ed25519SigVerify111111111111111111111111111", ed25519), (judge(), bytes([7])?)]))?
  let result = run(scenario, sets)?
  let filed = relayed(scenario)?
  assert(count_of(kinds(result)?, "fork_kind_1") == 1)
  assert(List.length(filed) == 1)
  let evidence = fork_decode(List.get(filed, 0))?
  assert(evidence.kind == 1 && evidence.ring_index == 1)
  let implicated = fork_verify(evidence,
    fork_log(log.public_key.bytes, a.public_key.bytes, b.public_key.bytes),
    Some(ring_entry(forked, 1)?))?
  Ok(implicated == ["witness-a"])
end

test("a same-size fork in the ring is proven from post_anchor and cosign data on the chain") do
  report(same_size_proof())
end

# --- Providers that disagree never produce a verdict.

fn disagreement_proof() -> Bool!String do
  let scenario = "disagree"
  let log = mtest_signer(91)?
  let a = mtest_signer(92)?
  let b = mtest_signer(93)?
  chain(scenario, log.public_key.bytes, a.public_key.bytes, b.public_key.bytes)?
  let sets = [set(log.public_key.bytes, a.public_key.bytes, b.public_key.bytes)?]
  let leaves = mtest_leaves(scenario, 6)?
  let first = checkpoint(log.private_key, log.public_key.bytes, 1, List.take(leaves, 4))?
  let second = checkpoint(log.private_key, log.public_key.bytes, 2, leaves)?
  anchor(scenario, 0, first, 100, 3, 0)?
  anchor(scenario, 1, second, 200, 3, 0)?
  header(scenario, 2, 2, 2, 6, 200)?
  mtest_serve_leaves(scenario, leaves)?
  # rpc2 shows a same-size fork of the first anchor; rpc3 is down.
  let forged = checkpoint(log.private_key, log.public_key.bytes, 2, mtest_leaves("forged", 4)?)?
  mtest_put(scenario, "rpc2-ring-1", mtest_anchor(forged, 200, 3, 0, epoch())?)?
  mtest_set(scenario, "rpc3-down", "1")?
  let split = run(scenario, sets)?
  assert(List.length(kinds(split)?) == 0)
  assert(String.contains(notes(split)?, "rpc_disagree"))
  assert(List.length(relayed(scenario)?) == 0)
  # A third provider agreeing with rpc1 outvotes rpc2.
  mtest_remove(scenario, "rpc3-down")
  let settled = run(scenario, sets)?
  assert(List.length(kinds(settled)?) == 0)
  assert(number(at(settled, "last_verified_pair")?, "new_sequence")? == 2)
  Ok(List.length(relayed(scenario)?) == 0)
end

test("providers that disagree produce no verdict until two agree") do
  report(disagreement_proof())
end

# --- The ring wraps; later the monitor falls a ring behind.

fn filler(scenario :: String, index :: Int, root :: Bytes) -> Result<(), String> do
  let sequence = (index - 4094 + 4096) % 4096 + 1
  mtest_put(scenario,
    "ring-#{index}",
    mtest_ring_entry(sequence,
      4,
      root,
      Crypto.sha256(Bytes.from_utf8("filler-#{sequence}")),
      now(),
      10,
      3,
      0,
      epoch()))
end

fn grown(scenario :: String,
  index :: Int,
  sequence :: Int,
  leaves :: List<Bytes>,
  size :: Int) -> Result<(), String> do
  mtest_put(scenario,
    "ring-#{index}",
    mtest_ring_entry(sequence,
      size,
      mtest_root(List.take(leaves, size))?,
      Crypto.sha256(Bytes.from_utf8("grown-#{sequence}")),
      now(),
      50,
      3,
      0,
      epoch()))
end

fn fill(scenario :: String, index :: Int, root :: Bytes) -> Result<(), String> do
  if index >= 4096 do
    Ok(nil)
  else
    filler(scenario, index, root)?
    fill(scenario, index + 1, root)
  end
end

fn wrap_proof() -> Bool!String do
  let scenario = "wrap"
  let log = mtest_signer(91)?
  let a = mtest_signer(92)?
  let b = mtest_signer(93)?
  chain(scenario, log.public_key.bytes, a.public_key.bytes, b.public_key.bytes)?
  let sets = [set(log.public_key.bytes, a.public_key.bytes, b.public_key.bytes)?]
  let leaves = mtest_leaves(scenario, 16)?
  mtest_serve_leaves(scenario, leaves)?
  fill(scenario, 0, mtest_root(List.take(leaves, 4))?)?
  header(scenario, 4094, 4096, 4096, 4, 10)?
  let full = run(scenario, sets)?
  assert(List.length(kinds(full)?) == 0)
  assert(number(at(full, "position")?, "ring_index")? == 4093)
  assert(number(at(full, "position")?, "sequence")? == 4096)
  assert(number(full, "pending_entries")? == 0)
  # Four more anchors across the end of the ring.
  grown(scenario, 4094, 4097, leaves, 6)?
  grown(scenario, 4095, 4098, leaves, 8)?
  grown(scenario, 0, 4099, leaves, 10)?
  grown(scenario, 1, 4100, leaves, 12)?
  header(scenario, 2, 4096, 4100, 12, 50)?
  mtest_remove(scenario, "dir-queries")
  let wrapped = run(scenario, sets)?
  assert(List.length(kinds(wrapped)?) == 0)
  assert(mtest_lines(scenario, "dir-queries") == ["4-6", "6-8", "8-10", "10-12"])
  assert(number(at(wrapped, "last_verified_pair")?, "new_sequence")? == 4100)
  # The ring laps the monitor: its last entry (index 1) is overwritten.
  grown(scenario, 1, 4101, leaves, 14)?
  grown(scenario, 2, 4102, leaves, 16)?
  header(scenario, 3, 4096, 4102, 16, 50)?
  let lapped = run(scenario, sets)?
  assert(count_of(kinds(lapped)?, "ring_gap") == 1)
  assert(List.length(kinds(lapped)?) == 1)
  Ok(number(at(lapped, "last_verified_pair")?, "new_sequence")? == 4102)
end

test("the monitor follows the ring across its end and reports a gap when lapped") do
  report(wrap_proof())
end

# --- Cosignature thresholds, judged once each cosign window has window_closed.

fn threshold_proof() -> Bool!String do
  let scenario = "threshold"
  let log = mtest_signer(91)?
  let a = mtest_signer(92)?
  let b = mtest_signer(93)?
  chain(scenario, log.public_key.bytes, a.public_key.bytes, b.public_key.bytes)?
  let sets = [set(log.public_key.bytes, a.public_key.bytes, b.public_key.bytes)?]
  let leaves = mtest_leaves(scenario, 8)?
  let first = checkpoint(log.private_key, log.public_key.bytes, 1, List.take(leaves, 2))?
  let second = checkpoint(log.private_key, log.public_key.bytes, 2, List.take(leaves, 5))?
  let third = checkpoint(log.private_key, log.public_key.bytes, 3, leaves)?
  anchor(scenario, 0, first, 100, 3, 0)?
  anchor(scenario, 1, second, 200, 1, 0)?
  anchor(scenario, 2, third, 900, 3, 0)?
  # rpc2 has not yet seen witness-b's cosign on the third anchor.
  mtest_put(scenario, "rpc2-ring-2", mtest_anchor(third, 900, 1, 0, epoch())?)?
  header(scenario, 3, 3, 3, 8, 900)?
  mtest_serve_leaves(scenario, leaves)?
  mtest_set(scenario, "slot", "1750")?
  let window_open = run(scenario, sets)?
  assert(kinds(window_open)? == ["below_threshold"])
  let details = Json.encode(at(window_open, "findings")?)
  assert(String.contains(details, "anchor 2 ") && String.contains(details, "1 of the 2"))
  mtest_remove(scenario, "rpc2-ring-2")
  mtest_set(scenario, "slot", "3000")?
  let window_closed = run(scenario, sets)?
  let current = Json.array_get(at(window_closed, "epochs")?, 0)?
  let witnesses = at(current, "witnesses")?
  assert(kinds(window_closed)? == ["below_threshold"])
  assert(number(current, "anchors")? == 3 && number(current, "below_threshold")? == 1)
  assert(number(Json.array_get(witnesses, 0)?, "cosigned")? == 3)
  Ok(number(Json.array_get(witnesses, 1)?, "cosigned")? == 2)
end

test("an anchor below every supported set's threshold is reported once its window closes") do
  report(threshold_proof())
end

# --- Registry changes the pinned sets never announced.

fn registry_proof() -> Bool!String do
  let scenario = "registry"
  let log = mtest_signer(91)?
  let a = mtest_signer(92)?
  let b = mtest_signer(93)?
  let intruder = mtest_signer(94)?
  chain(scenario, log.public_key.bytes, a.public_key.bytes, b.public_key.bytes)?
  let sets = [set(log.public_key.bytes, a.public_key.bytes, b.public_key.bytes)?]
  registry(scenario, [("witness-a", a.public_key.bytes), ("witness-b", b.public_key.bytes)])?
  let initial = run(scenario, sets)?
  assert(List.length(kinds(initial)?) == 0)
  registry(scenario, [("witness-a", intruder.public_key.bytes)])?
  let changed = kinds(run(scenario, sets)?)?
  assert(count_of(changed, "registry_key_changed") == 1)
  assert(count_of(changed, "pinned_key_differs") == 1)
  Ok(count_of(changed, "pinned_witness_missing") == 1)
end

test("a registry key change and a vanished pinned witness are reported") do
  report(registry_proof())
end

# --- A restarted monitor resumes from its state file.

fn restart_args(scenario :: String) -> List<String> do
  [
    "--log",
    "morse-main",
    "--directory",
    mtest_url(port(), scenario, "dir"),
    "--judge",
    judge(),
    "--log-account",
    log_account(),
    "--rpc",
    mtest_url(port(), scenario, "rpc/rpc1"),
    "--rpc",
    mtest_url(port(), scenario, "rpc/rpc2"),
    "--config",
    mtest_file(scenario, "config"),
    "--relay",
    mtest_url(port(), scenario, "relay"),
    "--state",
    mtest_file(scenario, "state.sqlite"),
    "--once"
  ]
end

fn restart_proof() -> Bool!String do
  let scenario = "restart"
  let log = mtest_signer(91)?
  let a = mtest_signer(92)?
  let b = mtest_signer(93)?
  chain(scenario, log.public_key.bytes, a.public_key.bytes, b.public_key.bytes)?
  mtest_set(scenario,
    "config",
    frame(log.public_key.bytes, a.public_key.bytes, b.public_key.bytes) <> "\n")?
  let leaves = mtest_leaves(scenario, 8)?
  anchor(scenario,
    0,
    checkpoint(log.private_key, log.public_key.bytes, 1, List.take(leaves, 4))?,
    100,
    3,
    0)?
  anchor(scenario,
    1,
    checkpoint(log.private_key, log.public_key.bytes, 2, List.take(leaves, 6))?,
    200,
    3,
    0)?
  header(scenario, 2, 2, 2, 6, 200)?
  mtest_serve_leaves(scenario, leaves)?
  monitor_cycle(monitor_config_parse(restart_args(scenario))?, now())?
  assert(mtest_lines(scenario, "dir-queries") == ["4-6"])
  # A new process, the same state file, one more anchor.
  mtest_remove(scenario, "dir-queries")
  anchor(scenario, 2, checkpoint(log.private_key, log.public_key.bytes, 3, leaves)?, 300, 3, 0)?
  header(scenario, 3, 3, 3, 8, 300)?
  let restarted = monitor_config_parse(restart_args(scenario))?
  assert(restarted.once && List.length(restarted.rpc_urls) == 2)
  monitor_cycle(restarted, now())?
  let result = status(scenario)?
  assert(mtest_lines(scenario, "dir-queries") == ["6-8"])
  assert(number(at(result, "last_verified_pair")?, "old_sequence")? == 2)
  Ok(number(at(result, "position")?, "sequence")? == 3)
end

test("a restarted monitor resumes from its state file") do
  report(restart_proof())
end

# --- The directory's anchor record names another checkpoint for a sequence
# the ring holds: a rollback proof (same sequence, other checkpoint).

fn record_proof() -> Bool!String do
  let scenario = "record"
  let log = mtest_signer(91)?
  let a = mtest_signer(92)?
  let b = mtest_signer(93)?
  chain(scenario, log.public_key.bytes, a.public_key.bytes, b.public_key.bytes)?
  let sets = [set(log.public_key.bytes, a.public_key.bytes, b.public_key.bytes)?]
  let leaves = mtest_leaves(scenario, 5)?
  let anchored = checkpoint(log.private_key, log.public_key.bytes, 1, List.take(leaves, 4))?
  let recorded = checkpoint(log.private_key, log.public_key.bytes, 1, leaves)?
  anchor(scenario, 0, anchored, 100, 3, 0)?
  header(scenario, 1, 1, 1, 4, 100)?
  mtest_serve_leaves(scenario, leaves)?
  mtest_set(scenario,
    "dir-anchor-1",
    "{\"sequence\":1,\"tree_size\":5,\"checkpoint_hash\":\"#{Bytes.to_hex(checkpoint_hash(recorded)?)}\",\"checkpoint\":\"#{Bytes.to_hex(encode_checkpoint(recorded)?)}\",\"ring_index\":0,\"tx_signature\":\"sig\",\"slot\":100}")?
  let result = run(scenario, sets)?
  let filed = relayed(scenario)?
  assert(count_of(kinds(result)?, "fork_kind_3") == 1)
  assert(List.length(filed) == 1)
  let evidence = fork_decode(List.get(filed, 0))?
  let implicated = fork_verify(evidence,
    fork_log(log.public_key.bytes, a.public_key.bytes, b.public_key.bytes),
    Some(ring_entry(anchored, 3)?))?
  Ok(evidence.kind == 3 && List.length(implicated) == 0)
end

test("an anchor record naming another checkpoint for the sequence yields a rollback proof") do
  report(record_proof())
end
