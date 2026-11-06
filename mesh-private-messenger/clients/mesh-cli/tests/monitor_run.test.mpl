from Monitor.Run import run_monitor_once
from Monitor.Config import MonitorConfig, monitor_configuration_for
from Monitor.State import MonitorState, load_monitor_state
from Transparency.Config import decode_security_config, encode_security_config
from Transparency.AnchorChain import AnchorPins, anchor_addresses
from Transparency.Merkle import (
  TransparencyCheckpoint,
  checkpoint_hash,
  sign_tree_checkpoint_for,
  merkle_root_for,
  leaf_hash_for,
  compact_consistency_proof_for,
  compact_inclusion_proof_for
)
from Transparency.Wire import encode_checkpoint, encode_consistency_proof
from Transparency.LeafProof import LeafProof, decode_leaf_query, encode_leaf_proof
from Transparency.Fork import ForkProof, ForkPaths, ForkTarget, decode_fork, encode_fork
from Transparency.AnchorContext import decode_anchor_context
from Transparency.Relay import RelayVerification, verify_relay_fork
from Solana.Read import Pubkey, pubkey

struct Fixture do
  mode_path :: String
  first :: TransparencyCheckpoint
  second :: TransparencyCheckpoint
  forked :: TransparencyCheckpoint
  grown :: TransparencyCheckpoint
  rollback :: TransparencyCheckpoint
  leaves :: List<Bytes>
  changed :: List<Bytes>
  log :: Bytes
  witnesses :: Bytes
  registry :: String
end

fn join(parts :: List<Bytes>) -> Bytes!String do
  if List.length(parts) == 0 do
    Ok(Bytes.empty())
  else
    Bytes.concat(List.head(parts), join(List.tail(parts))?)
  end
end

fn zeroes(count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat("00", count))
end

fn wide(number :: Int) -> U64!String do
  U64.parse(Int.to_string(number))
end

fn le(number :: Int, width :: Int) -> Bytes!String do
  Bytes.write_uint_le(Int.to_string(number), width)
end

fn frame() -> Bytes do
  Bytes.from_utf8(String.join([
      "4",
      String.repeat("11", 32),
      String.repeat("22", 32),
      "8",
      "2",
      "2",
      "a #{String.repeat("01", 32)} Morse",
      "b #{String.repeat("02", 32)} Outside",
      "5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb",
      "3",
      "https://one.example",
      "https://two.example",
      "https://three.example",
      "-",
      "2",
      "2",
      "2",
      "a #{String.repeat("01", 32)} Morse",
      "b #{String.repeat("02", 32)} Outside",
      String.repeat("1", 32),
      "morse-main"
    ],
    "\n"))
end

fn member(id :: String, number :: Int) -> Bytes!String do
  let key = Bytes.from_hex(String.repeat(if number == 1 do
      "01"
    else
      "02"
    end,
    32))?
  join([key, le(1, 1)?, zeroes(7)?, Bytes.from_utf8(id), zeroes(63)?, key, key])
end

fn checkpoints(fixture :: Fixture, mode :: String) -> List<TransparencyCheckpoint> do
  if mode == "single" || mode == "hide" do
    [fixture.first]
  else if mode == "f1" do
    [fixture.first, fixture.second, fixture.forked]
  else if mode == "f2" do
    [fixture.first, fixture.second, fixture.grown]
  else if mode == "f3" do
    [fixture.first, fixture.second, fixture.rollback]
  else
    [fixture.first, fixture.second]
  end
end

fn entry(checkpoint :: TransparencyCheckpoint, position :: Int, mode :: String) -> Bytes!String do
  let signed = if position == 0 || mode == "late" || mode == "rotated" do
    3
  else
    0
  end
  join([
    le(U64.to_int(checkpoint.sequence)?, 8)?,
    le(U64.to_int(checkpoint.tree_size)?, 8)?,
    checkpoint.tree_root,
    checkpoint_hash(checkpoint)?,
    le(U64.to_int(checkpoint.timestamp)?, 8)?,
    le(100 + position * 100, 8)?,
    le(signed, 2)?,
    le(checkpoint.version, 1)?,
    le(if mode == "f3" && position == 2 do
        1
      else
        0
      end,
      1)?,
    le(signed, 2)?,
    le(1, 2)?
  ])
end

fn rpc(request :: Request, fixture :: Fixture) -> Bytes!String do
  let mode = File.read(fixture.mode_path)?
  if mode == "outage" do
    return Err("offline")
  end
  let document = Json.parse(Request.body(request))?
  let method = Json.as_string(Json.object_get(document, "method")?)?
  if method == "getBlockTime" do
    return Ok(Bytes.from_utf8("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":1700000000}"))
  end
  let params = Json.object_get(document, "params")?
  let options = Json.array_get(params, 1)?
  let slice = Json.object_get(options, "dataSlice")?
  let offset = Json.as_int(Json.object_get(slice, "offset")?)?
  let length = Json.as_int(Json.object_get(slice, "length")?)?
  let values = checkpoints(fixture, mode)
  let count = List.length(values)
  let last = List.get(values, count - 1)
  let header = join([
    Bytes.from_hex("4d524701")?,
    Crypto.sha256(Bytes.from_utf8("morse-main")),
    le(count - 1, 2)?,
    le(count, 2)?,
    le(U64.to_int(last.sequence)?, 8)?,
    le(U64.to_int(last.tree_size)?, 8)?,
    le(count * 100, 8)?
  ])?
  let bytes = if length == 352 do
    fixture.log
  else if length == 2752 do
    fixture.witnesses
  else if offset == 0 do
    header
  else
    let start = (offset - 64) / 104
    join(for position in start..(start + length / 104) do
      entry(List.get(values, position), position, mode)?
    end)?
  end
  let slot = if mode == "expired" do
    1801
  else
    400
  end
  Ok(Bytes.from_utf8("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"slot\":#{slot}},\"value\":{\"data\":[\"#{Bytes.to_base64(bytes)}\",\"base64\"],\"executable\":false,\"lamports\":1,\"owner\":\"11111111111111111111111111111111\",\"rentEpoch\":0}}}"))
end

fn response(result :: Bytes!String) -> Response do
  case result do
    Err(_) -> HTTP.response(503, "unavailable")
    Ok(bytes) -> HTTP.response_bytes(200, bytes)
  end
end

fn checkpoint_response(request :: Request, fixture :: Fixture) -> Bytes!String do
  let sequence = case Bytes.read_u64_be(Request.body_bytes(request), 0) do
    Err(_) -> return Err("bad sequence")
    Ok(value) -> U64.to_int(value)?
  end
  let values = checkpoints(fixture, File.read(fixture.mode_path)?)
  if sequence < 1 || sequence > List.length(values) do
    return Err("not found")
  end
  encode_checkpoint(List.get(values, sequence - 1))
end

fn consistency(fixture :: Fixture) -> Bytes!String do
  let mode = File.read(fixture.mode_path)?
  if mode == "bad" || mode == "f2" do
    return Ok(Bytes.from_utf8("invalid proof"))
  end
  encode_consistency_proof(compact_consistency_proof_for(fixture.first.version,
    List.take(fixture.leaves, U64.to_int(fixture.first.tree_size)?),
    List.take(fixture.leaves, U64.to_int(fixture.second.tree_size)?))?)
end

fn leaf(request :: Request, fixture :: Fixture) -> Bytes!String do
  let query = decode_leaf_query(Request.body_bytes(request))?
  let mode = File.read(fixture.mode_path)?
  if mode == "bad" do
    return Err("no leaf")
  end
  let leaves = List.take(if mode == "f2"
      && query.tree_size == U64.to_int(fixture.grown.tree_size)? do
      fixture.changed
    else
      fixture.leaves
    end,
    query.tree_size)
  encode_leaf_proof(LeafProof {
    leaf_hash: List.get(leaves, query.leaf_index),
    inclusion: compact_inclusion_proof_for(fixture.first.version, leaves, query.leaf_index)?
  })
end

fn registry(fixture :: Fixture) -> Response do
  let changed = File.read(fixture.mode_path).unwrap_or("") == "rotated"
  HTTP.response(200,
    if changed do
      "{\"witnesses\":[{\"witness_id\":\"a\",\"public_key\":\"#{String.repeat("03",
        32)}\",\"status\":\"pinned\"},{\"witness_id\":\"b\",\"public_key\":\"#{String.repeat("02",
        32)}\",\"status\":\"pinned\"}]}"
    else
      fixture.registry
    end)
end

actor server(port :: Int, fixture :: Fixture) do
  let prefix = "/v#{fixture.first.version}/transparency/"
  HTTP.router()
    |> HTTP.on_post("/", fn(request :: Request) do response(rpc(request, fixture)) end)
    |> HTTP.on_post(prefix <> "checkpoint",
      fn(request :: Request) do response(checkpoint_response(request, fixture)) end)
    |> HTTP.on_post(prefix <> "consistency",
      fn(_request :: Request) do response(consistency(fixture)) end)
    |> HTTP.on_post(prefix <> "leaf",
      fn(request :: Request) do response(leaf(request, fixture)) end)
    |> HTTP.on_get("/v1/transparency/registry", fn(_request :: Request) do registry(fixture) end)
    |> HTTP.serve(port)
end

fn has(report :: String, issue :: String) -> Bool do
  String.contains(report, Json.encode_string(issue))
end

fn healthy(report :: String) -> Bool!String do
  Json.as_bool(Json.object_get(Json.parse(report)?, "healthy")?)
end

fn scenario(version :: Int) -> Result<(), String> do
  let signer = case Crypto.signing_generate() do
    Err(_) -> return Err("signer")
    Ok(value) -> value
  end
  let leaves = for text in ["a", "b", "c"] do
    leaf_hash_for(version, Bytes.from_utf8(text))?
  end
  let changed = [leaf_hash_for(version, Bytes.from_utf8("different"))?] ++ List.drop(leaves, 1)
  let first = sign_tree_checkpoint_for(version,
    signer.private_key,
    signer.public_key.bytes,
    wide(1)?,
    wide(1)?,
    merkle_root_for(version, List.take(leaves, 1))?,
    zeroes(32)?,
    wide(1700000000000)?)?
  let second = sign_tree_checkpoint_for(version,
    signer.private_key,
    signer.public_key.bytes,
    wide(2)?,
    wide(2)?,
    merkle_root_for(version, List.take(leaves, 2))?,
    checkpoint_hash(first)?,
    wide(1700000001000)?)?
  let forked = sign_tree_checkpoint_for(version,
    signer.private_key,
    signer.public_key.bytes,
    wide(3)?,
    wide(2)?,
    merkle_root_for(version, List.take(changed, 2))?,
    checkpoint_hash(second)?,
    wide(1700000002000)?)?
  let grown = sign_tree_checkpoint_for(version,
    signer.private_key,
    signer.public_key.bytes,
    wide(3)?,
    wide(3)?,
    merkle_root_for(version, changed)?,
    checkpoint_hash(second)?,
    wide(1700000002000)?)?
  let rollback = sign_tree_checkpoint_for(version,
    signer.private_key,
    signer.public_key.bytes,
    wide(3)?,
    wide(1)?,
    first.tree_root,
    checkpoint_hash(second)?,
    wide(1700000002000)?)?
  let directory = "/tmp/morse-monitor-run-" <> Crypto.uuid4()
  let mode_path = directory <> "-mode"
  File.write(mode_path, "single")?
  let port = 19120 + version * 10
  let origin = "http://127.0.0.1:#{port}"
  let config_frame = decode_security_config(frame())?
  let config = monitor_configuration_for("morse-main",
    origin,
    directory <> "-monitor.sqlite",
    [encode_security_config(%{config_frame | service_public_key: signer.public_key.bytes})?],
    version)?
  let config = %{config |
    pins: %{config.pins |
      endpoints: for offset in 0..3 do
        "http://127.0.0.1:#{port + offset}"
      end
    }
  }
  let name = Bytes.from_utf8("morse-main")
  let note_origin = if version == 2 do
    "morse.example/log"
  else
    ""
  end
  let log = join([
    Bytes.from_hex("4d4c4701")?,
    le(version, 1)?,
    le(0, 1)?,
    le(10, 1)?,
    le(0, 1)?,
    name,
    zeroes(22)?,
    config.pins.log_id,
    signer.public_key.bytes,
    signer.public_key.bytes,
    config.pins.ring.bytes,
    zeroes(32)?,
    le(0, 8)?,
    le(1, 2)?,
    le(String.length(note_origin), 2)?,
    Bytes.from_utf8(note_origin),
    zeroes(128 - String.length(note_origin))?,
    zeroes(12)?
  ])?
  let witnesses = join([
    Bytes.from_hex("4d575301")?,
    config.pins.log_id,
    le(1, 2)?,
    le(2, 1)?,
    le(0, 1)?,
    zeroes(24)?,
    member("a", 1)?,
    member("b", 2)?,
    zeroes(14 * 168)?
  ])?
  let fixture = Fixture {
    mode_path: mode_path,
    first: first,
    second: second,
    forked: forked,
    grown: grown,
    rollback: rollback,
    leaves: leaves,
    changed: changed,
    log: log,
    witnesses: witnesses,
    registry: "{\"witnesses\":[{\"witness_id\":\"a\",\"public_key\":\"#{String.repeat("01",
      32)}\",\"status\":\"pinned\"},{\"witness_id\":\"b\",\"public_key\":\"#{String.repeat("02",
      32)}\",\"status\":\"pinned\"}]}"
  }
  let _one = spawn(server, port, fixture)
  let _two = spawn(server, port + 1, fixture)
  let _three = spawn(server, port + 2, fixture)
  Timer.sleep(100)
  let now = 1700000010000
  assert(healthy(run_monitor_once(config, now)?)?)
  File.write(mode_path, "pair")?
  let waiting = run_monitor_once(config, now + 1000)?
  assert(!healthy(waiting)? && has(waiting, "witness_threshold_pending"))
  assert(Bytes.length(load_monitor_state(config.path, config.identity)?.pending_entry) == 0)
  File.write(mode_path, "late")?
  assert(healthy(run_monitor_once(config, now + 2000)?)?)
  File.write(mode_path, "rotated")?
  assert(has(run_monitor_once(config, now + 3000)?, "registry_key_changed"))
  assert(has(run_monitor_once(config, now + 4000)?, "registry_key_changed"))
  File.write(mode_path, "outage")?
  assert(!healthy(run_monitor_once(config, now + 5000)?)?)
  File.write(mode_path, "late")?
  assert(healthy(run_monitor_once(config, now + 6000)?)?)
  for kind in [1, 2, 3] do
    let separate = %{config | path: directory <> "-fork-#{kind}.sqlite"}
    assert(healthy(run_monitor_once(separate, now)?)?)
    File.write(mode_path, "f#{kind}")?
    let report = run_monitor_once(separate, now + 1000)?
    assert(has(report, "fork_detected"))
    let saved = load_monitor_state(separate.path, separate.identity)?
    assert(decode_fork(saved.proof)?.kind == kind)
    let context = decode_anchor_context(saved.proof_context)?
    assert(Bytes.secure_equals(context.fork, saved.proof) && Bytes.length(context.entry) == 104)
    let verified = verify_relay_fork(config.pins,
      signer.public_key.bytes,
      version,
      saved.proof,
      wide(0)?)?
    assert(Bytes.secure_equals(verified.proof, saved.proof))
    assert(Bytes.secure_equals(verified.finder, zeroes(32)?))
    assert(Bytes.length(verified.anchor_entry) == 104 && !verified.service_slashed)
    # A relay preserves the finder and canonical proof exactly. Its proof hash
    # remains independent of the finder for the judge's pay-once account.
    let named = encode_fork(%{decode_fork(saved.proof)? | finder: signer.public_key.bytes})?
    let named_verdict = verify_relay_fork(config.pins,
      signer.public_key.bytes,
      version,
      named,
      wide(0)?)?
    assert(Bytes.secure_equals(named_verdict.proof_hash, verified.proof_hash))
    assert(Bytes.secure_equals(named_verdict.finder, signer.public_key.bytes))
    let signed = encode_fork(%{decode_fork(named)? |
      second: SignedCheckpoint(List.get(checkpoints(fixture, "f#{kind}"), 2))
    })?
    let signed_verdict = verify_relay_fork(config.pins,
      signer.public_key.bytes,
      version,
      signed,
      wide(0)?)?
    assert(Bytes.secure_equals(signed_verdict.proof, signed)
      && Bytes.length(signed_verdict.anchor_entry) == 0)
    File.write(mode_path, "late")?
    case verify_relay_fork(config.pins, signer.public_key.bytes, version, saved.proof, wide(0)?) do
      Err(error) -> assert(error == "relay_anchor_missing")
      Ok(_) -> assert(false)
    end
    assert(has(run_monitor_once(separate, now + 2000)?, "fork_detected"))
    assert(Bytes.secure_equals(load_monitor_state(separate.path, separate.identity)?.proof,
      saved.proof))
    assert(Bytes.secure_equals(load_monitor_state(separate.path, separate.identity)?.proof_context,
      saved.proof_context))
  end
  let pending = %{config | path: directory <> "-pending.sqlite"}
  File.write(mode_path, "single")?
  assert(healthy(run_monitor_once(pending, now)?)?)
  File.write(mode_path, "bad")?
  assert(has(run_monitor_once(pending, now + 1000)?, "consistency_mismatch"))
  let unresolved = load_monitor_state(pending.path, pending.identity)?
  assert(Bytes.length(unresolved.proof) == 0 && Bytes.length(unresolved.pending_entry) == 104)
  File.write(mode_path, "hide")?
  assert(!healthy(run_monitor_once(pending, now + 2000)?)?)
  assert(Bytes.secure_equals(load_monitor_state(pending.path, pending.identity)?.pending_entry,
    unresolved.pending_entry))
  File.write(mode_path, "late")?
  assert(healthy(run_monitor_once(pending, now + 3000)?)?)
  let missed = %{config | path: directory <> "-missed.sqlite"}
  File.write(mode_path, "expired")?
  assert(has(run_monitor_once(missed, now)?, "witness_threshold_missed"))
  # The only contradictory leaf lies beyond the first pass's sixteen probes.
  # A new run must resume the saved probe, not restart at the first leaf.
  let many = for index in 0..21 do
    leaf_hash_for(version, Bytes.from_utf8("leaf-#{index}"))?
  end
  let altered = List.take(many, 19)
    ++ [leaf_hash_for(version, Bytes.from_utf8("conflict-at-19"))?]
    ++ List.drop(many, 20)
  let base = sign_tree_checkpoint_for(version,
    signer.private_key,
    signer.public_key.bytes,
    wide(1)?,
    wide(19)?,
    merkle_root_for(version, List.take(many, 19))?,
    zeroes(32)?,
    wide(1700000000000)?)?
  let next = sign_tree_checkpoint_for(version,
    signer.private_key,
    signer.public_key.bytes,
    wide(2)?,
    wide(20)?,
    merkle_root_for(version, List.take(many, 20))?,
    checkpoint_hash(base)?,
    wide(1700000001000)?)?
  let bigger = sign_tree_checkpoint_for(version,
    signer.private_key,
    signer.public_key.bytes,
    wide(3)?,
    wide(21)?,
    merkle_root_for(version, altered)?,
    checkpoint_hash(next)?,
    wide(1700000002000)?)?
  let long_fixture = %{fixture |
    first: base,
    second: next,
    grown: bigger,
    leaves: many,
    changed: altered
  }
  let _four = spawn(server, port + 100, long_fixture)
  let _five = spawn(server, port + 101, long_fixture)
  let _six = spawn(server, port + 102, long_fixture)
  Timer.sleep(100)
  let long_config = monitor_configuration_for("morse-main",
    "http://127.0.0.1:#{port + 100}",
    directory <> "-long.sqlite",
    [encode_security_config(%{config_frame | service_public_key: signer.public_key.bytes})?],
    version)?
  let long_config = %{long_config |
    pins: %{long_config.pins |
      endpoints: for offset in 100..103 do
        "http://127.0.0.1:#{port + offset}"
      end
    }
  }
  File.write(mode_path, "late")?
  assert(healthy(run_monitor_once(long_config, now)?)?)
  File.write(mode_path, "f2")?
  assert(has(run_monitor_once(long_config, now + 1000)?, "consistency_mismatch"))
  let searching = load_monitor_state(long_config.path, long_config.identity)?
  assert(searching.probe_index == 16 && Bytes.length(searching.proof) == 0)
  assert(has(run_monitor_once(long_config, now + 2000)?, "fork_detected"))
  case decode_fork(load_monitor_state(long_config.path,
    long_config.identity)?.proof)?.contradiction do
    None -> assert(false)
    Some(paths) -> assert(U64.to_string(paths.leaf_index) == "19")
  end
  for suffix in [
    "-monitor.sqlite",
    "-fork-1.sqlite",
    "-fork-2.sqlite",
    "-fork-3.sqlite",
    "-pending.sqlite",
    "-missed.sqlite",
    "-long.sqlite",
    "-mode"
  ] do
    File.delete(directory <> suffix)?
  end
  Ok(nil)
end

test("monitor polls both log versions, revisits late cosigns, retains registry warnings and F1/F2/F3 across restart") do
  for version in [1, 2] do
    case scenario(version) do
      Err(error) -> do
        println(error)
        assert(false)
      end
      Ok(_) -> nil
    end
  end
end
