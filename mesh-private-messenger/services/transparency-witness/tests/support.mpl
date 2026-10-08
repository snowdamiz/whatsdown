##! A stub directory and relay for the witness tests. Each scenario is a path
##! prefix (http://127.0.0.1:<port>/<scenario>) whose answers the test writes
##! into /tmp files; what the witness posts is appended to /tmp files.

from Transparency.CompactWire import CompactConsistency, transparency_encode_consistency_v2
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  checkpoint_hash,
  consistency_proof,
  leaf_hash,
  sign_checkpoint
)
from Transparency.Tree import tlog_consistency_path, tlog_list_oracle
from Transparency.Wire import (
  decode_witnesses,
  encode_checkpoint,
  encode_consistency_proof,
  encode_witnesses
)

pub fn stub_file(scenario :: String, name :: String) -> String do
  "/tmp/morse-witness-stub-#{scenario}-#{name}"
end

fn scenario_of(request :: Request) -> String do
  case Request.param(request, "scenario") do
    None -> "none"
    Some(value) -> value
  end
end

fn stored(scenario :: String, name :: String) -> Option<Bytes> do
  case File.read(stub_file(scenario, name)) do
    Err(_) -> None
    Ok(text) -> case Bytes.from_hex(String.trim(text)) do
      Err(_) -> None
      Ok(value) -> Some(value)
    end
  end
end

fn status_override(scenario :: String, name :: String, fallback :: Int) -> Int do
  case File.read(stub_file(scenario, name)) do
    Err(_) -> fallback
    Ok(text) -> case String.to_int(String.trim(text)) do
      None -> fallback
      Some(value) -> value
    end
  end
end

fn record(scenario :: String, name :: String, body :: Bytes) do
  File.append(stub_file(scenario, name), Bytes.to_hex(body) <> "\n")
end

fn stub_checkpoint(request :: Request) -> Response do
  let scenario = scenario_of(request)
  let status = status_override(scenario, "checkpoint-status", 200)
  case stored(scenario, "checkpoint") do
    None -> HTTP.response(404, "")
    Some(body) -> HTTP.response_bytes(status, body)
  end
end

fn stub_witnesses(request :: Request) -> Response do
  let scenario = scenario_of(request)
  case stored(scenario, "witnesses") do
    Some(body) -> HTTP.response_bytes(200, body)
    None -> case encode_witnesses([]) do
      Err(_) -> HTTP.response(500, "")
      Ok(body) -> HTTP.response_bytes(200, body)
    end
  end
end

fn stub_submit(request :: Request) -> Response do
  let scenario = scenario_of(request)
  record(scenario, "posted", Request.body_bytes(request))
  HTTP.response(status_override(scenario, "post-status", 201), "")
end

fn stub_consistency(request :: Request) -> Response do
  let scenario = scenario_of(request)
  let body = Request.body_bytes(request)
  record(scenario, "queries", body)
  let version = case Bytes.get(body, 0) do
    Err(_) -> 0
    Ok(value) -> value
  end
  let answer = if version == 2 && !File.exists(stub_file(scenario, "v1-only")) do
    stored(scenario, "consistency-v2")
  else if version == 1 do
    stored(scenario, "consistency-v1")
  else
    None
  end
  case answer do
    None -> HTTP.response(400, "")
    Some(proof) -> HTTP.response_bytes(200, proof)
  end
end

fn stub_relay(request :: Request) -> Response do
  record(scenario_of(request), "relayed", Request.body_bytes(request))
  HTTP.response(202, "")
end

actor stub_server(port :: Int) do
  if Process.register("witness-stub-#{port}", self()) == 0 do
    HTTP.router()
      |> HTTP.on_get("/:scenario/v1/transparency/checkpoint", stub_checkpoint)
      |> HTTP.on_get("/:scenario/v1/transparency/witnesses", stub_witnesses)
      |> HTTP.on_post("/:scenario/v1/transparency/witnesses", stub_submit)
      |> HTTP.on_post("/:scenario/v1/transparency/consistency", stub_consistency)
      |> HTTP.on_post("/:scenario/v1/fork-evidence", stub_relay)
      |> HTTP.serve(port)
  end
end

# Starts the stub once per test binary: a later server finds the name taken
# and returns without listening.

pub fn stub_start(port :: Int) do
  let _server = spawn(stub_server, port)
  Timer.sleep(150)
end

pub fn stub_url(port :: Int, scenario :: String) -> String do
  "http://127.0.0.1:#{port}/#{scenario}"
end

pub fn stub_reset(scenario :: String) do
  for name in [
    "checkpoint",
    "checkpoint-status",
    "witnesses",
    "posted",
    "post-status",
    "consistency-v2",
    "consistency-v1",
    "v1-only",
    "queries",
    "relayed",
    "state",
    "state.halted",
    "guard"
  ] do
    File.delete(stub_file(scenario, name))
  end
end

pub fn stub_put(scenario :: String, name :: String, value :: Bytes) -> Result<(), String> do
  File.write(stub_file(scenario, name), Bytes.to_hex(value))
end

pub fn stub_set(scenario :: String, name :: String, text :: String) -> Result<(), String> do
  File.write(stub_file(scenario, name), text)
end

pub fn stub_serve(scenario :: String, checkpoint :: TransparencyCheckpoint) -> Result<(), String> do
  stub_put(scenario, "checkpoint", encode_checkpoint(checkpoint)?)
end

fn recorded(scenario :: String, name :: String) -> List<Bytes> do
  case File.read(stub_file(scenario, name)) do
    Err(_) -> List.new()
    Ok(text) -> List.flat_map(String.split(text, "\n"),
      fn line -> case Bytes.from_hex(line) do
        Err(_) -> List.new()
        Ok(value) -> if Bytes.length(value) == 0 do
          List.new()
        else
          [value]
        end
      end end)
  end
end

pub fn stub_posted(scenario :: String) -> List<WitnessAttestation>!String do
  let bodies = recorded(scenario, "posted")
  Ok(List.flat_map(bodies,
    fn body -> case decode_witnesses(body) do
      Err(_) -> List.new()
      Ok(values) -> values
    end end))
end

pub fn stub_relayed(scenario :: String) -> List<Bytes> do
  recorded(scenario, "relayed")
end

pub fn stub_queries(scenario :: String) -> List<Bytes> do
  recorded(scenario, "queries")
end

# What an honest directory does with the posted attestations: serves the ones
# for the current checkpoint from GET /v1/transparency/witnesses.

pub fn stub_publish(scenario :: String,
  checkpoint :: TransparencyCheckpoint) -> Result<(), String> do
  let hash = checkpoint_hash(checkpoint)?
  let current = List.filter(stub_posted(scenario)?,
    fn value -> Bytes.secure_equals(value.checkpoint_hash, hash) end)
  stub_put(scenario, "witnesses", encode_witnesses(current)?)
end

pub fn stub_consistency_v2(scenario :: String,
  leaves :: List<Bytes>,
  old_size :: Int,
  new_size :: Int) -> Result<(), String> do
  let path = tlog_consistency_path(1, tlog_list_oracle(1, leaves), old_size, new_size)?
  stub_put(scenario,
    "consistency-v2",
    transparency_encode_consistency_v2(CompactConsistency {
      old_size: old_size,
      new_size: new_size,
      path: path
    })?)
end

pub fn stub_consistency_v1(scenario :: String,
  old_leaves :: List<Bytes>,
  new_leaves :: List<Bytes>) -> Result<(), String> do
  stub_put(scenario,
    "consistency-v1",
    encode_consistency_proof(consistency_proof(old_leaves, new_leaves)?)?)
end

pub fn fixture_seed(value :: Int) -> Bytes!String do
  case Bytes.repeat(value, 32) do
    Err(_) -> Err("seed failed")
    Ok(bytes)
  end
end

pub fn fixture_signer(value :: Int) -> SigningKeyPair!String do
  case Crypto.signing_from_seed(fixture_seed(value)?) do
    Err(_) -> Err("signing key failed")
    Ok(pair)
  end
end

pub fn fixture_now() -> Int do
  DateTime.to_unix_ms(DateTime.utc_now())
end

pub fn fixture_leaves(prefix :: String, count :: Int) -> List<Bytes>!String do
  let entries = for index in 0..count do
    Bytes.from_utf8("#{prefix}-#{index}")
  end
  Ok(List.flat_map(entries,
    fn entry -> case leaf_hash(entry) do
      Err(_) -> List.new()
      Ok(value) -> [value]
    end end))
end

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

pub fn fixture_zero_hash() -> Bytes!String do
  case Bytes.repeat(0, 32) do
    Err(_) -> Err("zero hash failed")
    Ok(bytes)
  end
end

# A checkpoint the log key signs over leaves, linked to previous (None: the
# first checkpoint), stamped at timestamp_ms.

pub fn fixture_checkpoint(log :: borrow SigningPrivateKey,
  log_public :: Bytes,
  sequence :: Int,
  leaves :: List<Bytes>,
  previous :: Option<TransparencyCheckpoint>,
  timestamp_ms :: Int) -> TransparencyCheckpoint!String do
  let previous_hash = case previous do
    None -> fixture_zero_hash()
    Some(value) -> checkpoint_hash(value)
  end?
  sign_checkpoint(log, log_public, wide(sequence)?, leaves, previous_hash, wide(timestamp_ms)?)
end

pub fn fixture_linked(log :: borrow SigningPrivateKey,
  log_public :: Bytes,
  sequence :: Int,
  leaves :: List<Bytes>,
  previous_hash :: Bytes,
  timestamp_ms :: Int) -> TransparencyCheckpoint!String do
  sign_checkpoint(log, log_public, wide(sequence)?, leaves, previous_hash, wide(timestamp_ms)?)
end

pub fn fixture_prefix(values :: List<Bytes>, count :: Int) -> List<Bytes> do
  List.take(values, count)
end
