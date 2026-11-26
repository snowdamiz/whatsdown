##! Stubs for the monitor tests, all on one local HTTP server: Solana RPC
##! providers (POST /<scenario>/rpc/<provider>), a directory
##! (/<scenario>/dir/v1/transparency/...) and a relay
##! (POST /<scenario>/relay/v1/fork-evidence). Each scenario's chain,
##! directory and recorded requests live in /tmp files the tests write. A
##! provider answers from its own override file (<provider>-<name>) when one
##! exists, else from the scenario's shared chain.

from Transparency.CompactWire import (
  CompactConsistency,
  CompactInclusion,
  TransparencyLeafProof,
  transparency_decode_leaf_query,
  transparency_decode_tree_query_v2,
  transparency_encode_consistency_v2,
  transparency_encode_leaf_proof
)
from Transparency.Merkle import TransparencyCheckpoint, checkpoint_hash, leaf_hash
from Transparency.Tree import (
  tlog_consistency_path,
  tlog_inclusion_path,
  tlog_list_oracle,
  tlog_root
)

pub fn mtest_file(scenario :: String, name :: String) -> String do
  "/tmp/morse-monitor-stub-#{scenario}-#{name}"
end

fn param(request :: Request, name :: String) -> String do
  case Request.param(request, name) do
    None -> ""
    Some(value) -> value
  end
end

fn read_text(scenario :: String, name :: String) -> Option<String> do
  case File.read(mtest_file(scenario, name)) do
    Err(_) -> None
    Ok(text) -> Some(text)
  end
end

fn read_hex(scenario :: String, name :: String) -> Option<Bytes> do
  case read_text(scenario, name) do
    None
    Some(text) -> case Bytes.from_hex(String.trim(text)) do
      Err(_) -> None
      Ok(value) -> Some(value)
    end
  end
end

fn record(scenario :: String, name :: String, line :: String) do
  File.append(mtest_file(scenario, name), line <> "\n")
end

pub fn mtest_put(scenario :: String, name :: String, value :: Bytes) -> Result<(), String> do
  File.write(mtest_file(scenario, name), Bytes.to_hex(value))
end

pub fn mtest_set(scenario :: String, name :: String, text :: String) -> Result<(), String> do
  File.write(mtest_file(scenario, name), text)
end

pub fn mtest_remove(scenario :: String, name :: String) do
  File.delete(mtest_file(scenario, name))
end

pub fn mtest_lines(scenario :: String, name :: String) -> List<String> do
  case read_text(scenario, name) do
    None -> List.new()
    Some(text) -> List.filter(String.split(text, "\n"), fn line -> String.length(line) > 0 end)
  end
end

# --- The RPC providers.

fn provider_hex(scenario :: String, provider :: String, name :: String) -> Option<Bytes> do
  case read_hex(scenario, "#{provider}-#{name}") do
    Some(value)
    None -> read_hex(scenario, name)
  end
end

fn provider_text(scenario :: String,
  provider :: String,
  name :: String,
  fallback :: String) -> String do
  case read_text(scenario, "#{provider}-#{name}") do
    Some(value) -> value
    None -> case read_text(scenario, name) do
      Some(value) -> value
      None -> fallback
    end
  end
end

fn zeros(count :: Int) -> Bytes do
  case Bytes.repeat(0, count) do
    Err(_) -> Bytes.empty()
    Ok(value) -> value
  end
end

fn joined(parts :: List<Bytes>) -> Bytes do
  List.reduce(parts,
    Bytes.empty(),
    fn acc, part -> case Bytes.concat(acc, part) do
      Err(_) -> acc
      Ok(value) -> value
    end end)
end

fn ring_entry_bytes(scenario :: String, provider :: String, index :: Int) -> Bytes do
  case provider_hex(scenario, provider, "ring-#{index}") do
    None -> zeros(104)
    Some(value) -> value
  end
end

fn ring_slice(scenario :: String,
  provider :: String,
  offset :: Int,
  length :: Int) -> Option<Bytes> do
  if offset == 0 do
    provider_hex(scenario, provider, "ring-header")
  else
    let first = (offset - 64) / 104
    Some(joined(for index in first..first + length / 104 do
      ring_entry_bytes(scenario, provider, index)
    end))
  end
end

fn account_slice(scenario :: String,
  provider :: String,
  address :: String,
  offset :: Int,
  length :: Int) -> Option<Bytes> do
  let ring = case read_text(scenario, "ring-address") do
    None -> ""
    Some(text) -> String.trim(text)
  end
  if address == ring do
    ring_slice(scenario, provider, offset, length)
  else
    case provider_hex(scenario, provider, "account-#{address}") do
      None
      Some(data) -> case Bytes.slice(data, offset, length) do
        Err(_) -> None
        Ok(value) -> Some(value)
      end
    end
  end
end

fn json_int(value :: Json, key :: String) -> Int do
  case Json.object_get(value, key) do
    Err(_) -> 0
    Ok(field) -> case Json.as_int(field) do
      Err(_) -> 0
      Ok(parsed) -> parsed
    end
  end
end

fn rpc_answer(result :: String) -> Response do
  HTTP.response_with_headers(200,
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":#{result}}",
    %{"Content-Type" => "application/json"})
end

fn account_info(scenario :: String, provider :: String, params :: Json) -> String!String do
  let address = Json.as_string(Json.array_get(params, 0)?)?
  let slice = Json.object_get(Json.array_get(params, 1)?, "dataSlice")?
  let slot = String.trim(provider_text(scenario, provider, "slot", "1000"))
  let owner = String.trim(provider_text(scenario, provider, "owner", ""))
  case account_slice(scenario,
    provider,
    address,
    json_int(slice, "offset"),
    json_int(slice, "length")) do
    None -> Ok("{\"context\":{\"slot\":#{slot}},\"value\":null}")
    Some(data) -> Ok("{\"context\":{\"slot\":#{slot}},\"value\":{\"data\":[\"#{Bytes.to_base64(data)}\",\"base64\"],\"owner\":\"#{owner}\",\"lamports\":1,\"executable\":false,\"rentEpoch\":0}}")
  end
end

fn transaction(scenario :: String, params :: Json) -> String!String do
  let signature = Json.as_string(Json.array_get(params, 0)?)?
  case read_text(scenario, "tx-#{signature}") do
    None -> Ok("null")
    Some(text) -> Ok(text)
  end
end

fn signatures(scenario :: String, params :: Json) -> String!String do
  let options = Json.array_get(params, 1)?
  case Json.object_get(options, "before") do
    Ok(_) -> Ok("[]")
    Err(_) -> Ok(case read_text(scenario, "signatures") do
      None -> "[]"
      Some(text) -> text
    end)
  end
end

fn rpc_result(scenario :: String, provider :: String, body :: String) -> String!String do
  let root = Json.parse(body)?
  let method = Json.as_string(Json.object_get(root, "method")?)?
  let params = Json.object_get(root, "params")?
  if method == "getAccountInfo" do
    account_info(scenario, provider, params)
  else if method == "getTransaction" do
    transaction(scenario, params)
  else if method == "getSignaturesForAddress" do
    signatures(scenario, params)
  else
    Err("unsupported method #{method}")
  end
end

fn stub_rpc(request :: Request) -> Response do
  let scenario = param(request, "scenario")
  let provider = param(request, "provider")
  if File.exists(mtest_file(scenario, "#{provider}-down")) do
    HTTP.response(503, "")
  else
    case rpc_result(scenario, provider, Request.body(request)) do
      Err(error) -> HTTP.response(400, error)
      Ok(result) -> rpc_answer(result)
    end
  end
end

# --- The directory, answering from its leaf list.

fn dir_leaves(scenario :: String) -> List<Bytes> do
  List.flat_map(mtest_lines(scenario, "dir-leaves"),
    fn line -> case Bytes.from_hex(line) do
      Err(_) -> List.new()
      Ok(value) -> [value]
    end end)
end

fn dir_down(scenario :: String) -> Bool do
  File.exists(mtest_file(scenario, "dir-down"))
end

fn stored_or_404(scenario :: String, name :: String) -> Response do
  case read_hex(scenario, name) do
    None -> HTTP.response(404, "")
    Some(body) -> HTTP.response_bytes(200, body)
  end
end

fn stub_checkpoint(request :: Request) -> Response do
  let scenario = param(request, "scenario")
  if dir_down(scenario) do
    HTTP.response(503, "")
  else
    stored_or_404(scenario, "dir-checkpoint")
  end
end

fn stub_witnesses(request :: Request) -> Response do
  stored_or_404(param(request, "scenario"), "dir-witnesses")
end

fn stub_registry(request :: Request) -> Response do
  case read_text(param(request, "scenario"), "dir-registry") do
    None -> HTTP.response(503, "")
    Some(text) -> HTTP.response(200, text)
  end
end

fn stub_anchor(request :: Request) -> Response do
  let scenario = param(request, "scenario")
  if dir_down(scenario) do
    HTTP.response(503, "")
  else
    case read_text(scenario, "dir-anchor-#{param(request, "sequence")}") do
      None -> HTTP.response(404, "")
      Some(text) -> HTTP.response(200, text)
    end
  end
end

fn consistency(scenario :: String, body :: Bytes) -> Bytes!String do
  let query = transparency_decode_tree_query_v2(body)?
  record(scenario, "dir-queries", "#{query.old_size}-#{query.new_size}")
  let leaves = dir_leaves(scenario)
  if query.new_size > List.length(leaves) do
    Err("beyond the log")
  else
    transparency_encode_consistency_v2(CompactConsistency {
      old_size: query.old_size,
      new_size: query.new_size,
      path: tlog_consistency_path(1, tlog_list_oracle(1, leaves), query.old_size, query.new_size)?
    })
  end
end

fn stub_consistency(request :: Request) -> Response do
  let scenario = param(request, "scenario")
  if dir_down(scenario) do
    HTTP.response(503, "")
  else
    case consistency(scenario, Request.body_bytes(request)) do
      Err(_) -> HTTP.response(400, "")
      Ok(proof) -> HTTP.response_bytes(200, proof)
    end
  end
end

fn leaf(scenario :: String, body :: Bytes) -> Bytes!String do
  let query = transparency_decode_leaf_query(body)?
  let leaves = List.take(dir_leaves(scenario), query.tree_size)
  if query.leaf_index >= List.length(leaves) || query.tree_size > List.length(leaves) do
    Err("beyond the log")
  else
    transparency_encode_leaf_proof(TransparencyLeafProof {
      leaf_hash: List.get(leaves, query.leaf_index),
      inclusion: CompactInclusion {
        leaf_index: query.leaf_index,
        tree_size: query.tree_size,
        path: tlog_inclusion_path(1,
          tlog_list_oracle(1, leaves),
          query.leaf_index,
          query.tree_size)?
      }
    })
  end
end

fn stub_leaf(request :: Request) -> Response do
  case leaf(param(request, "scenario"), Request.body_bytes(request)) do
    Err(_) -> HTTP.response(400, "")
    Ok(proof) -> HTTP.response_bytes(200, proof)
  end
end

fn query_int(request :: Request, name :: String) -> Int do
  case Request.query(request, name) do
    None -> 0
    Some(text) -> case String.to_int(text) do
      None -> 0
      Some(value) -> value
    end
  end
end

fn stub_leaves(request :: Request) -> Response do
  let scenario = param(request, "scenario")
  let leaves = List.take(List.drop(dir_leaves(scenario), query_int(request, "start")),
    query_int(request, "count"))
  HTTP.response_bytes(200, joined(leaves))
end

fn stub_relay(request :: Request) -> Response do
  let scenario = param(request, "scenario")
  record(scenario, "relayed", Bytes.to_hex(Request.body_bytes(request)))
  HTTP.response(202, "")
end

actor stub_server(port :: Int) do
  if Process.register("monitor-stub-#{port}", self()) == 0 do
    HTTP.router()
      |> HTTP.on_post("/:scenario/rpc/:provider", stub_rpc)
      |> HTTP.on_get("/:scenario/dir/v1/transparency/checkpoint", stub_checkpoint)
      |> HTTP.on_get("/:scenario/dir/v1/transparency/witnesses", stub_witnesses)
      |> HTTP.on_get("/:scenario/dir/v1/transparency/registry", stub_registry)
      |> HTTP.on_get("/:scenario/dir/v1/transparency/anchor/:sequence", stub_anchor)
      |> HTTP.on_post("/:scenario/dir/v1/transparency/consistency", stub_consistency)
      |> HTTP.on_post("/:scenario/dir/v1/transparency/leaf", stub_leaf)
      |> HTTP.on_get("/:scenario/dir/v1/transparency/leaves", stub_leaves)
      |> HTTP.on_post("/:scenario/relay/v1/fork-evidence", stub_relay)
      |> HTTP.serve(port)
  end
end

pub fn mtest_start(port :: Int) do
  let _server = spawn(stub_server, port)
  Timer.sleep(150)
end

pub fn mtest_url(port :: Int, scenario :: String, part :: String) -> String do
  "http://127.0.0.1:#{port}/#{scenario}/#{part}"
end

# --- Fixtures: keys, addresses, judge account bytes.

pub fn mtest_signer(value :: Int) -> SigningKeyPair!String do
  case Bytes.repeat(value, 32) do
    Err(_) -> Err("seed failed")
    Ok(seed) -> case Crypto.signing_from_seed(seed) do
      Err(_) -> Err("signing key failed")
      Ok(pair)
    end
  end
end

pub fn mtest_address(value :: Int) -> String do
  case Bytes.repeat(value, 32) do
    Err(_) -> ""
    Ok(bytes) -> Bytes.to_base58(bytes)
  end
end

fn le(value :: Int, width :: Int) -> Bytes do
  case Bytes.write_uint_le(Int.to_string(value), width) do
    Err(_) -> zeros(width)
    Ok(bytes) -> bytes
  end
end

fn padded(value :: Bytes, width :: Int) -> Bytes do
  joined([value, zeros(width - Bytes.length(value))])
end

pub struct MtestWitness do
  witness_id :: String
  public_key :: Bytes
  since_slot :: Int
end

fn list_entry(witness :: MtestWitness) -> Bytes do
  let id = Bytes.from_utf8(witness.witness_id)
  joined([
    le(Bytes.length(id), 1),
    padded(id, 64),
    zeros(7),
    witness.public_key,
    zeros(32),
    le(witness.since_slot, 8)
  ])
end

fn address_bytes(address :: String) -> Bytes do
  case Bytes.from_base58(address) do
    Err(_) -> zeros(32)
    Ok(bytes) -> bytes
  end
end

pub fn mtest_log_id(name :: String) -> Bytes do
  padded(Bytes.from_utf8(name), 32)
end

pub fn mtest_log_account(name :: String,
  service_key :: Bytes,
  ring :: String,
  witnesses :: List<MtestWitness>) -> Bytes do
  let list = joined(List.map(witnesses, list_entry))
  joined([
    le(2, 1),
    le(1, 1),
    zeros(1),
    zeros(1),
    le(List.length(witnesses), 1),
    zeros(11),
    mtest_log_id(name),
    service_key,
    zeros(32),
    address_bytes(ring),
    zeros(32),
    zeros(32),
    zeros(8),
    zeros(64),
    padded(list, 2304)
  ])
end

pub fn mtest_ring_header(name :: String,
  head :: Int,
  count :: Int,
  last_sequence :: Int,
  last_size :: Int,
  last_slot :: Int) -> Bytes do
  joined([
    mtest_log_id(name),
    le(head, 4),
    le(count, 4),
    le(last_sequence, 8),
    le(last_size, 8),
    le(last_slot, 8)
  ])
end

pub fn mtest_ring_entry(sequence :: Int,
  tree_size :: Int,
  root :: Bytes,
  hash :: Bytes,
  timestamp_ms :: Int,
  slot :: Int,
  bitmap :: Int,
  evidence :: Int,
  epoch :: Int) -> Bytes do
  joined([
    le(sequence, 8),
    le(tree_size, 8),
    root,
    hash,
    le(timestamp_ms, 8),
    le(slot, 8),
    le(bitmap, 2),
    le(evidence, 1),
    zeros(1),
    le(epoch, 4)
  ])
end

fn int_of(value :: U64) -> Int do
  case U64.to_int(value) do
    Err(_) -> 0
    Ok(parsed) -> parsed
  end
end

pub fn mtest_anchor(checkpoint :: TransparencyCheckpoint,
  slot :: Int,
  bitmap :: Int,
  evidence :: Int,
  epoch :: Int) -> Bytes!String do
  Ok(mtest_ring_entry(int_of(checkpoint.sequence),
    int_of(checkpoint.tree_size),
    checkpoint.tree_root,
    checkpoint_hash(checkpoint)?,
    int_of(checkpoint.timestamp),
    slot,
    bitmap,
    evidence,
    epoch))
end

pub fn mtest_leaves(prefix :: String, count :: Int) -> List<Bytes>!String do
  Ok(for index in 0..count do
    leaf_hash(Bytes.from_utf8("#{prefix}-#{index}"))?
  end)
end

pub fn mtest_root(leaves :: List<Bytes>) -> Bytes!String do
  tlog_root(1, tlog_list_oracle(1, leaves), List.length(leaves))
end

pub fn mtest_serve_leaves(scenario :: String, leaves :: List<Bytes>) -> Result<(), String> do
  mtest_set(scenario,
    "dir-leaves",
    String.join(List.map(leaves, fn value -> Bytes.to_hex(value) end), "\n"))
end

pub fn mtest_reset(scenario :: String) do
  for name in [
    "dir-leaves",
    "dir-checkpoint",
    "dir-witnesses",
    "dir-registry",
    "dir-down",
    "dir-queries",
    "relayed",
    "signatures",
    "ring-address",
    "ring-header",
    "slot",
    "owner",
    "rpc1-down",
    "rpc2-down",
    "rpc3-down",
    "rpc1-slot",
    "rpc2-slot",
    "rpc3-slot",
    "state.sqlite",
    "state.sqlite-journal",
    "config"
  ] do
    File.delete(mtest_file(scenario, name))
  end
end

# Ed25519 program instruction data holding one witness statement, laid out as
# @solana/web3.js does (protocol/morse-judge-v1.md §5).

pub fn mtest_ed25519(public_key :: Bytes, signature :: Bytes, message :: Bytes) -> Bytes do
  joined([
    le(1, 1),
    zeros(1),
    le(48, 2),
    le(65535, 2),
    le(16, 2),
    le(65535, 2),
    le(112, 2),
    le(Bytes.length(message), 2),
    le(65535, 2),
    public_key,
    signature,
    message
  ])
end

# A getTransaction answer (json encoding) with one instruction per (program,
# data) pair; account keys are the programs in order.

pub fn mtest_transaction(slot :: Int, instructions :: List<(String, Bytes)>) -> String do
  let keys = for (program, _) in instructions do
    Json.encode_string(program)
  end
  let items = for index in 0..List.length(instructions) do
    mtest_instruction_json(index, instructions)
  end
  "{\"slot\":#{slot},\"meta\":{\"err\":null},\"transaction\":{\"signatures\":[],\"message\":{\"accountKeys\":[#{String.join(keys,
    ",")}],\"instructions\":[#{String.join(items, ",")}]}}}"
end

pub fn mtest_instruction_json(index :: Int, instructions :: List<(String, Bytes)>) -> String do
  let (_, data) = List.get(instructions, index)
  "{\"programIdIndex\":#{index},\"accounts\":[],\"data\":\"#{Bytes.to_base58(data)}\"}"
end
