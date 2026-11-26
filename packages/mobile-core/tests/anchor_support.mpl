from MobileCore import (
  anchor_check_export,
  network_status_export,
  trust_alarm_details_export,
  verify_transparency_export
)
from Mobile.Platform import native_security_config
from Mobile.TrustAlarm import (
  TrustAlarm,
  trust_alarm_clear_mismatch,
  trust_alarm_raise,
  trust_summary_none
)
from Mobile.Types import MobileSecurityConfig
from Security.Config import SecurityConfig, SecurityWitness, security_config_encode
from Tests.GroupConsistencySupport import request, wide
from Tests.Support import append, consistency_v2, evidence_v2, read_u32, repeated, vector, write_u32
from Transparency.CompactWire import (
  CompactInclusion,
  TransparencyLeafProof,
  transparency_decode_leaf_query,
  transparency_decode_tree_query_v2,
  transparency_encode_leaf_proof
)
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  checkpoint_hash,
  sign_checkpoint,
  sign_witness
)
from Transparency.Tree import tlog_inclusion_path, tlog_list_oracle

##! A fake Solana chain, fake RPC providers, a fake directory and fake relays
##! for the anchor check (Mobile.Anchor), and a driver that answers each step
##! the way the app does.

pub struct FakeAccount do
  address :: String
  owner :: String
  data :: Bytes
  entries :: List<Bytes>
  indexes :: List<Int>
end

pub struct FakeProvider do
  url :: String
  accounts :: List<FakeAccount>
  block_time :: Int
  up :: Bool
end

pub struct FakeAnswer do
  status :: Int
  body :: Bytes
end

pub struct AnchorTrace do
  kind :: Int
  tag :: String
  target :: String
  body :: Bytes
  status :: Int
  answer :: Bytes
end

pub struct DetailRelay do
  url :: String
  status :: Int
end

pub struct DetailFrk do
  bytes :: Bytes
  proof_hash :: Bytes
  complete :: Bool
  landed :: Bool
  paid_to :: Bytes
  relays :: List<DetailRelay>
end

pub struct DetailAlarm do
  kind :: Int
  active :: Bool
  frks :: List<DetailFrk>
end

pub fn join(parts :: List<Bytes>) -> Bytes!String do
  join_from(parts, 0, Bytes.empty())
end

fn join_from(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    join_from(parts, index + 1, append(output, List.get(parts, index))?)
  end
end

pub fn le(value :: Int, width :: Int) -> Bytes!String do
  case Bytes.write_uint_le(Int.to_string(value), width) do
    Err(_) -> Err("test integer encoding failed")
    Ok(encoded)
  end
end

pub fn bytes_of(values :: List<Int>) -> Bytes!String do
  case Bytes.from_list(values) do
    Err(_) -> Err("test byte encoding failed")
    Ok(encoded)
  end
end

fn slice(value :: Bytes, offset :: Int, length :: Int) -> Bytes!String do
  case Bytes.slice(value, offset, length) do
    Err(_) -> Err("test slice failed")
    Ok(bytes)
  end
end

# Addresses and keys are fixed per seed so every helper derives the same ones.

pub fn seeded(seed :: Int) -> SigningKeyPair!String do
  case Crypto.signing_from_seed(repeated(seed, 32)?) do
    Err(_) -> Err("test signing key generation failed")
    Ok(value)
  end
end

pub fn address_bytes(seed :: Int) -> Bytes!String do
  repeated(seed, 32)
end

pub fn address(seed :: Int) -> String!String do
  Ok(Bytes.to_base58(address_bytes(seed)?))
end

pub fn judge() -> String!String do
  address(201)
end

pub fn log_address() -> String!String do
  address(202)
end

pub fn ring_address() -> String!String do
  address(203)
end

pub fn vault_address() -> String!String do
  address(204)
end

pub fn usdc_mint() -> String!String do
  address(205)
end

pub fn witness_account(index :: Int) -> String!String do
  address(210 + index)
end

pub fn witness_vault(index :: Int) -> String!String do
  address(220 + index)
end

pub fn rpc_urls() -> List<String> do
  ["https://rpc-1.test/v1", "https://rpc-2.test/v1", "https://rpc-3.test/v1"]
end

pub fn relay_urls() -> List<String> do
  ["https://relay-a.test", "https://relay-b.test", "https://relay-c.test"]
end

pub fn witness_ids() -> List<String> do
  ["witness-a", "witness-b", "witness-c"]
end

pub fn service_public_key() -> Bytes!String do
  Ok(seeded(91)?.public_key.bytes)
end

fn witness_key(index :: Int) -> Bytes!String do
  Ok(seeded(92 + index)?.public_key.bytes)
end

# A version 2 config pinning three Morse witnesses; with `anchored` also the
# judge, the log, three RPC providers and three relays.

pub fn install_anchor_config(anchored :: Bool) -> Bool!String do
  let delivery = case Crypto.x25519_generate() do
    Err(_) -> Err("test delivery key generation failed")
    Ok(value)
  end?
  let witnesses = for index in 0..3 do
    SecurityWitness {
      witness_id: List.get(witness_ids(), index),
      public_key: witness_key(index)?,
      label: "Morse"
    }
  end
  let frame = security_config_encode(SecurityConfig {
    version: 2,
    service_public_key: service_public_key()?,
    delivery_public_key: delivery.public_key.bytes,
    abuse_difficulty: 8,
    threshold: 2,
    witnesses: witnesses,
    judge_program_id: if anchored do
      judge()?
    else
      ""
    end,
    log_account: if anchored do
      log_address()?
    else
      ""
    end,
    rpc_urls: if anchored do
      rpc_urls()
    else
      List.new()
    end,
    relays: relay_urls(),
    issuer_origin: "",
    c2sp_origin: "",
    minimum_suite: 1,
    ohttp_key_config: Bytes.empty(),
    ohttp_relay: "",
    set_id: Bytes.empty()
  })?
  Ok(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), frame))
end

pub fn signed_checkpoint(sequence :: Int, leaves :: List<Bytes>) -> TransparencyCheckpoint!String do
  let signer = seeded(91)?
  let now = case U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now()))) do
    Err(_) -> Err("test time failed")
    Ok(value)
  end?
  sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    wide(sequence)?,
    leaves,
    repeated(0, 32)?,
    now)
end

pub fn attestations(checkpoint :: TransparencyCheckpoint) -> List<WitnessAttestation>!String do
  let a = seeded(92)?
  let b = seeded(93)?
  Ok([
    sign_witness("witness-a", a.private_key, checkpoint)?,
    sign_witness("witness-b", b.private_key, checkpoint)?
  ])
end

# The phone looks `username` up and verifies the answer: `entry_bytes` at
# `index` of `leaves`, consistent from `old_size`.

pub fn lookup(path :: String,
  username :: String,
  entry_bytes :: Bytes,
  leaves :: List<Bytes>,
  index :: Int,
  old_size :: Int,
  checkpoint :: TransparencyCheckpoint) -> Bytes!String do
  let evidence = evidence_v2(entry_bytes,
    leaves,
    index,
    old_size,
    checkpoint,
    attestations(checkpoint)?)?
  verify_transparency_export(request([Bytes.from_utf8(path), Bytes.from_utf8(username), evidence])?)
end

fn padded(text :: String, length :: Int) -> Bytes!String do
  let value = Bytes.from_utf8(text)
  append(value, repeated(0, length - Bytes.length(value))?)
end

fn list_entry(index :: Int) -> Bytes!String do
  let id = List.get(witness_ids(), index)
  join([
    bytes_of([String.length(id)])?,
    padded(id, 64)?,
    repeated(0, 7)?,
    witness_key(index)?,
    address_bytes(210 + index)?,
    le(0, 8)?
  ])
end

# The judge's Log account (morse-judge-v1.md §4.2) listing witness-a..c.

pub fn log_data(name :: String, slashed :: Bool) -> Bytes!String do
  let flag = if slashed do
    1
  else
    0
  end
  let entries = for index in 0..3 do
    list_entry(index)?
  end
  join([
    bytes_of([
      2,
      1,
      255,
      flag,
      3,
      if slashed do
        3
      else
        1
      end,
      0,
      255
    ])?,
    repeated(0, 8)?,
    padded(name, 32)?,
    service_public_key()?,
    repeated(7, 32)?,
    address_bytes(203)?,
    address_bytes(204)?,
    repeated(8, 32)?,
    repeated(0, 8)?,
    repeated(0, 64)?
  ]
    ++ entries
    ++ [repeated(0, 144 * 13)?])
end

pub fn ring_header(name :: String,
  head :: Int,
  count :: Int,
  last :: TransparencyCheckpoint,
  slot :: Int) -> Bytes!String do
  join([
    padded(name, 32)?,
    le(head, 4)?,
    le(count, 4)?,
    le(U64.to_int(last.sequence)?, 8)?,
    le(U64.to_int(last.tree_size)?, 8)?,
    le(slot, 8)?
  ])
end

pub fn ring_entry(checkpoint :: TransparencyCheckpoint,
  slot :: Int,
  bitmap :: Int,
  evidence :: Int) -> Bytes!String do
  join([
    le(U64.to_int(checkpoint.sequence)?, 8)?,
    le(U64.to_int(checkpoint.tree_size)?, 8)?,
    checkpoint.tree_root,
    checkpoint_hash(checkpoint)?,
    le(U64.to_int(checkpoint.timestamp)?, 8)?,
    le(slot, 8)?,
    le(bitmap, 2)?,
    bytes_of([evidence, 0])?,
    le(0, 4)?
  ])
end

pub fn account(address :: String, owner :: String, data :: Bytes) -> FakeAccount do
  FakeAccount {
    address: address,
    owner: owner,
    data: data,
    entries: List.new(),
    indexes: List.new()
  }
end

# The ring with its header and the entries at `indexes` (others read as zeros).

pub fn ring_account(header :: Bytes,
  indexes :: List<Int>,
  entries :: List<Bytes>) -> FakeAccount!String do
  Ok(FakeAccount {
    address: ring_address()?,
    owner: judge()?,
    data: header,
    entries: entries,
    indexes: indexes
  })
end

pub fn log_account(data :: Bytes) -> FakeAccount!String do
  Ok(account(log_address()?, judge()?, data))
end

pub fn provider(url :: String, accounts :: List<FakeAccount>, block_time :: Int) -> FakeProvider do
  FakeProvider { url: url, accounts: accounts, block_time: block_time, up: true }
end

fn account_slice(value :: FakeAccount, offset :: Int, length :: Int) -> Option<Bytes> do
  if offset + length <= Bytes.length(value.data) do
    case Bytes.slice(value.data, offset, length) do
      Ok(bytes) -> Some(bytes)
      Err(_) -> None
    end
  else if offset >= 64 && length == 104 && (offset - 64) % 104 == 0 do
    let index = (offset - 64) / 104
    let found = for position in 0..List.length(value.indexes) when List.get(value.indexes,
      position) == index do
      List.get(value.entries, position)
    end
    case found do
      [] -> case Bytes.repeat(0, 104) do
        Ok(bytes) -> Some(bytes)
        Err(_) -> None
      end
      entry :: _ -> Some(entry)
    end
  else
    None
  end
end

fn account_json(owner :: String, data :: Bytes) -> String do
  "{\"data\":[\"#{Bytes.to_base64(data)}\",\"base64\"],\"executable\":false,\"lamports\":1,\"owner\":\"#{owner}\",\"rentEpoch\":0,\"space\":#{Bytes.length(data)}}"
end

fn find_account(accounts :: List<FakeAccount>, address :: String) -> Option<FakeAccount> do
  List.find(accounts, fn value -> value.address == address end)
end

fn sliced_json(accounts :: List<FakeAccount>,
  address :: String,
  offset :: Int,
  length :: Int) -> String do
  case find_account(accounts, address) do
    None -> "null"
    Some(value) -> case account_slice(value, offset, length) do
      None -> "null"
      Some(bytes) -> account_json(value.owner, bytes)
    end
  end
end

fn field(value :: Json, key :: String) -> Json!String do
  Json.object_get(value, key)
end

fn int_field(value :: Json, key :: String) -> Int!String do
  Json.as_int(field(value, key)?)
end

fn slice_of(options :: Json) -> (Int, Int)!String do
  let slice = field(options, "dataSlice")?
  Ok((int_field(slice, "offset")?, int_field(slice, "length")?))
end

fn matches(value :: FakeAccount, filters :: Json, count :: Int, index :: Int) -> Bool!String do
  if index >= count do
    Ok(true)
  else
    let filter = Json.array_get(filters, index)?
    let holds = case Json.object_get(filter, "dataSize") do
      Ok(size) -> Bytes.length(value.data) == Json.as_int(size)?
      Err(_) -> do
        let memcmp = field(filter, "memcmp")?
        let offset = int_field(memcmp, "offset")?
        let expected = case Bytes.from_base58(Json.as_string(field(memcmp, "bytes")?)?) do
          Err(_) -> Err("bad memcmp")
          Ok(bytes)
        end?
        case Bytes.slice(value.data, offset, Bytes.length(expected)) do
          Err(_) -> false
          Ok(actual) -> Bytes.secure_equals(actual, expected)
        end
      end
    end
    if holds do
      matches(value, filters, count, index + 1)
    else
      Ok(false)
    end
  end
end

fn matches_all(value :: FakeAccount, filters :: Json, count :: Int) -> Bool do
  case matches(value, filters, count, 0) do
    Ok(holds) -> holds
    Err(_) -> false
  end
end

fn result(text :: String) -> FakeAnswer do
  FakeAnswer {
    status: 200,
    body: Bytes.from_utf8("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":#{text}}")
  }
end

fn rpc_answer(value :: FakeProvider, body :: Bytes) -> FakeAnswer!String do
  let root = Json.parse(Bytes.to_utf8(body)?)?
  let method = Json.as_string(field(root, "method")?)?
  let params = field(root, "params")?
  let context = "{\"context\":{\"slot\":1000},\"value\":"
  if method == "getAccountInfo" do
    let (offset, length) = slice_of(Json.array_get(params, 1)?)?
    let address = Json.as_string(Json.array_get(params, 0)?)?
    Ok(result(context <> sliced_json(value.accounts, address, offset, length) <> "}"))
  else if method == "getMultipleAccounts" do
    let (offset, length) = slice_of(Json.array_get(params, 1)?)?
    let addresses = Json.array_get(params, 0)?
    let count = Json.array_length(addresses)?
    let items = for index in 0..count do
      sliced_json(value.accounts,
        Json.as_string(Json.array_get(addresses, index)?)?,
        offset,
        length)
    end
    Ok(result(context <> "[" <> String.join(items, ",") <> "]}"))
  else if method == "getProgramAccounts" do
    let program = Json.as_string(Json.array_get(params, 0)?)?
    let filters = field(Json.array_get(params, 1)?, "filters")?
    let count = Json.array_length(filters)?
    let owned = List.filter(value.accounts, fn candidate -> candidate.owner == program end)
    let matching = List.filter(owned, fn candidate -> matches_all(candidate, filters, count) end)
    let found = for candidate in matching do
      "{\"account\":#{account_json(candidate.owner,
        candidate.data)},\"pubkey\":\"#{candidate.address}\"}"
    end
    Ok(result("[" <> String.join(found, ",") <> "]"))
  else if method == "getBlockTime" do
    Ok(result(Int.to_string(value.block_time)))
  else
    Err("unknown method " <> method)
  end
end

# What one fake provider answers a JSON-RPC request with.

pub fn fake_rpc(providers :: List<FakeProvider>, url :: String, body :: Bytes) -> FakeAnswer do
  case List.find(providers, fn value -> value.url == url end) do
    None -> FakeAnswer { status: 0, body: Bytes.empty() }
    Some(value) -> if !value.up do
      FakeAnswer { status: 0, body: Bytes.empty() }
    else
      case rpc_answer(value, body) do
        Ok(answer) -> answer
        Err(error) -> FakeAnswer { status: 500, body: Bytes.from_utf8(error) }
      end
    end
  end
end

# The directory: consistency (KTS v2) and leaf (KTP v2) proofs over `leaves`;
# `refuse` answers every consistency query with 400.

pub fn fake_directory(leaves :: List<Bytes>,
  refuse :: Bool,
  target :: String,
  body :: Bytes) -> FakeAnswer do
  let answered = if target == "/v1/transparency/consistency" do
    if refuse do
      Ok(FakeAnswer { status: 400, body: Bytes.empty() })
    else
      consistency_answer(leaves, body)
    end
  else if target == "/v1/transparency/leaf" do
    leaf_answer(leaves, body)
  else
    Ok(FakeAnswer { status: 404, body: Bytes.empty() })
  end
  case answered do
    Ok(answer) -> answer
    Err(_) -> FakeAnswer { status: 400, body: Bytes.empty() }
  end
end

fn consistency_answer(leaves :: List<Bytes>, body :: Bytes) -> FakeAnswer!String do
  let query = transparency_decode_tree_query_v2(body)?
  Ok(FakeAnswer { status: 200, body: consistency_v2(leaves, query.old_size, query.new_size)? })
end

fn leaf_answer(leaves :: List<Bytes>, body :: Bytes) -> FakeAnswer!String do
  let query = transparency_decode_leaf_query(body)?
  let tree = List.take(leaves, query.tree_size)
  let oracle = tlog_list_oracle(1, tree)
  Ok(FakeAnswer {
    status: 200,
    body: transparency_encode_leaf_proof(TransparencyLeafProof {
      leaf_hash: List.get(tree, query.leaf_index),
      inclusion: CompactInclusion {
        leaf_index: query.leaf_index,
        tree_size: query.tree_size,
        path: tlog_inclusion_path(1, oracle, query.leaf_index, query.tree_size)?
      }
    })?
  })
end

# Relays: a lands proofs (202 with the proof hash), b refuses them (422), c
# is down unless `all_up`.

pub fn fake_relay(target :: String, body :: Bytes, all_up :: Bool) -> FakeAnswer do
  let hash = Bytes.to_hex(Crypto.sha256(body))
  if String.starts_with(target, "https://relay-a.test") do
    FakeAnswer {
      status: 202,
      body: Bytes.from_utf8("{\"status\":\"submitting\",\"proof_hash\":\"#{hash}\",\"completed\":false}")
    }
  else if String.starts_with(target, "https://relay-b.test") do
    FakeAnswer { status: 422, body: Bytes.from_utf8("{\"error\":\"not_a_fork\"}") }
  else if all_up do
    FakeAnswer { status: 202, body: Bytes.from_utf8("{\"status\":\"submitting\"}") }
  else
    FakeAnswer { status: 0, body: Bytes.empty() }
  end
end

# A fresh address per finder request (the tag names the proof).

pub fn finder_address(tag :: String) -> Bytes do
  Crypto.sha256(Bytes.from_utf8(tag))
end

fn u16(value :: Int) -> Bytes!String do
  case Bytes.write_u16_be(value) do
    Err(_) -> Err("test integer encoding failed")
    Ok(encoded)
  end
end

fn exchange_part(trace :: AnchorTrace, request :: Bytes) -> Bytes!String do
  join([vector(request)?, u16(trace.status)?, vector(trace.answer)?])
end

fn exchange_frame(traces :: List<AnchorTrace>, requests :: List<Bytes>) -> Bytes!String do
  let parts = for index in 0..List.length(traces) do
    exchange_part(List.get(traces, index), List.get(requests, index))?
  end
  join([u16(List.length(traces))?] ++ parts)
end

fn read_vector_at(input :: Bytes, offset :: Int) -> (Bytes, Int)!String do
  let length = read_u32(slice(input, offset, 4)?)?
  Ok((slice(input, offset + 4, length)?, offset + 4 + length))
end

fn byte_at(input :: Bytes, offset :: Int) -> Int!String do
  case Bytes.get(input, offset) do
    Err(_) -> Err("test byte read failed")
    Ok(value)
  end
end

fn u16_at(input :: Bytes, offset :: Int) -> Int!String do
  Ok(byte_at(input, offset)? * 256 + byte_at(input, offset + 1)?)
end

fn parse_request(input :: Bytes) -> AnchorTrace!String do
  let kind = byte_at(input, 0)?
  let (tag, after_tag) = read_vector_at(input, 1)?
  let (target, after_target) = read_vector_at(input, after_tag)?
  let (body, _) = read_vector_at(input, after_target)?
  Ok(AnchorTrace {
    kind: kind,
    tag: Bytes.to_utf8(tag)?,
    target: Bytes.to_utf8(target)?,
    body: body,
    status: 0,
    answer: Bytes.empty()
  })
end

fn step_requests(output :: Bytes) -> (Bool, List<Bytes>)!String do
  if !Bytes.secure_equals(slice(output, 1, 3)?, Bytes.from_utf8("ACS")) do
    Err("not an anchor step")
  else
    let done = byte_at(output, 4)? == 1
    let count = u16_at(output, 5)?
    Ok((done, read_requests(output, 7, count, List.new())?))
  end
end

fn read_requests(input :: Bytes,
  offset :: Int,
  count :: Int,
  output :: List<Bytes>) -> List<Bytes>!String do
  if List.length(output) >= count do
    Ok(output)
  else
    let (value, next) = read_vector_at(input, offset)?
    read_requests(input, next, count, List.append(output, value))
  end
end

fn answer_one(value :: Bytes,
  respond :: Fun(Int, String, String, Bytes) -> FakeAnswer) -> AnchorTrace!String do
  let parsed = parse_request(value)?
  let answer = respond(parsed.kind, parsed.tag, parsed.target, parsed.body)
  Ok(AnchorTrace {
    kind: parsed.kind,
    tag: parsed.tag,
    target: parsed.target,
    body: parsed.body,
    status: answer.status,
    answer: answer.body
  })
end

# Runs one anchor check to the end the way the app does: each step's requests
# are answered by `respond` (kind, tag, target, body) and every exchange so far
# goes back with the next call. Returns every exchange of the run.

pub fn drive(path :: String,
  respond :: Fun(Int, String, String, Bytes) -> FakeAnswer) -> List<AnchorTrace>!String do
  drive_steps(path, fn input -> anchor_check_export(input) end, respond)
end

# The same for any run that speaks Mobile.AnchorSteps (checkpoint gossip too).

pub fn drive_steps(path :: String,
  step :: Fun(Bytes) -> Result<Bytes, String>,
  respond :: Fun(Int, String, String, Bytes) -> FakeAnswer) -> List<AnchorTrace>!String do
  drive_from(path, step, respond, List.new(), List.new(), 0)
end

fn drive_from(path :: String,
  step :: Fun(Bytes) -> Result<Bytes, String>,
  respond :: Fun(Int, String, String, Bytes) -> FakeAnswer,
  traces :: List<AnchorTrace>,
  requests :: List<Bytes>,
  round :: Int) -> List<AnchorTrace>!String do
  if round > 24 do
    return Err("anchor check did not finish")
  end
  let output = step(request([Bytes.from_utf8(path), exchange_frame(traces, requests)?])?)?
  let (done, asked) = step_requests(output)?
  if done do
    Ok(traces)
  else
    let answered = for value in asked do
      answer_one(value, respond)?
    end
    drive_from(path, step, respond, traces ++ answered, requests ++ asked, round + 1)
  end
end

# A network status section's body (Mobile.NetworkStatus), if present.

pub fn status_section(path :: String, tag :: Int) -> Option<Bytes>!String do
  let status = network_status_export(Bytes.from_utf8(path))?
  let (_, after_profile) = read_vector_at(status, 4)?
  let count = byte_at(status, after_profile + 1)?
  let offset = skip_witnesses(status, after_profile + 3 + 32, count)?
  let sections = byte_at(status, offset)?
  find_section(status, offset + 1, sections, tag)
end

fn skip_witnesses(input :: Bytes, offset :: Int, count :: Int) -> Int!String do
  if count == 0 do
    Ok(offset)
  else
    let (_, after_id) = read_vector_at(input, offset)?
    let (_, after_label) = read_vector_at(input, after_id)?
    skip_witnesses(input, after_label + 1, count - 1)
  end
end

fn find_section(input :: Bytes, offset :: Int, count :: Int, tag :: Int) -> Option<Bytes>!String do
  if count == 0 do
    Ok(None)
  else
    let found = u16_at(input, offset)?
    let (body, next) = read_vector_at(input, offset + 2)?
    if found == tag do
      Ok(Some(body))
    else
      find_section(input, next, count - 1, tag)
    end
  end
end

pub fn outcome(path :: String) -> Int!String do
  case status_section(path, 2)? do
    None -> Err("no anchor section")
    Some(body) -> byte_at(body, 0)
  end
end

pub fn alarm_kind(path :: String) -> Int!String do
  case status_section(path, 4)? do
    None -> Ok(0)
    Some(body) -> byte_at(body, 0)
  end
end

fn read_relays(input :: Bytes,
  offset :: Int,
  count :: Int,
  output :: List<DetailRelay>) -> (List<DetailRelay>, Int)!String do
  if List.length(output) >= count do
    Ok((output, offset))
  else
    let (url, after_url) = read_vector_at(input, offset)?
    let status = byte_at(input, after_url)?
    read_relays(input,
      after_url + 1 + 32,
      count,
      List.append(output, DetailRelay { url: Bytes.to_utf8(url)?, status: status }))
  end
end

fn read_frk(input :: Bytes) -> DetailFrk!String do
  let (bytes, offset) = read_vector_at(input, 0)?
  let hash = slice(input, offset, 32)?
  let complete = byte_at(input, offset + 32)? == 1
  let landed = byte_at(input, offset + 33)? == 1
  let paid_to = slice(input, offset + 34, 32)?
  let relays = byte_at(input, offset + 74)?
  let (values, _) = read_relays(input, offset + 75, relays, List.new())?
  Ok(DetailFrk {
    bytes: bytes,
    proof_hash: hash,
    complete: complete,
    landed: landed,
    paid_to: paid_to,
    relays: values
  })
end

fn read_frks(input :: Bytes,
  offset :: Int,
  count :: Int,
  output :: List<DetailFrk>) -> List<DetailFrk>!String do
  if List.length(output) >= count do
    Ok(output)
  else
    let (record, next) = read_vector_at(input, offset)?
    read_frks(input, next, count, List.append(output, read_frk(record)?))
  end
end

fn read_alarm(input :: Bytes) -> DetailAlarm!String do
  let kind = byte_at(input, 0)?
  let active = byte_at(input, 1)? == 1
  let offset = 10 + 49 + 49
  let count = byte_at(input, offset)?
  Ok(DetailAlarm {
    kind: kind,
    active: active,
    frks: read_frks(input, offset + 1, count, List.new())?
  })
end

fn read_alarms(input :: Bytes,
  offset :: Int,
  count :: Int,
  output :: List<DetailAlarm>) -> List<DetailAlarm>!String do
  if List.length(output) >= count do
    Ok(output)
  else
    let (record, next) = read_vector_at(input, offset)?
    read_alarms(input, next, count, List.append(output, read_alarm(record)?))
  end
end

pub fn details(path :: String) -> List<DetailAlarm>!String do
  let frame = trust_alarm_details_export(Bytes.from_utf8(path))?
  if !Bytes.secure_equals(slice(frame, 1, 3)?, Bytes.from_utf8("TAD")) do
    Err("not trust alarm details")
  else
    read_alarms(frame, 5, byte_at(frame, 4)?, List.new())
  end
end

pub fn random_leaf() -> Bytes!String do
  case Crypto.random_bytes(32) do
    Err(_) -> Err("test random failed")
    Ok(value)
  end
end

pub fn now_seconds() -> Int do
  DateTime.to_unix_ms(DateTime.utc_now()) / 1000
end

# An anchor mismatch alarm for the pinned service key, as the check raises it.

pub fn raise_test_alarm(path :: String) -> Result<(), String> do
  let config = native_security_config()?
  trust_alarm_raise(path,
    TrustAlarm {
      kind: 1,
      active: true,
      raised_at: 0,
      service_key: config.transparency_service_public_key,
      first: trust_summary_none()?,
      second: trust_summary_none()?,
      frks: List.new()
    })
end

pub fn clear_test_alarm(path :: String) -> Result<(), String> do
  trust_alarm_clear_mismatch(path)
end
