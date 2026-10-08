from MobileCore import (
  account_deletion_export,
  anchor_check_export,
  create_account_export,
  privacy_submission_export,
  register_request_export,
  resolve_request_export,
  verify_transparency_export
)
from Credits.MailboxExtras import (
  credits_decode_retention_answer,
  credits_sign_policy,
  credits_sign_retention
)
from Identity.Device import DeviceKeys
from Mobile.Anchor import AnchorRecord, anchor_record_load
from Mobile.Platform import native_security_config
from Mobile.Profile import load_profile, open_device
from Mobile.Types import MobileSecurityConfig
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.V1 import DirectoryEntry, OuterEnvelope, protocol_sealed_outer_suite
from Storage.Keys import platform_key
from Transport.Packet import ClientProfile, decode_client_profile

##! The canary device of the bootstrap acceptance suite (plan §4.3 checks 1, 2
##! and 4; ops/acceptance/README.md): a phone without a person. It runs the
##! real mobile core with an in-memory secure store and the release's security
##! config (MORSE_CANARY_CONFIG), talks to the directory at
##! MORSE_CANARY_DIRECTORY, and appends one JSON line per result to
##! MORSE_CANARY_OUT as it goes. MORSE_CANARY_ROLE picks what it does:
##!
##! - check: a fresh device looks up every MORSE_CANARY_ACCOUNTS name and
##!   verifies the evidence under the pinned set; with MORSE_CANARY_ANCHOR=on
##!   it then runs the phone's check against the public record.
##! - watch: one device looks up the first account every
##!   MORSE_CANARY_INTERVAL_MS until the file MORSE_CANARY_STOP exists (the
##!   outage drill). Every round after the first also proves the log
##!   consistent with the round before, as a phone does.
##! - create: creates and registers each account, once. Its keys live only in
##!   this run's memory, so nobody can renew, move or delete them later.
##! - extras: the credits drill's device (check 8). With the tokens in
##!   MORSE_CANARY_TOKENS (hex, one per line) it registers a fresh drill
##!   account (with 20 tokens for priority sign-up while a surge is on), prices
##!   its inbox at 1 credit and sends it an envelope through the privacy edge
##!   (MORSE_CANARY_EDGE) without and then with a token, buys 30 more days of
##!   storage with 10 tokens, and deletes the account again.

struct Canary do
  directory :: String
  out :: String
  workdir :: String
  accounts :: List<String>
end

struct Exchange do
  request :: Bytes
  kind :: Int
  target :: String
  status :: Int
  answer :: Bytes
end

fn append(left :: Bytes, right :: Bytes) -> Bytes!String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("canary encoding failed")
    Ok(value)
  end
end

fn join_from(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    join_from(parts, index + 1, append(output, List.get(parts, index))?)
  end
end

fn u16(value :: Int) -> Bytes!String do
  case Bytes.write_u16_be(value) do
    Err(_) -> Err("canary encoding failed")
    Ok(encoded)
  end
end

fn u32(value :: Int) -> Bytes!String do
  let wide = case U64.parse(Int.to_string(value)) do
    Err(_) -> Err("canary encoding failed")
    Ok(parsed)
  end?
  case Bytes.write_u32_be(wide) do
    Err(_) -> Err("canary encoding failed")
    Ok(encoded)
  end
end

fn vector(value :: Bytes) -> Bytes!String do
  append(u32(Bytes.length(value))?, value)
end

# The core's request framing: each value as u32 length || bytes.

fn request(values :: List<Bytes>) -> Bytes!String do
  let parts = for value in values do
    vector(value)?
  end
  join_from(parts, 0, Bytes.empty())
end

fn byte_at(input :: Bytes, offset :: Int) -> Int!String do
  case Bytes.get(input, offset) do
    Err(_) -> Err("canary decoding failed")
    Ok(value)
  end
end

fn u32_at(input :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u32_be(input, offset) do
    Err(_) -> Err("canary decoding failed")
    Ok(wide) -> case U64.to_int(wide) do
      Err(_) -> Err("canary decoding failed")
      Ok(value)
    end
  end
end

fn vector_at(input :: Bytes, offset :: Int) -> (Bytes, Int)!String do
  let length = u32_at(input, offset)?
  case Bytes.slice(input, offset + 4, length) do
    Err(_) -> Err("canary decoding failed")
    Ok(value) -> Ok((value, offset + 4 + length))
  end
end

fn now_ms() -> Int do
  DateTime.to_unix_ms(DateTime.utc_now())
end

fn emit(canary :: Canary, line :: String) -> () do
  println(line)
  let _written = File.append(canary.out, line <> "\n")
  nil
end

fn post(url :: String, content_type :: String, body :: Bytes) -> (Int, Bytes) do
  let response = Http.build(:post, url)
    |> Http.header("Content-Type", content_type)
    |> Http.body_bytes(body)
    |> Http.timeout(8000)
    |> Http.max_response_bytes(4000000)
    |> Http.send()
  case response do
    Err(_) -> (0, Bytes.empty())
    Ok(value) -> (value.status, value.body_bytes)
  end
end

fn put(url :: String, body :: Bytes) -> (Int, Bytes) do
  let response = Http.build(:put, url)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.body_bytes(body)
    |> Http.timeout(8000)
    |> Http.max_response_bytes(600000)
    |> Http.send()
  case response do
    Err(_) -> (0, Bytes.empty())
    Ok(value) -> (value.status, value.body_bytes)
  end
end

fn database_path(canary :: Canary, label :: String) -> String!String do
  case Crypto.random_bytes(8) do
    Err(_) -> Err("canary path generation failed")
    Ok(value) -> Ok(canary.workdir <> "/canary-" <> label <> "-" <> Bytes.to_hex(value) <> ".db")
  end
end

# The witnesses sign a new checkpoint seconds after the directory makes it, so
# a lookup that lands in between is retried, as the app does (network.ts).

fn witness_wait_ms(attempt :: Int) -> Int do
  List.get([1000, 2000, 3000, 4000, 5000, 5000], attempt)
end

fn lookup(canary :: Canary, database :: String, username :: String, attempt :: Int) -> Int!String do
  let query = resolve_request_export(request([
    Bytes.from_utf8(database),
    Bytes.from_utf8(username)
  ])?)?
  let (status, evidence) = post(canary.directory <> "/v1/devices/resolve",
    "application/octet-stream",
    query)
  if status != 200 do
    Err("resolve_status_#{status}")
  else
    case verify_transparency_export(request([
      Bytes.from_utf8(database),
      Bytes.from_utf8(username),
      evidence
    ])?) do
      Ok(set) -> Ok(Bytes.length(set))
      Err(error) -> if attempt < 6 && String.contains(error, "transparency_verification_failed") do
        Timer.sleep(witness_wait_ms(attempt))
        lookup(canary, database, username, attempt + 1)
      else
        Err(error)
      end
    end
  end
end

fn lookup_line(round :: Int, username :: String, started :: Int, result :: Int!String) -> String do
  let head = "{\"kind\":\"lookup\",\"round\":#{round},\"account\":"
    <> Json.encode_string(username)
    <> ",\"at_ms\":#{started},\"ms\":#{now_ms() - started}"
  case result do
    Ok(_) -> head <> ",\"ok\":true}"
    Err(error) -> head <> ",\"ok\":false,\"error\":" <> Json.encode_string(error) <> "}"
  end
end

fn lookup_all(canary :: Canary, database :: String, index :: Int) -> () do
  if index < List.length(canary.accounts) do
    let username = List.get(canary.accounts, index)
    let started = now_ms()
    emit(canary, lookup_line(0, username, started, lookup(canary, database, username, 0)))
    lookup_all(canary, database, index + 1)
  end
end

# The phone's check against the public record, driven the way the app drives
# it (network.ts checkPublicRecordOnce): Mesh returns the requests it needs,
# they are made, and every exchange so far goes back with the next call.

fn step_requests(input :: Bytes,
  offset :: Int,
  count :: Int,
  output :: List<Bytes>) -> List<Bytes>!String do
  if List.length(output) >= count do
    Ok(output)
  else
    let (value, next) = vector_at(input, offset)?
    step_requests(input, next, count, List.append(output, value))
  end
end

fn anchor_step(output :: Bytes) -> (Bool, List<Bytes>)!String do
  let magic = case Bytes.slice(output, 1, 3) do
    Err(_) -> Err("not an anchor step")
    Ok(value)
  end?
  if byte_at(output, 0)? != 1 || !Bytes.secure_equals(magic, Bytes.from_utf8("ACS")) do
    Err("not an anchor step")
  else
    let count = byte_at(output, 5)? * 256 + byte_at(output, 6)?
    Ok((byte_at(output, 4)? == 1, step_requests(output, 7, count, List.new())?))
  end
end

fn answer(canary :: Canary, kind :: Int, target :: String, body :: Bytes) -> (Int, Bytes)!String do
  if kind == 4 do
    # No finder address: the canary collects no bounties.
    Ok((200, Bytes.empty()))
  else if kind == 2 do
    if String.starts_with(target, "/v1/transparency/") do
      Ok(post(canary.directory <> target, "application/octet-stream", body))
    else
      Err("invalid_anchor_request")
    end
  else if kind == 1 do
    Ok(post(target, "application/json", body))
  else
    Ok(post(target, "application/octet-stream", body))
  end
end

fn perform(canary :: Canary, raw :: Bytes) -> Exchange!String do
  let kind = byte_at(raw, 0)?
  let (_tag, after_tag) = vector_at(raw, 1)?
  let (target_bytes, after_target) = vector_at(raw, after_tag)?
  let (body, _) = vector_at(raw, after_target)?
  let target = Bytes.to_utf8(target_bytes)?
  let (status, reply) = answer(canary, kind, target, body)?
  Ok(Exchange { request: raw, kind: kind, target: target, status: status, answer: reply })
end

fn exchange_bytes(exchange :: Exchange) -> Bytes!String do
  join_from([vector(exchange.request)?, u16(exchange.status)?, vector(exchange.answer)?],
    0,
    Bytes.empty())
end

fn anchor_drive(canary :: Canary,
  database :: String,
  exchanges :: List<Exchange>,
  round :: Int) -> List<Exchange>!String do
  if round > 24 do
    return Err("anchor_check_incomplete")
  end
  let parts = for exchange in exchanges do
    exchange_bytes(exchange)?
  end
  let frame = join_from([u16(List.length(exchanges))?] ++ parts, 0, Bytes.empty())?
  let output = anchor_check_export(request([Bytes.from_utf8(database), frame])?)?
  let (done, asked) = anchor_step(output)?
  if done do
    Ok(exchanges)
  else
    let answered = for raw in asked do
      perform(canary, raw)?
    end
    anchor_drive(canary, database, exchanges ++ answered, round + 1)
  end
end

fn outcome_name(code :: Int) -> String do
  let names = [
    "never_checked",
    "ok",
    "stale",
    "rpc_disagree",
    "rpc_unavailable",
    "mismatch",
    "service_slashed",
    "off",
    "directory_unavailable",
    "chain_invalid"
  ]
  if code >= 0 && code < List.length(names) do
    List.get(names, code)
  else
    "unknown"
  end
end

fn rpc_json(exchange :: Exchange) -> String do
  "{\"url\":" <> Json.encode_string(exchange.target) <> ",\"status\":#{exchange.status}}"
end

fn anchor_line(exchanges :: List<Exchange>, record :: Option<AnchorRecord>) -> String do
  let rpc = for exchange in List.filter(exchanges, fn value -> value.kind == 1 end) do
    rpc_json(exchange)
  end
  let head = "{\"kind\":\"anchor\",\"rpc\":[" <> String.join(rpc, ",") <> "]"
  case record do
    None -> head <> ",\"outcome\":\"never_checked\",\"code\":0}"
    Some(value) -> head
      <> ",\"outcome\":"
      <> Json.encode_string(outcome_name(value.outcome))
      <> ",\"code\":#{value.outcome},\"checked_at_ms\":#{value.checked_at},\"anchor_ms\":#{value.anchor_ms}"
      <> ",\"anchor_slot\":#{value.anchor_slot},\"public_size\":#{value.public_size}}"
  end
end

fn anchor_role(canary :: Canary, database :: String) -> () do
  case anchor_drive(canary, database, List.new(), 0) do
    Err(error) -> emit(canary,
      "{\"kind\":\"anchor\",\"outcome\":\"error\",\"error\":" <> Json.encode_string(error) <> "}")
    Ok(exchanges) -> case anchor_record_load(database) do
      Err(error) -> emit(canary,
        "{\"kind\":\"anchor\",\"outcome\":\"error\",\"error\":" <> Json.encode_string(error) <> "}")
      Ok(record) -> emit(canary, anchor_line(exchanges, record))
    end
  end
end

# Waits out one interval a second at a time, so the stop file ends a round's
# wait promptly. True when the file is there.

fn pause(stop :: String, remaining :: Int) -> Bool do
  if File.exists(stop) do
    true
  else if remaining <= 0 do
    false
  else
    Timer.sleep(1000)
    pause(stop, remaining - 1000)
  end
end

fn watch(canary :: Canary, database :: String, round :: Int) -> () do
  let username = List.head(canary.accounts)
  let started = now_ms()
  emit(canary, lookup_line(round, username, started, lookup(canary, database, username, 0)))
  let stop = Env.get("MORSE_CANARY_STOP", "")
  let interval = case String.to_int(Env.get("MORSE_CANARY_INTERVAL_MS", "60000")) do
    None -> 60000
    Some(value) -> value
  end
  # A drill lasts minutes; a forgotten stop file must not keep this running.
  if round < 180 && String.length(stop) > 0 && !pause(stop, interval) do
    watch(canary, database, round + 1)
  end
end

fn create_all(canary :: Canary, index :: Int) -> ()!String do
  if index < List.length(canary.accounts) do
    let username = List.get(canary.accounts, index)
    let database = database_path(canary, "create")?
    let _account = create_account_export(request([
      Bytes.from_utf8(database),
      Bytes.from_utf8(username)
    ])?)?
    let (status, _) = put(canary.directory <> "/v1/devices/register",
      register_request_export(Bytes.from_utf8(database))?)
    emit(canary,
      "{\"kind\":\"created\",\"account\":"
        <> Json.encode_string(username)
        <> ",\"status\":#{status}}")
    create_all(canary, index + 1)
  else
    Ok(nil)
  end
end

# ---- the credits drill's device (role extras) ----

fn get(url :: String) -> (Int, Bytes) do
  let response = Http.build(:get, url)
    |> Http.timeout(8000)
    |> Http.max_response_bytes(4096)
    |> Http.send()
  case response do
    Err(_) -> (0, Bytes.empty())
    Ok(value) -> (value.status, value.body_bytes)
  end
end

fn random(length :: Int) -> Bytes!String do
  case Crypto.random_bytes(length) do
    Err(_) -> Err("canary random generation failed")
    Ok(value)
  end
end

fn one_byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("canary encoding failed")
    Ok(encoded)
  end
end

fn hex_bytes(text :: String) -> Bytes!String do
  case Bytes.from_hex(text) do
    Err(_) -> Err("invalid canary token")
    Ok(value)
  end
end

# CRD || body (protocol/credits-v1.md): the frame binds the tokens to exactly
# this body.

fn attach(tokens :: List<Bytes>, body :: Bytes) -> Bytes!String do
  join_from([hex_bytes("01435244")?, Crypto.sha256(body), one_byte(List.length(tokens))?]
      ++ tokens
      ++ [body],
    0,
    Bytes.empty())
end

fn tokens_from(path :: String) -> List<Bytes>!String do
  let text = case File.read(path) do
    Err(_) -> Err("MORSE_CANARY_TOKENS is unreadable")
    Ok(value)
  end?
  let lines = List.filter(String.split(text, "\n"), fn line -> String.length(line) > 0 end)
  let tokens = for line in lines do
    hex_bytes(line)?
  end
  Ok(tokens)
end

fn tokens_at(tokens :: List<Bytes>, start :: Int, count :: Int) -> List<Bytes> do
  for index in start..(start + count) do
    List.get(tokens, index)
  end
end

fn extra_line(extra :: String, fields :: String) -> String do
  "{\"kind\":\"extra\",\"extra\":" <> Json.encode_string(extra) <> fields <> "}"
end

fn drill_profile(database :: String) -> ClientProfile!String do
  decode_client_profile(load_profile(database)?)
end

fn mailbox_hash(database :: String) -> Bytes!String do
  Ok(Crypto.sha256(drill_profile(database)?.entry.mailbox_token))
end

fn signed_policy(database :: String, postage :: Int) -> Bytes!String do
  let profile = drill_profile(database)?
  let wrapping_key = platform_key()?
  let device = open_device(profile, wrapping_key, database)?
  credits_sign_policy(device.signing_private_key,
    Crypto.sha256(profile.entry.mailbox_token),
    now_ms(),
    postage)
end

fn signed_retention(database :: String, periods :: Int) -> Bytes!String do
  let profile = drill_profile(database)?
  let wrapping_key = platform_key()?
  let device = open_device(profile, wrapping_key, database)?
  credits_sign_retention(device.signing_private_key,
    Crypto.sha256(profile.entry.mailbox_token),
    periods,
    now_ms())
end

# A stranger's envelope to the drill account's public address. Nobody reads
# it: delivery never opens the ciphertext, and the account is deleted after.

fn stranger_envelope(database :: String) -> Bytes!String do
  let expiration = case U64.parse(Int.to_string(now_ms() + 86400000)) do
    Err(_) -> Err("canary encoding failed")
    Ok(value)
  end?
  case encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: random(16)?,
    mailbox_token: drill_profile(database)?.entry.mailbox_token,
    suite: protocol_sealed_outer_suite(),
    expiration: expiration,
    padding_bucket: 256,
    ciphertext: random(200)?
  }) do
    Err(_) -> Err("canary envelope encoding failed")
    Ok(value)
  end
end

# Registration, as priority sign-up while a surge raises the work (WRK above
# the pinned base), else plainly. The answer's status and whether it paid.

fn drill_register(canary :: Canary, database :: String, tokens :: List<Bytes>) -> Int!String do
  let registration = register_request_export(Bytes.from_utf8(database))?
  let (work_status, work) = get(canary.directory <> "/v1/devices/register/work")
  let base = native_security_config()?.abuse_difficulty
  let difficulty = if work_status == 200 && Bytes.length(work) == 6 do
    byte_at(work, 4)?
  else
    -1
  end
  if difficulty > base do
    let started = now_ms()
    let (status, _) = put(canary.directory <> "/v1/devices/register",
      attach(tokens_at(tokens, 0, 20), registration)?)
    emit(canary,
      extra_line("signup",
        ",\"surge\":true,\"difficulty\":#{difficulty},\"base\":#{base},\"status\":#{status},\"ms\":#{now_ms() - started}"))
    Ok(status)
  else
    let (status, _) = put(canary.directory <> "/v1/devices/register", registration)
    emit(canary,
      extra_line("signup",
        ",\"surge\":false,\"work_status\":#{work_status},\"difficulty\":#{difficulty},\"base\":#{base},\"status\":#{status}"))
    Ok(status)
  end
end

fn drill_postage(canary :: Canary,
  edge :: String,
  database :: String,
  token :: Bytes) -> ()!String do
  let policy = signed_policy(database, 1)?
  let (policy_status, _) = put(canary.directory <> "/v1/mailbox/policy", policy)
  let envelope = stranger_envelope(database)?
  let (unpaid, answer) = post(edge <> "/v1/envelopes/batch",
    "application/octet-stream",
    privacy_submission_export(envelope)?)
  let started = now_ms()
  let (status, _) = post(edge <> "/v1/envelopes/batch",
    "application/octet-stream",
    attach([token], privacy_submission_export(envelope)?)?)
  let answered_policy = Bytes.secure_equals(answer, policy)
  emit(canary,
    extra_line("postage",
      ",\"policy_status\":#{policy_status},\"unpaid_status\":#{unpaid},\"policy_returned\":#{answered_policy},\"status\":#{status},\"ms\":#{now_ms() - started}"))
  Ok(nil)
end

fn drill_storage(canary :: Canary,
  edge :: String,
  database :: String,
  tokens :: List<Bytes>) -> ()!String do
  let started = now_ms()
  let (status, answer) = post(edge <> "/v1/mailbox/retention",
    "application/octet-stream",
    attach(tokens, signed_retention(database, 1)?)?)
  let ms = now_ms() - started
  let days = if status == 201 do
    case credits_decode_retention_answer(answer) do
      Err(_) -> -1
      Ok((retention_days, _)) -> retention_days
    end
  else
    -1
  end
  emit(canary,
    extra_line("storage", ",\"status\":#{status},\"retention_days\":#{days},\"ms\":#{ms}"))
  Ok(nil)
end

fn extras_role(canary :: Canary) -> ()!String do
  let tokens = tokens_from(Env.get("MORSE_CANARY_TOKENS", ""))?
  let edge = Env.get("MORSE_CANARY_EDGE", "")
  if List.length(tokens) < 31 || String.length(edge) == 0 do
    return Err("the extras role needs 31 tokens in MORSE_CANARY_TOKENS and MORSE_CANARY_EDGE")
  end
  let database = database_path(canary, "drill")?
  let username = "morse-drill-" <> Bytes.to_hex(random(4)?)
  let _account = create_account_export(request([
    Bytes.from_utf8(database),
    Bytes.from_utf8(username)
  ])?)?
  let registered = drill_register(canary, database, tokens)?
  if registered != 201 do
    return Err("the drill account's registration answered #{registered}")
  end
  let postage = drill_postage(canary, edge, database, List.get(tokens, 20))
  let storage = drill_storage(canary, edge, database, tokens_at(tokens, 21, 10))
  let (deleted, _) = post(canary.directory <> "/v1/accounts/delete",
    "application/octet-stream",
    account_deletion_export(Bytes.from_utf8(database))?)
  emit(canary,
    extra_line("cleanup",
      ",\"account\":" <> Json.encode_string(username) <> ",\"status\":#{deleted}"))
  postage?
  storage?
  Ok(nil)
end

fn canary_from_env() -> Canary!String do
  let directory = Env.get("MORSE_CANARY_DIRECTORY", "")
  let out = Env.get("MORSE_CANARY_OUT", "")
  let accounts = String.split(Env.get("MORSE_CANARY_ACCOUNTS",
      "morse-canary-1,morse-canary-2,morse-canary-3"),
    ",")
  if String.length(directory) == 0 || String.length(out) == 0 do
    Err("MORSE_CANARY_DIRECTORY and MORSE_CANARY_OUT are required")
  else
    Ok(Canary {
      directory: directory,
      out: out,
      workdir: Env.get("MORSE_CANARY_WORKDIR", "/tmp"),
      accounts: accounts
    })
  end
end

fn run() -> Bool!String do
  let canary = canary_from_env()?
  let config = Env.get("MORSE_CANARY_CONFIG", "")
  if String.length(config) == 0 do
    return Err("MORSE_CANARY_CONFIG (the release's security config frame) is required")
  end
  if !Test.install_in_memory_secure_store()
    || !Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), Bytes.from_utf8(config)) do
    return Err("the secure store or config fixture is unavailable")
  end
  let role = Env.get("MORSE_CANARY_ROLE", "check")
  if role == "create" do
    create_all(canary, 0)?
  else if role == "extras" do
    extras_role(canary)?
  else if role == "watch" do
    watch(canary, database_path(canary, "watch")?, 0)
  else
    let database = database_path(canary, "check")?
    lookup_all(canary, database, 0)
    if Env.get("MORSE_CANARY_ANCHOR", "off") == "on" do
      anchor_role(canary, database)
    end
  end
  Ok(true)
end

test("canary device") do
  case run() do
    Err(error) -> do
      println("{\"kind\":\"error\",\"error\":" <> Json.encode_string(error) <> "}")
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
