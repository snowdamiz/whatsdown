from MobileCore import (
  create_account_export,
  directory_entry_export,
  oblivious_decapsulate_export,
  oblivious_encapsulate_export,
  resolve_request_export,
  verify_transparency_export
)
from Mobile.Codec import current_time
from Mobile.Oblivious import ObliviousPin, oblivious_exchange, oblivious_pin
from Privacy.Bhttp import bhttp_decode_request
from Privacy.Edge import decode_stamped_request
from Privacy.Ohttp import ohttp_decapsulate_request, ohttp_encapsulate_response
from Privacy.OhttpWire import OhttpKeyConfig, ohttp_key_config_encode, ohttp_response_message
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set
from Protocol.IdentityWire import decode_account_identity
from Protocol.V1 import DeviceSet
from Security.Config import SecurityConfig, SecurityWitness, security_config_encode
from Tests.Support import append, database_path, evidence_v2, repeated, vector
from Transparency.CompactWire import transparency_decode_lookup_v2
from Transparency.Wire import TransparencyLookup
from Transparency.Merkle import leaf_hash, sign_checkpoint, sign_witness

##! A lookup through Oblivious HTTP (protocol/ohttp-v1.md): the core seals the
##! stamped lookup to the pinned gateway key, the app posts it to the pinned
##! relay, and the core opens the answer and verifies the evidence. A fake
##! relay and gateway share a port here; the answers they give come from
##! files, since a request handler holds no state.

fn port() -> Int do
  18992
end

fn file(name :: String) -> String do
  "/tmp/mesh_mobile_oblivious_" <> name
end

fn must<T, E>(value :: Result<T, E>, error :: String) -> T!String do
  case value do
    Err(_) -> Err(error)
    Ok(output)
  end
end

fn read(name :: String) -> Bytes do
  case File.size(file(name)) do
    Err(_) -> Bytes.empty()
    Ok(size) -> case File.read_bytes(file(name), 0, size) do
      Err(_) -> Bytes.empty()
      Ok(value) -> value
    end
  end
end

fn gateway_pair() -> X25519KeyPair!String do
  case Crypto.x25519_from_seed(Bytes.from_hex("3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a")?) do
    Err(_) -> Err("gateway key failed")
    Ok(pair)
  end
end

# The gateway's answer to one inner request: the evidence for a lookup, and
# "claimed:" and the body for anything else.

fn inner_answer(method :: String, path :: String, content :: Bytes) -> (Int, Bytes)!String do
  if Bytes.length(content) > 0 do
    must(File.write_bytes(file("seen"), 0, content, true), "record failed")?
  else
    nil
  end
  if method == "POST" && path == "/v1/devices/resolve" do
    Ok((200, read("evidence")))
  else if method == "POST" && path == "/v1/prekeys/bundle" do
    Ok((200, must(Bytes.concat(Bytes.from_utf8("claimed:"), content), "concat failed")?))
  else
    Ok((404, Bytes.empty()))
  end
end

fn gateway_answer(body :: Bytes) -> Bytes!String do
  let pair = gateway_pair()?
  let (message, context) = ohttp_decapsulate_request(1, pair.private_key, body)?
  let inner = bhttp_decode_request(message)?
  let (status, content) = inner_answer(inner.method, inner.path, inner.content)?
  ohttp_encapsulate_response(context, ohttp_response_message(status, content)?)
end

fn oblivious_relay_handler(request :: Request) -> Response do
  if Request.header(request, "content-type") != Some("message/ohttp-req")
    && Request.header(request, "Content-Type") != Some("message/ohttp-req") do
    HTTP.response(415, "")
  else
    case gateway_answer(Request.body_bytes(request)) do
      Err(_) -> HTTP.response(422, "")
      Ok(sealed) -> HTTP.response_bytes(200, sealed)
    end
  end
end

actor oblivious_fake_relay() do
  HTTP.router()
    |> HTTP.on_post("/v1/ohttp", oblivious_relay_handler)
    |> HTTP.serve(18992)
end

fn signing_pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("signing key failed")
    Ok(pair)
  end
end

fn install(log_key :: Bytes,
  witness_a :: Bytes,
  witness_b :: Bytes,
  ohttp :: Bytes,
  relay_origin :: String) -> Bool!String do
  let delivery = case Crypto.x25519_generate() do
    Err(_) -> Err("delivery key failed")
    Ok(pair)
  end?
  let frame = security_config_encode(SecurityConfig {
    version: 2,
    service_public_key: log_key,
    delivery_public_key: delivery.public_key.bytes,
    abuse_difficulty: 8,
    threshold: 2,
    witnesses: [
      SecurityWitness { witness_id: "witness-a", public_key: witness_a, label: "Morse" },
      SecurityWitness { witness_id: "witness-b", public_key: witness_b, label: "Morse" }
    ],
    judge_program_id: "",
    log_account: "",
    rpc_urls: List.new(),
    relays: List.new(),
    issuer_origin: "",
    c2sp_origin: "",
    minimum_suite: 1,
    ohttp_key_config: ohttp,
    ohttp_relay: relay_origin,
    set_id: Bytes.empty()
  })?
  Ok(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), frame))
end

fn join(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts,
    Ok(Bytes.empty()),
    fn acc, part -> case acc do
      Err(error)
      Ok(bytes) -> append(bytes, part)
    end end)
end

fn vectors(parts :: List<Bytes>) -> Bytes!String do
  join(List.map(parts,
    fn part -> case vector(part) do
      Err(_) -> Bytes.empty()
      Ok(value) -> value
    end end))
end

# (relay origin, encapsulated request, sealed response key) of an answer.

fn encapsulated(answer :: Bytes) -> (String, Bytes, Bytes)!String do
  let first = must(Bytes.read_u32_be(answer, 0), "bad output")?
  let first_length = must(U64.to_int(first), "bad output")?
  let relay_origin = must(Bytes.to_utf8(must(Bytes.slice(answer, 4, first_length), "bad output")?),
    "bad output")?
  let rest = must(Bytes.slice(answer, 4 + first_length, Bytes.length(answer) - 4 - first_length),
    "bad output")?
  let second_length = must(U64.to_int(must(Bytes.read_u32_be(rest, 0), "bad output")?),
    "bad output")?
  let request = must(Bytes.slice(rest, 4, second_length), "bad output")?
  let tail = must(Bytes.slice(rest, 4 + second_length, Bytes.length(rest) - 4 - second_length),
    "bad output")?
  let third_length = must(U64.to_int(must(Bytes.read_u32_be(tail, 0), "bad output")?),
    "bad output")?
  Ok((relay_origin, request, must(Bytes.slice(tail, 4, third_length), "bad output")?))
end

fn post(url :: String, body :: Bytes) -> Bytes!String do
  let response = must(Http.build(:post, url)
      |> Http.header("Content-Type", "message/ohttp-req")
      |> Http.body_bytes(body)
      |> Http.max_response_bytes(1048640)
      |> Http.send(),
    "relay unreachable")?
  if response.status != 200 do
    Err("relay answered #{response.status}")
  else
    Ok(response.body_bytes)
  end
end

fn lookup_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("oblivious")?
  let path_bytes = Bytes.from_utf8(path)
  create_account_export(append(vector(path_bytes)?, vector(Bytes.from_utf8("alice"))?)?)?
  let entry = must(decode_directory_entry(directory_entry_export(path_bytes)?),
    "entry decode failed")?
  let account = must(decode_account_identity(entry.account_identity), "account decode failed")?
  let device_set = must(encode_device_set(DeviceSet {
      version: 1,
      username: entry.username,
      account_identity: entry.account_identity,
      sequence: account.directory_sequence,
      devices: [entry],
      revoked_device_ids: List.new()
    }),
    "device set encode failed")?
  let leaves = [leaf_hash(device_set)?]
  let log_pair = signing_pair()?
  let witness_a = signing_pair()?
  let witness_b = signing_pair()?
  let gateway = gateway_pair()?
  let key_config = ohttp_key_config_encode(OhttpKeyConfig {
    key_id: 1,
    public_key: gateway.public_key.bytes
  })?
  # Development builds have no gateway pinned: nothing to encapsulate.
  assert(install(log_pair.public_key.bytes,
    witness_a.public_key.bytes,
    witness_b.public_key.bytes,
    Bytes.empty(),
    "")?)
  let unpinned = oblivious_encapsulate_export(vectors([
    Bytes.from_utf8("POST"),
    Bytes.from_utf8("/v1/devices/resolve"),
    Bytes.from_utf8("x")
  ])?)?
  assert(Bytes.length(unpinned) == 0)
  let origin = "http://127.0.0.1:" <> Int.to_string(port())
  assert(install(log_pair.public_key.bytes,
    witness_a.public_key.bytes,
    witness_b.public_key.bytes,
    key_config,
    origin)?)
  let checkpoint = sign_checkpoint(log_pair.private_key,
    log_pair.public_key.bytes,
    U64.parse("1")?,
    leaves,
    repeated(0, 32)?,
    current_time()?)?
  let evidence = evidence_v2(device_set,
    leaves,
    0,
    0,
    checkpoint,
    [
      sign_witness("witness-a", witness_a.private_key, checkpoint)?,
      sign_witness("witness-b", witness_b.private_key, checkpoint)?
    ])?
  must(File.write_bytes(file("evidence"), 0, evidence, true), "evidence write failed")?
  # The core stamps the lookup and seals it; the app sees the relay, the
  # sealed request and a sealed response key, and posts the request.
  let lookup = resolve_request_export(vectors([path_bytes, Bytes.from_utf8("alice")])?)?
  let (relay_origin, sealed_request, sealed_key) = encapsulated(oblivious_encapsulate_export(vectors([
    Bytes.from_utf8("POST"),
    Bytes.from_utf8("/v1/devices/resolve"),
    lookup
  ])?)?)?
  assert(relay_origin == origin)
  assert(!String.contains(Bytes.to_hex(sealed_request), Bytes.to_hex(lookup)))
  assert(!String.contains(Bytes.to_hex(sealed_request), Bytes.to_hex(Bytes.from_utf8("alice"))))
  let sealed_answer = post(relay_origin <> "/v1/ohttp", sealed_request)?
  assert(!String.contains(Bytes.to_hex(sealed_answer), Bytes.to_hex(evidence)))
  # The gateway got exactly the stamped lookup the core made.
  let seen = read("seen")
  assert(Bytes.secure_equals(seen, lookup))
  let (_, payload) = must(decode_stamped_request(seen, 80), "stamp decode failed")?
  assert(must(transparency_decode_lookup_v2(payload), "lookup decode failed")?.username == "alice")
  # The core opens the answer: status 200 and the evidence, which verifies.
  let opened = oblivious_decapsulate_export(vectors([sealed_key, sealed_answer])?)?
  assert(must(Bytes.read_u16_be(opened, 0), "status read failed")? == 200)
  let body = must(Bytes.slice(opened, 2, Bytes.length(opened) - 2), "body slice failed")?
  assert(Bytes.secure_equals(body, evidence))
  let verified = verify_transparency_export(vectors([path_bytes, Bytes.from_utf8("alice"), body])?)?
  assert(Bytes.secure_equals(verified, device_set))
  # A changed answer, or the key of another request, opens nothing.
  let last = Bytes.length(sealed_answer) - 1
  let changed = join([
    must(Bytes.slice(sealed_answer, 0, last), "slice failed")?,
    must(Bytes.from_list([(must(Bytes.get(sealed_answer, last), "get failed")? + 1) % 256]),
      "byte failed")?
  ])?
  assert(case oblivious_decapsulate_export(vectors([sealed_key, changed])?) do
    Err(error) -> error == "oblivious_response_invalid"
    Ok(_) -> false
  end)
  let (_, _, other_key) = encapsulated(oblivious_encapsulate_export(vectors([
    Bytes.from_utf8("POST"),
    Bytes.from_utf8("/v1/devices/resolve"),
    lookup
  ])?)?)?
  assert(case oblivious_decapsulate_export(vectors([other_key, sealed_answer])?) do
    Err(_) -> true
    Ok(_) -> false
  end)
  # Only this build's routes, and no query on a lookup.
  assert(case oblivious_encapsulate_export(vectors([
    Bytes.from_utf8("DELETE"),
    Bytes.from_utf8("/v1/devices/resolve"),
    lookup
  ])?) do
    Err(error) -> error == "invalid_oblivious_request"
    Ok(_) -> false
  end)
  Ok(true)
end

fn exchange_proof() -> Bool!String do
  # A request the core makes itself (a prekey claim) takes the pinned relay.
  let pin = case oblivious_pin()? do
    None -> Err("no pin")
    Some(value) -> Ok(value)
  end?
  let (status, body) = oblivious_exchange(pin,
    "POST",
    "/v1/prekeys/bundle",
    Bytes.from_utf8("claim"),
    5000)?
  assert(status == 200 && Bytes.to_utf8(body) == Ok("claimed:claim"))
  let (missing, _) = oblivious_exchange(pin, "POST", "/v1/unknown", Bytes.empty(), 5000)?
  assert(missing == 404)
  # A relay that doesn't answer is an error, not an empty answer.
  let gone = ObliviousPin { config: pin.config, relay: "http://127.0.0.1:1" }
  assert(case oblivious_exchange(gone, "POST", "/v1/prekeys/bundle", Bytes.empty(), 2000) do
    Err(error) -> error == "oblivious_relay_unavailable"
    Ok(_) -> false
  end)
  Ok(true)
end

test("a lookup goes through the pinned relay sealed, and its evidence verifies once opened") do
  let _server = spawn(oblivious_fake_relay)
  Timer.sleep(100)
  case lookup_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
  case exchange_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
  Process.request_shutdown()
  Timer.sleep(50)
end
