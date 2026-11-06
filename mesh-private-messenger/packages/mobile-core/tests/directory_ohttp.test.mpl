from Ohttp.Keys import OhttpKeyConfig, encode_key_config
from Ohttp.BinaryHttp import decode_request, encode_response
from Ohttp.Types import BhttpResponse, BhttpField, BhttpFraming, default_bhttp_limits
from Mobile.DirectoryResolve import resolve_directory_device_set, native_directory_resolve
from MobileCore import (
  create_account_export,
  directory_entry_export,
  erase_account_export,
  verify_transparency_export
)
from Mobile.Platform import native_security_config
from Mobile.Profile import load_profile
from Mobile.Codec import current_time, mobile_write_u64
from Privacy.Edge import decode_stamped_request, verify_request_stamp
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set
from Protocol.IdentityWire import decode_account_identity
from Protocol.V1 import DeviceSet
from Tests.Support import append, vector, database_path, install_security_config, repeated
from Transparency.Config import encode_security_config
from Transparency.C2spText import checkpoint_note_text
from Transparency.Merkle import (
  WitnessAttestation,
  TransparencyCheckpoint,
  checkpoint_hash,
  leaf_hash_for,
  merkle_root_for,
  sign_tree_checkpoint_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  sign_witness
)
from Transparency.Wire import (
  TransparencyEvidence,
  encode_transparency_evidence,
  encode_checkpoint,
  decode_transparency_lookup
)
from Storage.Blobs import load_blob
from Storage.Keys import platform_key
from Mobile.Transparency import store_transparency_origin
from Mobile.OhttpContext import capture_native_ohttp_context

fn pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("fixture signer")
    Ok(value)
  end
end

fn witness(key :: borrow SigningPrivateKey,
  id :: String,
  checkpoint :: TransparencyCheckpoint,
  now :: U64) -> WitnessAttestation!String do
  if checkpoint.version == 1 do
    return sign_witness(id, key, checkpoint)
  end
  let seconds = U64.parse(Int.to_string(U64.to_int(now)? / 1000))?
  let statement = Bytes.from_utf8("cosignature/v1\ntime "
    <> U64.to_string(seconds)
    <> "\n"
    <> checkpoint_note_text(encode_checkpoint(checkpoint)?)?)
  let signature = case Crypto.sign(key, statement) do
    Err(_) -> return Err("fixture cosignature")
    Ok(value) -> value.bytes
  end
  Ok(WitnessAttestation {
    witness_id: id,
    checkpoint_hash: checkpoint_hash(checkpoint)?,
    signature: append(mobile_write_u64(seconds)?, signature)?
  })
end

fn evidence(version :: Int,
  entry :: Bytes,
  signer :: borrow SigningPrivateKey,
  service_public :: Bytes,
  a :: borrow SigningPrivateKey,
  b :: borrow SigningPrivateKey,
  now :: U64,
  old :: Int) -> Bytes!String do
  let leaves = [leaf_hash_for(version, entry)?]
  let checkpoint = sign_tree_checkpoint_for(version,
    signer,
    service_public,
    U64.parse("1")?,
    U64.parse("1")?,
    merkle_root_for(version, leaves)?,
    repeated(0, 32)?,
    now)?
  encode_transparency_evidence(TransparencyEvidence {
    entry_bytes: entry,
    inclusion: compact_inclusion_proof_for(version, leaves, 0)?,
    consistency: compact_consistency_proof_for(version,
      if old == 0 do
        []
      else
        leaves
      end,
      leaves)?,
    checkpoint: checkpoint,
    witnesses: [
      witness(a, "witness-a", checkpoint, now)?,
      witness(b, "witness-b", checkpoint, now)?
    ]
  })
end

fn fixture_new_account(path :: String) -> Bytes!String do
  create_account_export(append(vector(Bytes.from_utf8(path))?,
    vector(Bytes.from_utf8("replacement"))?)?)
end

fn fixture_request(path :: String, evidence :: Bytes) -> Bytes!String do
  append(append(vector(Bytes.from_utf8(path))?, vector(Bytes.from_utf8("alice"))?)?,
    vector(evidence)?)
end

fn reply(input :: Request,
  path :: String,
  version :: Int,
  first :: Bytes,
  same :: Bytes,
  mode :: Int) -> Response do
  case File.write(path <> ".direct-count", Int.to_string(count(path <> ".direct-count") + 1)) do
    Err(error) -> return HTTP.response(500, error)
    Ok(_) -> nil
  end
  if Request.header(input, "authorization") != None || Request.header(input, "cookie") != None do
    return HTTP.response(400, "private headers")
  end
  let (stamp, body) = case decode_stamped_request(Request.body_bytes(input), 76) do
    Err(_) -> return HTTP.response(400, "missing work")
    Ok(value) -> value
  end
  let lookup = case decode_transparency_lookup(body) do
    Err(_) -> return HTTP.response(400, "bad lookup")
    Ok(value) -> value
  end
  case verify_request_stamp("mesh-msg/v1/work/resolve",
    body,
    stamp,
    case current_time() do
      Ok(value) -> value
      Err(_) -> return HTTP.response(500, "clock")
    end,
    case U64.parse("300000") do
      Ok(value) -> value
      Err(_) -> return HTTP.response(500, "window")
    end,
    1) do
    Ok(true) -> nil
    _ -> return HTTP.response(403, "work rejected")
  end
  File.write(path <> ".v#{version}", Int.to_string(lookup.previous_tree_size))
  if version == 2 && (mode == 5 || mode == 6 || (mode == 8 && lookup.previous_tree_size > 0)) do
    return HTTP.response(404,
      if mode == 6 do
        "transparency_v2_not_active "
      else
        "transparency_v2_not_active"
      end)
  end
  if mode == 1 do
    return HTTP.response_bytes(200, Bytes.from_utf8("malformed evidence"))
  end
  if mode == 2 do
    return HTTP.response_with_headers(307, "", Map.put(Map.new(), "Location", "/untrusted"))
  end
  if mode == 9 do
    return case Bytes.repeat(0, 570419) do
      Err(_) -> HTTP.response(500, "fixture allocation")
      Ok(oversized) -> HTTP.response_bytes(200, oversized)
    end
  end
  if mode == 10 do
    Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
      Bytes.from_utf8("1\n1\nhttp://127.0.0.1:9\nhttp://127.0.0.1:18087\nhttp://127.0.0.1:18089\nws://127.0.0.1:18090/v1/mailbox/stream"))
  end
  if mode == 16 && lookup.previous_tree_size == 0 do
    # Another authenticated lookup wins after this request selected its basis.
    let request = case fixture_request(path, first) do
      Err(_) -> return HTTP.response(500, "fixture input")
      Ok(value) -> value
    end
    case verify_transparency_export(request) do
      Err(error) -> return HTTP.response(500, error)
      Ok(_) -> nil
    end
  end
  if mode == 4 || mode == 15 do
    case erase_account_export(Bytes.from_utf8(path)) do
      Err(_) -> return HTTP.response(500, "erase fixture")
      Ok(_) -> nil
    end
    if mode == 15 do
      case fixture_new_account(path) do
        Err(_) -> return HTTP.response(500, "replacement fixture")
        Ok(_) -> nil
      end
    end
  end
  HTTP.response_bytes(200,
    if lookup.previous_tree_size == 0 do
      first
    else
      same
    end)
end

actor resolve_peer(port :: Int,
  path :: String,
  first1 :: Bytes,
  same1 :: Bytes,
  first2 :: Bytes,
  same2 :: Bytes,
  mode :: Int) do
  HTTP.router()
    |> HTTP.on_post("/v1/devices/resolve",
      fn(input) -> reply(input, path, 1, first1, same1, mode) end)
    |> HTTP.on_post("/v2/devices/resolve",
      fn(input) -> reply(input,
        path,
        2,
        if mode == 7 do
          first1
        else
          first2
        end,
        same2,
        mode) end)
    |> HTTP.on_post("/v1/ohttp",
      fn(input) do
        case opaque_reply(input, path, first1, same1, first2, same2, port, mode) do
          Err(error) -> HTTP.response(500, error)
          Ok(value) -> value
        end
      end)
    |> HTTP.on_post("/untrusted",
      fn(_) do
        File.write(path <> ".redirect", "bad")
        HTTP.response(500, "followed")
      end)
    |> HTTP.serve(port)
end

fn run_case(mode :: Int) -> Result<(), String> do
  let signer = pair()?
  let a = pair()?
  let b = pair()?
  let delivery = case Crypto.x25519_generate() do
    Err(_) -> return Err("fixture delivery")
    Ok(value) -> value
  end
  assert(install_security_config(signer.public_key.bytes,
    a.public_key.bytes,
    b.public_key.bytes,
    delivery.public_key.bytes,
    1))
  if mode >= 5 && mode <= 8 do
    let config = native_security_config()?
    assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
      encode_security_config(%{config |
        version: 3,
        log_version: 2,
        legacy_threshold: config.threshold,
        legacy_witnesses: config.witnesses
      })?))
  end
  let path = database_path("native_resolve")?
  create_account_export(append(vector(Bytes.from_utf8(path))?, vector(Bytes.from_utf8("alice"))?)?)?
  let entry = case decode_directory_entry(directory_entry_export(Bytes.from_utf8(path))?) do
    Err(_) -> return Err("fixture directory entry")
    Ok(value) -> value
  end
  let account = case decode_account_identity(entry.account_identity) do
    Err(_) -> return Err("fixture account")
    Ok(value) -> value
  end
  let devices = case encode_device_set(DeviceSet {
    version: 1,
    username: entry.username,
    account_identity: entry.account_identity,
    sequence: account.directory_sequence,
    devices: [entry],
    revoked_device_ids: []
  }) do
    Err(_) -> return Err("fixture device set")
    Ok(value) -> value
  end
  let now = current_time()?
  let stamp = if mode == 13 do
    U64.subtract(now, U64.parse("300001")?)?
  else if mode == 14 do
    U64.add(now, U64.parse("90000")?)?
  else
    now
  end
  let first1 = evidence(1,
    devices,
    signer.private_key,
    signer.public_key.bytes,
    a.private_key,
    b.private_key,
    stamp,
    0)?
  let same1 = evidence(1,
    devices,
    signer.private_key,
    signer.public_key.bytes,
    a.private_key,
    b.private_key,
    stamp,
    1)?
  let first2 = evidence(2,
    devices,
    signer.private_key,
    signer.public_key.bytes,
    a.private_key,
    b.private_key,
    stamp,
    0)?
  let same2 = evidence(2,
    devices,
    signer.private_key,
    signer.public_key.bytes,
    a.private_key,
    b.private_key,
    stamp,
    1)?
  let attacker = pair()?
  let first1 = if mode == 11 do
    evidence(1,
      devices,
      attacker.private_key,
      attacker.public_key.bytes,
      a.private_key,
      b.private_key,
      stamp,
      0)?
  else if mode == 12 do
    evidence(1,
      devices,
      signer.private_key,
      signer.public_key.bytes,
      attacker.private_key,
      b.private_key,
      stamp,
      0)?
  else
    first1
  end
  let port = 20100 + mode
  let _server = spawn(resolve_peer, port, path, first1, same1, first2, same2, mode)
  Timer.sleep(75)
  let network = Bytes.from_utf8("1\n1\nhttp://127.0.0.1:#{port}\nhttp://127.0.0.1:#{port}\nhttp://127.0.0.1:18089\nws://127.0.0.1:18090/v1/mailbox/stream")
  assert(Test.set_push_token(Bytes.from_utf8("messenger/network/v1"), network))
  let security = encode_security_config(native_security_config()?)?
  let key = encode_key_config(OhttpKeyConfig { key_id: 37, public_key: ohttp_pair()?.public_key })?
  let companion = Bytes.from_utf8("1\n"
    <> Bytes.to_hex(Crypto.sha256(network))
    <> "\n"
    <> Bytes.to_hex(Crypto.sha256(security))
    <> "\n1\nrequired\n1\n0 18446744073709551615 "
    <> Bytes.to_base64(key))
  if mode == 22 do
    assert(Test.set_push_token(Bytes.from_utf8("messenger/ohttp/v1"), Bytes.empty()))
  else if mode == 23 do
    assert(Test.set_push_token(Bytes.from_utf8("messenger/ohttp/v1"), Bytes.from_utf8("malformed")))
  else
    assert(Test.set_push_token(Bytes.from_utf8("messenger/ohttp/v1"),
      if mode == 21 do
        Bytes.from_utf8("1\n"
          <> Bytes.to_hex(Crypto.sha256(network))
          <> "\n"
          <> Bytes.to_hex(Crypto.sha256(security))
          <> "\n1\noff\n0")
      else
        companion
      end))
  end
  if mode == 27 do
    store_transparency_origin(path, platform_key()?, "http://127.0.0.1:9")?
  end
  let original_fence = if mode == 16 do
    let context = capture_native_ohttp_context(path, load_blob(path, "profile/v1")?)?
    List.head(context.basis.records)
  else
    Bytes.empty()
  end
  let result = if mode == 0 || mode == 20 || mode == 21 do
    native_directory_resolve(append(vector(Bytes.from_utf8(path))?,
      vector(Bytes.from_utf8("alice"))?)?)
  else
    resolve_directory_device_set(path,
      if mode == 3 do
        "bob"
      else
        "alice"
      end)
  end
  if mode == 20 || mode == 21 do
    assert(Bytes.secure_equals(result?, devices))
    assert(Bytes.length(load_blob(path, "transparency-checkpoint/v1")?) > 0)
    assert(Bytes.length(load_blob(path, "transparency-witnesses/v2")?) > 0)
    println("m3-lookup-authenticated-device-cache:passed")
    let direct = count(path <> ".direct-count")
    let opaque = count(path <> ".ohttp-count")
    println("m3-lookup-transport direct=#{direct} ohttp=#{opaque}")
    assert(direct == if mode == 21 do
        1
      else
        0
      end)
    assert(opaque == if mode == 21 do
        0
      else
        1
      end)
    erase_account_export(Bytes.from_utf8(path))?
    for suffix in [".v1", ".v2", ".direct-count", ".ohttp-count"] do
      if File.exists(path <> suffix) do
        File.delete(path <> suffix)?
      end
    end
    File.delete(path)?
    return Ok(nil)
  end
  if mode == 0 || mode == 5 || mode == 8 || mode == 16 do
    assert(Bytes.secure_equals(result?, devices))
    let checkpoint = load_blob(path, "transparency-checkpoint/v1")?
    if mode != 8 do
      assert(Bytes.secure_equals(resolve_directory_device_set(path,
          if mode == 0 do
            "@" <> Bytes.to_hex(account.account_id)
          else
            "alice"
          end)?,
        devices))
      assert(Bytes.secure_equals(load_blob(path, "transparency-checkpoint/v1")?, checkpoint))
    else
      assert(Result.is_err(resolve_directory_device_set(path, "alice")))
      assert(!File.exists(path <> ".v1"))
    end
  else
    assert(Result.is_err(result))
    assert(Result.is_err(load_blob(path, "transparency-checkpoint/v1")))
    if mode == 4 do
      assert(Result.is_err(load_profile(path)))
    end
    if mode == 15 do
      assert(Result.is_ok(load_profile(path)))
    end
    if mode == 6 || mode == 7 do
      assert(!File.exists(path <> ".v1"))
    end
  end
  if mode == 16 do
    assert(File.read(path <> ".v1")? == "1")
    assert(Bytes.secure_equals(original_fence, load_blob(path, "ohttp-revision/v1")?))
  end
  if mode == 22 || mode == 23 || mode == 27 do
    assert(count(path <> ".direct-count") == 0)
    assert(count(path <> ".ohttp-count") == 0)
  else
    assert(count(path <> ".direct-count") == 0)
    assert(count(path <> ".ohttp-count") > 0)
  end
  assert(!File.exists(path <> ".redirect"))
  erase_account_export(Bytes.from_utf8(path))?
  for suffix in [".v1", ".v2", ".direct-count", ".ohttp-count"] do
    if File.exists(path <> suffix) do
      File.delete(path <> suffix)?
    end
  end
  File.delete(path)?
  Ok(nil)
end

fn count(path :: String) -> Int do
  case File.read(path) do
    Err(_) -> 0
    Ok(value) -> Option.unwrap_or(String.to_int(value), -1)
  end
end

fn ohttp_pair() -> X25519KeyPair!String do
  case Crypto.x25519_from_seed(Bytes.from_hex("ef0106ca50fd40bd29f8e1cfb6079fd37b4052d3bf4ce20b616aff8dd2bd8c5f")?) do
    Err(_) -> Err("fixture OHTTP key")
    Ok(value)
  end
end

fn opaque_reply(input :: Request,
  path :: String,
  first1 :: Bytes,
  same1 :: Bytes,
  first2 :: Bytes,
  same2 :: Bytes,
  port :: Int,
  mode :: Int) -> Response!String do
  File.write(path <> ".ohttp-count", Int.to_string(count(path <> ".ohttp-count") + 1))?
  assert(Request.header(input, "authorization") == None)
  assert(Request.header(input, "cookie") == None)
  assert(Request.header(input, "content-type") == Some("message/ohttp-req"))
  if mode == 2 do
    return Ok(HTTP.response_with_headers(307, "", Map.put(Map.new(), "Location", "/untrusted")))
  end
  if mode == 25 do
    return Ok(HTTP.response(404, "transparency_v2_not_active"))
  end
  let key = ohttp_pair()?.private_key
  let opening = case Ohttp.decapsulate_request(key, 37, Request.body_bytes(input)) do
    Err(_) -> return Err("fixture OHTTP authentication")
    Ok(value) -> value
  end
  let request = case decode_request(opening.plaintext, default_bhttp_limits()) do
    Err(_) -> return Err("fixture Binary HTTP request")
    Ok(value) -> value
  end
  assert(Bytes.secure_equals(request.method, Bytes.from_utf8("POST")))
  assert(Bytes.secure_equals(request.scheme, Bytes.from_utf8("http")))
  assert(Bytes.secure_equals(request.authority, Bytes.from_utf8("127.0.0.1:#{port}")))
  assert(List.length(request.trailers) == 0)
  let version = if Bytes.secure_equals(request.path, Bytes.from_utf8("/v1/devices/resolve")) do
    1
  else if Bytes.secure_equals(request.path, Bytes.from_utf8("/v2/devices/resolve")) do
    2
  else
    return Err("fixture target refused")
  end
  let first = if version == 1 || mode == 7 do
    first1
  else
    first2
  end
  let same = if version == 1 do
    same1
  else
    same2
  end
  let (stamp, body) = decode_stamped_request(request.content, 76)?
  assert(verify_request_stamp("mesh-msg/v1/work/resolve",
    body,
    stamp,
    current_time()?,
    U64.parse("300000")?,
    1)?)
  let lookup = decode_transparency_lookup(body)?
  File.write(path <> ".v#{version}", Int.to_string(lookup.previous_tree_size))?
  if mode == 10 do
    assert(Test.set_push_token(Bytes.from_utf8("messenger/network/v1"), Bytes.from_utf8("changed")))
  end
  if mode == 16 && lookup.previous_tree_size == 0 do
    verify_transparency_export(fixture_request(path, first)?)?
  end
  if mode == 4 || mode == 15 do
    erase_account_export(Bytes.from_utf8(path))?
    if mode == 15 do
      fixture_new_account(path)?
    end
  end
  let not_active = version == 2
    && (mode == 5 || mode == 6 || (mode == 8 && lookup.previous_tree_size > 0))
  let response = BhttpResponse {
    informational: [],
    status: if not_active do
      404
    else
      200
    end,
    fields: [
      BhttpField {
        name: Bytes.from_utf8("content-type"),
        value: Bytes.from_utf8("application/octet-stream")
      },
      BhttpField { name: Bytes.from_utf8("cache-control"), value: Bytes.from_utf8("no-store") }
    ],
    content: if not_active do
      Bytes.from_utf8(if mode == 6 do
        "transparency_v2_not_active "
      else
        "transparency_v2_not_active"
      end)
    else if mode == 1 do
      Bytes.from_utf8("malformed evidence")
    else if mode == 9 do
      repeated(0, 570419)?
    else if lookup.previous_tree_size == 0 do
      first
    else
      same
    end,
    trailers: []
  }
  let clear = case encode_response(response, BhttpKnownLength, default_bhttp_limits()) do
    Err(_) -> return Err("fixture Binary HTTP reply")
    Ok(value) -> value
  end
  let wire = case Ohttp.encapsulate_response(opening.response_context, clear) do
    Err(_) -> return Err("fixture OHTTP reply")
    Ok(value) -> value
  end
  Ok(HTTP.response_bytes_with_headers(200,
    if mode == 24 do
      append(Bytes.slice(wire, 0, Bytes.length(wire) - 1)?,
        repeated((Bytes.get(wire, Bytes.length(wire) - 1)? + 1) % 256, 1)?)?
    else
      wire
    end,
    Map.new()
      |> Map.put("Content-Type", "message/ohttp-res")
      |> Map.put("Cache-Control", "no-store")))
end

test("required native directory lookup verifies signed witnesses and never sends directly") do
  assert(Test.install_in_memory_secure_store())
  case run_case(20) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> println("m3-native-lookup-required:passed")
  end
end

test("explicit off alone retains the native direct directory route") do
  assert(Test.install_in_memory_secure_store())
  case run_case(21) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> println("m3-native-lookup-off:passed")
  end
end

test("required lookup errors refuse cache publication and direct fallback") do
  assert(Test.install_in_memory_secure_store())
  for mode in [1, 2, 3, 4, 6, 7, 9, 10, 11, 12, 13, 14, 15, 22, 23, 24, 25, 27] do
    case run_case(mode) do
      Err(error) -> do
        println("mode=#{mode}: #{error}")
        assert(false)
      end
      Ok(_) -> nil
    end
  end
  println("m3-native-lookup-refusals:passed")
end

test("only authenticated exact inner not-active selects the existing legacy plan") do
  assert(Test.install_in_memory_secure_store())
  case run_case(5) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> println("m3-native-lookup-cutover:passed")
  end
end

test("a winning signed checkpoint retries from a fresh checkpoint without replacing the original fence") do
  assert(Test.install_in_memory_secure_store())
  case run_case(16) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> println("m3-native-lookup-checkpoint-race:passed")
  end
end
